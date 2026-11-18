use super::Registry;
use super::transport::{http_error, limited_body, same_origin, valid_url};
use crate::config::parse_size;
use crate::error::Code;
use crate::reference::{validate_repository, validate_tag};
use crate::{Error, Result};
use http::header::{self, HeaderMap};
use http::{Method, StatusCode};
use serde_json::Value;
use std::collections::BTreeSet;

const TAG_PAGE_SIZE: usize = 1000;
const SMALL_PAGE_SIZE: usize = 100;

impl Registry {
    /// Fetch the repository's tag pages under the configured metadata and object limits.
    pub async fn list_tags(&self, repo: &str) -> Result<Vec<String>> {
        validate_repository(repo)?;
        self.paginated(
            &format!("v2/{repo}/tags/list"),
            "tags",
            &Self::scope(repo, "pull"),
            TAG_PAGE_SIZE,
            validate_tag,
        )
        .await
    }
    /// Find the highest numeric x.y.z tag, allowing an optional lowercase v prefix.
    ///
    /// Only unsuffixed versions match by default. A variant selects an exact suffix
    /// after a hyphen, such as `alpine` or `bookworm-slim`. Floating aliases and
    /// other suffixes are excluded; a plain version wins ties with a v-prefixed one.
    /// This compares versions, not push dates or a publisher's stable channel.
    pub async fn latest_tag(&self, repo: &str, variant: Option<&str>) -> Result<String> {
        if let Some(variant) = variant {
            validate_tag(variant).map_err(|_| {
                Error::input("variant must be a nonempty tag suffix, such as alpine")
            })?;
        }
        let pattern = variant.map_or_else(|| "*.*.*".to_owned(), |v| format!("*.*.*-{v}"));
        self.latest_matching_tag(repo, &pattern).await
    }
    /// Find the highest numeric release version matching a full tag pattern.
    ///
    /// Each `*` matches one nonempty numeric component, without leading zeros.
    /// All other characters are literal. An unprefixed pattern also accepts `v`-prefixed
    /// releases. The pattern determines the number of release components, so
    /// `*.*-trixie` accepts versions such as `18.7-trixie`. The numeric release
    /// comes first, followed by wildcard components in pattern order. A plain
    /// version wins ties with a v-prefixed one. The original tag is returned.
    pub async fn latest_matching_tag(&self, repo: &str, pattern: &str) -> Result<String> {
        if pattern.contains("**") || validate_tag(&pattern.replace('*', "0")).is_err() {
            return Err(Error::input(
                "--match expects a tag pattern with separated numeric wildcards, such as *.*.*-alpine*.*-slim",
            ));
        }
        let release = pattern.split('-').next().unwrap_or_default();
        let release = release.strip_prefix('v').unwrap_or(release);
        if !release.split('.').all(|part| {
            // Use the smallest wildcard digits that permit a multi-digit component.
            let mut sample = part.replace('*', "0");
            if part.starts_with('*') && part.len() > 1 {
                sample.replace_range(..1, "1");
            }
            version_number(&sample).is_some()
        }) {
            return Err(Error::input(
                "--match requires a numeric release before the suffix (for example, 18.*-trixie or v*.*.*). To copy a named tag, specify it directly without --latest.",
            ));
        }
        let prefix = if pattern.starts_with('v') { "" } else { "v?" };
        let expression = regex::escape(pattern).replace(r"\*", "([0-9]+)");
        let matcher = regex::Regex::new(&format!(r"\A{prefix}{expression}\z"))
            .map_err(|_| Error::input("invalid version tag pattern"))?;
        self.list_tags(repo)
            .await?
            .into_iter()
            .filter_map(|tag| {
                let captures = matcher.captures(&tag)?;
                let version = release_version(tag.split('-').next()?)?;
                let numbers = captures.iter().skip(1)
                    .map(|part| version_number(part?.as_str()))
                    .collect::<Option<Vec<_>>>()?;
                Some(((version, numbers, !tag.starts_with('v')), tag))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, tag)| tag)
            .ok_or_else(|| {
                Error::new(
                    Code::NotFound,
                    format!(
                        "no version tag matching {pattern} found in {}/{repo}; use `tag ls` to list available tags",
                        self.name(),
                    ),
                )
            })
    }
    /// Fetch registry catalog pages when the server exposes that optional API.
    pub async fn list_repositories(&self) -> Result<Vec<String>> {
        self.paginated(
            "v2/_catalog",
            "repositories",
            "registry:catalog:*",
            SMALL_PAGE_SIZE,
            validate_repository,
        )
        .await
    }
    async fn paginated(
        &self,
        path: &str,
        field: &str,
        scope: &str,
        mut page_size: usize,
        validate: fn(&str) -> Result<()>,
    ) -> Result<Vec<String>> {
        let base = self.url(path)?;
        let page_url = |size: usize, last: Option<&str>| {
            let mut url = base.clone();
            url.query_pairs_mut().append_pair("n", &size.to_string());
            if let Some(last) = last {
                url.query_pairs_mut().append_pair("last", last);
            }
            url
        };
        let mut next = page_url(page_size, None);
        let mut visited = BTreeSet::new();
        let mut values = BTreeSet::new();
        let page_limit = parse_size(&self.config().transfer.max_manifest_size)?;
        let metadata_limit = parse_size(&self.config().transfer.max_metadata_size)?;
        let mut bytes = 0;
        for page in 0..1000 {
            if bytes == metadata_limit {
                return Err(Error::input("registry listing exceeds metadata limit"));
            }
            if !visited.insert(next.as_str().to_string()) {
                return Err(Error::input("registry pagination loop detected"));
            }
            let (response, _) = self
                .request(
                    Method::GET,
                    next.clone(),
                    scope,
                    HeaderMap::new(),
                    None,
                    false,
                    true,
                )
                .await?;
            // The initial request has only one query parameter. Some registries reject a
            // large n instead of returning a smaller page with a continuation link.
            if page == 0
                && page_size > SMALL_PAGE_SIZE
                && matches!(
                    response.status(),
                    StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
                )
            {
                page_size = SMALL_PAGE_SIZE;
                next = page_url(page_size, None);
                continue;
            }
            if response.status() != StatusCode::OK {
                return Err(http_error(&response));
            }
            let mut link = None;
            for h in response.headers().get_all(header::LINK) {
                if let Some(v) = h.to_str().ok().and_then(next_link) {
                    link = Some(v);
                    break;
                }
            }
            let raw = limited_body(response, page_limit.min(metadata_limit - bytes)).await?;
            bytes += raw.len() as u64;
            let body: Value = serde_json::from_slice(&raw)?;
            let list = match body.get(field) {
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|v| {
                        let value = v
                            .as_str()
                            .ok_or_else(|| Error::input("non-string item in registry listing"))?;
                        validate(value)?;
                        Ok(value.to_owned())
                    })
                    .collect::<Result<Vec<_>>>()?,
                Some(Value::Null) => vec![],
                _ => return Err(Error::input("registry listing omitted the expected array")),
            };
            let count = list.len();
            let last = list.last().cloned();
            let previous = values.len();
            values.extend(list);
            if values.len() > self.config().transfer.max_objects {
                return Err(Error::input("listing exceeds configured max_objects"));
            }
            if let Some(link) = link {
                let url = next.join(&link)?;
                valid_url(&url)?;
                if !same_origin(&url, &base) || url.path() != base.path() {
                    return Err(Error::input("unsafe registry pagination URL"));
                }
                next = url;
            } else if count >= page_size {
                if values.len() == previous {
                    return Err(Error::input("registry ignored pagination parameters"));
                }
                next = page_url(page_size, last.as_deref());
            } else {
                return Ok(values.into_iter().collect());
            }
        }
        Err(Error::input("pagination page limit exceeded"))
    }
}

fn release_version(tag: &str) -> Option<Vec<u64>> {
    tag.strip_prefix('v')
        .unwrap_or(tag)
        .split('.')
        .map(version_number)
        .collect()
}

fn version_number(part: &str) -> Option<u64> {
    if part.is_empty()
        || !part.bytes().all(|b| b.is_ascii_digit())
        || (part.len() > 1 && part.starts_with('0'))
    {
        return None;
    }
    part.parse().ok()
}

pub(super) fn next_link(header: &str) -> Option<String> {
    // Split only after closing angle bracket so a comma in a URI is preserved.
    let mut rest = header;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let end = rest.find('>')?;
        let uri = &rest[..end];
        let after = &rest[end + 1..];
        let split = after.find(',').unwrap_or(after.len());
        let parameters = &after[..split];
        if parameters.split(';').any(|p| {
            p.trim()
                .strip_prefix("rel=")
                .is_some_and(|v| v.trim_matches('"').split_whitespace().any(|r| r == "next"))
        }) {
            return Some(uri.to_string());
        }
        rest = &after[split..];
    }
    None
}

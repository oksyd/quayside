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

impl Registry {
    /// Fetch the repository's tag pages under the configured metadata and object limits.
    pub async fn list_tags(&self, repo: &str) -> Result<Vec<String>> {
        validate_repository(repo)?;
        self.paginated(
            &format!("v2/{repo}/tags/list"),
            "tags",
            &Self::scope(repo, "pull"),
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
        self.list_tags(repo)
            .await?
            .into_iter()
            .filter_map(|tag| {
                let (version, suffix) = tag
                    .split_once('-')
                    .map_or((tag.as_str(), None), |(v, suffix)| (v, Some(suffix)));
                if suffix != variant {
                    return None;
                }
                release_version(version).map(|version| (version, tag))
            })
            .max_by_key(|(version, tag)| (*version, !tag.starts_with('v')))
            .map(|(_, tag)| tag)
            .ok_or_else(|| {
                let pattern = match variant {
                    Some(variant) => format!("x.y.z-{variant}"),
                    None => "x.y.z".into(),
                };
                Error::new(
                    Code::NotFound,
                    format!(
                        "no {pattern} version tag found in {}/{repo}; use `tag ls` to list available tags",
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
            validate_repository,
        )
        .await
    }
    async fn paginated(
        &self,
        path: &str,
        field: &str,
        scope: &str,
        validate: fn(&str) -> Result<()>,
    ) -> Result<Vec<String>> {
        let base = self.url(path)?;
        let mut next = base.clone();
        next.query_pairs_mut().append_pair("n", "100");
        let mut visited = BTreeSet::new();
        let mut values = BTreeSet::new();
        let page_limit = parse_size(&self.config().transfer.max_manifest_size)?;
        let metadata_limit = parse_size(&self.config().transfer.max_metadata_size)?;
        let mut bytes = 0;
        for _ in 0..1000 {
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
            } else if count >= 100 {
                if values.len() == previous {
                    return Err(Error::input("registry ignored pagination parameters"));
                }
                next = base.clone();
                next.query_pairs_mut()
                    .append_pair("n", "100")
                    .append_pair("last", last.as_deref().unwrap_or(""));
            } else {
                return Ok(values.into_iter().collect());
            }
        }
        Err(Error::input("pagination page limit exceeded"))
    }
}

fn release_version(tag: &str) -> Option<[u64; 3]> {
    let mut parts = tag.strip_prefix('v').unwrap_or(tag).split('.');
    let mut version = [0; 3];
    for component in &mut version {
        let part = parts.next()?;
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *component = part.parse().ok()?;
    }
    parts.next().is_none().then_some(version)
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

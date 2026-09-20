use super::Registry;
use super::transport::{http_error, limited_body, same_origin, valid_url};
use crate::config::parse_size;
use crate::reference::validate_repository;
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
        )
        .await
    }
    /// Fetch registry catalog pages when the server exposes that optional API.
    pub async fn list_repositories(&self) -> Result<Vec<String>> {
        self.paginated("v2/_catalog", "repositories", "registry:catalog:*")
            .await
    }
    async fn paginated(&self, path: &str, field: &str, scope: &str) -> Result<Vec<String>> {
        let base = self.url(path)?;
        let mut next = base.clone();
        next.query_pairs_mut().append_pair("n", "100");
        let mut visited = BTreeSet::new();
        let mut values = BTreeSet::new();
        for _ in 0..1000 {
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
            let body: Value = serde_json::from_slice(
                &limited_body(
                    response,
                    parse_size(&self.config().transfer.max_manifest_size)?,
                )
                .await?,
            )?;
            let list = match body.get(field) {
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| Error::input("non-string item in registry listing"))
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

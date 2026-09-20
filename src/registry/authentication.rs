use super::Registry;
use super::transport::{
    authority, client, http_error, is_connect, is_timeout, limited_body, retry_delay, same_origin,
    valid_url,
};
use crate::auth::Credential;
use crate::config::duration;
use crate::error::Code;
use crate::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{self, HeaderValue};
use http::{Method, StatusCode};
use serde_json::Value;
use std::time::{Duration, Instant};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(super) enum CachedAuth {
    Basic,
    Bearer {
        token: Zeroizing<String>,
        until: Instant,
    },
}
impl CachedAuth {
    pub(super) fn fresh(&self) -> bool {
        match self {
            Self::Basic => true,
            Self::Bearer { until, .. } => Instant::now() < *until,
        }
    }
}
pub(super) fn basic_auth(credential: &Credential) -> Result<HeaderValue> {
    let raw = Zeroizing::new(format!("{}:{}", credential.username, credential.secret));
    let encoded = Zeroizing::new(format!("Basic {}", STANDARD.encode(raw.as_bytes())));
    let mut value =
        HeaderValue::from_str(&encoded).map_err(|_| Error::input("invalid basic credentials"))?;
    value.set_sensitive(true);
    Ok(value)
}
impl Registry {
    pub(super) async fn token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
    ) -> Result<CachedAuth> {
        let mut url = Url::parse(realm)?;
        valid_url(&url)?;
        let host = authority(&url);
        let local = same_origin(&url, &self.inner.base);
        // Only the original registry origin may issue this challenge (enforced by request()).
        // A verified HTTPS registry can delegate authentication to an HTTPS token service.
        // A nonempty auth_hosts list remains an optional explicit restriction.
        let listed = self.inner.policy.auth_hosts.iter().any(|h| h == &host);
        if !local && !self.inner.policy.auth_hosts.is_empty() && !listed {
            return Err(Error::new(
                Code::Unauthorized,
                "token host is excluded by this registry's auth_hosts policy",
            ));
        }
        if !local && self.inner.base.scheme() != "https" && !listed {
            return Err(Error::new(
                Code::Unauthorized,
                "an HTTP registry cannot automatically authorize a cross-origin token service; use HTTPS or explicitly configure --auth-host",
            ));
        }
        if self.inner.base.scheme() == "https" && url.scheme() != "https" {
            return Err(Error::new(
                Code::Unauthorized,
                "refusing HTTPS-to-HTTP token service downgrade",
            ));
        }
        let policy = if local {
            self.inner.policy.clone()
        } else {
            self.inner.config.for_registry(&host)
        };
        if url.scheme() == "http" && !policy.plain_http {
            return Err(Error::new(
                Code::Unauthorized,
                "refusing credentials over HTTP to a token service without explicit plain_http configuration",
            ));
        }
        // A registry-selected token host never inherits another host's CA / insecure settings.
        let http = client(&url, &self.inner.config, &policy)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = service {
                query.append_pair("service", service);
            }
            if !scope.is_empty() {
                query.append_pair("scope", scope);
            }
            query.append_pair("client_id", "quayside");
        }
        let max_retries = self.inner.config.transfer.max_retries;
        let mut attempt = 0;
        let response = loop {
            let mut request = http
                .inner
                .request(Method::GET, url.as_str())
                .total_timeout(duration(&self.inner.config.transfer.metadata_timeout)?);
            if let Some(credential) = &self.inner.credential {
                request = request.header(header::AUTHORIZATION, basic_auth(credential)?);
            }
            match request.send_stream().await {
                Ok(r)
                    if (r.status() == StatusCode::TOO_MANY_REQUESTS
                        || r.status().is_server_error())
                        && attempt < max_retries =>
                {
                    let delay = retry_delay(Some(&r), attempt);
                    drop(r);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Err(e)
                    if crate::error::certificate_code(&e).is_none()
                        && (is_timeout(&e) || is_connect(&e))
                        && attempt < max_retries =>
                {
                    tokio::time::sleep(retry_delay(None, attempt)).await;
                    attempt += 1;
                }
                Ok(r) => break r,
                Err(e) => return Err(http.failure(e, &url)),
            }
        };
        if response.status() != StatusCode::OK {
            return Err(http_error(&response));
        }
        let bytes = Zeroizing::new(limited_body(response, 1024 * 1024).await?.to_vec());
        let mut v: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::input("token service returned invalid JSON"))?;
        let mut token = None;
        for key in ["token", "access_token"] {
            if let Some(value) = v.get_mut(key)
                && let Value::String(candidate) = value.take()
                && !candidate.is_empty()
            {
                token = Some(candidate);
                break;
            }
        }
        let token = token
            .ok_or_else(|| Error::new(Code::Unauthorized, "token service returned no token"))?;
        let ttl = v
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(60)
            .clamp(1, 86_400);
        let margin = (ttl / 10).clamp(0, 30);
        Ok(CachedAuth::Bearer {
            token: Zeroizing::new(token),
            until: Instant::now() + Duration::from_secs(ttl.saturating_sub(margin)),
        })
    }
}

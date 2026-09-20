use super::Registry;
use super::authentication::{CachedAuth, basic_auth};
use crate::auth::{Challenge, challenges};
use crate::config::{Config, RegistryConfig, duration};
use crate::diagnostics::{self, Level};
use crate::error::Code;
use crate::{Error, Result};
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode};
use reqx::prelude::{RedirectPolicy, RetryPolicy, StatusPolicy, TlsRootStore};
use reqx::{Client, ResponseStream as Response, TransportErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncReadExt;
use url::Url;

struct PendingWrite<'a>(Option<&'a AtomicBool>);

impl Drop for PendingWrite<'_> {
    fn drop(&mut self) {
        if let Some(changed) = self.0 {
            changed.store(true, Ordering::SeqCst);
        }
    }
}

pub(super) fn content_length(response: &Response) -> Option<u64> {
    response
        .headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

pub(super) struct HttpClient {
    pub(super) inner: Client,
    proxy: crate::proxy::Proxy,
}
impl HttpClient {
    pub(super) fn failure(&self, error: reqx::Error, url: &Url) -> Error {
        Error::request(error, url, self.proxy.description(url))
    }
}

pub(super) fn client(base: &Url, config: &Config, policy: &RegistryConfig) -> Result<HttpClient> {
    let proxy = crate::proxy::for_scheme(base.scheme());
    if policy.insecure_skip_tls_verify {
        return Err(Error::unsupported(
            "reqx does not support insecure_skip_tls_verify; configure ca_file with a trusted CA instead",
        ));
    }
    let mut builder = Client::builder(base.as_str())
        .redirect_policy(RedirectPolicy::none())
        .retry_policy(RetryPolicy::disabled())
        .default_status_policy(StatusPolicy::Response)
        .auto_accept_encoding(false)
        .tls_root_store(TlsRootStore::System)
        .connect_timeout(duration(&config.transfer.connect_timeout)?)
        .request_timeout(duration(&config.transfer.idle_timeout)?)
        .default_header(
            header::USER_AGENT,
            HeaderValue::from_static(concat!("quayside/", env!("CARGO_PKG_VERSION"))),
        );
    if let Some(url) = &proxy.url {
        let uri = url.parse().map_err(|_| Error::input("invalid proxy URL"))?;
        builder = builder.http_proxy(uri).no_proxy(proxy.transport_rules());
    }
    if let Some(path) = &policy.ca_file {
        let bytes = std::fs::read(path)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::input("CA bundle exceeds 4MiB"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::input("CA file must be a PEM bundle"))?;
        let mut remaining = text;
        let mut count = 0;
        while let Some(start) = remaining.find("-----BEGIN CERTIFICATE-----") {
            remaining = &remaining[start..];
            let end = remaining
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| Error::input("incomplete PEM certificate"))?
                + "-----END CERTIFICATE-----".len();
            builder = builder.tls_root_ca_pem(remaining.as_bytes()[..end].to_vec());
            remaining = &remaining[end..];
            count += 1;
        }
        if count == 0 {
            return Err(Error::input("CA file contains no PEM certificates"));
        }
    }
    let inner = builder.build().map_err(|error| match error {
        reqx::Error::InvalidNoProxyRule { .. } => Error::input("Invalid no_proxy rule: expected a hostname, IP address, CIDR, optional port, or wildcard"),
        _ => error.into(),
    })?;
    Ok(HttpClient { inner, proxy })
}
pub(super) fn is_connect(error: &reqx::Error) -> bool {
    matches!(
        error,
        reqx::Error::Transport {
            kind: TransportErrorKind::Dns | TransportErrorKind::Connect | TransportErrorKind::Tls,
            ..
        }
    )
}
pub(super) fn is_timeout(error: &reqx::Error) -> bool {
    matches!(
        error,
        reqx::Error::Timeout { .. } | reqx::Error::DeadlineExceeded { .. }
    )
}
pub(super) fn authority(url: &Url) -> String {
    url[url::Position::BeforeHost..url::Position::AfterPort].to_string()
}
pub(super) fn valid_url(url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::input("unsafe or unsupported server-provided URL"));
    }
    Ok(())
}
pub(super) fn same_origin(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin()
}
pub(super) fn http_error(response: &Response) -> Error {
    let status = response.status();
    let code = match status.as_u16() {
        401 => Code::Unauthorized,
        403 => Code::Forbidden,
        404 => Code::NotFound,
        405 | 415 | 501 => Code::Unsupported,
        409 | 412 => Code::Conflict,
        408 | 429 | 500..=599 => Code::Network,
        _ => Code::Execution,
    };
    // Deliberately omit server bodies, paths and query strings from errors.
    Error::new(
        code,
        format!(
            "{} returned HTTP {status}",
            Url::parse(response.uri_raw())
                .map(|url| authority(&url))
                .unwrap_or_else(|_| "server".into())
        ),
    )
}
/// Read a response into memory while enforcing a hard byte limit.
pub async fn limited_body(mut response: Response, limit: u64) -> Result<Bytes> {
    if content_length(&response).is_some_and(|n| n > limit) {
        return Err(Error::input("HTTP body exceeds configured size limit"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = response
            .read(&mut buffer)
            .await
            .map_err(|_| Error::network("HTTP response body read failed"))?;
        if size == 0 {
            break;
        }
        let chunk = &buffer[..size];
        if bytes.len() as u64 + chunk.len() as u64 > limit {
            return Err(Error::input("HTTP body exceeds configured size limit"));
        }
        bytes.extend_from_slice(chunk);
    }
    Ok(Bytes::from(bytes))
}
pub(super) fn retry_delay(response: Option<&Response>, attempt: usize) -> Duration {
    if let Some(value) = response
        .and_then(|r| r.headers().get(header::RETRY_AFTER))
        .and_then(|h| h.to_str().ok())
    {
        let secs = value.parse::<u64>().ok().or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .and_then(|d| d.duration_since(SystemTime::now()).ok())
                .map(|d| d.as_secs())
        });
        if let Some(secs) = secs {
            return Duration::from_secs(secs.min(60));
        }
    }
    let jitter = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_millis() as u64 % 200)
        .unwrap_or(0);
    Duration::from_millis((250u64 << attempt.min(6)) + jitter)
}

impl Registry {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn request(
        &self,
        method: Method,
        mut url: Url,
        scope: &str,
        headers: HeaderMap,
        body: Option<Bytes>,
        streaming: bool,
        retry_safe: bool,
    ) -> Result<(Response, bool)> {
        valid_url(&url)?;
        let mut auth = self
            .inner
            .cache
            .lock()
            .await
            .get(scope)
            .filter(|a| a.fresh())
            .cloned();
        let mut refreshes = 0usize;
        let mut retries = 0usize;
        let mut redirects = 0usize;
        loop {
            let local = same_origin(&url, &self.inner.base);
            let http = if local {
                &self.inner.client
            } else {
                &self.inner.public_client
            };
            let mut request = http.inner.request(method.clone(), url.as_str()).header(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            for (name, value) in &headers {
                request = request.header(name.clone(), value.clone());
            }
            if !streaming {
                request =
                    request.total_timeout(duration(&self.inner.config.transfer.metadata_timeout)?);
            }
            if let Some(b) = &body {
                request = request.body(b.clone());
            } else if method == Method::POST || method == Method::PUT || method == Method::PATCH {
                request = request.header(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            let mut used_auth = false;
            if local && let Some(a) = &auth {
                match a {
                    CachedAuth::Basic => {
                        if let Some(c) = &self.inner.credential {
                            request = request.header(header::AUTHORIZATION, basic_auth(c)?);
                            used_auth = true;
                        }
                    }
                    CachedAuth::Bearer { token, .. } => {
                        let mut value =
                            HeaderValue::from_str(&format!("Bearer {}", token.as_str())).map_err(
                                |_| {
                                    Error::new(
                                        Code::Unauthorized,
                                        "token service returned invalid token characters",
                                    )
                                },
                            )?;
                        value.set_sensitive(true);
                        request = request.header(header::AUTHORIZATION, value);
                        used_auth = true;
                    }
                }
            }
            diagnostics::log(
                Level::Debug,
                format_args!(
                    "HTTP {method} to {} attempt {}",
                    authority(&url),
                    retries + 1
                ),
            );
            diagnostics::log(
                Level::Trace,
                format_args!(
                    "HTTP body bytes: {}; streaming: {streaming}",
                    body.as_ref().map_or(0, Bytes::len)
                ),
            );
            let started = Instant::now();
            let mutation = method != Method::GET && method != Method::HEAD;
            // Cancellation before the response arrives leaves a write's outcome uncertain.
            // Completed requests retain the precise status/connect-error handling below.
            let mut pending = PendingWrite(mutation.then_some(self.inner.changed.as_ref()));
            let response = request.send_stream().await;
            pending.0 = None;
            let response = match response {
                Ok(r) => r,
                Err(e)
                    if crate::error::certificate_code(&e).is_none()
                        && retry_safe
                        && retries < self.inner.config.transfer.max_retries
                        && (is_connect(&e)
                            || is_timeout(&e)
                            || matches!(e, reqx::Error::Transport { .. })) =>
                {
                    if mutation && !is_connect(&e) {
                        self.inner.changed.store(true, Ordering::SeqCst);
                    }
                    tokio::time::sleep(retry_delay(None, retries)).await;
                    retries += 1;
                    continue;
                }
                Err(e) => {
                    if mutation && !is_connect(&e) {
                        self.inner.changed.store(true, Ordering::SeqCst);
                    }
                    return Err(http.failure(e, &url));
                }
            };
            diagnostics::log(
                Level::Debug,
                format_args!(
                    "HTTP {method} from {}: {} in {}ms",
                    authority(&url),
                    response.status(),
                    started.elapsed().as_millis()
                ),
            );
            // 401/403 rejection alone is not a partial write. Success, a server error or
            // a lost write response can mean remote state was already changed.
            if mutation && (response.status().is_success() || response.status().is_server_error()) {
                self.inner.changed.store(true, Ordering::SeqCst);
            }
            if response.status() == StatusCode::UNAUTHORIZED && local && refreshes < 2 {
                let refresh_lock = self.auth_refresh_lock(scope).await;
                let _refresh = refresh_lock.lock().await;
                let recent = self
                    .inner
                    .cache
                    .lock()
                    .await
                    .get(scope)
                    .filter(|a| a.fresh())
                    .cloned();
                // Another request may have refreshed the rejected credential while we waited.
                // Different permission scopes have separate locks and can authenticate concurrently.
                if recent.is_some() && recent != auth {
                    auth = recent;
                    refreshes += 1;
                    continue;
                }
                let mut offers = Vec::new();
                for h in response.headers().get_all(header::WWW_AUTHENTICATE) {
                    let h = h
                        .to_str()
                        .map_err(|_| Error::input("invalid authentication header"))?;
                    offers.extend(challenges(h)?);
                }
                let selected = offers
                    .iter()
                    .find(|c| matches!(c, Challenge::Bearer { .. }))
                    .or_else(|| offers.first());
                auth = match selected {
                    Some(Challenge::Bearer {
                        realm,
                        service,
                        scope: offered_scope,
                    }) => {
                        let requested = if scope.is_empty() {
                            offered_scope.as_deref().unwrap_or("")
                        } else {
                            scope
                        };
                        Some(self.token(realm, service.as_deref(), requested).await?)
                    }
                    Some(Challenge::Basic) if self.inner.credential.is_some() => {
                        Some(CachedAuth::Basic)
                    }
                    _ => {
                        return Err(Error::new(
                            Code::Unauthorized,
                            "registry requires authentication; use quayside login",
                        ));
                    }
                };
                if let Some(a) = &auth {
                    self.inner
                        .cache
                        .lock()
                        .await
                        .insert(scope.to_owned(), a.clone());
                }
                refreshes += 1;
                continue;
            }
            if response.status().is_redirection() && response.status() != StatusCode::NOT_MODIFIED {
                if method != Method::GET && method != Method::HEAD {
                    return Err(Error::unsupported(
                        "redirected write request refused; configure the canonical registry endpoint",
                    ));
                }
                if redirects >= 8 {
                    return Err(Error::network("redirect limit exceeded"));
                }
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::input("redirect has no valid Location"))?;
                let next = url.join(location)?;
                valid_url(&next)?;
                if next.scheme() == "http"
                    && (!same_origin(&next, &self.inner.base) || url.scheme() == "https")
                {
                    return Err(Error::new(
                        Code::Unauthorized,
                        "refusing insecure cross-origin redirect or HTTPS downgrade",
                    ));
                }
                // `headers` never contains Authorization. Only the local-origin branch adds it.
                url = next;
                redirects += 1;
                continue;
            }
            if retry_safe
                && retries < self.inner.config.transfer.max_retries
                && (response.status() == StatusCode::TOO_MANY_REQUESTS
                    || response.status() == StatusCode::REQUEST_TIMEOUT
                    || response.status().is_server_error())
            {
                let delay = retry_delay(Some(&response), retries);
                drop(response);
                diagnostics::log(
                    Level::Warn,
                    format_args!(
                        "retrying HTTP {method} to {} after {}ms",
                        authority(&url),
                        delay.as_millis()
                    ),
                );
                tokio::time::sleep(delay).await;
                retries += 1;
                continue;
            }
            return Ok((response, used_auth));
        }
    }
}

//! Bounded response diagnostics without URLs, credentials or arbitrary server messages.
use super::transport::{http_error, limited_body};
use crate::Error;
use http::Method;
use reqx::ResponseStream;
use std::time::Duration;
use url::Url;

pub(super) fn operation(method: &Method, url: &Url) -> &'static str {
    let path = url.path();
    if path.starts_with("/v2/") {
        if let Some((_, selector)) = path.rsplit_once("/manifests/")
            && !selector.is_empty()
            && !selector.contains('/')
        {
            return if *method == Method::PUT {
                if selector.contains(':') {
                    "publish manifest by digest"
                } else {
                    "publish manifest tag"
                }
            } else {
                "read manifest"
            };
        }
        if path.contains("/blobs/uploads/") {
            return match *method {
                Method::POST => "start blob upload",
                Method::PATCH => "upload blob chunk",
                Method::PUT => "commit blob upload",
                Method::GET => "check blob upload",
                _ => "blob upload request",
            };
        }
        if path.contains("/blobs/") {
            return if *method == Method::HEAD {
                "check blob"
            } else {
                "download blob"
            };
        }
        if path.contains("/referrers/") {
            return "list referrers";
        }
        if path.ends_with("/tags/list") {
            return "list tags";
        }
        if path == "/v2/" {
            return "check registry";
        }
    }
    "content request"
}

pub(super) async fn response_error(
    response: ResponseStream,
    operation: &str,
    authorization: &str,
) -> Error {
    let mut error = http_error(&response);
    error.message.push_str(&format!(
        "\nOperation: {operation}\nAuthorization: {authorization}"
    ));
    for name in ["x-acs-request-id", "x-oss-request-id", "x-request-id"] {
        if let Some(id) = response.headers().get(name).and_then(|v| v.to_str().ok())
            && !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            error.message.push_str(&format!("\nRequest ID: {id}"));
            break;
        }
    }
    // A broken or slow error body must never replace the original HTTP error.
    if let Ok(Ok(body)) =
        tokio::time::timeout(Duration::from_secs(1), limited_body(response, 16 * 1024)).await
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body)
    {
        let mut codes = std::collections::BTreeSet::new();
        if let Some(entries) = value.get("errors").and_then(|v| v.as_array()) {
            for entry in entries {
                if let Some(code) = entry.get("code").and_then(|v| v.as_str())
                    && let Some(code) = known_code(code)
                {
                    codes.insert(code);
                }
            }
        }
        if let Some(code) = value.get("Code").and_then(|v| v.as_str())
            && let Some(code) = known_code(code)
        {
            codes.insert(code);
        }
        if !codes.is_empty() {
            error.message.push_str(&format!(
                "\nRegistry error: {}",
                codes.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    error
}

fn known_code(code: &str) -> Option<&'static str> {
    // Return only constants: error messages/details and unknown codes may echo secrets.
    const CODES: &[&str] = &[
        "BLOB_UNKNOWN",
        "BLOB_UPLOAD_INVALID",
        "BLOB_UPLOAD_UNKNOWN",
        "DIGEST_INVALID",
        "MANIFEST_BLOB_UNKNOWN",
        "MANIFEST_INVALID",
        "MANIFEST_UNKNOWN",
        "NAME_INVALID",
        "NAME_UNKNOWN",
        "SIZE_INVALID",
        "UNAUTHORIZED",
        "DENIED",
        "UNSUPPORTED",
        "TOOMANYREQUESTS",
        "AccessDenied",
        "InvalidSecurityToken",
        "SecurityTokenExpired",
        "SignatureDoesNotMatch",
        "RequestTimeTooSkewed",
        "Forbidden",
        "Throttling",
    ];
    CODES.iter().copied().find(|known| *known == code)
}

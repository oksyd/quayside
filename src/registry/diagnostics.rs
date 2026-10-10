//! Bounded response diagnostics without URLs, credentials or arbitrary server messages.
use super::transport::{http_error, limited_body};
use crate::{
    Error,
    digest::Digest,
    model::{Manifest, ManifestKind, OCI_MANIFEST},
};
use bytes::Bytes;
use http::Method;
use reqx::ResponseStream;
use std::time::Duration;
use url::Url;

pub(super) enum Operation {
    PublishManifest(Option<Digest>),
    Other(&'static str),
}

impl Operation {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::PublishManifest(Some(_)) => "publish manifest by digest",
            Self::PublishManifest(None) => "publish manifest tag",
            Self::Other(label) => label,
        }
    }
}

pub(super) fn operation(method: &Method, url: &Url) -> Operation {
    let path = url.path();
    if path.starts_with("/v2/") {
        if let Some((_, selector)) = path.rsplit_once("/manifests/")
            && !selector.is_empty()
            && !selector.contains('/')
        {
            return if *method == Method::PUT {
                Operation::PublishManifest(selector.parse().ok())
            } else {
                Operation::Other("read manifest")
            };
        }
        if path.contains("/blobs/uploads/") {
            return Operation::Other(match *method {
                Method::POST => "start blob upload",
                Method::PATCH => "upload blob chunk",
                Method::PUT => "commit blob upload",
                Method::GET => "check blob upload",
                _ => "blob upload request",
            });
        }
        if path.contains("/blobs/") {
            return Operation::Other(if *method == Method::HEAD {
                "check blob"
            } else {
                "download blob"
            });
        }
        if path.contains("/referrers/") {
            return Operation::Other("list referrers");
        }
        if path.ends_with("/tags/list") {
            return Operation::Other("list tags");
        }
        if path == "/v2/" {
            return Operation::Other("check registry");
        }
    }
    Operation::Other("content request")
}

pub(super) fn manifest_rejection(
    error: &mut Error,
    body: &Bytes,
    expected: Option<&Digest>,
    status: http::StatusCode,
) {
    // Inspect only the submitted, bounded manifest. Never infer its type from server messages.
    let Ok(manifest) = Manifest::parse(body.clone(), None, expected) else {
        return;
    };
    let attestation = manifest.descriptor.media_type == OCI_MANIFEST
        && (manifest.value["artifactType"].as_str()
            == Some("application/vnd.docker.attestation.manifest.v1+json")
            || manifest.value["layers"].as_array().is_some_and(|layers| {
                layers.iter().any(|layer| {
                    layer["mediaType"].as_str() == Some("application/vnd.in-toto+json")
                })
            }));
    let kind = if attestation {
        "build attestation"
    } else if manifest.is_artifact().unwrap_or(false) {
        "OCI artifact"
    } else if manifest.kind == ManifestKind::Index {
        "image index"
    } else {
        "container image"
    };
    // Manifest media types and digests have been validated by Manifest::parse.
    error.message.push_str(&format!(
        "\nManifest: {} ({kind})\nMedia type: {}",
        manifest.digest(),
        manifest.descriptor.media_type,
    ));
    if let Ok(config) = manifest.config() {
        let media_type = match config.media_type.as_str() {
            "application/vnd.oci.empty.v1+json" => "application/vnd.oci.empty.v1+json",
            "application/vnd.oci.image.config.v1+json" => {
                "application/vnd.oci.image.config.v1+json"
            }
            "application/vnd.docker.container.image.v1+json" => {
                "application/vnd.docker.container.image.v1+json"
            }
            _ => "custom",
        };
        error
            .message
            .push_str(&format!("\nConfig media type: {media_type}"));
    }
    if attestation && matches!(status.as_u16(), 400 | 403 | 405 | 415 | 422 | 501) {
        error.message.push_str(
            "\nHint: Check destination support for attestation manifests and permission to publish artifacts.\nFor image-only copies, use an image tag with the default platform or --platform; omit --all, --include-attestations and --referrers all.",
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::Code, model::Descriptor};
    use http::StatusCode;
    use serde_json::json;

    #[test]
    fn rejection_classification_handles_legacy_attestations_without_echoing_metadata() {
        for (config_type, layer_type, attestation) in [
            (
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.in-toto+json",
                true,
            ),
            (
                "application/vnd.oci.empty.v1+json",
                "application/vnd.in-toto+json",
                true,
            ),
            (
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.oci.image.layer.v1.tar",
                false,
            ),
            (
                "private-config\nsecret",
                "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
                false,
            ),
        ] {
            let descriptor =
                |media_type: &str| Descriptor::new(media_type, Digest::sha256(b"{}"), 2);
            let body: Bytes = serde_json::to_vec(&json!({
                "schemaVersion":2, "mediaType":OCI_MANIFEST,
                "config": descriptor(config_type), "layers":[descriptor(layer_type)],
                "annotations":{"private":"secret"}
            }))
            .unwrap()
            .into();
            // Preserve the selected digest algorithm and the original permission error.
            let expected: Digest = format!("sha512:{}", "00".repeat(64)).parse().unwrap();
            let mut hasher = expected.hasher();
            hasher.update(&body);
            let expected = hasher.finish();
            let mut error = Error::new(Code::Forbidden, "registry returned HTTP 403 Forbidden");
            manifest_rejection(&mut error, &body, Some(&expected), StatusCode::FORBIDDEN);
            assert_eq!(error.code, Code::Forbidden);
            assert!(
                error.message.contains(expected.as_str()),
                "{}",
                error.message
            );
            assert_eq!(error.message.contains("(build attestation)"), attestation);
            assert_eq!(error.message.contains("Hint:"), attestation);
            assert!(!error.message.contains("secret"));
            assert!(!error.message.contains("private"));
            if config_type.starts_with("private") {
                assert!(error.message.contains("Config media type: custom"));
            }
        }
    }
}

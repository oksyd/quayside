use serde::Serialize;

/// Result type used by Quayside operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable machine-readable categories serialized in error envelopes.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    /// A local operation, filesystem action or command setup failed.
    Execution,
    /// A reference, configuration value or supplied payload is invalid.
    InvalidInput,
    /// Authentication is required or supplied credentials were rejected.
    Unauthorized,
    /// The authenticated identity is not permitted to perform the operation.
    Forbidden,
    /// The requested registry resource does not exist.
    NotFound,
    /// The requested protocol feature or operation is not supported.
    Unsupported,
    /// A network request or response transfer failed.
    Network,
    /// The peer's TLS certificate has expired.
    TlsCertificateExpired,
    /// The peer's certificate is invalid for the requested hostname.
    TlsNameMismatch,
    /// The peer's certificate issuer is not trusted.
    TlsUnknownIssuer,
    /// TLS certificate validation failed for another reason.
    TlsInvalidCertificate,
    /// Content size, digest or published bytes failed verification.
    Integrity,
    /// An existing destination conflicts with the requested write policy.
    Conflict,
    /// The operation could not establish that the supplied credentials were used.
    UnverifiedCredentials,
    /// The user interrupted the operation.
    Interrupted,
}

/// A sanitized error category and user-facing message.
#[derive(Debug, Serialize)]
pub struct Error {
    /// Stable error classification for programmatic handling.
    pub code: Code,
    /// User-facing diagnostic text; sensitive transport details must be omitted.
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Construct an error with an explicit category and sanitized message.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    /// Construct an invalid-input error.
    pub fn input(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidInput, message)
    }
    /// Construct a content-integrity error.
    pub fn integrity(message: impl Into<String>) -> Self {
        Self::new(Code::Integrity, message)
    }
    /// Construct an unsupported-operation error.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(Code::Unsupported, message)
    }
    /// Construct a network-operation error.
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(Code::Network, message)
    }
    /// Construct a destination-conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(Code::Conflict, message)
    }
    /// Return whether this error category permits a bounded retry.
    pub fn retryable(&self) -> bool {
        self.code == Code::Network
    }
    /// Return the category's CLI exit code; partial writes are handled separately by the CLI.
    pub fn exit_code(&self) -> i32 {
        match self.code {
            Code::Execution => 1,
            Code::InvalidInput => 2,
            Code::Unauthorized | Code::Forbidden | Code::UnverifiedCredentials => 3,
            Code::NotFound => 4,
            Code::Unsupported => 5,
            Code::Network
            | Code::TlsCertificateExpired
            | Code::TlsNameMismatch
            | Code::TlsUnknownIssuer
            | Code::TlsInvalidCertificate => 6,
            Code::Integrity => 7,
            Code::Conflict => 8,
            Code::Interrupted => 130,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(Code::Execution, e.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::input(format!("invalid JSON: {e}"))
    }
}
/// Inspect typed causes, never parse or expose attacker-controlled diagnostic text.
pub(crate) fn certificate_code(error: &(dyn std::error::Error + 'static)) -> Option<Code> {
    let mut cause = Some(error);
    for _ in 0..64 {
        let current = cause?;
        if let Some(rustls::Error::InvalidCertificate(cert)) =
            current.downcast_ref::<rustls::Error>()
        {
            use rustls::CertificateError as Cert;
            return Some(match cert {
                Cert::Expired | Cert::ExpiredContext { .. } => Code::TlsCertificateExpired,
                Cert::NotValidForName | Cert::NotValidForNameContext { .. } => {
                    Code::TlsNameMismatch
                }
                Cert::UnknownIssuer => Code::TlsUnknownIssuer,
                _ => Code::TlsInvalidCertificate,
            });
        }
        cause = if let Some(io) = current.downcast_ref::<std::io::Error>() {
            io.get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static))
                .or_else(|| current.source())
        } else {
            current.source()
        };
    }
    None
}
impl From<reqx::Error> for Error {
    fn from(e: reqx::Error) -> Self {
        if let Some(code) = certificate_code(&e) {
            let message = match code {
                Code::TlsCertificateExpired => "TLS certificate has expired",
                Code::TlsNameMismatch => "TLS certificate does not match the requested hostname",
                Code::TlsUnknownIssuer => {
                    "TLS certificate issuer is not trusted; configure ca_file for a private CA"
                }
                _ => "TLS certificate validation failed",
            };
            return Self::new(code, message);
        }
        // Transport diagnostics must not disclose URLs, signed queries or server bodies.
        let detail = match &e {
            reqx::Error::Transport { kind, .. } => kind.to_string(),
            _ => e.code().as_str().to_owned(),
        };
        Self::network(format!("HTTP transport failed ({detail})"))
    }
}
pub(crate) fn endpoint(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or("unknown host");
    match url.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}
impl Error {
    pub(crate) fn request(error: reqx::Error, url: &url::Url, proxy: Option<String>) -> Self {
        let connecting = matches!(
            &error,
            reqx::Error::Transport {
                kind: reqx::TransportErrorKind::Dns
                    | reqx::TransportErrorKind::Connect
                    | reqx::TransportErrorKind::Tls,
                ..
            }
        );
        let reason = network_reason(&error);
        let mut result = Self::from(error);
        let reason = if result.code != Code::Network {
            result.message.clone()
        } else {
            reason.to_owned()
        };
        let endpoint = endpoint(url);
        let destination = if url.host_str() == Some("registry-1.docker.io") {
            format!("Docker Hub ({endpoint})")
        } else {
            endpoint
        };
        result.message = if connecting {
            format!("Unable to connect to {destination}")
        } else {
            format!("Request to {destination} failed")
        };
        if let Some(proxy) = proxy {
            result.message.push_str(&format!("\nProxy: {proxy}"));
        }
        result.message.push_str(&format!("\nReason: {reason}"));
        result
    }
}
fn network_reason(error: &reqx::Error) -> &'static str {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    for _ in 0..64 {
        let Some(current) = cause else {
            break;
        };
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind;
            let reason = match io.kind() {
                ErrorKind::ConnectionRefused => Some("Connection refused"),
                ErrorKind::TimedOut => Some("Connection timed out"),
                ErrorKind::ConnectionReset => Some("Connection reset"),
                ErrorKind::ConnectionAborted => Some("Connection aborted"),
                ErrorKind::NetworkUnreachable => Some("Network unreachable"),
                ErrorKind::HostUnreachable => Some("Host unreachable"),
                _ => None,
            };
            if let Some(reason) = reason {
                return reason;
            }
            cause = io
                .get_ref()
                .map(|e| e as &(dyn std::error::Error + 'static))
                .or_else(|| current.source());
        } else {
            cause = current.source();
        }
    }
    match error {
        reqx::Error::Transport { kind, .. } => match kind {
            reqx::TransportErrorKind::Dns => "DNS resolution failed",
            reqx::TransportErrorKind::Connect => "Connection failed",
            reqx::TransportErrorKind::Tls => "TLS handshake failed",
            reqx::TransportErrorKind::Read => "Failed to read response",
            _ => "HTTP transport failed",
        },
        reqx::Error::Timeout { .. } | reqx::Error::DeadlineExceeded { .. } => "Request timed out",
        _ => "HTTP request failed",
    }
}
impl From<url::ParseError> for Error {
    fn from(_: url::ParseError) -> Self {
        Self::input("invalid URL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_context_hides_paths_queries_and_unverified_reasons() {
        let url = url::Url::parse("https://registry.example/private?signature=secret").unwrap();
        let error = Error::request(
            reqx::Error::Transport {
                kind: reqx::TransportErrorKind::Connect,
                method: http::Method::GET,
                uri: url.to_string(),
                message: "Connection refused secret".into(),
                source: Box::new(std::io::Error::other("Connection refused secret")),
            },
            &url,
            None,
        );
        assert_eq!(
            error.message,
            "Unable to connect to registry.example:443\nReason: Connection failed"
        );
    }
    #[test]
    fn transport_errors_do_not_disclose_signed_urls_or_source_messages() {
        let error = Error::from(reqx::Error::Transport {
            kind: reqx::TransportErrorKind::Tls,
            method: http::Method::GET,
            uri: "https://registry.example/private?signature=secret".into(),
            message: "secret diagnostic".into(),
            source: Box::new(std::io::Error::other("secret source")),
        });
        assert_eq!(error.code, Code::Network);
        assert_eq!(error.message, "HTTP transport failed (tls)");
    }
}

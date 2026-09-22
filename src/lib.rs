//! Daemonless OCI registry operations with optional local Docker image export.
#[cfg(not(unix))]
compile_error!("quayside supports Unix platforms only");

/// CLI application orchestration, parameter conversion and result presentation.
pub mod app;
/// Decrypted credential access and registry authentication challenge parsing.
pub mod auth;
/// Command-line definitions and conversion to core operation options.
pub mod cli;
mod completion;
/// Persistent registry policies and bounded transfer configuration.
pub mod config;
pub mod diagnostics;
/// Validated content digests and incremental payload verification.
pub mod digest;
/// Sanitized operation errors, stable codes and exit-status mapping.
pub mod error;
/// Bounded traversal and deduplication of OCI dependency graphs.
pub mod graph;
pub mod layout;
/// OCI descriptors, platforms and byte-preserving manifests.
pub mod model;
pub mod observer;
pub mod options;
mod progress;
mod proxy;
/// Registry, repository, tag and digest reference parsing.
pub mod reference;
pub mod registry;
pub mod storage;
mod temporary;
/// Platform selection, verified blob copying and manifest publication.
pub mod transfer;
mod vault;

pub use error::{Error, Result};

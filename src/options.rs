//! Operation options independent of command-line parsing.
/// Optional graph expansion and durable transfer behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferOptions {
    /// Discover and transfer independent referrers recursively.
    pub referrers: bool,
    /// Keep indexed attestations when selecting a platform, producing a filtered OCI index.
    pub include_attestations: bool,
    /// Persist verified download progress and upload sessions across invocations.
    pub resume: bool,
}
/// Core write policy shared by copying, publication and local import/export.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOptions {
    /// Plan the operation without publishing or replacing content.
    pub dry_run: bool,
    /// Allow intentional replacement of an existing destination.
    pub overwrite: bool,
}
/// Supported representations for a local OCI export.
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveFormat {
    /// An uncompressed tar archive containing an OCI Image Layout.
    OciArchive,
    /// An OCI Image Layout stored as a directory.
    OciLayout,
}

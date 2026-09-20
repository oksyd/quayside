//! Operation options independent of command-line parsing.
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

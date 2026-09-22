use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Parsed top-level command and global output/storage options.
#[derive(Debug, Parser)]
#[command(
    name = "quayside",
    version,
    about = "Daemonless OCI registry operations",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Use this configuration file instead of the default user configuration.
    #[arg(long, global = true, env = "QUAYSIDE_CONFIG")]
    pub config: Option<PathBuf>,
    /// Use this encrypted credential store instead of the default auth file.
    #[arg(long, global = true, env = "QUAYSIDE_AUTHFILE")]
    pub authfile: Option<PathBuf>,
    /// Master key file; defaults to the Quayside XDG data directory.
    #[arg(long, global = true, env = "QUAYSIDE_KEYFILE")]
    pub keyfile: Option<PathBuf>,
    /// Emit a structured JSON result envelope.
    #[arg(long, global = true)]
    pub json: bool,
    /// Suppress diagnostic messages and progress while retaining results and errors.
    #[arg(long, global = true)]
    pub quiet: bool,
    /// Diagnostic verbosity on stderr; never includes credentials or request URLs.
    #[arg(long, global = true, value_enum, default_value = "warn")]
    pub log_level: crate::diagnostics::Level,
    /// Disable interactive progress display.
    #[arg(long, global = true)]
    pub no_progress: bool,
    /// Disable color; current output styles already avoid colors.
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Operation to execute within this command group.
    #[command(subcommand)]
    pub command: Command,
}
/// Top-level operations supported by the CLI.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Authenticate to a registry and store the verified credential encrypted.
    Login(Login),
    /// Manage local encrypted credential storage.
    Auth {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Remove the locally stored credential for a registry.
    Logout {
        /// Registry hostname and optional port, without a scheme or repository.
        registry: String,
    },
    /// Check registry connectivity and configure connection policies.
    Registry {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// List repositories available from a registry.
    Repo {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// List tags belonging to a repository.
    Tag {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: TagCommand,
    },
    /// Inspect, copy, import, export and tag OCI images or artifacts.
    Image {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Retrieve raw or structured manifest content.
    Manifest {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Create an OCI index from explicitly selected platform images.
    Index {
        /// Operation to execute within this command group.
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Print the program version.
    Version,
    /// Export or manage shell completion scripts.
    Completion(Completion),
}
/// Local credential-store maintenance operations.
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Encrypt an existing plaintext credential file in place, without a plaintext backup.
    Migrate,
}

/// Arguments for completion script export or managed installation.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct Completion {
    /// Print a completion script for this shell.
    #[arg(value_enum, required = true)]
    pub shell: Option<clap_complete::Shell>,
    /// Operation to execute within this command group.
    #[command(subcommand)]
    pub command: Option<CompletionCommand>,
}

/// Explicit shell completion installation and removal operations.
#[derive(Debug, Subcommand)]
pub enum CompletionCommand {
    /// Install completion and configure shell loading where needed.
    Install(CompletionTarget),
    /// Inspect installed completion and shell loading configuration.
    Status(CompletionTarget),
    /// Remove managed completion and shell loading configuration.
    Uninstall(CompletionTarget),
}

/// Shell and optional destination for managed completion operations.
#[derive(Debug, Args)]
pub struct CompletionTarget {
    /// Shell for which completion scripts are generated or managed.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
    /// Use this file instead of the shell's managed default path.
    #[arg(long)]
    pub path: Option<PathBuf>,
}

/// Registry login arguments, with interactive or standard-input secret entry.
#[derive(Debug, Args)]
pub struct Login {
    /// Registry hostname and optional port, without a scheme or repository.
    pub registry: String,
    /// Registry account name used for authentication.
    #[arg(short, long)]
    pub username: String,
    /// Read the password or token from standard input instead of prompting.
    #[arg(long)]
    pub password_stdin: bool,
    /// Store without claiming the registry verified the credential.
    #[arg(long)]
    pub save_unverified: bool,
    /// Check pull access to a private repository instead of anonymous /v2/.
    #[arg(long)]
    pub repository: Option<String>,
}
/// Registry connectivity and persisted policy operations.
#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// Check the registry Distribution API endpoint.
    Ping {
        /// Registry hostname and optional port, without a scheme or repository.
        registry: String,
    },
    /// Update the stored policy for a registry.
    Set(RegistrySet),
}
/// Changes to one registry's TLS, HTTP and authentication-host policy.
#[derive(Debug, Args)]
pub struct RegistrySet {
    /// Registry hostname and optional port, without a scheme or repository.
    pub registry: String,
    /// Optional PEM bundle containing additional trusted CA certificates.
    #[arg(long, conflicts_with = "clear_ca")]
    pub ca_file: Option<PathBuf>,
    /// Remove the custom CA bundle from the registry policy.
    #[arg(long)]
    pub clear_ca: bool,
    /// Use unencrypted HTTP for this explicitly configured registry.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub plain_http: Option<bool>,
    /// Legacy setting: only false is supported; use --ca-file for private CAs.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub insecure_skip_tls_verify: Option<bool>,
    /// Restrict cross-origin token services to these hosts; also permits explicit HTTP-registry delegation.
    #[arg(long = "auth-host", conflicts_with = "clear_auth_hosts")]
    pub auth_hosts: Vec<String>,
    /// Remove the explicit token-host allowlist from the registry policy.
    #[arg(long)]
    pub clear_auth_hosts: bool,
}
/// Repository discovery operations.
#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    /// List entries exposed by the selected registry or repository.
    Ls {
        /// Registry hostname and optional port, without a scheme or repository.
        registry: String,
    },
}
/// Tag discovery operations.
#[derive(Debug, Subcommand)]
pub enum TagCommand {
    /// List entries exposed by the selected registry or repository.
    Ls {
        /// Repository reference, optionally including a registry, without a tag or digest.
        repository: String,
    },
}
/// Explicit platform filtering; omitted filters preserve all source platforms.
#[derive(Debug, Clone, Default, Args)]
pub struct Selection {
    /// Explicitly select the complete source graph across platforms.
    #[arg(long, conflicts_with = "platform")]
    pub all: bool,
    /// Optional platform selector in `os/architecture[/variant]` form.
    #[arg(long)]
    pub platform: Option<String>,
}
/// CLI flags controlling planning and destination replacement.
#[derive(Debug, Clone, Default, Args)]
pub struct WriteOptions {
    /// Plan the operation without publishing or replacing content.
    #[arg(long)]
    pub dry_run: bool,
    /// Allow intentional replacement of an existing destination.
    #[arg(long)]
    pub overwrite: bool,
}
/// Supported local OCI export representations.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ArchiveFormat {
    /// An uncompressed tar archive containing an OCI Image Layout.
    OciArchive,
    /// An OCI Image Layout stored as a directory.
    OciLayout,
}
/// Image and OCI artifact operations.
#[derive(Debug, Subcommand)]
pub enum ImageCommand {
    /// Resolve and print a manifest's content digest.
    Digest {
        /// Image reference identifying the manifest to operate on.
        reference: String,
        /// Optional platform selector in `os/architecture[/variant]` form.
        #[arg(long)]
        platform: Option<String>,
    },
    /// Inspect manifest metadata and, when applicable, image configuration.
    Inspect {
        /// Image reference identifying the manifest to operate on.
        reference: String,
        /// Optional platform selector in `os/architecture[/variant]` form.
        #[arg(long)]
        platform: Option<String>,
    },
    /// Copy the selected dependency graph between registry references.
    Copy {
        /// Source registry reference.
        source: String,
        /// Fully qualified destination reference with an explicit tag or digest.
        destination: String,
        /// Platform selection options.
        #[command(flatten)]
        selection: Selection,
        /// Dry-run and overwrite policy for this operation.
        #[command(flatten)]
        write: WriteOptions,
    },
    /// Export a selected remote dependency graph to a local OCI layout or archive.
    Pull {
        /// Image reference identifying the manifest to operate on.
        reference: String,
        /// Destination path for the exported layout directory or archive.
        #[arg(short, long)]
        output: PathBuf,
        /// OCI layout directory or uncompressed tar archive format.
        #[arg(long, value_enum, default_value = "oci-archive")]
        format: ArchiveFormat,
        /// Platform selection options.
        #[command(flatten)]
        selection: Selection,
        /// Dry-run and overwrite policy for this operation.
        #[command(flatten)]
        write: WriteOptions,
    },
    /// Push an OCI layout, Docker save archive, or local Docker image.
    Push {
        /// Export an image from Docker using its CLI and current context.
        #[arg(long)]
        docker: bool,
        /// Local layout/archive path, or a Docker image name when --docker is set.
        path: PathBuf,
        /// Fully qualified destination reference with an explicit tag or digest.
        destination: String,
        /// Select a layout root or an exact image tag from a multi-image Docker archive.
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Dry-run and overwrite policy for this operation.
        #[command(flatten)]
        write: WriteOptions,
    },
    /// Publish a new tag for an existing manifest within the same registry repository.
    Tag {
        /// Source registry reference.
        source: String,
        /// Fully qualified destination reference with an explicit tag or digest.
        destination: String,
        /// Dry-run and overwrite policy for this operation.
        #[command(flatten)]
        write: WriteOptions,
    },
}
/// Manifest retrieval operations.
#[derive(Debug, Subcommand)]
pub enum ManifestCommand {
    /// Retrieve the manifest at a registry reference.
    Get {
        /// Image reference identifying the manifest to operate on.
        reference: String,
        /// Write the original manifest bytes without reserializing JSON.
        #[arg(long, conflicts_with = "json")]
        raw: bool,
    },
}
/// OCI image-index construction operations.
#[derive(Debug, Subcommand)]
pub enum IndexCommand {
    /// Assemble an index from single-platform images, detecting each platform from its config.
    Create {
        /// Fully qualified destination reference with an explicit tag or digest.
        destination: String,
        /// Fully qualified source image reference; repeat for each platform.
        #[arg(long = "from", required = true, value_name = "IMAGE")]
        sources: Vec<String>,
        /// Dry-run and overwrite policy for this operation.
        #[command(flatten)]
        write: WriteOptions,
    },
}

impl Command {
    /// Return the stable command label used in result envelopes and diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Login(_) => "login",
            Self::Auth { .. } => "auth migrate",
            Self::Logout { .. } => "logout",
            Self::Registry {
                command: RegistryCommand::Ping { .. },
            } => "registry ping",
            Self::Registry {
                command: RegistryCommand::Set(_),
            } => "registry set",
            Self::Repo { .. } => "repo ls",
            Self::Tag { .. } => "tag ls",
            Self::Image { command } => match command {
                ImageCommand::Digest { .. } => "image digest",
                ImageCommand::Inspect { .. } => "image inspect",
                ImageCommand::Copy { .. } => "image copy",
                ImageCommand::Pull { .. } => "image pull",
                ImageCommand::Push { .. } => "image push",
                ImageCommand::Tag { .. } => "image tag",
            },
            Self::Manifest { .. } => "manifest get",
            Self::Index { .. } => "index create",
            Self::Version => "version",
            Self::Completion(completion) => match completion.command {
                Some(CompletionCommand::Install(_)) => "completion install",
                Some(CompletionCommand::Status(_)) => "completion status",
                Some(CompletionCommand::Uninstall(_)) => "completion uninstall",
                None => "completion",
            },
        }
    }
}

impl From<&WriteOptions> for crate::options::WriteOptions {
    fn from(value: &WriteOptions) -> Self {
        Self {
            dry_run: value.dry_run,
            overwrite: value.overwrite,
        }
    }
}
impl From<ArchiveFormat> for crate::options::ArchiveFormat {
    fn from(value: ArchiveFormat) -> Self {
        match value {
            ArchiveFormat::OciArchive => Self::OciArchive,
            ArchiveFormat::OciLayout => Self::OciLayout,
        }
    }
}

impl ValueEnum for crate::diagnostics::Level {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Off,
            Self::Error,
            Self::Warn,
            Self::Info,
            Self::Debug,
            Self::Trace,
        ]
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn clap_contract() {
        Cli::command().debug_assert();
    }
    #[test]
    fn rejects_all_with_platform() {
        assert!(
            Cli::try_parse_from([
                "quayside",
                "image",
                "copy",
                "a.io/b:v1",
                "b.io/a:v1",
                "--all",
                "--platform",
                "linux/amd64"
            ])
            .is_err()
        );
    }
    #[test]
    fn json_is_global() {
        assert!(
            Cli::try_parse_from(["quayside", "tag", "ls", "a.io/b", "--json"])
                .unwrap()
                .json
        );
    }
}

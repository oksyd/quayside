//! CLI completion generation and installation. No registry configuration is loaded.
use crate::{
    Error, Result,
    app::Output,
    cli::{Cli, Completion, CompletionCommand},
    error::Code,
};
use clap::CommandFactory;
use serde_json::{Value, json};
use shellcomp::{ActivationMode, ActivationReport, Availability, FileChange};

fn script(shell: clap_complete::Shell) -> Vec<u8> {
    let mut bytes = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "quayside", &mut bytes);
    bytes
}

fn change(value: FileChange) -> &'static str {
    match value {
        FileChange::Created => "created",
        FileChange::Updated => "updated",
        FileChange::Unchanged => "unchanged",
        FileChange::Removed => "removed",
        FileChange::Absent => "absent",
    }
}
fn mode(value: ActivationMode) -> &'static str {
    match value {
        ActivationMode::SystemLoader => "system_loader",
        ActivationMode::ManagedRcBlock => "managed_rc_block",
        ActivationMode::NativeDirectory => "native_directory",
        ActivationMode::Manual => "manual",
    }
}
fn activation(value: &ActivationReport) -> Value {
    let availability = match value.availability {
        Availability::ActiveNow => "active_now",
        Availability::AvailableAfterNewShell => "available_after_new_shell",
        Availability::AvailableAfterSource => "available_after_source",
        Availability::ManualActionRequired => "manual_action_required",
        Availability::Unknown => "unknown",
    };
    json!({"mode":mode(value.mode),"availability":availability,
        "location":value.location,"reason":value.reason,"next_step":value.next_step})
}
fn failure(error: shellcomp::Error) -> Error {
    let mut message = format!("{}: {error}", error.error_code());
    if let Some(report) = error.as_failure() {
        if let Some(file_change) = report.file_change {
            message.push_str(&format!("; completion file: {}", change(file_change)));
        }
        if let Some(cleanup) = &report.cleanup {
            message.push_str(&format!("; activation cleanup: {}", change(cleanup.change)));
        }
        if let Some(next_step) = &report.next_step {
            message.push_str(&format!("; {next_step}"));
        }
    }
    Error::new(Code::Execution, message)
}

pub fn run(options: &Completion) -> Result<Output> {
    let Some(command) = &options.command else {
        let shell = options
            .shell
            .ok_or_else(|| Error::input("specify a shell or completion subcommand"))?;
        let bytes = script(shell);
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::input("completion generator returned invalid UTF-8"))?;
        return Ok(Output {
            data: json!({"shell":shell.to_string(),"script":text}),
            text: String::new(),
            raw: Some(bytes),
        });
    };
    let (CompletionCommand::Install(target)
    | CompletionCommand::Status(target)
    | CompletionCommand::Uninstall(target)) = command;
    let shell = match target.shell {
        clap_complete::Shell::Bash => shellcomp::Shell::Bash,
        clap_complete::Shell::Zsh => shellcomp::Shell::Zsh,
        clap_complete::Shell::Fish => shellcomp::Shell::Fish,
        clap_complete::Shell::Elvish => shellcomp::Shell::Elvish,
        clap_complete::Shell::PowerShell => shellcomp::Shell::Powershell,
        _ => return Err(Error::unsupported("unsupported completion shell")),
    };
    let (data, text) = match command {
        CompletionCommand::Install(_) => {
            let report = shellcomp::install(shellcomp::InstallRequest {
                shell,
                program_name: "quayside",
                script: &script(target.shell),
                path_override: target.path.clone(),
            })
            .map_err(failure)?;
            let text = format!(
                "Completion {}: {}\n{}\n{}",
                change(report.file_change),
                report.target_path.display(),
                report.activation.reason.as_deref().unwrap_or(""),
                report.activation.next_step.as_deref().unwrap_or("")
            );
            (
                json!({"shell":report.shell.to_string(),"target_path":report.target_path,
                "file_change":change(report.file_change),"activation":activation(&report.activation),
                "affected_locations":report.affected_locations}),
                text,
            )
        }
        CompletionCommand::Status(_) => {
            let path = match &target.path {
                Some(path) => path.clone(),
                None => {
                    shellcomp::default_install_path(shell.clone(), "quayside").map_err(failure)?
                }
            };
            let report = shellcomp::detect_activation_at_path(shell.clone(), "quayside", &path)
                .map_err(failure)?;
            let installed = path.try_exists()?;
            let text = format!(
                "Completion {}: {}\n{}\n{}",
                if installed { "present" } else { "absent" },
                path.display(),
                report.reason.as_deref().unwrap_or(""),
                report.next_step.as_deref().unwrap_or("")
            );
            (
                json!({"shell":shell.to_string(),"target_path":path,"installed":installed,
                "activation":activation(&report)}),
                text,
            )
        }
        CompletionCommand::Uninstall(_) => {
            let report = shellcomp::uninstall(shellcomp::UninstallRequest {
                shell,
                program_name: "quayside",
                path_override: target.path.clone(),
            })
            .map_err(failure)?;
            let text = format!(
                "Completion {}: {}\n{}\n{}",
                change(report.file_change),
                report.target_path.display(),
                report.cleanup.reason.as_deref().unwrap_or(""),
                report.cleanup.next_step.as_deref().unwrap_or("")
            );
            (
                json!({"shell":report.shell.to_string(),"target_path":report.target_path,
                "file_change":change(report.file_change),"affected_locations":report.affected_locations,
                "cleanup":{"mode":mode(report.cleanup.mode),"change":change(report.cleanup.change),
                    "location":report.cleanup.location,"reason":report.cleanup.reason,
                    "next_step":report.cleanup.next_step}}),
                text,
            )
        }
    };
    Ok(Output::new(data, text.trim_end()))
}

use clap::Parser;
use quayside::{
    Error,
    app::{self, Context, Output},
    cli::Cli,
    error::Code,
};
use serde_json::json;
use std::{
    io::{self, Write},
    sync::atomic::Ordering,
};

fn emit(output: Output, command: &str, json_mode: bool, warnings: &[String]) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if json_mode {
        serde_json::to_writer(
            &mut stdout,
            &json!({"schema_version":1,"command":command,"status":"success",
            "data":output.data,"warnings":warnings,"error":null}),
        )
        .map_err(io::Error::other)?;
        writeln!(stdout)?;
    } else if let Some(raw) = output.raw {
        stdout.write_all(&raw)?;
    } else if !output.text.is_empty() {
        writeln!(stdout, "{}", output.text)?;
    }
    stdout.flush()?;
    if !json_mode {
        for warning in warnings {
            quayside::diagnostics::log(
                quayside::diagnostics::Level::Warn,
                format_args!("{warning}"),
            );
        }
    }
    Ok(())
}
fn emit_error(
    error: &Error,
    command: &str,
    json_mode: bool,
    partial: bool,
    warnings: &[String],
) -> i32 {
    let exit = if error.code == Code::Interrupted {
        130
    } else if partial {
        9
    } else {
        error.exit_code()
    };
    if json_mode {
        let envelope = json!({"schema_version":1,"command":command,"status":if partial {"partial"} else {"error"},
            "data":{"remote_writes_may_have_occurred":partial},"warnings":warnings,"error":error});
        let mut stdout = io::stdout().lock();
        let _ = serde_json::to_writer(&mut stdout, &envelope);
        let _ = writeln!(stdout);
    } else {
        eprintln!("error [{:?}]: {}", error.code, error.message);
        if partial {
            eprintln!(
                "warning: remote writes may have occurred; no remote objects were automatically deleted."
            );
        }
        for warning in warnings {
            quayside::diagnostics::log(
                quayside::diagnostics::Level::Warn,
                format_args!("{warning}"),
            );
        }
    }
    exit
}
#[tokio::main]
async fn main() {
    let json_requested = std::env::args_os().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            if e.exit_code() == 0 {
                let _ = e.print();
                std::process::exit(0);
            }
            if json_requested {
                let error = Error::input(e.to_string());
                std::process::exit(emit_error(&error, "parse", true, false, &[]));
            }
            e.exit();
        }
    };
    app::init_diagnostics(cli.log_level, cli.quiet);
    let label = cli.command.label();
    quayside::diagnostics::log(
        quayside::diagnostics::Level::Info,
        format_args!("{label}: started"),
    );
    match app::local_command(&cli) {
        Ok(Some(output)) => {
            if let Err(e) = emit(output, label, cli.json, &[])
                && e.kind() != io::ErrorKind::BrokenPipe
            {
                eprintln!("output error: {e}");
                std::process::exit(1);
            }
            quayside::diagnostics::log(
                quayside::diagnostics::Level::Info,
                format_args!("{label}: completed"),
            );
            return;
        }
        Err(e) => std::process::exit(emit_error(&e, label, cli.json, false, &[])),
        Ok(None) => {}
    }
    let ctx = match Context::new(&cli) {
        Ok(ctx) => ctx,
        Err(e) => std::process::exit(emit_error(&e, label, cli.json, false, &[])),
    };
    let result = tokio::select! {
        result = app::run(&ctx, &cli.command) => result,
        signal = tokio::signal::ctrl_c() => match signal {
            Ok(()) => Err(Error::new(Code::Interrupted, "interrupted by user")),
            Err(e) => Err(Error::from(e)),
        },
    };
    let warnings = ctx.warnings();
    let exit = match result {
        Ok(output) => match emit(output, label, cli.json, &warnings) {
            Ok(()) => 0,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
            Err(e) => emit_error(
                &e.into(),
                label,
                cli.json,
                ctx.changed.load(Ordering::SeqCst),
                &warnings,
            ),
        },
        Err(e) => emit_error(
            &e,
            label,
            cli.json,
            ctx.changed.load(Ordering::SeqCst),
            &warnings,
        ),
    };
    quayside::diagnostics::log(
        quayside::diagnostics::Level::Info,
        format_args!("{label}: finished with exit code {exit}"),
    );
    // Drop context before exit so in-memory credentials are zeroized.
    drop(ctx);
    if exit != 0 {
        std::process::exit(exit);
    }
}

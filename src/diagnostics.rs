//! Application diagnostics contain only explicitly selected, non-secret fields.
use std::{
    fmt,
    io::Write,
    sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

/// Diagnostic verbosity, ordered from disabled to the most detailed output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Disable all diagnostic messages.
    Off,
    /// Emit error-level diagnostics only.
    Error,
    /// Also emit operational warnings.
    Warn,
    /// Also emit command-level status messages.
    Info,
    /// Also emit sanitized request timing and configuration diagnostics.
    Debug,
    /// Also emit the most detailed non-secret diagnostic metadata.
    Trace,
}

type Writer = for<'a> fn(Level, fmt::Arguments<'a>);
static WRITER: Mutex<Writer> = Mutex::new(default_writer);

fn default_writer(level: Level, message: fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "{level:?}: {message}");
}
/// Configure presentation at the application boundary; core logging knows no terminal renderer.
pub fn set_writer(writer: Writer) {
    if let Ok(mut output) = WRITER.lock() {
        *output = writer;
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Warn as u8);

/// Set the diagnostic threshold; quiet mode overrides the threshold to off.
pub fn init(level: Level, quiet: bool) {
    LEVEL.store(
        if quiet { Level::Off } else { level } as u8,
        Ordering::Relaxed,
    );
}

/// Emit an allowed diagnostic through the configured writer without exposing raw request data.
pub fn log(level: Level, message: fmt::Arguments<'_>) {
    if level != Level::Off && level as u8 <= LEVEL.load(Ordering::Relaxed) {
        // A closed diagnostic pipe must never panic or affect a registry operation.
        let writer = WRITER
            .lock()
            .map(|writer| *writer)
            .unwrap_or(default_writer);
        writer(level, message);
    }
}

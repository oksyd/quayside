use super::{BlobOutcome, BlobPhase, Phase, Row, State, Status};
use console::{measure_text_width as width, truncate_str};
use std::time::Instant;

const SPINNERS: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BLOCKS: [char; 9] = ['⠀', '⡀', '⣀', '⣄', '⣤', '⣦', '⣶', '⣷', '⣿'];

fn label(phase: Phase) -> &'static str {
    match phase {
        Phase::Resolving => "Resolving manifests",
        Phase::CheckingDestination => "Checking destination",
        Phase::Copying => "Copying",
        Phase::Pulling => "Pulling",
        Phase::Pushing => "Pushing",
        Phase::ReadingLocal => "Reading local image",
        Phase::VerifyingLocal => "Verifying local content",
        Phase::ExportingDocker => "Exporting Docker image",
        Phase::Saving => "Saving local image",
        Phase::Planning => "Planning",
        Phase::Publishing => "Publishing manifests",
    }
}
fn elapsed(start: Instant, stop: Option<Instant>, now: Instant) -> String {
    format!(
        "{:.1}s",
        stop.unwrap_or(now)
            .saturating_duration_since(start)
            .as_secs_f64()
    )
}
fn line(left: &str, right: &str, columns: usize) -> String {
    if right.is_empty() || columns < width(right) + 16 {
        return truncate_str(left, columns, "…").into_owned();
    }
    let available = columns.saturating_sub(width(right) + 1);
    let left = truncate_str(left, available, "…");
    format!(
        "{left}{}{right}",
        " ".repeat(columns.saturating_sub(width(&left) + width(right)))
    )
}
fn bytes(value: u64) -> String {
    indicatif::HumanBytes(value).to_string()
}
fn outcome(value: BlobOutcome) -> &'static str {
    match value {
        BlobOutcome::Copied => "Copied",
        BlobOutcome::Downloaded => "Downloaded",
        BlobOutcome::Uploaded => "Uploaded",
        BlobOutcome::Reused => "Copied (local)",
        BlobOutcome::AlreadyExists => "Already exists",
        BlobOutcome::Mounted => "Mounted",
        BlobOutcome::Planned => "Would transfer",
    }
}
fn row_line(row: &Row, state: &State, columns: usize, now: Instant, spinner: &str) -> String {
    let status = if let Some(value) = row.outcome {
        outcome(value)
    } else if row.failed {
        "Failed"
    } else if state.status != Status::Running {
        if state.status == Status::Interrupted {
            "Interrupted"
        } else {
            "Cancelled"
        }
    } else if row.started.is_none() {
        "Waiting"
    } else {
        match row.phase {
            None => "Checking",
            Some(BlobPhase::Downloading) => "Downloading",
            Some(BlobPhase::Uploading) => "Uploading",
            Some(BlobPhase::Verifying) => "Verifying",
            Some(BlobPhase::Committing) => "Committing",
            Some(BlobPhase::Waiting) if row.downloaded == row.size => "Waiting to upload",
            Some(BlobPhase::Waiting) => "Waiting",
        }
    };
    let icon = if row.failed {
        "✘"
    } else if row.outcome.is_some() {
        "✔"
    } else if state.status != Status::Running || row.started.is_none() {
        "-"
    } else {
        spinner
    };
    let digest: String = row
        .digest
        .rsplit(':')
        .next()
        .unwrap_or(&row.digest)
        .chars()
        .take(if columns < 40 { 8 } else { 12 })
        .collect();
    let mut text = format!("   {icon} {digest} {status:<11}");
    let timing = row
        .started
        .map(|started| elapsed(started, row.stopped.or(state.stopped), now))
        .unwrap_or_default();
    if state.status == Status::Running
        && !row.settled()
        && matches!(
            row.phase,
            Some(BlobPhase::Downloading | BlobPhase::Uploading)
        )
    {
        let total = bytes(row.size);
        let amount = format!(
            "{:>size_width$}/{total}",
            bytes(row.position),
            size_width = total.len()
        );
        let room = columns.saturating_sub(width(&text) + width(&timing) + width(&amount) + 5);
        if room >= 8 {
            let count = room.min(30);
            let done = if row.size == 0 {
                0
            } else {
                (u128::from(row.position) * count as u128 / u128::from(row.size)) as usize
            };
            let bar = if done == count {
                "=".repeat(count)
            } else {
                format!("{}>{}", "=".repeat(done), " ".repeat(count - done - 1))
            };
            text.push_str(&format!(" [{bar}] {amount}"));
        } else if columns >= width(&text) + width(&timing) + width(&amount) + 2 {
            text.push_str(&format!(" {amount}"));
        }
    }
    line(&text, &timing, columns)
}

pub(super) fn frame(state: &State, columns: usize, height: usize, now: Instant) -> String {
    let columns = columns.max(1);
    let limit = height.saturating_sub(2).max(1);
    let done = state
        .rows
        .iter()
        .filter(|row| row.outcome.is_some())
        .count();
    let action = if state.planning {
        "Planning"
    } else {
        label(state.action)
    };
    let mut heading = format!("[+] {action}");
    if let Some(total) = state.total {
        heading.push_str(&format!(" {done}/{total} blobs"));
    }
    let spinner =
        SPINNERS[(now.saturating_duration_since(state.started).as_millis() / 100 % 10) as usize];
    let status = match state.status {
        Status::Complete if state.planning => "Planned",
        Status::Complete => match state.action {
            Phase::Pulling => "Pulled",
            Phase::Pushing => "Pushed",
            _ => "Copied",
        },
        Status::Failed => "Failed",
        Status::Interrupted => "Interrupted",
        Status::Running => label(state.phase),
    };
    if limit == 1 {
        return line(&format!("{status}: {}", state.image), "", columns);
    }
    let mut lines = vec![line(&heading, "", columns)];
    let icon = match state.status {
        Status::Running => spinner,
        Status::Complete => "✔",
        Status::Failed => "✘",
        Status::Interrupted => "-",
    };
    let mut details = status.to_owned();
    if !state.rows.is_empty() && state.status == Status::Running && columns >= 60 {
        let (current, total) = state
            .rows
            .iter()
            .map(|row| row.progress(state.action))
            .fold((0u128, 0u128), |(a, b), (c, d)| (a + c, b + d));
        let percent = current * 100 / total.max(1);
        let mut blocks = String::new();
        for group in state.rows.chunks(state.rows.len().div_ceil(16)) {
            let (current, total) = group
                .iter()
                .map(|row| row.progress(state.action))
                .fold((0u128, 0u128), |(a, b), (c, d)| (a + c, b + d));
            blocks.push(BLOCKS[(current * 8 / total.max(1)) as usize]);
        }
        details = format!("[{blocks}] {percent}% {status}");
    }
    let timing = elapsed(state.started, state.stopped, now);
    let name_space = columns
        .saturating_sub(width(&details) + width(&timing) + 5)
        .max(8);
    let name = truncate_str(&state.image, name_space, "…");
    let parent = if columns < 40 {
        format!(" {icon} {status} {name}")
    } else {
        format!(" {icon} {name} {details}")
    };
    lines.push(line(&parent, &timing, columns));
    let capacity = limit.saturating_sub(2);
    if state.rows.len() <= capacity {
        lines.extend(
            state
                .rows
                .iter()
                .map(|row| row_line(row, state, columns, now, spinner)),
        );
    } else if capacity > 0 {
        // Fold only when the terminal cannot fit all rows. Visible rows retain graph order.
        let mut indices: Vec<_> = (0..state.rows.len()).collect();
        indices.sort_by_key(|i| {
            let row = &state.rows[*i];
            (
                if row.failed {
                    0
                } else if row.started.is_some() && !row.settled() {
                    1
                } else if row.outcome.is_some() {
                    2
                } else {
                    3
                },
                *i,
            )
        });
        indices.truncate(capacity - 1);
        indices.sort_unstable();
        lines.extend(
            indices
                .iter()
                .map(|i| row_line(&state.rows[*i], state, columns, now, spinner)),
        );
        let waiting = state
            .rows
            .iter()
            .filter(|row| row.started.is_none())
            .count();
        lines.push(line(
            &format!(
                "   … {} hidden ({done} complete, {waiting} waiting in total)",
                state.rows.len() - indices.len()
            ),
            "",
            columns,
        ));
    }
    lines.join("\n")
}

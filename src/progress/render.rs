use super::{BlobOutcome, BlobPhase, Phase, Row, State, Status};
use console::{Style, measure_text_width as width, truncate_str};
use std::{ops::Range, time::Instant};

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
fn line(
    left: &str,
    right: &str,
    columns: usize,
    color: bool,
    styles: &[(Range<usize>, Style)],
) -> String {
    let right = if columns < width(right) + 16 {
        ""
    } else {
        right
    };
    let available = columns.saturating_sub(width(right) + usize::from(!right.is_empty()));
    let truncated = width(left) > available;
    let left = truncate_str(left, available, "…");
    let padding = columns.saturating_sub(width(&left) + width(right));
    // All offsets refer to plain UTF-8 text. Fit the line first, then style only retained
    // segments, leaving the ellipsis, padding and elapsed time outside the color spans.
    let mut result = String::new();
    let mut cursor = 0;
    if color {
        let end = left.len() - if truncated { "…".len() } else { 0 };
        for (range, style) in styles {
            if range.start >= end {
                break;
            }
            let stop = range.end.min(end);
            result.push_str(&left[cursor..range.start]);
            result.push_str(
                &style
                    .clone()
                    .force_styling(true)
                    .apply_to(&left[range.start..stop])
                    .to_string(),
            );
            cursor = stop;
        }
    }
    result.push_str(&left[cursor..]);
    if !right.is_empty() {
        result.push_str(&" ".repeat(padding));
        result.push_str(right);
    }
    result
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
fn row_line(
    row: &Row,
    state: &State,
    columns: usize,
    now: Instant,
    spinner: &str,
    color: bool,
) -> String {
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
    let waiting = row.started.is_none() || row.phase == Some(BlobPhase::Waiting);
    let icon = if row.failed {
        "✘"
    } else if row.outcome.is_some() {
        "✔"
    } else if state.status != Status::Running || waiting {
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
    let compact = columns < 6 + width(&digest) + width(status);
    let prefix = if compact {
        format!("   {icon} ")
    } else {
        format!("   {icon} {digest} ")
    };
    let mut text = if compact {
        format!("{prefix}{status}")
    } else {
        format!("{prefix}{status:<11}")
    };
    let (icon_style, status_style) = if row.failed {
        (Style::new().red(), Style::new().red())
    } else if matches!(
        row.outcome,
        Some(BlobOutcome::AlreadyExists | BlobOutcome::Planned)
    ) {
        (Style::new().dim(), Style::new().dim())
    } else if row.outcome.is_some() {
        (Style::new().green(), Style::new())
    } else if state.status == Status::Interrupted {
        (Style::new().yellow(), Style::new().yellow())
    } else if state.status != Status::Running || waiting {
        (Style::new().dim(), Style::new().dim())
    } else {
        (Style::new().cyan(), Style::new())
    };
    let mut timing = row
        .started
        .map(|started| elapsed(started, row.stopped.or(state.stopped), now))
        .unwrap_or_default();
    if columns < width(text.trim_end()) + width(&timing) + 1 {
        timing.clear();
    }
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
    line(
        text.trim_end(),
        &timing,
        columns,
        color,
        &[
            (3..3 + icon.len(), icon_style),
            (prefix.len()..prefix.len() + status.len(), status_style),
        ],
    )
}

fn hidden_summary(state: &State, hidden: &[usize]) -> String {
    let (mut failed, mut active, mut complete, mut waiting) = (0, 0, 0, 0);
    for &index in hidden {
        let row = &state.rows[index];
        if row.failed {
            failed += 1;
        } else if row.outcome.is_some() {
            complete += 1;
        } else if row.started.is_some() {
            active += 1;
        } else {
            waiting += 1;
        }
    }
    let cancelled = if state.status == Status::Running {
        0
    } else {
        let count = active + waiting;
        active = 0;
        waiting = 0;
        count
    };
    let cancelled_label = if state.status == Status::Interrupted {
        "interrupted"
    } else {
        "cancelled"
    };
    let counts = [
        (failed, "failed"),
        (active, "active"),
        (cancelled, cancelled_label),
        (complete, "complete"),
        (waiting, "waiting"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect::<Vec<_>>()
    .join(", ");
    format!("   … {} hidden ({counts})", hidden.len())
}

pub(super) fn frame(
    state: &State,
    columns: usize,
    height: usize,
    now: Instant,
    color: bool,
) -> String {
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
    if let Some(platforms) = &state.platforms {
        heading.push_str(&format!(" | {platforms}"));
    }
    let spinner =
        SPINNERS[(now.saturating_duration_since(state.started).as_millis() / 100 % 10) as usize];
    let status = match state.status {
        Status::UpToDate => "Up to date",
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
    let (icon_style, status_style) = match state.status {
        Status::Running => (Style::new().cyan(), Style::new()),
        Status::Complete if state.planning => (Style::new().dim(), Style::new()),
        Status::Complete | Status::UpToDate => (Style::new().green(), Style::new()),
        Status::Failed => (Style::new().red(), Style::new().red()),
        Status::Interrupted => (Style::new().yellow(), Style::new().yellow()),
    };
    if limit == 1 {
        return line(
            &format!("{status}: {}", state.image),
            "",
            columns,
            color,
            &[(0..status.len(), status_style)],
        );
    }
    let mut lines = vec![line(&heading, "", columns, false, &[])];
    let icon = match state.status {
        Status::Running => spinner,
        Status::Complete | Status::UpToDate => "✔",
        Status::Failed => "✘",
        Status::Interrupted => "-",
    };
    let mut details = status.to_owned();
    if !state.rows.is_empty()
        && state.status == Status::Running
        && matches!(
            state.phase,
            Phase::Copying | Phase::Pulling | Phase::Pushing
        )
        && columns >= 60
    {
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
    let mut timing = elapsed(state.started, state.stopped, now);
    let name_space = columns.saturating_sub(width(&details) + width(&timing) + 5);
    let status_start;
    let parent = if columns < 40 || name_space < 8 {
        status_start = 2 + icon.len();
        let prefix = format!(" {icon} {status}");
        if columns < width(&prefix) + width(&timing) + 1 {
            timing.clear();
        }
        let time_space = if timing.is_empty() {
            0
        } else {
            width(&timing) + 1
        };
        let name_space = columns.saturating_sub(width(&prefix) + time_space + 1);
        if name_space > 0 {
            format!("{prefix} {}", truncate_str(&state.image, name_space, "…"))
        } else {
            prefix
        }
    } else {
        let name = truncate_str(&state.image, name_space, "…");
        let text = format!(" {icon} {name} {details}");
        status_start = text.len() - status.len();
        text
    };
    lines.push(line(
        &parent,
        &timing,
        columns,
        color,
        &[
            (1..1 + icon.len(), icon_style),
            (status_start..status_start + status.len(), status_style),
        ],
    ));
    let capacity = limit.saturating_sub(2);
    if state.rows.len() <= capacity {
        lines.extend(
            state
                .rows
                .iter()
                .map(|row| row_line(row, state, columns, now, spinner, color)),
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
        // Even a single available row must show a failure or active transfer.
        let visible = capacity.saturating_sub(1).max(1);
        let summary = (capacity > 1).then(|| hidden_summary(state, &indices[visible..]));
        indices.truncate(visible);
        indices.sort_unstable();
        lines.extend(
            indices
                .iter()
                .map(|i| row_line(&state.rows[*i], state, columns, now, spinner, color)),
        );
        if let Some(summary) = summary {
            lines.push(line(&summary, "", columns, false, &[]));
        }
    }
    lines.join("\n")
}

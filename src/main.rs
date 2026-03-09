#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[allow(dead_code, unused_imports, unused_variables)]
mod detect;
#[allow(dead_code, unused_imports, unused_variables)]
mod error;
#[allow(dead_code, unused_imports, unused_variables)]
mod types;
#[allow(dead_code, unused_imports, unused_variables)]
mod wipe;

use chrono::{Local, TimeZone};
use iced::widget::{
    Space, button, column, container, progress_bar, row, scrollable, text, text_input,
};
use iced::{Element, Length, Settings, Subscription, Task, application, time, window};
use iced_aw::{style, widget::Card};
#[cfg(target_os = "windows")]
use rfd::AsyncFileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Read;
#[cfg(target_os = "windows")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "windows")]
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(target_os = "windows")]
use types::{DeviceInfo as AlgoDeviceInfo, DeviceType as AlgoDeviceType};
use types::{
    ProgressInfo as AlgoProgressInfo, WipeMethod, WipeResult as AlgoWipeResult, WipeStandard,
};
use wipe::WipeEngine;

const DEFAULT_VOLUME_LABEL: &str = "ChangeMe";
const EXFAT_LABEL_MAX: usize = 15;
const ELEVATION_MARKER_ARG: &str = "--eternalrust-elevated";
const DETAILS_SCROLLABLE_ID: &str = "details-scrollable";
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;
const NATIVE_PROGRESS_UNKNOWN: u32 = u32::MAX;

fn main() -> iced::Result {
    match maybe_relaunch_with_elevation() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => {
            eprintln!("Elevation is required: {error}");
            return Ok(());
        }
    }

    application(boot, update, view)
        .title("EternalRust")
        .settings(Settings::default())
        .subscription(subscription)
        .window(window::Settings {
            icon: load_window_icon(),
            ..window::Settings::default()
        })
        .run()
}

fn subscription(state: &WelcomeApp) -> Subscription<Message> {
    if state.is_wiping {
        time::every(Duration::from_secs(1)).map(|_| Message::WipeProgressTick)
    } else {
        Subscription::none()
    }
}

fn maybe_relaunch_with_elevation() -> Result<bool, String> {
    if is_running_with_admin_privileges() {
        return Ok(false);
    }

    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == ELEVATION_MARKER_ARG) {
        return Err(
            "Elevation relaunch marker present, but process is still not elevated.".to_string(),
        );
    }
    args.push(ELEVATION_MARKER_ARG.to_string());

    let exe_path =
        env::current_exe().map_err(|error| format!("Failed getting executable path: {error}"))?;

    #[cfg(target_os = "windows")]
    {
        let exe_str = exe_path.to_string_lossy().to_string();
        let quoted_exe = powershell_single_quote(&exe_str);
        let quoted_args = args
            .iter()
            .map(|arg| powershell_single_quote(arg))
            .collect::<Vec<String>>()
            .join(", ");

        let script = if quoted_args.is_empty() {
            format!("Start-Process -FilePath {quoted_exe} -Verb RunAs")
        } else {
            format!(
                "Start-Process -FilePath {quoted_exe} -ArgumentList @({quoted_args}) -Verb RunAs"
            )
        };

        let status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status()
            .map_err(|error| format!("Failed requesting UAC elevation: {error}"))?;

        if status.success() {
            return Ok(true);
        }

        return Err(
            "UAC elevation was canceled or failed. Continue manually as Administrator.".to_string(),
        );
    }

    #[cfg(target_os = "linux")]
    {
        if !command_exists("sudo") {
            return Err("sudo is required for Linux execution, but it was not found.".to_string());
        }

        let _ = Command::new("sudo").arg("-k").status();
        let status = Command::new("sudo")
            .arg("-E")
            .arg(&exe_path)
            .args(&args)
            .status()
            .map_err(|error| format!("Failed launching sudo: {error}"))?;

        if status.success() {
            return Ok(true);
        }

        return Err("sudo elevation was canceled or failed.".to_string());
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
fn powershell_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "''"))
}

fn load_window_icon() -> Option<window::Icon> {
    window::icon::from_file_data(include_bytes!("../assets/icon_16.png"), None).ok()
}

#[derive(Debug, Clone)]
struct DriveInfo {
    device_path: String,
    volume_name: String,
    vendor: String,
    model: String,
    serial: String,
    transport: String,
    file_system: String,
    mount_point: String,
    mount_state: String,
    drive_type: String,
    capacity_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct PreflightReport {
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl PreflightReport {
    fn can_run_destructive_ops(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    blocked_device_ids: Vec<String>,
    last_log_dir: Option<String>,
    default_volume_label: String,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            blocked_device_ids: Vec::new(),
            last_log_dir: None,
            default_volume_label: DEFAULT_VOLUME_LABEL.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct CommandRecord {
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl CommandRecord {
    fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }
}

#[derive(Debug, Clone)]
struct WipeExecution {
    drive: DriveInfo,
    wipe_standard: String,
    wipe_method: String,
    passes_completed: u32,
    verified: bool,
    success: bool,
    started_unix: u64,
    ended_unix: u64,
    commands: Vec<CommandRecord>,
}

#[derive(Debug, Clone)]
struct SavedWipeLog {
    path: PathBuf,
    execution: WipeExecution,
}

#[derive(Debug, Clone)]
struct FormatLogInfo {
    partition_scheme: String,
    filesystem: String,
    volume_label: String,
    status: String,
    device_sha256: String,
}

#[derive(Debug, Clone)]
struct FormatTaskResult {
    message: String,
    device_sha256: String,
}

struct WelcomeApp {
    drives: Vec<DriveInfo>,
    selected_drive: Option<usize>,
    status_message: String,
    os_strategy: String,
    preflight: PreflightReport,
    blocked_device_ids: HashSet<String>,
    persist_path: PathBuf,
    persisted: PersistedState,
    volume_label_input: String,
    show_format_confirmation: bool,
    is_wiping: bool,
    wipe_progress: f32,
    wipe_eta_seconds: Option<u64>,
    wipe_started_at: Option<Instant>,
    wipe_estimated_total_seconds: Option<u64>,
    wipe_native_progress: Option<Arc<AtomicU32>>,
    wiping_device_path: Option<String>,
    is_formatting: bool,
    pending_post_wipe_drive: Option<DriveInfo>,
    pending_log_execution: Option<WipeExecution>,
    saved_wipe_log: Option<SavedWipeLog>,
    last_format_attempt_label: Option<String>,
}

#[derive(Debug, Clone)]
enum Message {
    RefreshDevices,
    SelectDrive(usize),
    ToggleBlockSelected,
    VolumeLabelChanged(String),
    StartWipe,
    WipeProgressTick,
    WipeCompleted(Result<WipeExecution, String>),
    LogSaveCompleted(Result<String, String>),
    StartFormat,
    ConfirmFormat,
    CancelFormatConfirmation,
    FormatCompleted(Result<FormatTaskResult, String>),
}

fn boot() -> (WelcomeApp, Task<Message>) {
    let (persist_path, persisted) = load_persisted_state();
    let blocked_device_ids: HashSet<String> =
        persisted.blocked_device_ids.iter().cloned().collect();

    let preflight = run_preflight_checks();
    let os_strategy = detect_os_strategy().to_string();
    let (drives, scan_status) = scan_with_status(&os_strategy);
    let safety_status = if preflight.can_run_destructive_ops() {
        "Preflight checks passed.".to_string()
    } else {
        "Preflight checks failed. Fix issues before wiping.".to_string()
    };

    (
        WelcomeApp {
            drives,
            selected_drive: None,
            status_message: format!("{scan_status} {safety_status}"),
            os_strategy,
            preflight,
            blocked_device_ids,
            persist_path,
            persisted: persisted.clone(),
            volume_label_input: sanitize_volume_label(&persisted.default_volume_label),
            show_format_confirmation: false,
            is_wiping: false,
            wipe_progress: 0.0,
            wipe_eta_seconds: None,
            wipe_started_at: None,
            wipe_estimated_total_seconds: None,
            wipe_native_progress: None,
            wiping_device_path: None,
            is_formatting: false,
            pending_post_wipe_drive: None,
            pending_log_execution: None,
            saved_wipe_log: None,
            last_format_attempt_label: None,
        },
        Task::none(),
    )
}

fn update(state: &mut WelcomeApp, message: Message) -> Task<Message> {
    match message {
        Message::RefreshDevices => {
            let (drives, status_message) = scan_with_status(&state.os_strategy);
            state.drives = drives;
            state.show_format_confirmation = false;
            if state
                .selected_drive
                .is_some_and(|index| index >= state.drives.len())
            {
                state.selected_drive = None;
            }
            state.status_message = status_message;
            Task::none()
        }
        Message::SelectDrive(index) => {
            state.selected_drive = Some(index);
            state.show_format_confirmation = false;
            if let Some(drive) = state.drives.get(index) {
                state.status_message =
                    format!("Selected {} ({})", drive.device_path, drive.drive_type);
            }
            Task::none()
        }
        Message::ToggleBlockSelected => {
            if state.is_wiping || state.is_formatting {
                return Task::none();
            }

            if let Some(index) = state.selected_drive {
                if let Some(drive) = state.drives.get(index) {
                    let identity = drive_identity(drive);
                    if state.blocked_device_ids.contains(&identity) {
                        state.blocked_device_ids.remove(&identity);
                        state.status_message = format!("Unblocked device {}", drive.device_path);
                    } else {
                        state.blocked_device_ids.insert(identity);
                        state.status_message = format!("Blocked device {}", drive.device_path);
                    }

                    state.persisted.blocked_device_ids =
                        state.blocked_device_ids.iter().cloned().collect();
                    state.persisted.blocked_device_ids.sort();
                    if let Err(error) = save_persisted_state(&state.persist_path, &state.persisted)
                    {
                        state.status_message =
                            format!("Device state changed, but failed to save: {error}");
                    }
                }
            }

            Task::none()
        }
        Message::VolumeLabelChanged(value) => {
            state.volume_label_input = value;
            state.show_format_confirmation = false;
            Task::none()
        }
        Message::StartWipe => {
            if state.is_wiping || state.is_formatting {
                return Task::none();
            }
            if !state.preflight.can_run_destructive_ops() {
                state.status_message =
                    "Cannot start wipe: preflight checks have errors.".to_string();
                return Task::none();
            }

            let Some(index) = state.selected_drive else {
                return Task::none();
            };
            let Some(drive) = state.drives.get(index).cloned() else {
                return Task::none();
            };

            if is_drive_blocked(&state.blocked_device_ids, &drive) {
                state.status_message = "This device is blocked. Unblock it first.".to_string();
                return Task::none();
            }

            let selected_standard = selected_wipe_standard_for_drive(&drive);
            let estimated_seconds = estimate_wipe_duration_seconds(&drive, &selected_standard);
            state.is_wiping = true;
            state.show_format_confirmation = false;
            state.pending_post_wipe_drive = None;
            state.pending_log_execution = None;
            state.saved_wipe_log = None;
            state.last_format_attempt_label = None;
            state.wipe_progress = 0.0;
            state.wipe_started_at = Some(Instant::now());
            state.wipe_estimated_total_seconds = Some(estimated_seconds);
            state.wipe_eta_seconds = Some(estimated_seconds);
            let native_progress = Arc::new(AtomicU32::new(NATIVE_PROGRESS_UNKNOWN));
            state.wipe_native_progress = Some(native_progress.clone());
            state.wiping_device_path = Some(drive.device_path.clone());
            state.status_message = format!(
                "Wipe started for {} (estimated {} remaining).",
                drive.device_path,
                format_eta(estimated_seconds)
            );
            Task::perform(
                run_wipe_task(drive, selected_standard, Some(native_progress)),
                Message::WipeCompleted,
            )
        }
        Message::WipeProgressTick => {
            if !state.is_wiping {
                return Task::none();
            }

            let mut consumed_native_progress = false;
            if let Some(native_progress) = &state.wipe_native_progress {
                let raw = native_progress.load(Ordering::Relaxed);
                if raw != NATIVE_PROGRESS_UNKNOWN {
                    let normalized = (raw as f32 / 10_000.0).clamp(0.0, 0.99);
                    state.wipe_progress = state.wipe_progress.max(normalized);
                    if let Some(started_at) = state.wipe_started_at {
                        let elapsed_seconds = started_at.elapsed().as_secs_f32();
                        if normalized > 0.01 && normalized < 0.99 {
                            let total_seconds = elapsed_seconds / normalized;
                            let remaining = (total_seconds - elapsed_seconds).max(0.0);
                            state.wipe_eta_seconds = Some(remaining.ceil() as u64);
                        } else {
                            state.wipe_eta_seconds = None;
                        }
                    } else {
                        state.wipe_eta_seconds = None;
                    }
                    consumed_native_progress = true;
                }
            }

            if !consumed_native_progress {
                if let (Some(started_at), Some(total_seconds)) =
                    (state.wipe_started_at, state.wipe_estimated_total_seconds)
                {
                    let elapsed_seconds = started_at.elapsed().as_secs_f32();
                    let total_seconds = total_seconds as f32;
                    let raw_ratio = if total_seconds > 0.0 {
                        elapsed_seconds / total_seconds
                    } else {
                        0.0
                    };
                    let progress = if raw_ratio <= 1.0 {
                        (raw_ratio * 0.90).clamp(0.0, 0.90)
                    } else {
                        // Monotonic finalizing curve after estimate to avoid backwards progress.
                        let over_seconds = elapsed_seconds - total_seconds;
                        let tail = 1.0 - (-over_seconds / 90.0).exp();
                        (0.90 + (0.09 * tail)).clamp(0.90, 0.99)
                    };
                    state.wipe_progress = state.wipe_progress.max(progress);
                    if raw_ratio <= 1.0 {
                        let remaining = (total_seconds - elapsed_seconds).max(0.0);
                        state.wipe_eta_seconds = Some(remaining.ceil() as u64);
                    } else {
                        state.wipe_eta_seconds = None;
                    }
                }
            }

            Task::none()
        }
        Message::WipeCompleted(result) => {
            state.is_wiping = false;
            state.show_format_confirmation = false;
            state.wipe_started_at = None;
            state.wipe_estimated_total_seconds = None;
            state.wipe_native_progress = None;
            match result {
                Ok(execution) => {
                    let selected_path = execution.drive.device_path.clone();
                    state.pending_post_wipe_drive = Some(execution.drive.clone());
                    state.pending_log_execution = Some(execution.clone());
                    state.saved_wipe_log = None;
                    state.wipe_progress = 1.0;
                    state.wipe_eta_seconds = Some(0);
                    state.wiping_device_path = None;
                    if cfg!(target_os = "windows") {
                        state.status_message = format!(
                            "Wipe finished for {}. Choose where to save the wipe log.",
                            selected_path
                        );
                    } else if cfg!(target_os = "linux") {
                        state.status_message = format!(
                            "Wipe finished for {}. Saving wipe log to Desktop/Host_Evidence/Wiping_Log...",
                            selected_path
                        );
                    } else {
                        state.status_message = format!("Wipe finished for {}.", selected_path);
                    }

                    let suggested_dir = state.persisted.last_log_dir.clone();
                    Task::batch([
                        iced::widget::operation::snap_to_end(DETAILS_SCROLLABLE_ID),
                        Task::perform(
                            save_wipe_log(execution, suggested_dir),
                            Message::LogSaveCompleted,
                        ),
                    ])
                }
                Err(error) => {
                    state.pending_log_execution = None;
                    state.saved_wipe_log = None;
                    state.wipe_progress = 0.0;
                    state.wipe_eta_seconds = None;
                    state.wiping_device_path = None;
                    state.status_message = format!("Wipe failed: {error}");
                    Task::none()
                }
            }
        }
        Message::LogSaveCompleted(result) => {
            match result {
                Ok(path) => {
                    if let Some(execution) = state.pending_log_execution.take() {
                        state.saved_wipe_log = Some(SavedWipeLog {
                            path: PathBuf::from(&path),
                            execution,
                        });
                    }
                    state.status_message = format!(
                        "Wipe log saved to {}. Enter a new label, then format as exFAT.",
                        path
                    );
                    if let Some(parent) = Path::new(&path).parent() {
                        state.persisted.last_log_dir = Some(parent.to_string_lossy().to_string());
                        if let Err(error) =
                            save_persisted_state(&state.persist_path, &state.persisted)
                        {
                            state.status_message =
                                format!("Log saved, but failed to persist last folder: {error}");
                        }
                    }
                }
                Err(error) => {
                    state.pending_log_execution = None;
                    state.saved_wipe_log = None;
                    state.status_message = format!(
                        "Wipe done. Log was not saved ({error}). Enter a label, then use Create GPT + Format exFAT."
                    );
                }
            }
            Task::none()
        }
        Message::StartFormat => {
            if state.is_wiping || state.is_formatting {
                return Task::none();
            }
            if !state.preflight.can_run_destructive_ops() {
                state.status_message = "Cannot format: preflight checks have errors.".to_string();
                return Task::none();
            }

            let Some(drive) = state.pending_post_wipe_drive.clone() else {
                state.status_message = "No post-wipe target available to format.".to_string();
                return Task::none();
            };

            let label = sanitize_volume_label(&state.volume_label_input);
            if label.is_empty() {
                state.status_message = "Volume label cannot be empty.".to_string();
                return Task::none();
            }

            state.show_format_confirmation = true;
            state.status_message = format!(
                "Confirm formatting {} as exFAT with label '{}'.",
                drive.device_path, label
            );
            Task::none()
        }
        Message::ConfirmFormat => {
            if state.is_wiping || state.is_formatting {
                return Task::none();
            }
            if !state.preflight.can_run_destructive_ops() {
                state.status_message = "Cannot format: preflight checks have errors.".to_string();
                return Task::none();
            }

            let Some(drive) = state.pending_post_wipe_drive.clone() else {
                state.status_message = "No post-wipe target available to format.".to_string();
                return Task::none();
            };

            let label = sanitize_volume_label(&state.volume_label_input);
            if label.is_empty() {
                state.status_message = "Volume label cannot be empty.".to_string();
                state.show_format_confirmation = false;
                return Task::none();
            }

            state.persisted.default_volume_label = label.clone();
            if let Err(error) = save_persisted_state(&state.persist_path, &state.persisted) {
                state.status_message =
                    format!("Formatting will continue, but failed to save default label: {error}");
            }

            state.is_formatting = true;
            state.show_format_confirmation = false;
            state.last_format_attempt_label = Some(label.clone());
            state.status_message = format!(
                "Creating GPT and formatting {} as exFAT ({})...",
                drive.device_path, label
            );
            Task::perform(run_format_task(drive, label), Message::FormatCompleted)
        }
        Message::CancelFormatConfirmation => {
            state.show_format_confirmation = false;
            state.status_message = "Format canceled. No changes were made.".to_string();
            Task::none()
        }
        Message::FormatCompleted(result) => {
            state.is_formatting = false;
            state.show_format_confirmation = false;
            let attempted_label = state.last_format_attempt_label.take();
            let mut log_update_warning: Option<String> = None;
            if let Some(saved_log) = &state.saved_wipe_log {
                let (format_status, device_sha256) = match &result {
                    Ok(outcome) => ("SUCCESS".to_string(), outcome.device_sha256.clone()),
                    Err(_) => ("FAILED".to_string(), "UNAVAILABLE".to_string()),
                };
                let format_info = FormatLogInfo {
                    partition_scheme: "GPT".to_string(),
                    filesystem: "exFAT".to_string(),
                    volume_label: attempted_label.clone().unwrap_or_else(|| "N/A".to_string()),
                    status: format_status,
                    device_sha256,
                };
                if let Err(error) = rewrite_wipe_log_with_format(saved_log, format_info) {
                    log_update_warning = Some(error);
                }
            }
            match result {
                Ok(outcome) => {
                    state.pending_post_wipe_drive = None;
                    let (drives, scan_status) = scan_with_status(&state.os_strategy);
                    state.drives = drives;
                    state.selected_drive = None;
                    state.status_message = format!("{} {scan_status}", outcome.message);
                }
                Err(error) => {
                    state.status_message = format!("Format failed: {error}");
                }
            }
            if let Some(error) = log_update_warning {
                state.status_message =
                    format!("{} (log update warning: {error})", state.status_message);
            }
            Task::none()
        }
    }
}

#[derive(Clone, Copy)]
enum StatTone {
    Neutral,
    Good,
    Warning,
    Danger,
    Info,
}

fn stat_pill(label: &'static str, value: String, _tone: StatTone) -> Element<'static, Message> {
    container(
        column![text(label).size(11), text(value).size(18)]
            .spacing(2)
            .width(Length::Shrink),
    )
    .padding([8, 12])
    .into()
}

fn neutral_card_header_style(theme: &iced::Theme, status: style::Status) -> style::card::Style {
    let mut card_style = style::card::primary(theme, status);
    let header_color = iced::Color::from_rgb8(0xAB, 0x9F, 0x9D);
    let header_text = iced::Color::from_rgb8(0x20, 0x20, 0x20);

    card_style.head_background = header_color.into();
    card_style.border_color = header_color;
    card_style.head_text_color = header_text;
    card_style.close_color = header_text;
    card_style
}

fn view(state: &WelcomeApp) -> Element<'_, Message> {
    let header = row![
        column![
            text("EternalRust").size(32),
            text("Forensic Wiping Utility").size(16)
        ]
        .spacing(2),
        Space::new().width(Length::Fill),
        button("Refresh Devices").on_press(Message::RefreshDevices)
    ];

    let mode_label = if state.is_wiping {
        "Wiping"
    } else if state.is_formatting {
        "Formatting"
    } else {
        "Idle"
    };
    let mode_tone = if state.is_wiping {
        StatTone::Warning
    } else if state.is_formatting {
        StatTone::Info
    } else {
        StatTone::Good
    };
    let selected_label = state
        .selected_drive
        .and_then(|index| state.drives.get(index))
        .map(|drive| {
            const MAX_LEN: usize = 24;
            let path = drive.device_path.clone();
            let char_count = path.chars().count();
            if char_count > MAX_LEN {
                let tail: String = path.chars().skip(char_count - (MAX_LEN - 3)).collect();
                format!("...{tail}")
            } else {
                path
            }
        })
        .unwrap_or_else(|| "None".to_string());

    let summary_strip = row![
        stat_pill(
            "Detected",
            state.drives.len().to_string(),
            StatTone::Neutral
        ),
        stat_pill(
            "Blocked",
            state.blocked_device_ids.len().to_string(),
            StatTone::Danger
        ),
        stat_pill("Mode", mode_label.to_string(), mode_tone),
        stat_pill("Selected", selected_label, StatTone::Info),
    ]
    .spacing(8)
    .width(Length::Fill);

    let header_panel = container(column![header, summary_strip].spacing(10))
        .padding(12)
        .width(Length::Fill);

    let mut preflight_panel = column![].spacing(4);
    if state.preflight.errors.is_empty() {
        preflight_panel = preflight_panel.push(text("Ready for wipe operations."));
    } else {
        preflight_panel = preflight_panel.push(text("Wipe operations are blocked:"));
        for error in &state.preflight.errors {
            preflight_panel = preflight_panel.push(text(format!("  - {}", error)));
        }
    }
    for warning in &state.preflight.warnings {
        preflight_panel = preflight_panel.push(text(format!("Warning: {}", warning)));
    }
    let preflight_card = Card::new(text("Preflight").size(20), preflight_panel)
        .style(neutral_card_header_style)
        .padding(12.into())
        .width(Length::Fill);

    let mut drive_list = column![].spacing(8).width(Length::Fill);

    if state.drives.is_empty() {
        drive_list = drive_list.push(text("No removable devices detected."));
    } else {
        for (index, drive) in state.drives.iter().enumerate() {
            let blocked_tag = if is_drive_blocked(&state.blocked_device_ids, drive) {
                " | BLOCKED"
            } else {
                ""
            };

            let label = format!(
                "{} - {} [{} | {} | {}{}]",
                drive.volume_name,
                drive.device_path,
                drive.drive_type,
                drive.mount_state,
                format_capacity(drive.capacity_bytes),
                blocked_tag
            );

            let drive_button = if Some(index) == state.selected_drive {
                button(text(label)).style(button::primary)
            } else {
                button(text(label)).style(button::secondary)
            }
            .width(Length::Fill)
            .on_press(Message::SelectDrive(index));

            drive_list = drive_list.push(drive_button);
        }
    }

    let drives_panel = Card::new(
        text("Removable Devices").size(20),
        scrollable(drive_list)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .style(neutral_card_header_style)
    .padding(12.into())
    .width(Length::FillPortion(2))
    .height(Length::Fill);

    let mut details_panel = column![].spacing(8).width(Length::Fill);

    if let Some(index) = state.selected_drive {
        if let Some(drive) = state.drives.get(index) {
            let blocked = is_drive_blocked(&state.blocked_device_ids, drive);

            details_panel = details_panel
                .push(text(format!("Device Path: {}", drive.device_path)))
                .push(text(format!("Volume Name: {}", drive.volume_name)))
                .push(text(format!("Vendor: {}", drive.vendor)))
                .push(text(format!("Model: {}", drive.model)))
                .push(text(format!("Serial Number: {}", drive.serial)))
                .push(text(format!("Transport: {}", drive.transport)))
                .push(text(format!("File System: {}", drive.file_system)))
                .push(text(format!("Mount Point: {}", drive.mount_point)))
                .push(text(format!("Mount State: {}", drive.mount_state)))
                .push(text(format!("Drive Type: {}", drive.drive_type)))
                .push(text(format!(
                    "Storage Capacity: {}",
                    format_capacity(drive.capacity_bytes)
                )))
                .push(text(format!(
                    "Device State: {}",
                    if blocked { "Blocked" } else { "Ready" }
                )));

            let block_label = if blocked {
                "Unblock Device"
            } else {
                "Block Device"
            };
            let mut block_button = button(text(block_label)).style(button::secondary);
            if !state.is_wiping && !state.is_formatting {
                block_button = block_button.on_press(Message::ToggleBlockSelected);
            }
            details_panel = details_panel.push(block_button);

            if is_usb_drive(drive) {
                details_panel = details_panel
                    .push(Space::new().height(8))
                    .push(text("USB Wipe Profile"))
                    .push(text("dc3dd, single pass, pattern 00"));
            }

            let can_wipe = can_start_wipe(state, drive);
            let mut wipe_button = button(text(if state.is_wiping {
                "Wiping..."
            } else {
                "Wipe Drive"
            }))
            .style(button::danger);

            if can_wipe {
                wipe_button = wipe_button.on_press(Message::StartWipe);
            }

            details_panel = details_panel.push(wipe_button);

            if state.is_wiping {
                let percent = (state.wipe_progress * 100.0).round();
                let eta_text = state
                    .wipe_eta_seconds
                    .map(format_eta)
                    .unwrap_or_else(|| "Finalizing...".to_string());
                let elapsed_text = state
                    .wipe_started_at
                    .map(|started| format_eta(started.elapsed().as_secs()))
                    .unwrap_or_else(|| "--:--".to_string());
                let target_text = state
                    .wiping_device_path
                    .as_deref()
                    .unwrap_or("Unknown target");
                details_panel = details_panel
                    .push(Space::new().height(8))
                    .push(text(format!("Wipe Progress (estimated): {percent:.0}%")))
                    .push(
                        container(progress_bar(0.0..=1.0, state.wipe_progress)).width(Length::Fill),
                    )
                    .push(text(format!("Estimated time remaining: {eta_text}")))
                    .push(text(format!("Elapsed: {elapsed_text}")))
                    .push(text(format!("Target: {target_text}")));
            }
        }
    } else {
        details_panel = details_panel.push(text("Select a removable device to view details."));
    }

    if let Some(post_wipe_drive) = &state.pending_post_wipe_drive {
        let sanitized = sanitize_volume_label(&state.volume_label_input);
        let mut format_button = button(text(if state.is_formatting {
            "Formatting..."
        } else {
            "Create GPT + Format exFAT"
        }))
        .style(button::warning);

        if !state.is_formatting && !state.is_wiping && !sanitized.is_empty() {
            format_button = format_button.on_press(Message::StartFormat);
        }

        details_panel = details_panel
            .push(Space::new().height(8))
            .push(text("Post-Wipe Actions").size(20))
            .push(text(format!("Target: {}", post_wipe_drive.device_path)))
            .push(
                text_input("New volume label (max 15 chars)", &state.volume_label_input)
                    .on_input(Message::VolumeLabelChanged)
                    .width(Length::Fill),
            )
            .push(text(format!("Sanitized label preview: {}", sanitized)))
            .push(format_button);

        if state.show_format_confirmation {
            let mut confirm_button = button("Confirm Format").style(button::danger);
            let mut cancel_button = button("Cancel").style(button::secondary);

            if !state.is_wiping && !state.is_formatting {
                confirm_button = confirm_button.on_press(Message::ConfirmFormat);
                cancel_button = cancel_button.on_press(Message::CancelFormatConfirmation);
            }

            details_panel = details_panel
                .push(text(
                    "Final confirmation: this will repartition and erase all data.",
                ))
                .push(row![confirm_button, cancel_button].spacing(8));
        }
    }

    let details_container = Card::new(
        text("Selected Device").size(20),
        scrollable(details_panel)
            .id(DETAILS_SCROLLABLE_ID)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .style(neutral_card_header_style)
    .padding(12.into())
    .width(Length::FillPortion(3))
    .height(Length::Fill);

    let body = row![drives_panel, details_container]
        .spacing(20)
        .width(Length::Fill)
        .height(Length::Fill);

    let footer = row![
        text(state.status_message.as_str()).size(14),
        Space::new().width(Length::Fill),
        text("Created by: 1ntrusi0n").size(14),
    ]
    .width(Length::Fill);

    container(
        column![header_panel, preflight_card, body, footer]
            .spacing(14)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .padding(20)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

fn can_start_wipe(state: &WelcomeApp, drive: &DriveInfo) -> bool {
    if state.is_wiping || state.is_formatting {
        return false;
    }
    if !state.preflight.can_run_destructive_ops() {
        return false;
    }
    if is_drive_blocked(&state.blocked_device_ids, drive) {
        return false;
    }
    true
}

fn selected_wipe_standard_for_drive(drive: &DriveInfo) -> WipeStandard {
    if is_usb_drive(drive) {
        WipeStandard::Nist80088Clear
    } else {
        WipeStandard::Nist80088Purge
    }
}

fn is_usb_drive(drive: &DriveInfo) -> bool {
    let drive_type = drive.drive_type.to_ascii_lowercase();
    let transport = drive.transport.to_ascii_lowercase();
    transport.contains("usb") || drive_type.contains("usb")
}

fn estimate_wipe_duration_seconds(drive: &DriveInfo, standard: &WipeStandard) -> u64 {
    let drive_type = drive.drive_type.to_ascii_lowercase();
    let transport = drive.transport.to_ascii_lowercase();
    let pass_multiplier = if is_usb_drive(drive) {
        match standard {
            WipeStandard::Nist80088Clear | WipeStandard::Nist80088Purge => 1,
            WipeStandard::DoD522022M => 3,
            WipeStandard::DoD522022MECE => 7,
            WipeStandard::Gutmann => 35,
            WipeStandard::Custom { passes } => passes.len().max(1) as u64,
        }
    } else {
        1
    };

    #[cfg(target_os = "windows")]
    let bytes_per_second: u64 = if transport.contains("usb") || drive_type.contains("usb") {
        25 * 1024 * 1024
    } else if drive_type.contains("nvme") {
        180 * 1024 * 1024
    } else if drive_type.contains("ssd") {
        95 * 1024 * 1024
    } else {
        80 * 1024 * 1024
    };

    #[cfg(target_os = "linux")]
    let bytes_per_second: u64 = if transport.contains("usb") || drive_type.contains("usb") {
        110 * 1024 * 1024
    } else if drive_type.contains("nvme") {
        700 * 1024 * 1024
    } else if drive_type.contains("ssd") {
        300 * 1024 * 1024
    } else {
        160 * 1024 * 1024
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let bytes_per_second: u64 = 80 * 1024 * 1024;

    let base = if drive.capacity_bytes == 0 {
        10 * 60
    } else {
        ((drive.capacity_bytes as f64 / bytes_per_second as f64).ceil() as u64).max(1)
    };

    let estimated = base.saturating_mul(pass_multiplier);
    (estimated + 90).clamp(60, 48 * 60 * 60)
}

fn format_eta(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes:02}:{secs:02}")
    }
}

fn drive_identity(drive: &DriveInfo) -> String {
    if !is_unknown(&drive.serial) {
        format!("serial:{}", drive.serial.to_ascii_lowercase())
    } else {
        format!("path:{}", drive.device_path.to_ascii_lowercase())
    }
}

fn is_drive_blocked(blocked: &HashSet<String>, drive: &DriveInfo) -> bool {
    blocked.contains(&drive_identity(drive))
}

fn is_unknown(value: &str) -> bool {
    value.trim().is_empty() || value.trim().eq_ignore_ascii_case("unknown")
}

fn detect_os_strategy() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        return "Windows scanner (PowerShell CIM)";
    }

    #[cfg(target_os = "linux")]
    {
        return "Linux scanner (lsblk)";
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        "Unsupported OS scanner"
    }
}

fn scan_with_status(os_strategy: &str) -> (Vec<DriveInfo>, String) {
    match scan_removable_drives() {
        Ok(mut drives) => {
            drives.sort_by(|a, b| a.device_path.cmp(&b.device_path));

            let status = if drives.is_empty() {
                format!("{os_strategy}: no removable drives detected.")
            } else {
                format!(
                    "{os_strategy}: detected {} removable drive(s).",
                    drives.len()
                )
            };

            (drives, status)
        }
        Err(error) => (
            Vec::new(),
            format!("{os_strategy}: failed to scan drives: {error}"),
        ),
    }
}

#[cfg(target_os = "windows")]
fn scan_removable_drives() -> Result<Vec<DriveInfo>, String> {
    scan_windows_removable_drives()
}

#[cfg(target_os = "linux")]
fn scan_removable_drives() -> Result<Vec<DriveInfo>, String> {
    scan_linux_removable_drives()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn scan_removable_drives() -> Result<Vec<DriveInfo>, String> {
    Err(format!(
        "Unsupported operating system: {}",
        std::env::consts::OS
    ))
}

#[cfg(target_os = "linux")]
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to run {program}: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("exit code {:?}", output.status.code())
        } else {
            stderr
        };
        return Err(format!("{program} returned error: {message}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn run_command_record(program: &str, args: &[String]) -> Result<CommandRecord, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to run {program}: {error}"))?;

    Ok(CommandRecord {
        command: format!("{} {}", program, args.join(" ")),
        exit_code: output.status.code(),
        stdout: truncate_for_log(String::from_utf8_lossy(&output.stdout).to_string()),
        stderr: truncate_for_log(String::from_utf8_lossy(&output.stderr).to_string()),
    })
}

fn truncate_for_log(input: String) -> String {
    let trimmed = input.trim().to_string();
    const MAX_LOG_CHARS: usize = 20_000;
    if trimmed.len() > MAX_LOG_CHARS {
        format!(
            "{}\n...[truncated {} chars]...",
            &trimmed[..MAX_LOG_CHARS],
            trimmed.len().saturating_sub(MAX_LOG_CHARS)
        )
    } else {
        trimmed
    }
}

fn format_capacity(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    format!("{value:.2} {}", UNITS[unit_index])
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn display_value_or_unknown(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        "Unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn format_local_datetime(unix: u64) -> String {
    if let Some(dt) = Local.timestamp_opt(unix as i64, 0).single() {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        "1970-01-01 00:00:00".to_string()
    }
}

fn format_log_timestamp_for_filename(unix: u64) -> String {
    if let Some(dt) = Local.timestamp_opt(unix as i64, 0).single() {
        dt.format("%Y%m%d_%H%M%S").to_string()
    } else {
        "19700101_000000".to_string()
    }
}

fn build_wipe_log_file_name(unix: u64) -> String {
    format!("WipeLog_{}.txt", format_log_timestamp_for_filename(unix))
}

fn format_elapsed_hms(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{hours}:{minutes:02}:{secs:02}")
}

fn build_wipe_log_text(
    execution: &WipeExecution,
    log_path: &Path,
    format_info: Option<&FormatLogInfo>,
    generated_unix: u64,
) -> String {
    let drive = &execution.drive;
    let elapsed = execution.ended_unix.saturating_sub(execution.started_unix);
    let divider = "================================================================";
    let section = "----------------------------------------------------------------";

    let default_format_info;
    let format_info = if let Some(info) = format_info {
        info
    } else {
        default_format_info = FormatLogInfo {
            partition_scheme: "GPT".to_string(),
            filesystem: "exFAT".to_string(),
            volume_label: "N/A".to_string(),
            status: "PENDING".to_string(),
            device_sha256: "PENDING".to_string(),
        };
        &default_format_info
    };

    let mut lines = Vec::new();
    lines.push(divider.to_string());
    lines.push("            REMOVABLE DEVICE WIPE LOG".to_string());
    lines.push(divider.to_string());
    lines.push(String::new());
    lines.push(format!(
        "Vendor        : {}",
        display_value_or_unknown(&drive.vendor)
    ));
    lines.push(format!(
        "Serial Number : {}",
        display_value_or_unknown(&drive.serial)
    ));
    lines.push(String::new());
    lines.push(section.to_string());
    lines.push("DEVICE INFORMATION".to_string());
    lines.push(section.to_string());
    lines.push(format!("Device Path   : {}", drive.device_path));
    lines.push(format!(
        "Model         : {}",
        display_value_or_unknown(&drive.model)
    ));
    lines.push(format!(
        "Size          : {}",
        format_capacity(drive.capacity_bytes)
    ));
    lines.push(format!(
        "Type          : {}",
        display_value_or_unknown(&drive.drive_type)
    ));
    lines.push(format!(
        "Volume Label  : {}",
        display_value_or_unknown(&drive.volume_name)
    ));
    lines.push(String::new());
    lines.push(section.to_string());
    lines.push("WIPE DETAILS".to_string());
    lines.push(section.to_string());
    lines.push(format!("Wipe Standard : {}", execution.wipe_standard));
    lines.push(format!("Wipe Method   : {}", execution.wipe_method));
    lines.push(format!(
        "Total Passes  : {}",
        execution.passes_completed.max(1)
    ));
    lines.push(format!(
        "Wipe Started  : {}",
        format_local_datetime(execution.started_unix)
    ));
    lines.push(format!(
        "Wipe Ended    : {}",
        format_local_datetime(execution.ended_unix)
    ));
    lines.push(format!("Total Elapsed : {}", format_elapsed_hms(elapsed)));
    lines.push(format!(
        "Verified      : {}",
        if execution.verified { "YES" } else { "NO" }
    ));
    lines.push(format!(
        "Wipe Status   : {}",
        if execution.success {
            "SUCCESS"
        } else {
            "FAILED"
        }
    ));
    lines.push(String::new());
    lines.push(section.to_string());
    lines.push("POST-WIPE FORMATTING".to_string());
    lines.push(section.to_string());
    lines.push(format!(
        "Partition Scheme : {}",
        format_info.partition_scheme
    ));
    lines.push(format!("Filesystem       : {}", format_info.filesystem));
    lines.push(format!(
        "Volume Label     : {}",
        display_value_or_unknown(&format_info.volume_label)
    ));
    lines.push(format!("Format Status    : {}", format_info.status));
    lines.push(format!(
        "Device SHA256    : {}",
        display_value_or_unknown(&format_info.device_sha256)
    ));
    lines.push(String::new());
    lines.push(section.to_string());
    lines.push(format!(
        "Log generated : {}",
        format_local_datetime(generated_unix)
    ));
    lines.push(format!("Log file      : {}", log_path.to_string_lossy()));
    lines.push(divider.to_string());
    lines.push(String::new());
    lines.push("COMMAND TRACE (Audit)".to_string());
    lines.push(section.to_string());
    for (index, record) in execution.commands.iter().enumerate() {
        lines.push(format!("Step {}: {}", index + 1, record.command));
        lines.push(format!(
            "Exit Code: {}",
            record
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "None".to_string())
        ));
        if !record.stdout.is_empty() {
            lines.push("STDOUT:".to_string());
            for line in record.stdout.lines() {
                lines.push(format!("  {}", line));
            }
        }
        if !record.stderr.is_empty() {
            lines.push("STDERR:".to_string());
            for line in record.stderr.lines() {
                lines.push(format!("  {}", line));
            }
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

fn config_file_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("."));
        return base.join("EternalRust").join("state.json");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let base = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(".config").join("eternalrust").join("state.json")
    }
}

fn load_persisted_state() -> (PathBuf, PersistedState) {
    let path = config_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut state = fs::read_to_string(&path)
        .ok()
        .and_then(|json| serde_json::from_str::<PersistedState>(&json).ok())
        .unwrap_or_default();

    if state.default_volume_label.trim().is_empty() {
        state.default_volume_label = DEFAULT_VOLUME_LABEL.to_string();
    }

    (path, state)
}

fn save_persisted_state(path: &Path, state: &PersistedState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed creating state directory: {error}"))?;
    }

    let json = serde_json::to_string_pretty(state)
        .map_err(|error| format!("Failed serializing state: {error}"))?;
    fs::write(path, json).map_err(|error| format!("Failed writing state: {error}"))
}

fn run_preflight_checks() -> PreflightReport {
    let mut report = PreflightReport::default();

    if !is_running_with_admin_privileges() {
        report.errors.push(
            "Administrator/root privileges are required for wipe/format operations.".to_string(),
        );
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(error) = ensure_linux_gdisk_installed() {
            report
                .warnings
                .push(format!("Automatic gdisk install attempt failed: {error}"));
        }

        let required_tools = ["dc3dd", "lsblk", "sgdisk", "mkfs.exfat", "partprobe"];
        let missing: Vec<String> = required_tools
            .iter()
            .filter(|tool| !command_exists(tool))
            .map(|tool| (*tool).to_string())
            .collect();
        if !missing.is_empty() {
            report.errors.push(format!(
                "Missing required Linux tools: {}",
                missing.join(", ")
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let required_tools = ["powershell", "diskpart"];
        let missing: Vec<String> = required_tools
            .iter()
            .filter(|tool| !command_exists(tool))
            .map(|tool| (*tool).to_string())
            .collect();
        if !missing.is_empty() {
            report.errors.push(format!(
                "Missing required Windows tools: {}",
                missing.join(", ")
            ));
        }
    }

    report
}

fn command_exists(binary_name: &str) -> bool {
    let Some(path_value) = env::var_os("PATH") else {
        return false;
    };

    #[cfg(target_os = "windows")]
    let exts: Vec<String> = env::var("PATHEXT")
        .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
        .split(';')
        .map(str::to_string)
        .collect();

    for directory in env::split_paths(&path_value) {
        #[cfg(target_os = "windows")]
        {
            let candidate = directory.join(binary_name);
            if candidate.is_file() {
                return true;
            }

            for extension in &exts {
                let candidate = directory.join(format!("{binary_name}{extension}"));
                if candidate.is_file() {
                    return true;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let candidate = directory.join(binary_name);
            if candidate.is_file() {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn run_linux_command_checked(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("Failed running {program}: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit code {:?}", output.status.code())
    };

    Err(format!("{program} {} failed: {detail}", args.join(" ")))
}

#[cfg(target_os = "linux")]
fn ensure_linux_gdisk_installed() -> Result<(), String> {
    if command_exists("gdisk") && command_exists("sgdisk") {
        return Ok(());
    }

    let package_manager = if command_exists("apt-get") {
        "apt-get"
    } else if command_exists("apt") {
        "apt"
    } else {
        return Err(
            "Neither apt-get nor apt was found for automatic gdisk installation.".to_string(),
        );
    };

    if is_running_with_admin_privileges() {
        run_linux_command_checked(package_manager, &["update"])?;
        run_linux_command_checked(package_manager, &["install", "-y", "gdisk"])?;
    } else if command_exists("sudo") {
        run_linux_command_checked("sudo", &[package_manager, "update"])?;
        run_linux_command_checked("sudo", &[package_manager, "install", "-y", "gdisk"])?;
    } else {
        return Err("sudo is required to automatically install gdisk.".to_string());
    }

    if command_exists("sgdisk") {
        Ok(())
    } else {
        Err("gdisk installation finished, but sgdisk is still missing from PATH.".to_string())
    }
}

#[cfg(target_os = "windows")]
fn is_running_with_admin_privileges() -> bool {
    let script = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output();

    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn is_running_with_admin_privileges() -> bool {
    let output = Command::new("id").args(["-u"]).output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim() == "0"
        }
        _ => false,
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn is_running_with_admin_privileges() -> bool {
    false
}

fn sanitize_volume_label(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '-' | '_'))
        .collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        DEFAULT_VOLUME_LABEL.to_string()
    } else {
        trimmed.chars().take(EXFAT_LABEL_MAX).collect()
    }
}

fn compute_device_sha256(device_path: &str) -> Result<String, String> {
    let mut file = fs::File::open(device_path)
        .map_err(|error| format!("unable to open {device_path}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed reading {device_path}: {error}"))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
}

async fn run_wipe_task(
    drive: DriveInfo,
    standard: WipeStandard,
    native_progress: Option<Arc<AtomicU32>>,
) -> Result<WipeExecution, String> {
    tokio::task::spawn_blocking(move || perform_wipe_sync(drive, standard, native_progress))
        .await
        .map_err(|error| format!("Wipe worker join error: {error}"))?
}

async fn run_format_task(
    drive: DriveInfo,
    volume_label: String,
) -> Result<FormatTaskResult, String> {
    tokio::task::spawn_blocking(move || {
        let message = perform_format_sync(drive.clone(), &volume_label)?;
        let device_sha256 = match compute_device_sha256(&drive.device_path) {
            Ok(hash) => hash,
            Err(error) => format!("UNAVAILABLE ({error})"),
        };
        Ok(FormatTaskResult {
            message,
            device_sha256,
        })
    })
    .await
    .map_err(|error| format!("Format worker join error: {error}"))?
}

fn rewrite_wipe_log_with_format(
    saved_log: &SavedWipeLog,
    format_info: FormatLogInfo,
) -> Result<(), String> {
    let log_text = build_wipe_log_text(
        &saved_log.execution,
        &saved_log.path,
        Some(&format_info),
        unix_now(),
    );
    fs::write(&saved_log.path, log_text).map_err(|error| {
        format!(
            "Failed updating wipe log {}: {error}",
            saved_log.path.to_string_lossy()
        )
    })
}

async fn save_wipe_log(
    execution: WipeExecution,
    suggested_dir: Option<String>,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        return save_wipe_log_windows(execution, suggested_dir).await;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = suggested_dir;
        return save_wipe_log_linux(execution);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = execution;
        let _ = suggested_dir;
        Err("Unsupported OS for wipe log saving.".to_string())
    }
}

#[cfg(target_os = "windows")]
async fn save_wipe_log_windows(
    execution: WipeExecution,
    suggested_dir: Option<String>,
) -> Result<String, String> {
    let timestamp = execution.ended_unix.max(unix_now());
    let file_name = build_wipe_log_file_name(timestamp);

    let mut dialog = AsyncFileDialog::new()
        .set_title("Save Wipe Log")
        .set_file_name(&file_name)
        .add_filter("Text Log", &["txt"]);

    if let Some(path) = suggested_dir {
        dialog = dialog.set_directory(path);
    }

    let Some(file_handle) = dialog.save_file().await else {
        return Err("Save canceled by user.".to_string());
    };

    let output_path = file_handle.path().to_path_buf();
    let log_text = build_wipe_log_text(&execution, &output_path, None, unix_now());
    fs::write(&output_path, log_text)
        .map_err(|error| format!("Failed writing log file: {error}"))?;
    Ok(output_path.to_string_lossy().to_string())
}

#[cfg(target_os = "linux")]
fn save_wipe_log_linux(execution: WipeExecution) -> Result<String, String> {
    let timestamp = execution.ended_unix.max(unix_now());
    let output_dir = linux_default_log_dir();
    fs::create_dir_all(&output_dir).map_err(|error| {
        format!(
            "Failed creating log directory {}: {error}",
            output_dir.to_string_lossy()
        )
    })?;
    chown_path_to_linux_user(&output_dir)?;

    let output_path = output_dir.join(build_wipe_log_file_name(timestamp));
    let log_text = build_wipe_log_text(&execution, &output_path, None, unix_now());
    fs::write(&output_path, log_text).map_err(|error| {
        format!(
            "Failed writing log file {}: {error}",
            output_path.to_string_lossy()
        )
    })?;
    chown_path_to_linux_user(&output_path)?;
    Ok(output_path.to_string_lossy().to_string())
}

#[cfg(target_os = "linux")]
fn chown_path_to_linux_user(path: &Path) -> Result<(), String> {
    let target_user = env::var("SUDO_USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "user".to_string());

    let status = Command::new("chown")
        .arg(format!("{target_user}:{target_user}"))
        .arg(path)
        .status()
        .map_err(|error| {
            format!(
                "Failed running chown for {}: {error}",
                path.to_string_lossy()
            )
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Failed changing ownership for {} to {target_user}",
            path.to_string_lossy()
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_default_log_dir() -> PathBuf {
    let preferred_home = linux_preferred_home_dir();
    preferred_home
        .join("Desktop")
        .join("Host_Evidence")
        .join("Wiping_Log")
}

#[cfg(target_os = "linux")]
fn linux_preferred_home_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        let home_path = PathBuf::from(home);
        if home_path != PathBuf::from("/root") {
            return home_path;
        }
    }

    if let Some(sudo_user) = env::var_os("SUDO_USER") {
        let candidate = PathBuf::from("/home").join(sudo_user);
        if candidate.exists() {
            return candidate;
        }
    }

    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn perform_wipe_sync(
    drive: DriveInfo,
    standard: WipeStandard,
    native_progress: Option<Arc<AtomicU32>>,
) -> Result<WipeExecution, String> {
    #[cfg(target_os = "linux")]
    {
        if is_usb_drive(&drive) {
            return perform_linux_usb_wipe_with_dc3dd(drive, native_progress);
        }

        return perform_wipe_with_algorithm(drive, standard, native_progress);
    }

    #[cfg(target_os = "windows")]
    {
        return perform_wipe_with_algorithm(drive, standard, native_progress);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = drive;
        let _ = standard;
        let _ = native_progress;
        Err("Unsupported OS for wipe operations.".to_string())
    }
}

fn perform_format_sync(drive: DriveInfo, volume_label: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        return perform_format_linux(drive, volume_label);
    }

    #[cfg(target_os = "windows")]
    {
        return perform_format_windows(drive, volume_label);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = volume_label;
        Err("Unsupported OS for format operations.".to_string())
    }
}

#[cfg(target_os = "linux")]
fn list_linux_mount_points(device_path: &str) -> Result<Vec<String>, String> {
    let output = run_command("lsblk", &["-nr", "-o", "MOUNTPOINT", device_path])?;
    let mut points = Vec::new();
    let mut seen = HashSet::new();

    for line in output.lines() {
        let mount = line.trim();
        if mount.is_empty() || mount == "-" {
            continue;
        }
        let mount = mount.to_string();
        if seen.insert(mount.clone()) {
            points.push(mount);
        }
    }

    Ok(points)
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn perform_wipe_with_algorithm(
    drive: DriveInfo,
    standard: WipeStandard,
    native_progress: Option<Arc<AtomicU32>>,
) -> Result<WipeExecution, String> {
    #[cfg(target_os = "linux")]
    {
        let mount_points = list_linux_mount_points(&drive.device_path)?;
        for mount_point in mount_points {
            let args = vec!["-f".to_string(), mount_point.clone()];
            let record = run_command_record("umount", &args)?;
            if !record.succeeded() {
                let detail = if !record.stderr.trim().is_empty() {
                    record.stderr.trim().to_string()
                } else if !record.stdout.trim().is_empty() {
                    record.stdout.trim().to_string()
                } else {
                    format!("exit code {:?}", record.exit_code)
                };
                return Err(format!(
                    "Failed to unmount {mount_point} before wipe: {detail}"
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        prepare_windows_disk_for_wipe(&drive)?;
    }

    let wipe_result = run_wipe_engine(&drive, standard, native_progress)?;
    Ok(convert_wipe_result_to_execution(drive, wipe_result))
}

#[cfg(target_os = "linux")]
fn perform_linux_usb_wipe_with_dc3dd(
    drive: DriveInfo,
    native_progress: Option<Arc<AtomicU32>>,
) -> Result<WipeExecution, String> {
    let mount_points = list_linux_mount_points(&drive.device_path)?;
    let mut commands = Vec::new();

    for mount_point in mount_points {
        let args = vec!["-f".to_string(), mount_point.clone()];
        let record = run_command_record("umount", &args)?;
        if !record.succeeded() {
            let detail = command_record_error_detail(&record);
            return Err(format!(
                "Failed to unmount {mount_point} before wipe: {detail}"
            ));
        }
        commands.push(record);
    }

    let started_unix = unix_now();
    let dc3dd_args = vec![format!("wipe={}", drive.device_path), "pat=00".to_string()];
    let record = run_command_record("dc3dd", &dc3dd_args)?;
    let ended_unix = unix_now();

    if let Some(tracker) = native_progress {
        tracker.store(10_000, Ordering::Relaxed);
    }

    if !record.succeeded() {
        let detail = command_record_error_detail(&record);
        return Err(format!(
            "dc3dd wipe failed for {}: {detail}",
            drive.device_path
        ));
    }

    commands.push(record);

    Ok(WipeExecution {
        drive,
        wipe_standard: wipe_standard_label(&WipeStandard::Nist80088Clear),
        wipe_method: "dc3dd pattern overwrite (1 pass, pat=00)".to_string(),
        passes_completed: 1,
        verified: false,
        success: true,
        started_unix,
        ended_unix,
        commands,
    })
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn run_wipe_engine(
    drive: &DriveInfo,
    standard: WipeStandard,
    native_progress: Option<Arc<AtomicU32>>,
) -> Result<AlgoWipeResult, String> {
    #[cfg(target_os = "linux")]
    let mut engine = WipeEngine::open(&drive.device_path)
        .map_err(|error| format!("WipeAlgorithm open failed: {error}"))?;

    #[cfg(target_os = "windows")]
    let mut engine = WipeEngine::with_device_info(build_windows_algo_device_info(drive));

    if let Some(progress_tracker) = native_progress.clone() {
        engine = engine.with_progress_callback(move |progress: AlgoProgressInfo| {
            progress_tracker.store(scale_progress_to_native(&progress), Ordering::Relaxed);
        });
    }

    let result = engine
        .wipe(standard)
        .map_err(|error| format!("WipeAlgorithm wipe failed: {error}"))?;

    if let Some(tracker) = native_progress {
        tracker.store(10_000, Ordering::Relaxed);
    }

    Ok(result)
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn scale_progress_to_native(progress: &AlgoProgressInfo) -> u32 {
    let total_passes = progress.total_passes.max(1) as f64;
    let pass_index = progress.current_pass.saturating_sub(1) as f64;
    let pass_progress = (progress.percentage / 100.0).clamp(0.0, 1.0);
    let overall = ((pass_index + pass_progress) / total_passes).clamp(0.0, 1.0);
    (overall * 10_000.0).round() as u32
}

fn wipe_standard_label(standard: &WipeStandard) -> String {
    match standard {
        WipeStandard::Nist80088Clear => "NIST 800-88 Clear (1-pass zero fill)".to_string(),
        WipeStandard::Nist80088Purge => "NIST 800-88 Purge".to_string(),
        WipeStandard::DoD522022M => "DoD 5220.22-M (3-pass)".to_string(),
        WipeStandard::DoD522022MECE => "USAF / DoD 5220.22-M ECE (7-pass)".to_string(),
        WipeStandard::Gutmann => "Gutmann (35-pass)".to_string(),
        WipeStandard::Custom { .. } => "Custom".to_string(),
    }
}

fn wipe_method_label(method: &WipeMethod) -> String {
    match method {
        WipeMethod::SoftwareOverwrite { passes } => {
            format!("Software overwrite ({} pass(es))", passes.len())
        }
        WipeMethod::AtaSecureErase => "ATA Secure Erase".to_string(),
        WipeMethod::AtaEnhancedSecureErase => "ATA Enhanced Secure Erase".to_string(),
        WipeMethod::NvmeSanitizeCryptoErase => "NVMe Sanitize Crypto Erase".to_string(),
        WipeMethod::NvmeSanitizeBlockErase => "NVMe Sanitize Block Erase".to_string(),
        WipeMethod::NvmeSanitizeOverwrite { pass_count } => {
            format!("NVMe Sanitize Overwrite ({pass_count} pass(es))")
        }
        WipeMethod::NvmeFormatUserDataErase => "NVMe Format User Data Erase".to_string(),
        WipeMethod::NvmeFormatCryptoErase => "NVMe Format Crypto Erase".to_string(),
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn convert_wipe_result_to_execution(drive: DriveInfo, result: AlgoWipeResult) -> WipeExecution {
    let result_json = result.to_json().unwrap_or_else(|error| {
        format!("{{\"error\":\"Failed serializing WipeResult: {error}\"}}")
    });
    let requested_standard = wipe_standard_label(&result.standard_requested);
    let record = CommandRecord {
        command: format!("wipe_algorithm::WipeEngine::wipe({requested_standard})"),
        exit_code: Some(if result.success { 0 } else { 1 }),
        stdout: truncate_for_log(result_json),
        stderr: truncate_for_log(result.messages.join("\n")),
    };

    WipeExecution {
        drive,
        wipe_standard: wipe_standard_label(&result.standard_requested),
        wipe_method: wipe_method_label(&result.method_used),
        passes_completed: result.passes_completed,
        verified: result.verified,
        success: result.success,
        started_unix: result.started_at_unix.max(0) as u64,
        ended_unix: result.completed_at_unix.max(0) as u64,
        commands: vec![record],
    }
}

#[cfg(target_os = "windows")]
fn build_windows_algo_device_info(drive: &DriveInfo) -> AlgoDeviceInfo {
    // Current Windows path uses software-overwrite metadata for the embedded wipe engine.
    AlgoDeviceInfo {
        path: drive.device_path.clone(),
        device_type: AlgoDeviceType::Usb,
        size_bytes: drive.capacity_bytes,
        model: if is_unknown(&drive.model) {
            None
        } else {
            Some(drive.model.clone())
        },
        serial: if is_unknown(&drive.serial) {
            None
        } else {
            Some(drive.serial.clone())
        },
        removable: true,
        sector_size: 512,
        ata_security_supported: false,
        ata_security_frozen: false,
        ata_enhanced_erase_supported: false,
        nvme_sanitize_caps: 0,
    }
}

#[cfg(target_os = "windows")]
fn prepare_windows_disk_for_wipe(drive: &DriveInfo) -> Result<(), String> {
    let disk_number = extract_windows_disk_number(&drive.device_path)
        .ok_or_else(|| format!("Could not parse disk number from {}", drive.device_path))?;

    let script =
        format!("select disk {disk_number}\nattributes disk clear readonly\nonline disk noerr\n");
    let record = run_diskpart_script(&script, None)?;
    if !record.succeeded() {
        return Err(format!(
            "diskpart prep failed for {}: {}",
            drive.device_path,
            command_record_error_detail(&record)
        ));
    }

    Ok(())
}

fn command_record_error_detail(record: &CommandRecord) -> String {
    if !record.stderr.trim().is_empty() {
        record.stderr.trim().to_string()
    } else if !record.stdout.trim().is_empty() {
        record.stdout.trim().to_string()
    } else {
        format!("exit code {:?}", record.exit_code)
    }
}

#[cfg(target_os = "linux")]
fn perform_format_linux(drive: DriveInfo, volume_label: &str) -> Result<String, String> {
    let label = sanitize_volume_label(volume_label);

    let mount_points = list_linux_mount_points(&drive.device_path)?;
    for mount_point in mount_points {
        let args = vec!["-f".to_string(), mount_point];
        let record = run_command_record("umount", &args)?;
        if !record.succeeded() {
            return Err("Failed to unmount partitions before format.".to_string());
        }
    }

    let prep_args = vec![
        "--clear".to_string(),
        "--new".to_string(),
        "1:0:0".to_string(),
        "--typecode".to_string(),
        "1:0700".to_string(),
        "--change-name".to_string(),
        format!("1:{label}"),
        drive.device_path.clone(),
    ];
    let prep_record = run_command_record("sgdisk", &prep_args)?;
    if !prep_record.succeeded() {
        return Err("Failed creating GPT partition table.".to_string());
    }

    let partprobe_args = vec![drive.device_path.clone()];
    let partprobe_record = run_command_record("partprobe", &partprobe_args)?;
    if !partprobe_record.succeeded() {
        return Err("partprobe failed after partitioning.".to_string());
    }

    let partition_path = wait_for_linux_partition(&drive.device_path, Duration::from_secs(15));
    let mkfs_args = vec!["-n".to_string(), label.clone(), partition_path.clone()];
    let mkfs_record = run_command_record("mkfs.exfat", &mkfs_args)?;
    if !mkfs_record.succeeded() {
        return Err(format!("mkfs.exfat failed for {partition_path}."));
    }

    Ok(format!(
        "Format complete: {} now has GPT + exFAT ({})",
        drive.device_path, label
    ))
}

#[cfg(target_os = "linux")]
fn linux_partition_path(device_path: &str) -> String {
    if device_path.contains("nvme") || device_path.contains("mmcblk") {
        format!("{device_path}p1")
    } else {
        format!("{device_path}1")
    }
}

#[cfg(target_os = "linux")]
fn wait_for_linux_partition(device_path: &str, timeout: Duration) -> String {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(output) = run_command("lsblk", &["-nr", "-o", "PATH", device_path]) {
            for line in output.lines() {
                let path = line.trim();
                if path.is_empty() {
                    continue;
                }
                if path != device_path {
                    return path.to_string();
                }
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    linux_partition_path(device_path)
}

#[cfg(target_os = "windows")]
fn run_diskpart_script(
    script_text: &str,
    native_progress: Option<&Arc<AtomicU32>>,
) -> Result<CommandRecord, String> {
    let temp_path = env::temp_dir().join(format!("eternalrust-diskpart-{}.txt", unix_now()));
    fs::write(&temp_path, script_text)
        .map_err(|error| format!("Failed writing diskpart script: {error}"))?;

    let mut child = Command::new("diskpart")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("/s")
        .arg(&temp_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed running diskpart: {error}"))?;

    let mut stdout_text = String::new();
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line_result in reader.lines() {
            let line =
                line_result.map_err(|error| format!("Failed reading diskpart output: {error}"))?;
            if let Some(progress) = parse_percent_from_line(&line) {
                if let Some(tracker) = native_progress {
                    tracker.store((progress * 100.0).round() as u32, Ordering::Relaxed);
                }
            }
            stdout_text.push_str(&line);
            stdout_text.push('\n');
        }
    }

    let status = child
        .wait()
        .map_err(|error| format!("Failed waiting for diskpart: {error}"))?;

    let mut stderr_text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        stderr
            .read_to_string(&mut stderr_text)
            .map_err(|error| format!("Failed reading diskpart stderr: {error}"))?;
    }

    let _ = fs::remove_file(&temp_path);
    if status.success() {
        if let Some(tracker) = native_progress {
            tracker.store(10_000, Ordering::Relaxed);
        }
    }

    Ok(CommandRecord {
        command: format!("diskpart /s {}", temp_path.display()),
        exit_code: status.code(),
        stdout: truncate_for_log(stdout_text),
        stderr: truncate_for_log(stderr_text),
    })
}

#[cfg(target_os = "windows")]
fn perform_format_windows(drive: DriveInfo, volume_label: &str) -> Result<String, String> {
    let label = sanitize_volume_label(volume_label);
    let disk_number = extract_windows_disk_number(&drive.device_path)
        .ok_or_else(|| format!("Could not parse disk number from {}", drive.device_path))?;

    let script = format!(
        "select disk {disk_number}\n\
attributes disk clear readonly\n\
online disk noerr\n\
clean\n\
convert gpt\n\
create partition primary\n\
format fs=exfat quick label=\"{label}\"\n\
assign\n"
    );

    let record = run_diskpart_script(&script, None)?;
    if !record.succeeded() {
        return Err("diskpart GPT/exFAT format failed.".to_string());
    }

    Ok(format!(
        "Format complete: {} now has GPT + exFAT ({})",
        drive.device_path, label
    ))
}

#[cfg(target_os = "windows")]
fn parse_percent_from_line(line: &str) -> Option<f32> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("percent") {
        return None;
    }

    for token in lower.split(|ch: char| !ch.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }

        if let Ok(value) = token.parse::<u32>() {
            if value <= 100 {
                return Some(value as f32);
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn extract_windows_disk_number(device_path: &str) -> Option<u32> {
    let uppercase = device_path.to_ascii_uppercase();

    if let Some(index) = uppercase.find("PHYSICALDRIVE") {
        let start = index + "PHYSICALDRIVE".len();
        let digits: String = uppercase[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            return digits.parse::<u32>().ok();
        }
    }

    let digits: String = uppercase.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

#[cfg(target_os = "windows")]
fn scan_windows_removable_drives() -> Result<Vec<DriveInfo>, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$disks = Get-CimInstance Win32_DiskDrive
$rows = foreach ($disk in $disks) {
  $partitions = @(Get-CimAssociatedInstance -InputObject $disk -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue)
  $logical = @()
  foreach ($partition in $partitions) {
    $logical += @(Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue)
  }

  $mounts = @($logical | ForEach-Object { $_.DeviceID } | Where-Object { $_ } | Sort-Object -Unique)
  $filesystems = @($logical | ForEach-Object { $_.FileSystem } | Where-Object { $_ } | Sort-Object -Unique)
  $labels = @($logical | ForEach-Object { $_.VolumeName } | Where-Object { $_ } | Sort-Object -Unique)
  $mountState = if ($mounts.Count -gt 0) { 'Mounted' } else { 'Unmounted' }
  $isRemovable = (($disk.InterfaceType -match 'USB') -or ($disk.MediaType -match 'Removable'))

  [PSCustomObject]@{
    DevicePath = $disk.DeviceID
    VolumeName = ($labels -join ', ')
    Vendor = $disk.Manufacturer
    Model = $disk.Model
    Serial = $disk.SerialNumber
    Transport = $disk.InterfaceType
    MediaType = $disk.MediaType
    CapacityBytes = [UInt64]$disk.Size
    FileSystem = ($filesystems -join ', ')
    MountPoint = ($mounts -join ', ')
    MountState = $mountState
    IsRemovable = $isRemovable
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
"#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|error| format!("Failed to invoke PowerShell: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("exit code {:?}", output.status.code())
        } else {
            stderr
        };
        return Err(format!("PowerShell disk scan failed: {detail}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Ok(Vec::new());
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|error| format!("Invalid JSON: {error}"))?;

    let entries: Vec<serde_json::Value> = if let Some(array) = parsed.as_array() {
        array.clone()
    } else if parsed.is_object() {
        vec![parsed]
    } else {
        Vec::new()
    };

    let mut drives = Vec::new();
    for entry in entries {
        let is_removable = entry
            .get("IsRemovable")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !is_removable {
            continue;
        }

        let device_path =
            clean_or_unknown(entry.get("DevicePath").and_then(|value| value.as_str()));
        let volume_name =
            clean_or_unknown(entry.get("VolumeName").and_then(|value| value.as_str()));
        let vendor = clean_or_unknown(entry.get("Vendor").and_then(|value| value.as_str()));
        let model = clean_or_unknown(entry.get("Model").and_then(|value| value.as_str()));
        let serial = clean_or_unknown(entry.get("Serial").and_then(|value| value.as_str()));
        let transport =
            normalize_transport(entry.get("Transport").and_then(|value| value.as_str()));
        let media_type = clean_or_unknown(entry.get("MediaType").and_then(|value| value.as_str()));
        let file_system =
            clean_or_unknown(entry.get("FileSystem").and_then(|value| value.as_str()));
        let mount_point =
            clean_or_unknown(entry.get("MountPoint").and_then(|value| value.as_str()));
        let mount_state =
            clean_or_unknown(entry.get("MountState").and_then(|value| value.as_str()));
        let capacity_bytes = entry
            .get("CapacityBytes")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);

        let drive_type = if transport.to_ascii_lowercase().contains("usb") {
            if model.to_ascii_lowercase().contains("nvme") {
                "USB (NVME enclosure)".to_string()
            } else {
                "USB".to_string()
            }
        } else if model.to_ascii_lowercase().contains("nvme")
            || media_type.to_ascii_lowercase().contains("nvme")
        {
            "NVME".to_string()
        } else if media_type.to_ascii_lowercase().contains("ssd")
            || media_type.to_ascii_lowercase().contains("solid state")
        {
            "SSD".to_string()
        } else {
            "Unknown".to_string()
        };

        drives.push(DriveInfo {
            device_path,
            volume_name,
            vendor,
            model,
            serial,
            transport,
            file_system,
            mount_point,
            mount_state,
            drive_type,
            capacity_bytes,
        });
    }

    Ok(drives)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Clone)]
struct LinuxLsblkResponse {
    blockdevices: Vec<LinuxLsblkDevice>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Clone)]
struct LinuxLsblkDevice {
    name: Option<String>,
    path: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_boolish")]
    rm: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_boolish")]
    hotplug: Option<bool>,
    tran: Option<String>,
    model: Option<String>,
    vendor: Option<String>,
    serial: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_u64ish")]
    size: Option<u64>,
    fstype: Option<String>,
    mountpoint: Option<String>,
    mountpoints: Option<Vec<Option<String>>>,
    label: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_boolish")]
    rota: Option<bool>,
    #[serde(rename = "type")]
    kind: Option<String>,
    children: Option<Vec<LinuxLsblkDevice>>,
}

#[cfg(target_os = "linux")]
fn deserialize_option_boolish<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|raw| match raw {
        serde_json::Value::Bool(flag) => Some(flag),
        serde_json::Value::Number(number) => number.as_u64().map(|n| n != 0),
        serde_json::Value::String(text) => {
            let lowered = text.trim().to_ascii_lowercase();
            match lowered.as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }))
}

#[cfg(target_os = "linux")]
fn deserialize_option_u64ish<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|raw| match raw {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }))
}

#[cfg(target_os = "linux")]
fn scan_linux_removable_drives() -> Result<Vec<DriveInfo>, String> {
    let output = run_command(
        "lsblk",
        &[
            "-J",
            "-b",
            "-o",
            "NAME,PATH,RM,HOTPLUG,TRAN,MODEL,VENDOR,SERIAL,SIZE,FSTYPE,MOUNTPOINT,MOUNTPOINTS,LABEL,ROTA,TYPE",
        ],
    )?;

    let parsed: LinuxLsblkResponse =
        serde_json::from_str(&output).map_err(|error| format!("lsblk parse error: {error}"))?;

    let mut drives = Vec::new();
    for device in parsed.blockdevices {
        if device.kind.as_deref() != Some("disk") {
            continue;
        }

        let transport = normalize_transport(device.tran.as_deref());
        let is_removable = device.rm.unwrap_or(false)
            || device.hotplug.unwrap_or(false)
            || transport.eq_ignore_ascii_case("USB");
        if !is_removable {
            continue;
        }

        let device_path = if let Some(path) = clean_optional(device.path.as_deref()) {
            path
        } else if let Some(name) = clean_optional(device.name.as_deref()) {
            format!("/dev/{name}")
        } else {
            "Unknown".to_string()
        };

        let (labels, filesystems, mount_points) = collect_linux_details(&device);
        let volume_name = if labels.is_empty() {
            clean_or_unknown(device.model.as_deref())
        } else {
            labels.join(", ")
        };
        let file_system = if filesystems.is_empty() {
            "Unknown".to_string()
        } else {
            filesystems.join(", ")
        };
        let mount_state = if mount_points.is_empty() {
            "Unmounted".to_string()
        } else {
            "Mounted".to_string()
        };
        let mount_point = if mount_points.is_empty() {
            "Not mounted".to_string()
        } else {
            mount_points.join(", ")
        };

        let model = clean_or_unknown(device.model.as_deref());
        let drive_type = classify_linux_drive_type(&device, &transport, &model);
        let capacity_bytes = device.size.unwrap_or(0);

        drives.push(DriveInfo {
            device_path,
            volume_name,
            vendor: clean_or_unknown(device.vendor.as_deref()),
            model,
            serial: clean_or_unknown(device.serial.as_deref()),
            transport,
            file_system,
            mount_point,
            mount_state,
            drive_type,
            capacity_bytes,
        });
    }

    Ok(drives)
}

#[cfg(target_os = "linux")]
fn collect_linux_details(device: &LinuxLsblkDevice) -> (Vec<String>, Vec<String>, Vec<String>) {
    fn walk(
        node: &LinuxLsblkDevice,
        labels: &mut Vec<String>,
        filesystems: &mut Vec<String>,
        mounts: &mut Vec<String>,
    ) {
        if let Some(label) = clean_optional(node.label.as_deref()) {
            if !labels.contains(&label) {
                labels.push(label);
            }
        }

        if let Some(fstype) = clean_optional(node.fstype.as_deref()) {
            if !filesystems.contains(&fstype) {
                filesystems.push(fstype);
            }
        }

        if let Some(mount) = clean_optional(node.mountpoint.as_deref()) {
            if !mounts.contains(&mount) {
                mounts.push(mount);
            }
        }

        if let Some(mount_list) = &node.mountpoints {
            for mount in mount_list {
                if let Some(mount) = clean_optional(mount.as_deref()) {
                    if !mounts.contains(&mount) {
                        mounts.push(mount);
                    }
                }
            }
        }

        if let Some(children) = &node.children {
            for child in children {
                walk(child, labels, filesystems, mounts);
            }
        }
    }

    let mut labels = Vec::new();
    let mut filesystems = Vec::new();
    let mut mounts = Vec::new();
    walk(device, &mut labels, &mut filesystems, &mut mounts);
    (labels, filesystems, mounts)
}

#[cfg(target_os = "linux")]
fn classify_linux_drive_type(device: &LinuxLsblkDevice, transport: &str, model: &str) -> String {
    let model_lower = model.to_ascii_lowercase();
    let path_lower = device
        .path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let transport_lower = transport.to_ascii_lowercase();

    if transport_lower.contains("usb") {
        if model_lower.contains("nvme") {
            "USB (NVME enclosure)".to_string()
        } else if device.rota == Some(false) {
            "USB SSD".to_string()
        } else if device.rota == Some(true) {
            "USB HDD".to_string()
        } else {
            "USB".to_string()
        }
    } else if path_lower.contains("nvme") || model_lower.contains("nvme") {
        "NVME".to_string()
    } else if device.rota == Some(false) {
        "SSD".to_string()
    } else if device.rota == Some(true) {
        "HDD".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn clean_optional(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim).and_then(|trimmed| {
        if trimmed.is_empty() || trimmed == "-" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn clean_or_unknown(raw: Option<&str>) -> String {
    clean_optional(raw).unwrap_or_else(|| "Unknown".to_string())
}

fn normalize_transport(raw: Option<&str>) -> String {
    match raw.map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if !value.is_empty() => match value.as_str() {
            "usb" => "USB".to_string(),
            "nvme" => "NVME".to_string(),
            "sata" => "SATA".to_string(),
            "ata" => "ATA".to_string(),
            "scsi" => "SCSI".to_string(),
            "sd" => "SD".to_string(),
            _ => value.to_ascii_uppercase(),
        },
        _ => "Unknown".to_string(),
    }
}

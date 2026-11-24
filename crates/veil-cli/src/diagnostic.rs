use serde::Serialize;

#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    pub code: &'static str,
    pub exit_code: u8,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hint: String,
}

impl Failure {
    pub fn new(
        code: &'static str,
        exit_code: u8,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            code,
            exit_code,
            message: message.into(),
            hint: hint.into(),
        }
    }

    pub fn from_error(error: &anyhow::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            let mut failure = failure.clone();
            failure.message = format!("{error:#}");
            return failure;
        }
        if let Some(refused) = error.downcast_ref::<crate::approval::Refused>() {
            return Self::new(
                "approval_required",
                4,
                refused.to_string(),
                "Use a device that can satisfy this Vault's approval policy; --yes cannot bypass it.",
            );
        }
        if let Some(client) = error.downcast_ref::<crate::client::Error>() {
            return match client {
                crate::client::Error::Status {
                    code: 401 | 403 | 410,
                    ..
                } => Self::new(
                    "access_denied",
                    3,
                    "The service refused this identity or its access.",
                    "Run: veil doctor. A revoked or restricted device may need enrollment or a grant, not a renewed session.",
                ),
                crate::client::Error::Status { code: 409, .. } => Self::new(
                    "revision_conflict",
                    5,
                    "The data changed before this write completed.",
                    "Inspect the current state before retrying; earlier writes in a batch may have succeeded.",
                ),
                crate::client::Error::Transport(_) => Self::new(
                    "service_unreachable",
                    1,
                    "Cannot reach the service.",
                    "Check connectivity and the service address with: veil doctor",
                ),
                crate::client::Error::Status { code, .. } => Self::new(
                    "service_error",
                    1,
                    format!("The service returned HTTP {code}."),
                    "Run: veil doctor",
                ),
                crate::client::Error::Other(_) => Self::new(
                    "invalid_response",
                    1,
                    "Cannot read the service response.",
                    "Check CLI and service compatibility with: veil version",
                ),
            };
        }
        if let Some(parse) = error.downcast_ref::<serde_json::Error>() {
            return Self::new(
                "invalid_local_data",
                1,
                format!(
                    "Cannot parse local JSON data at line {}, column {}; values are not shown.",
                    parse.line(),
                    parse.column()
                ),
                "Preserve state and key files before attempting recovery. Run: veil doctor",
            );
        }
        Self::new("command_failed", 1, format!("{error:#}"), "")
    }
}

pub fn report(error: &anyhow::Error, command_not_started: bool) -> u8 {
    let failure = Failure::from_error(error);
    if crate::ui::output().json {
        eprintln!(
            "{}",
            serde_json::json!({"type": "error", "error": failure, "command_started": if command_not_started { Some(false) } else { None }})
        );
    } else {
        let label = if crate::ui::color() {
            "\x1b[1;31merror\x1b[0m"
        } else {
            "error"
        };
        eprintln!(
            "{label}[{}]: {}",
            failure.code,
            crate::ui::safe(&failure.message)
        );
        if !failure.hint.is_empty() {
            eprintln!("\n{}", crate::ui::safe(&failure.hint));
        }
        if command_not_started {
            eprintln!(
                "The command was not started; secrets were not delivered to a child process."
            );
        }
    }
    failure.exit_code
}

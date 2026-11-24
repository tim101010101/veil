//! Presence approval: a human action at the machine that no program running as the user can
//! perform.
//!
//! On macOS this is LocalAuthentication's device-owner check: Touch ID, or the login password
//! where Touch ID is unavailable. Both need the person at the keyboard; the system draws the
//! prompt, so a program cannot answer it. Other platforms have no such check yet, and refuse.

#[cfg(target_os = "macos")]
use std::time::Duration;

/// How a confirmation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// The person confirmed.
    Approved,
    /// The person declined, or did not answer in time.
    Denied,
    /// No confirmation is possible here; the reason says why.
    Unavailable(String),
}

/// How long the prompt waits for the person.
#[cfg(target_os = "macos")]
const TIMEOUT: Duration = Duration::from_secs(120);

/// Asks the person at the machine to confirm `reason`, which the system prompt shows.
///
/// `VEIL_PRESENCE=unavailable` makes the check refuse without prompting. It can only take
/// approval away, so tests and CI use it to exercise the refusal path on a Mac.
pub fn confirm(reason: &str) -> Presence {
    if std::env::var("VEIL_PRESENCE").as_deref() == Ok("unavailable") {
        return Presence::Unavailable("VEIL_PRESENCE=unavailable".to_owned());
    }
    platform::confirm(reason)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::{Presence, TIMEOUT};

    pub fn confirm(reason: &str) -> Presence {
        // Touch ID, falling back to the login password: both are the device owner, in person.
        let policy = LAPolicy::DeviceOwnerAuthentication;
        #[allow(unsafe_code)]
        // SAFETY: `new` returns a fresh, owned LAContext; it has no preconditions.
        let context = unsafe { LAContext::new() };
        #[allow(unsafe_code)]
        // SAFETY: the context is alive for the call, and `policy` is a defined LAPolicy value.
        let available = unsafe { context.canEvaluatePolicy_error(policy) };
        if let Err(error) = available {
            return Presence::Unavailable(error.localizedDescription().to_string());
        }

        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |approved: Bool, _error: *mut NSError| {
            let _ = sender.send(approved.as_bool());
        });
        let reason = NSString::from_str(reason);
        #[allow(unsafe_code)]
        // SAFETY: the context, the reason, and the reply block are alive for the call; the
        // framework copies the block before returning and calls it once, on its own queue. The
        // block only sends a bool on a channel, which is safe from any thread.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
        }
        match receiver.recv_timeout(TIMEOUT) {
            Ok(true) => Presence::Approved,
            _ => Presence::Denied,
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::Presence;

    pub fn confirm(_reason: &str) -> Presence {
        Presence::Unavailable(
            "presence approval needs Touch ID, which only macOS provides".to_owned(),
        )
    }
}

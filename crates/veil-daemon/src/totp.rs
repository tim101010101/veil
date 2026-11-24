//! Time-based one-time codes for Bitwarden two-step login (RFC 6238): HMAC-SHA-1, six digits,
//! 30-second steps, which every authenticator app accepts by default.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

/// Seconds per step.
pub const STEP_SECONDS: u64 = 30;
/// Steps of clock drift accepted either side of now.
const DRIFT_STEPS: u64 = 1;

/// Whether `secret` is a usable base32 secret of at least 128 bits.
pub fn valid_secret(secret: &str) -> bool {
    decode(secret).is_some_and(|key| key.len() >= 16)
}

/// The time step `code` belongs to, if it is valid at `at` (Unix seconds).
pub fn verify(secret: &str, code: &str, at: u64) -> Option<u64> {
    let key = decode(secret)?;
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let now = at / STEP_SECONDS;
    (now.saturating_sub(DRIFT_STEPS)..=now + DRIFT_STEPS)
        .find(|step| constant_time_eq(hotp(&key, *step).as_bytes(), code.as_bytes()))
}

/// The code for time step `step`, as an authenticator app shows it.
pub fn code(secret: &str, step: u64) -> Option<String> {
    Some(hotp(&decode(secret)?, step))
}

fn decode(secret: &str) -> Option<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD.decode(normalized.as_bytes()).ok()
}

fn hotp(key: &[u8], counter: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let word = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    format!("{:06}", word % 1_000_000)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B's SHA-1 secret, "12345678901234567890", in base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_the_rfc_6238_vectors() {
        // The RFC lists eight digits; six-digit codes are their last six.
        for (at, eight) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            let step = verify(RFC_SECRET, &eight[2..], at).expect("valid code");
            assert_eq!(step, at / STEP_SECONDS);
        }
    }

    #[test]
    fn accepts_one_step_of_drift_and_no_more() {
        let code = hotp(&decode(RFC_SECRET).expect("secret"), 1000);
        assert_eq!(verify(RFC_SECRET, &code, 1000 * 30 + 29), Some(1000));
        assert_eq!(verify(RFC_SECRET, &code, 1001 * 30), Some(1000));
        assert_eq!(verify(RFC_SECRET, &code, 999 * 30), Some(1000));
        assert_eq!(verify(RFC_SECRET, &code, 1002 * 30), None);
    }

    #[test]
    fn refuses_malformed_codes_and_secrets() {
        assert_eq!(verify(RFC_SECRET, "12345", 59), None);
        assert_eq!(verify(RFC_SECRET, "28708a", 59), None);
        assert_eq!(verify("not base32!", "287082", 59), None);
        assert!(valid_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"));
        assert!(!valid_secret("GEZDGNBV"));
    }
}

//! The recovery code: a second, full-entropy secret that wraps the account key.
//!
//! The code goes through the same SDK path as the master password (`MasterKey` derivation, then
//! the user-key wrap and the server authorization hash), so recovery adds no cryptography of its
//! own. Because the code carries 256 bits of entropy, it uses the SDK's minimum KDF cost.

use crate::{Error, Kdf, Key, MasterPassword};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ENCODED_LEN: usize = 52;
const KEY_LEN: usize = 32;

/// A 256-bit code shown once, grouped for transcription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    canonical: String,
}

impl RecoveryCode {
    /// Draws a new code from the operating system.
    pub fn generate() -> Self {
        use rand_core::RngCore;
        let mut bytes = [0u8; KEY_LEN];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self {
            canonical: group(&encode_base32(&bytes)),
        }
    }

    /// Parses a code, ignoring case, dashes, and spaces.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if cleaned.len() != ENCODED_LEN {
            return Err(Error::Recovery);
        }
        decode_base32(&cleaned)?;
        Ok(Self {
            canonical: group(&cleaned),
        })
    }

    /// The canonical grouped form.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The master-key derivation of the code for this account.
    pub fn derive(&self, email: &str) -> Result<MasterPassword, Error> {
        MasterPassword::derive(&self.canonical, email, &Kdf::MINIMUM)
    }

    /// The value the service stores to authorize a recovery. Sending it proves possession of the
    /// code; the code itself never travels.
    pub fn verifier(&self, email: &str) -> Result<String, Error> {
        Ok(self.derive(email)?.auth_hash().to_owned())
    }

    /// Wraps the account key with the code.
    pub fn wrap(&self, email: &str, account_key: &Key) -> Result<String, Error> {
        self.derive(email)?.protect(account_key)
    }

    /// Unwraps the account key with the code.
    pub fn unwrap(&self, email: &str, wrapped: &str) -> Result<Key, Error> {
        self.derive(email)?.unlock(wrapped)
    }
}

fn group(encoded: &str) -> String {
    encoded
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(ENCODED_LEN);
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn decode_base32(encoded: &str) -> Result<[u8; KEY_LEN], Error> {
    let mut buffer = 0u64;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(KEY_LEN);
    for character in encoded.bytes() {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .ok_or(Error::Recovery)? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out.truncate(KEY_LEN);
    out.try_into().map_err(|_| Error::Recovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_code_round_trips() {
        let code = RecoveryCode::generate();
        let parsed = RecoveryCode::parse(code.as_str()).expect("parse");
        assert_eq!(parsed, code);
    }

    #[test]
    fn the_code_unwraps_what_it_wrapped() {
        let code = RecoveryCode::generate();
        let account_key = Key::generate();
        let wrapped = code.wrap("me@example.com", &account_key).expect("wrap");
        let parsed = RecoveryCode::parse(&code.as_str().to_lowercase()).expect("parse");
        assert_eq!(
            parsed.unwrap("me@example.com", &wrapped).expect("unwrap"),
            account_key
        );
        assert_eq!(
            RecoveryCode::generate()
                .unwrap("me@example.com", &wrapped)
                .err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn case_dashes_and_spaces_are_ignored() {
        let code = RecoveryCode::generate();
        let messy = code.as_str().to_lowercase().replace('-', " ");
        let parsed = RecoveryCode::parse(&messy).expect("parse");
        assert_eq!(parsed, code);
    }

    #[test]
    fn a_different_code_yields_a_different_verifier() {
        let first = RecoveryCode::generate();
        let second = RecoveryCode::generate();
        assert_ne!(
            first.verifier("me@example.com").expect("first"),
            second.verifier("me@example.com").expect("second")
        );
    }

    #[test]
    fn malformed_codes_are_rejected() {
        assert_eq!(RecoveryCode::parse(""), Err(Error::Recovery));
        assert_eq!(RecoveryCode::parse("SHORT"), Err(Error::Recovery));
        assert_eq!(RecoveryCode::parse(&"1".repeat(52)), Err(Error::Recovery));
    }

    #[test]
    fn encoding_is_standard_base32() {
        // RFC 4648: "foobar" encodes to "MZXW6YTBOI".
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }
}

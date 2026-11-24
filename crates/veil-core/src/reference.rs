//! `veil://` references, resolved on the client.

use std::{fmt, str::FromStr};

use crate::Error;

/// A pointer to one field of one Item: `veil://<vault>/<item>/<field>`.
///
/// Segments may contain any character; `/` and `%` are percent-encoded when rendered. A
/// reference grants nothing: resolving it needs a Grant for its Vault.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    /// Vault name.
    pub vault: String,
    /// Item name.
    pub item: String,
    /// Field name: `username`, `password`, `notes`, `uri`, or a custom field.
    pub field: String,
}

impl Reference {
    /// Builds a reference, rejecting empty segments.
    pub fn new(vault: &str, item: &str, field: &str) -> Result<Self, Error> {
        if vault.is_empty() || item.is_empty() || field.is_empty() {
            return Err(Error::Reference);
        }
        Ok(Self {
            vault: vault.to_owned(),
            item: item.to_owned(),
            field: field.to_owned(),
        })
    }
}

impl FromStr for Reference {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let rest = input.strip_prefix("veil://").ok_or(Error::Reference)?;
        let segments = rest.split('/').map(decode).collect::<Result<Vec<_>, _>>()?;
        match segments.as_slice() {
            [vault, item, field] => Self::new(vault, item, field),
            _ => Err(Error::Reference),
        }
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "veil://{}/{}/{}",
            encode(&self.vault),
            encode(&self.item),
            encode(&self.field)
        )
    }
}

fn decode(segment: &str) -> Result<String, Error> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3).ok_or(Error::Reference)?;
            let text = std::str::from_utf8(hex).map_err(|_| Error::Reference)?;
            out.push(u8::from_str_radix(text, 16).map_err(|_| Error::Reference)?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::Reference)
}

fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for character in segment.chars() {
        match character {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vault_item_and_field() {
        assert_eq!(
            "veil://example/demo-service/password"
                .parse::<Reference>()
                .expect("parse"),
            Reference::new("example", "demo-service", "password").expect("valid")
        );
    }

    #[test]
    fn display_round_trips_with_escapes() {
        let reference = Reference::new("api", "a/b%c", "client secret").expect("valid");
        assert_eq!(reference.to_string(), "veil://api/a%2Fb%25c/client secret");
        assert_eq!(
            reference.to_string().parse::<Reference>().expect("parse"),
            reference
        );
    }

    #[test]
    fn malformed_references_are_rejected() {
        for input in [
            "",
            "example/bot/password",
            "veil://",
            "veil://bot",
            "veil://example/bot",
            "veil://a/b/c/d",
            "veil://example//password",
            "veil://example/bot/",
            "veil://example/bot/%zz",
            "veil://example/bot/%2",
        ] {
            assert_eq!(input.parse::<Reference>(), Err(Error::Reference), "{input}");
        }
    }
}

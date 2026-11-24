//! Redaction: delivered values printed verbatim are replaced with a fixed marker.
//!
//! It catches a value that appears byte for byte in the output, even when the value arrives
//! split across reads. It does not catch a value that was encoded, split by the program
//! itself, or written somewhere other than its output.

/// What replaces a value.
pub const MARKER: &[u8] = b"[redacted]";

/// Values shorter than this are not redacted: replacing every `1` or `ok` would destroy the
/// output and protect nothing.
pub const MIN_LEN: usize = 4;

/// A streaming replacer for one output stream.
pub struct Redactor {
    needles: Vec<Vec<u8>>,
    longest: usize,
    pending: Vec<u8>,
}

impl Redactor {
    /// Redacts these values, longest first so a value containing another wins.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut needles: Vec<Vec<u8>> = values
            .into_iter()
            .map(|value| value.as_ref().to_vec())
            .filter(|value| value.len() >= MIN_LEN)
            .collect();
        needles.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
        needles.dedup();
        let longest = needles.first().map_or(0, Vec::len);
        Self {
            needles,
            longest,
            pending: Vec::new(),
        }
    }

    /// Accepts the next chunk and returns what can be released. Up to `longest - 1` bytes are
    /// held back in case a value continues in the next chunk.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        if self.needles.is_empty() {
            return std::mem::take(&mut self.pending);
        }
        let (out, consumed) = self.scan(false);
        self.pending.drain(..consumed);
        out
    }

    /// Releases everything held back, at the end of the stream.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, consumed) = self.scan(true);
        self.pending.drain(..consumed);
        let mut out = out;
        out.append(&mut self.pending);
        out
    }

    /// Emits from the front of `pending` while every value could still fit; at the end of the
    /// stream, emits everything.
    fn scan(&self, last: bool) -> (Vec<u8>, usize) {
        let data = &self.pending;
        let mut out = Vec::with_capacity(data.len());
        let mut at = 0;
        while at < data.len() && (last || at + self.longest <= data.len()) {
            if let Some(needle) = self
                .needles
                .iter()
                .find(|needle| data[at..].starts_with(needle))
            {
                out.extend_from_slice(MARKER);
                at += needle.len();
            } else {
                out.push(data[at]);
                at += 1;
            }
        }
        (out, at)
    }
}

/// Redacts a whole buffer at once.
pub fn redact_all<I, S>(values: I, text: &[u8]) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
{
    let mut redactor = Redactor::new(values);
    let mut out = redactor.feed(text);
    out.extend(redactor.finish());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through(values: &[&str], chunks: &[&str]) -> String {
        let mut redactor = Redactor::new(values);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(redactor.feed(chunk.as_bytes()));
        }
        out.extend(redactor.finish());
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn a_value_is_replaced() {
        assert_eq!(
            through(&["s3cret-token"], &["token=s3cret-token\n"]),
            "token=[redacted]\n"
        );
    }

    #[test]
    fn a_value_split_across_reads_is_replaced() {
        assert_eq!(
            through(&["s3cret-token"], &["a s3c", "ret-to", "ken b"]),
            "a [redacted] b"
        );
    }

    #[test]
    fn the_longest_value_wins() {
        assert_eq!(
            through(&["abcd", "abcdefgh"], &["xabcdefghx abcd"]),
            "x[redacted]x [redacted]"
        );
    }

    #[test]
    fn short_values_and_other_text_pass_through() {
        assert_eq!(through(&["ok", "1"], &["ok 1 done"]), "ok 1 done");
        assert_eq!(through(&[], &["anything"]), "anything");
        assert_eq!(through(&["s3cret"], &["s3cr"]), "s3cr");
    }

    #[test]
    fn redact_all_matches_streaming() {
        assert_eq!(
            redact_all(["hunter22"], b"pw=hunter22;hunter22"),
            b"pw=[redacted];[redacted]".to_vec()
        );
    }
}

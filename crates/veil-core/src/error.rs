//! Errors raised by the cryptographic core.

/// Something the caller supplied cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A base64 field, key, or code is malformed.
    #[error("malformed encoding")]
    Encoding,
    /// The key derivation parameters are outside the supported range.
    #[error("invalid key derivation parameters")]
    Kdf,
    /// Authentication failed: wrong key, wrong password, or tampered bytes.
    #[error("authentication failed")]
    Decryption,
    /// A reference is not a well-formed `veil://` address.
    #[error("malformed reference")]
    Reference,
    /// A recovery code is malformed.
    #[error("malformed recovery code")]
    Recovery,
    /// A signature did not verify.
    #[error("signature verification failed")]
    Signature,
    /// A sealed record opened but its content is not an Item record.
    #[error("the record is not a valid Item")]
    Item,
    /// The SDK refused an operation that cannot fail on valid input.
    #[error("cryptographic operation failed")]
    Crypto,
}

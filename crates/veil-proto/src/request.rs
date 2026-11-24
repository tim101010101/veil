//! Signed device requests.
//!
//! A device proves who it is by signing a canonical string, so the service can reject a
//! replayed or altered request without holding any shared secret.

use sha2::{Digest, Sha256};

use crate::binding;

/// The parts of a request a device signs.
#[derive(Debug, Clone, Copy)]
pub struct RequestToSign<'a> {
    /// Account the request belongs to.
    pub account_id: &'a str,
    /// HTTP method, uppercase.
    pub method: &'a str,
    /// Path including the API prefix.
    pub path: &'a str,
    /// SHA-256 of the body, or 32 zero bytes for an empty body.
    pub body_hash: &'a [u8],
    /// Unix seconds, checked for skew by the service.
    pub timestamp: u64,
    /// Single-use nonce.
    pub nonce: &'a [u8],
}

/// The bytes a machine signs when it polls for its enrollment.
pub fn enrollment_input(device_id: uuid::Uuid, code: &str, timestamp: u64) -> Vec<u8> {
    binding(&[
        b"veil enrollment v1",
        device_id.as_bytes(),
        code.as_bytes(),
        &timestamp.to_be_bytes(),
    ])
}

/// The domain-separated identity and intent signed during master-password login.
pub fn session_input(email: &str, auth_hash: &str, proof: &crate::DeviceLogin) -> Vec<u8> {
    binding(&[
        b"veil session v1",
        email.trim().to_lowercase().as_bytes(),
        auth_hash.as_bytes(),
        proof.keys.id.as_bytes(),
        proof.keys.name.as_bytes(),
        proof.keys.seal_pk.as_bytes(),
        proof.keys.auth_pk.as_bytes(),
        &[u8::from(proof.promote)],
        &proof.timestamp.to_be_bytes(),
        proof.nonce.as_bytes(),
    ])
}

/// Hashes a request body for the signature.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// The exact bytes a device signs.
pub fn signing_input(request: &RequestToSign<'_>) -> Vec<u8> {
    binding(&[
        b"veil request v1",
        request.account_id.as_bytes(),
        request.method.as_bytes(),
        request.path.as_bytes(),
        request.body_hash,
        &request.timestamp.to_be_bytes(),
        request.nonce,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signing_input_is_unambiguous() {
        let first = RequestToSign {
            account_id: "a",
            method: "GET",
            path: "/bc",
            body_hash: &[],
            timestamp: 1,
            nonce: &[],
        };
        let second = RequestToSign {
            account_id: "ab",
            method: "GET",
            path: "/c",
            body_hash: &[],
            timestamp: 1,
            nonce: &[],
        };
        assert_ne!(signing_input(&first), signing_input(&second));
    }

    #[test]
    fn every_part_changes_the_input() {
        let base = RequestToSign {
            account_id: "account",
            method: "GET",
            path: "/api/v1/sync",
            body_hash: &[0; 32],
            timestamp: 1_700_000_000,
            nonce: b"nonce",
        };
        let reference = signing_input(&base);
        for changed in [
            RequestToSign {
                account_id: "other",
                ..base
            },
            RequestToSign {
                method: "POST",
                ..base
            },
            RequestToSign {
                path: "/api/v1/other",
                ..base
            },
            RequestToSign {
                timestamp: 1_700_000_001,
                ..base
            },
            RequestToSign {
                nonce: b"other",
                ..base
            },
        ] {
            assert_ne!(signing_input(&changed), reference);
        }
    }

    #[test]
    fn enrollment_inputs_differ_by_every_part() {
        let id = uuid::Uuid::from_u128(7);
        let base = enrollment_input(id, "123456", 1);
        assert_ne!(
            base,
            enrollment_input(uuid::Uuid::from_u128(8), "123456", 1)
        );
        assert_ne!(base, enrollment_input(id, "654321", 1));
        assert_ne!(base, enrollment_input(id, "123456", 2));
    }

    #[test]
    fn session_proof_binds_every_identity_and_intent_field() {
        let proof = crate::DeviceLogin {
            keys: crate::DeviceKeys {
                id: uuid::Uuid::from_u128(1),
                name: "laptop".to_owned(),
                seal_pk: "seal".to_owned(),
                auth_pk: "auth".to_owned(),
            },
            promote: false,
            timestamp: 123,
            nonce: "nonce".to_owned(),
            signature: String::new(),
        };
        let input = session_input("me@example.com", "hash", &proof);
        assert_eq!(input, session_input(" ME@EXAMPLE.COM ", "hash", &proof));
        assert_ne!(input, session_input("other@example.com", "hash", &proof));
        assert_ne!(input, session_input("me@example.com", "other", &proof));
        let mut variants = vec![proof.clone(); 7];
        variants[0].keys.id = uuid::Uuid::from_u128(2);
        variants[1].keys.name = "other".to_owned();
        variants[2].keys.seal_pk = "other".to_owned();
        variants[3].keys.auth_pk = "other".to_owned();
        variants[4].promote = true;
        variants[5].timestamp += 1;
        variants[6].nonce = "other".to_owned();
        for changed in variants {
            assert_ne!(input, session_input("me@example.com", "hash", &changed));
        }
    }

    #[test]
    fn the_body_hash_is_sha256() {
        assert_eq!(
            body_hash(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }
}

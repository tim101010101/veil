//! KDF parameters between the wire contract and the core.

/// Core parameters as sent to the service.
pub fn to_wire(kdf: veil_core::Kdf) -> veil_proto::Kdf {
    match kdf {
        veil_core::Kdf::Pbkdf2 { iterations } => veil_proto::Kdf::Pbkdf2 { iterations },
        veil_core::Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => veil_proto::Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        },
    }
}

/// Parameters from the service, for the core.
pub fn from_wire(kdf: veil_proto::Kdf) -> veil_core::Kdf {
    match kdf {
        veil_proto::Kdf::Pbkdf2 { iterations } => veil_core::Kdf::Pbkdf2 { iterations },
        veil_proto::Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => veil_core::Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_survive_the_round_trip() {
        for kdf in [veil_core::Kdf::default(), veil_core::Kdf::MINIMUM] {
            assert_eq!(from_wire(to_wire(kdf)), kdf);
        }
    }
}

use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

const TARGET: &str = "linux-x86_64";

fn archive(binary: &[u8], link: bool, extra: bool) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(if link { 0 } else { binary.len() as u64 });
    header.set_mode(0o755);
    if link {
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/outside").unwrap();
    }
    header.set_cksum();
    archive
        .append_data(&mut header, "veil", if link { &[][..] } else { binary })
        .unwrap();
    if extra {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        archive
            .append_data(&mut header, "unexpected", &[][..])
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

fn signed(archive: &[u8], version: &str) -> (Vec<u8>, Vec<u8>, SigningKey) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let manifest = Manifest {
        schema: 1,
        version: version.into(),
        protocol: 1,
        artifacts: vec![Artifact {
            target: TARGET.into(),
            file: format!("veil-{version}-{TARGET}.tar.gz"),
            size: archive.len() as u64,
            sha256: digest(archive),
        }],
    };
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let signature = STANDARD.encode(key.sign(&bytes).to_bytes()).into_bytes();
    (bytes, signature, key)
}

fn verified(binary: &[u8]) -> VerifiedRelease {
    let archive = archive(binary, false, false);
    let (bytes, signature, key) = signed(&archive, "0.4.0");
    verify_release(
        &bytes,
        &signature,
        &key.verifying_key(),
        "0.4.0",
        TARGET,
        &archive,
    )
    .unwrap()
}

#[test]
fn release_requires_trusted_signature_version_platform_and_digest() {
    let archive = archive(b"new executable", false, false);
    let (bytes, signature, key) = signed(&archive, "0.4.0");
    let keys = &key.verifying_key();
    assert!(verify_release(&bytes, &signature, keys, "0.4.0", TARGET, &archive).is_ok());
    assert!(
        verify_release(
            &bytes,
            &signature,
            &SigningKey::from_bytes(&[43; 32]).verifying_key(),
            "0.4.0",
            TARGET,
            &archive
        )
        .is_err()
    );
    assert!(verify_release(&bytes, b"invalid", keys, "0.4.0", TARGET, &archive).is_err());
    assert!(verify_release(&bytes, &signature, keys, "0.5.0", TARGET, &archive).is_err());
    assert!(verify_release(&bytes, &signature, keys, "0.4.0", "linux-aarch64", &archive).is_err());
    let mut tampered = bytes.clone();
    tampered.push(b' ');
    assert!(verify_release(&tampered, &signature, keys, "0.4.0", TARGET, &archive).is_err());
    let mut tampered = archive.clone();
    tampered[0] ^= 1;
    assert!(verify_release(&bytes, &signature, keys, "0.4.0", TARGET, &tampered).is_err());
}

#[test]
fn signed_metadata_still_must_obey_schema_and_filename_constraints() {
    let archive = archive(b"new executable", false, false);
    let (bytes, _, key) = signed(&archive, "0.4.0");
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for mutation in ["schema", "file", "size", "duplicate"] {
        let mut value = original.clone();
        match mutation {
            "schema" => value["schema"] = 2.into(),
            "file" => value["artifacts"][0]["file"] = "../outside".into(),
            "size" => value["artifacts"][0]["size"] = (MAX_ARCHIVE + 1).into(),
            _ => {
                let duplicate = value["artifacts"][0].clone();
                value["artifacts"].as_array_mut().unwrap().push(duplicate);
            }
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let signature = STANDARD.encode(key.sign(&bytes).to_bytes());
        assert!(
            verify_release(
                &bytes,
                signature.as_bytes(),
                &key.verifying_key(),
                "0.4.0",
                TARGET,
                &archive
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn archive_links_and_extra_members_are_not_installed() {
    for archive in [archive(b"new", true, false), archive(b"new", false, true)] {
        let (bytes, signature, key) = signed(&archive, "0.4.0");
        assert!(
            verify_release(
                &bytes,
                &signature,
                &key.verifying_key(),
                "0.4.0",
                TARGET,
                &archive
            )
            .is_err()
        );
    }
}

const ROOT: [u8; 32] = [1; 32];
const BACKUP_ROOT: [u8; 32] = [2; 32];
const RELEASE: [u8; 32] = [42; 32];

fn trust_with(revoked: &[[u8; 32]]) -> Trust {
    let encode = |seed: &[u8; 32]| encode_key(&SigningKey::from_bytes(seed).verifying_key());
    Trust::parse(
        &serde_json::json!({
            "schema": 1,
            "roots": [encode(&ROOT), encode(&BACKUP_ROOT)],
            "revoked_release_keys": revoked.iter().map(encode).collect::<Vec<_>>(),
        })
        .to_string(),
    )
    .unwrap()
}

fn at(time: &str) -> jiff::Timestamp {
    time.parse().unwrap()
}

fn delegation(root: &[u8; 32], key: &[u8; 32], start: &str, end: &str) -> (Vec<u8>, Vec<u8>) {
    let bytes = serde_json::to_vec(&Delegation {
        schema: 1,
        purpose: DELEGATION_PURPOSE.into(),
        key: encode_key(&SigningKey::from_bytes(key).verifying_key()),
        not_before: start.into(),
        expires: end.into(),
    })
    .unwrap();
    let signature = STANDARD
        .encode(SigningKey::from_bytes(root).sign(&bytes).to_bytes())
        .into_bytes();
    (bytes, signature)
}

#[test]
fn either_root_can_delegate_a_release_key_for_a_bounded_period() {
    let trust = trust_with(&[]);
    let release = SigningKey::from_bytes(&RELEASE).verifying_key();
    for root in [&ROOT, &BACKUP_ROOT] {
        let (bytes, signature) = delegation(
            root,
            &RELEASE,
            "2026-11-15T00:00:00Z",
            "2027-11-15T00:00:00Z",
        );
        let (key, _) = trust
            .release_key(&bytes, &signature, at("2027-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(key, release);
        // Tolerates a slightly slow clock, not a delegation from the future.
        assert!(
            trust
                .release_key(&bytes, &signature, at("2026-11-14T23:58:00Z"))
                .is_ok()
        );
        assert!(
            trust
                .release_key(&bytes, &signature, at("2026-11-14T00:00:00Z"))
                .is_err()
        );
        assert!(
            trust
                .release_key(&bytes, &signature, at("2027-11-15T00:00:00Z"))
                .is_err()
        );
    }
}

#[test]
fn delegations_from_untrusted_keys_or_to_revoked_keys_are_refused() {
    let now = at("2027-01-01T00:00:00Z");
    let (bytes, signature) = delegation(
        &[9; 32],
        &RELEASE,
        "2026-11-15T00:00:00Z",
        "2027-11-15T00:00:00Z",
    );
    assert!(
        trust_with(&[])
            .release_key(&bytes, &signature, now)
            .is_err()
    );

    let (bytes, signature) = delegation(
        &ROOT,
        &RELEASE,
        "2026-11-15T00:00:00Z",
        "2027-11-15T00:00:00Z",
    );
    assert!(
        trust_with(&[RELEASE])
            .release_key(&bytes, &signature, now)
            .is_err()
    );
    let mut tampered = bytes.clone();
    tampered.push(b' ');
    assert!(
        trust_with(&[])
            .release_key(&tampered, &signature, now)
            .is_err()
    );

    // Roots stay offline: one cannot be delegated as a release key.
    let (bytes, signature) = delegation(
        &ROOT,
        &BACKUP_ROOT,
        "2026-11-15T00:00:00Z",
        "2027-11-15T00:00:00Z",
    );
    assert!(
        trust_with(&[])
            .release_key(&bytes, &signature, now)
            .is_err()
    );

    // Validity is capped even when a root signs a longer period.
    let (bytes, signature) = delegation(
        &ROOT,
        &RELEASE,
        "2026-11-15T00:00:00Z",
        "2028-11-15T00:00:00Z",
    );
    assert!(
        trust_with(&[])
            .release_key(&bytes, &signature, now)
            .is_err()
    );
}

#[test]
fn an_empty_trust_root_refuses_upgrades() {
    assert!(
        Trust::parse(r#"{"schema":1,"roots":[],"revoked_release_keys":[]}"#)
            .unwrap_err()
            .to_string()
            .contains("not configured")
    );
}

#[test]
fn latest_discovery_cannot_force_a_downgrade_or_prerelease() {
    assert!(select_version("0.4.0", "v0.5.0", false, false).is_ok());
    assert!(select_version("0.4.0", "v0.3.0", false, true).is_err());
    assert!(select_version("0.4.0", "0.3.0", true, false).is_err());
    assert!(select_version("0.4.0", "0.3.0", true, true).is_ok());
    assert!(select_version("0.4.0", "0.5.0-beta.1", false, false).is_err());
    assert!(select_version("0.4.0", "../outside", true, true).is_err());
    assert!(bounded_read(&b"too large"[..], 3).is_err());
}

#[cfg(unix)]
struct Managed(PathBuf);
#[cfg(unix)]
impl Managed {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("veil-update-test-{}", uuid::Uuid::now_v7()));
        let directory = base.join(".veil/0.3.0-test");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("veil"), b"old executable").unwrap();
        let receipt = Receipt {
            schema: 1,
            source: INSTALLER.into(),
            version: "0.3.0".into(),
            target: TARGET.into(),
            sha256: digest(b"old executable"),
        };
        fs::write(
            directory.join("install.toml"),
            toml::to_string(&receipt).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(directory.join("veil"), base.join("veil")).unwrap();
        Self(base)
    }
    fn inspect(&self) -> Result<Installation> {
        Installation::inspect(&self.0.join(".veil/0.3.0-test/veil"), "0.3.0", TARGET)
    }
}
#[cfg(unix)]
impl Drop for Managed {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn activation_switches_only_the_launcher_and_retains_the_old_binary() {
    use std::os::unix::fs::PermissionsExt as _;
    let managed = Managed::new();
    let install = managed.inspect().unwrap();
    let lock = install.lock().unwrap();
    assert!(install.lock().is_err());
    let result = install
        .activate(&verified(b"new executable"), &lock)
        .unwrap();
    assert_eq!(fs::read(&install.executable).unwrap(), b"old executable");
    assert_eq!(fs::read(&install.launcher).unwrap(), b"new executable");
    assert_eq!(
        fs::metadata(&result.executable)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(Installation::inspect(&result.executable, "0.4.0", TARGET).is_ok());
    assert!(managed.inspect().is_err());
    drop(lock);
    assert!(!install.root.join("upgrade.lock").exists());
}

#[cfg(unix)]
#[test]
fn unknown_or_modified_installations_are_not_owned() {
    let managed = Managed::new();
    fs::write(
        managed.0.join(".veil/0.3.0-test/veil"),
        b"external replacement",
    )
    .unwrap();
    assert!(managed.inspect().is_err());
    let outside = managed.0.join("unmanaged");
    fs::write(&outside, b"binary").unwrap();
    assert!(Installation::inspect(&outside, "0.3.0", TARGET).is_err());
}

#[cfg(unix)]
#[test]
fn concurrent_launcher_changes_are_not_overwritten_and_preparation_is_cleaned() {
    let managed = Managed::new();
    let install = managed.inspect().unwrap();
    let lock = install.lock().unwrap();
    fs::remove_file(&install.launcher).unwrap();
    fs::write(&install.launcher, b"external installer").unwrap();
    assert!(install.activate(&verified(b"replacement"), &lock).is_err());
    assert_eq!(fs::read(&install.launcher).unwrap(), b"external installer");
    assert_eq!(fs::read(&install.executable).unwrap(), b"old executable");
    assert_eq!(fs::read_dir(&install.root).unwrap().count(), 2);
}

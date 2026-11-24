use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_MANIFEST: u64 = 256 * 1024;
pub const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
pub const MAX_BINARY: u64 = 128 * 1024 * 1024;
pub const INSTALLER: &str = "veil-installer-v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub version: String,
    pub protocol: u32,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub target: String,
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub source: String,
    pub version: String,
    pub target: String,
    pub sha256: String,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn file_digest(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Purpose string a root key signs into every release-key delegation.
pub const DELEGATION_PURPOSE: &str = "veil-release-signing";
/// Longest validity a root may grant a release key; limits the damage of a stolen release key.
pub const MAX_DELEGATION_DAYS: i64 = 400;
/// Tolerated client clock error when a delegation starts.
const CLOCK_SKEW_SECONDS: i64 = 300;

/// The compiled trust root: offline root keys, and release keys they must no longer vouch for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema: u32,
    roots: Vec<String>,
    revoked_release_keys: Vec<String>,
}

#[derive(Debug)]
pub struct Trust {
    pub roots: Vec<VerifyingKey>,
    pub revoked: Vec<VerifyingKey>,
}

/// A root key's statement that `key` may sign Veil releases during `[not_before, expires)`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub schema: u32,
    pub purpose: String,
    pub key: String,
    pub not_before: String,
    pub expires: String,
}

pub fn public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = STANDARD
        .decode(encoded.trim())
        .map_err(|_| anyhow::anyhow!("Invalid public key encoding"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

pub fn encode_key(key: &VerifyingKey) -> String {
    STANDARD.encode(key.as_bytes())
}

fn signature(encoded: &[u8]) -> Result<Signature> {
    let encoded = std::str::from_utf8(encoded).context("Invalid signature encoding")?;
    let bytes = STANDARD
        .decode(encoded.trim())
        .context("Invalid signature encoding")?;
    Signature::from_slice(&bytes).context("Invalid signature length")
}

/// The trust root compiled into this build from `releases/trust-root.json`.
pub fn trust() -> Result<Trust> {
    Trust::parse(include_str!("../../../releases/trust-root.json"))
}

impl Trust {
    pub fn parse(json: &str) -> Result<Self> {
        let file: TrustFile =
            serde_json::from_str(json).context("Invalid compiled release trust configuration")?;
        ensure!(file.schema == 1, "Unsupported release trust schema");
        ensure!(
            !file.roots.is_empty(),
            "Release signing is not configured in this build; an operator must provision the root keys before signed upgrades are available"
        );
        let roots = file
            .roots
            .iter()
            .map(|key| public_key(key))
            .collect::<Result<Vec<_>>>()?;
        let revoked = file
            .revoked_release_keys
            .iter()
            .map(|key| public_key(key))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !roots.iter().any(|root| revoked.contains(root)),
            "A root key cannot also be a revoked release key"
        );
        Ok(Self { roots, revoked })
    }

    /// Verifies a root-signed delegation at time `now` and returns the release key it vouches for.
    pub fn release_key(
        &self,
        delegation: &[u8],
        signature_bytes: &[u8],
        now: jiff::Timestamp,
    ) -> Result<(VerifyingKey, Delegation)> {
        ensure!(
            delegation.len() <= 4096,
            "Release key delegation is too large"
        );
        let signed =
            signature(signature_bytes).context("Invalid release key delegation signature")?;
        ensure!(
            self.roots
                .iter()
                .any(|root| root.verify_strict(delegation, &signed).is_ok()),
            "Release key delegation is not signed by a trusted root; nothing was installed"
        );
        let parsed: Delegation = serde_json::from_slice(delegation)
            .map_err(|_| anyhow::anyhow!("Signed release key delegation has an invalid format"))?;
        ensure!(
            parsed.schema == 1 && parsed.purpose == DELEGATION_PURPOSE,
            "Unsupported release key delegation"
        );
        let key = public_key(&parsed.key)?;
        ensure!(
            !self.revoked.contains(&key),
            "The release signing key has been revoked; nothing was installed"
        );
        ensure!(
            !self.roots.contains(&key),
            "A root key must not sign releases directly"
        );
        let not_before: jiff::Timestamp = parsed
            .not_before
            .parse()
            .context("Invalid delegation start time")?;
        let expires: jiff::Timestamp = parsed
            .expires
            .parse()
            .context("Invalid delegation expiry time")?;
        ensure!(
            not_before < expires
                && expires.as_second() - not_before.as_second() <= MAX_DELEGATION_DAYS * 86_400,
            "Release key delegation has an invalid validity period"
        );
        ensure!(
            now.as_second() + CLOCK_SKEW_SECONDS >= not_before.as_second(),
            "Release key delegation is not valid until {not_before}; check this machine's clock"
        );
        ensure!(
            now < expires,
            "Release key delegation expired at {expires}; the publisher must renew it. Check this machine's clock"
        );
        Ok((key, parsed))
    }
}

pub fn verify_manifest(
    bytes: &[u8],
    signature_bytes: &[u8],
    key: &VerifyingKey,
    version: &str,
) -> Result<Manifest> {
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST,
        "Release manifest is too large"
    );
    let signed = signature(signature_bytes).context("Invalid release signature")?;
    ensure!(
        key.verify_strict(bytes, &signed).is_ok(),
        "Release signature verification failed; nothing was installed"
    );
    let manifest: Manifest = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Signed release manifest has an invalid format"))?;
    ensure!(manifest.schema == 1, "Unsupported release manifest schema");
    ensure!(
        manifest.version == version,
        "Signed release version does not match the requested version"
    );
    ensure!(
        semver::Version::parse(version)?.to_string() == version,
        "Release version is not canonical"
    );
    Ok(manifest)
}

pub fn artifact<'a>(manifest: &'a Manifest, target: &str) -> Result<&'a Artifact> {
    let mut matches = manifest
        .artifacts
        .iter()
        .filter(|item| item.target == target);
    let artifact = matches
        .next()
        .context("This release has no artifact for this platform")?;
    ensure!(
        matches.next().is_none(),
        "Release has duplicate platform artifacts"
    );
    ensure!(
        artifact.file == format!("veil-{}-{target}.tar.gz", manifest.version),
        "Invalid release artifact filename"
    );
    ensure!(
        artifact.size > 0 && artifact.size <= MAX_ARCHIVE,
        "Invalid release artifact size"
    );
    ensure!(
        artifact.sha256.len() == 64
            && artifact
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "Invalid release artifact digest"
    );
    Ok(artifact)
}

pub fn unpack(bytes: &[u8], artifact: &Artifact) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() as u64 == artifact.size && digest(bytes) == artifact.sha256,
        "Release archive checksum or size mismatch; nothing was installed"
    );
    let mut archive =
        tar::Archive::new(flate2::read::GzDecoder::new(bytes).take(MAX_BINARY + MAX_MANIFEST));
    let mut entries = archive.entries().context("Invalid release archive")?;
    let mut entry = entries.next().context("Empty release archive")??;
    ensure!(
        entry.path()? == Path::new("veil") && entry.header().entry_type().is_file(),
        "Release archive must contain only a regular file named veil"
    );
    ensure!(
        entry.size() > 0 && entry.size() <= MAX_BINARY,
        "Invalid release binary size"
    );
    let mut binary = Vec::new();
    entry.read_to_end(&mut binary)?;
    drop(entry);
    ensure!(
        entries.next().is_none(),
        "Release archive contains unexpected members"
    );
    Ok(binary)
}

pub fn bounded_read(mut input: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "Update response exceeds its size limit"
    );
    Ok(bytes)
}

pub fn platform() -> Result<String> {
    ensure!(
        std::env::consts::OS == "linux",
        "Signed self-update supports managed Linux installations only. macOS CI archives and source builds must use their original installation method"
    );
    ensure!(
        matches!(std::env::consts::ARCH, "x86_64" | "aarch64"),
        "No release artifact for this architecture"
    );
    Ok(format!("linux-{}", std::env::consts::ARCH))
}

pub fn parse_version(requested: &str) -> Result<semver::Version> {
    semver::Version::parse(requested.strip_prefix('v').unwrap_or(requested))
        .map_err(|_| anyhow::anyhow!("Expected a semantic release version, for example 0.3.1"))
}

pub fn select_version(
    current: &str,
    requested: &str,
    explicit: bool,
    allow_downgrade: bool,
) -> Result<semver::Version> {
    let current = semver::Version::parse(current)?;
    let version = parse_version(requested)?;
    ensure!(
        explicit || version.pre.is_empty(),
        "The latest release is a prerelease; select a version explicitly"
    );
    ensure!(
        version >= current || (explicit && allow_downgrade),
        "Refusing to downgrade; select --version and --allow-downgrade explicitly"
    );
    Ok(version)
}

#[derive(Debug)]
pub struct Installation {
    pub executable: PathBuf,
    pub launcher: PathBuf,
    pub root: PathBuf,
}

impl Installation {
    pub fn inspect(executable: &Path, version: &str, target: &str) -> Result<Self> {
        let executable =
            fs::canonicalize(executable).context("Cannot locate the running executable")?;
        let directory = executable.parent().context("Executable has no directory")?;
        let root = directory
            .parent()
            .context("Executable has no installation root")?
            .to_path_buf();
        ensure!(
            root.file_name().is_some_and(|name| name == ".veil")
                && executable.file_name().is_some_and(|name| name == "veil"),
            "This is not an installer-managed Veil. Use its package manager, or explicitly migrate a standalone install with install.sh --adopt"
        );
        let receipt = bounded_read(
            fs::File::open(directory.join("install.toml"))
                .context("Installation receipt is missing; refusing to take ownership")?,
            4096,
        )?;
        let receipt: Receipt = toml::from_str(std::str::from_utf8(&receipt)?)
            .map_err(|_| anyhow::anyhow!("Invalid installation receipt"))?;
        ensure!(
            receipt.schema == 1
                && receipt.source == INSTALLER
                && receipt.version == version
                && receipt.target == target,
            "Installation receipt does not describe this build; use the original installation method"
        );
        ensure!(
            file_digest(&executable)? == receipt.sha256,
            "Installed binary does not match its receipt; refusing to overwrite an unknown installation"
        );
        let launcher = root
            .parent()
            .context("Installation root has no parent")?
            .join("veil");
        let install = Self {
            executable,
            launcher,
            root,
        };
        install.check_launcher()?;
        Ok(install)
    }

    pub fn check_launcher(&self) -> Result<()> {
        ensure!(
            fs::symlink_metadata(&self.launcher)?
                .file_type()
                .is_symlink(),
            "The launch path is no longer an installer-managed symlink"
        );
        ensure!(
            fs::canonicalize(&self.launcher)? == self.executable,
            "The launch path selects a different build; run that veil before updating"
        );
        Ok(())
    }

    pub fn lock(&self) -> Result<UpdateLock> {
        let path = self.root.join("upgrade.lock");
        let mut lock = fs::OpenOptions::new().write(true).create_new(true).open(&path)
            .with_context(|| format!("Cannot acquire {}. Another update may be running; inspect it before removing a stale lock", path.display()))?;
        let guard = UpdateLock(path);
        writeln!(lock, "pid={}", std::process::id())?;
        lock.sync_all()?;
        Ok(guard)
    }

    #[cfg(unix)]
    pub fn activate(&self, release: &VerifiedRelease, _lock: &UpdateLock) -> Result<Activation> {
        use std::os::unix::{
            fs::PermissionsExt as _,
            fs::{OpenOptionsExt as _, symlink},
        };
        let binary = &release.binary;
        let version = release.version();
        let target = release.target.as_str();
        ensure!(
            _lock.0 == self.root.join("upgrade.lock"),
            "Update lock belongs to another installation"
        );
        ensure!(
            semver::Version::parse(version)?.to_string() == version,
            "Invalid release version"
        );
        let directory = self
            .root
            .join(format!("{version}-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&directory)?;
        let link = self
            .launcher
            .with_extension(format!("next-{}", uuid::Uuid::now_v7()));
        let prepare = (|| {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
            let path = directory.join("veil");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .open(&path)?;
            file.write_all(binary)?;
            file.set_permissions(fs::Permissions::from_mode(0o755))?;
            file.sync_all()?;
            let receipt = Receipt {
                schema: 1,
                source: INSTALLER.into(),
                version: version.into(),
                target: target.into(),
                sha256: digest(binary),
            };
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(directory.join("install.toml"))?;
            file.write_all(toml::to_string(&receipt)?.as_bytes())?;
            file.sync_all()?;
            fs::File::open(&directory)?.sync_all()?;
            fs::File::open(&self.root)?.sync_all()?;
            self.check_launcher()?;
            symlink(&path, &link)?;
            fs::rename(&link, &self.launcher)?;
            Ok::<_, anyhow::Error>(path)
        })();
        match prepare {
            Ok(path) => {
                let durable =
                    fs::File::open(self.launcher.parent().expect("validated installation"))
                        .and_then(|dir| dir.sync_all())
                        .is_ok();
                Ok(Activation {
                    executable: path,
                    durable,
                })
            }
            Err(error) => {
                let _ = fs::remove_file(&link);
                let _ = fs::remove_dir_all(&directory);
                Err(error)
                    .context("Update was not activated; the previous launcher remains selected")
            }
        }
    }

    #[cfg(not(unix))]
    pub fn activate(&self, _release: &VerifiedRelease, _lock: &UpdateLock) -> Result<Activation> {
        anyhow::bail!("Managed updates require a Unix filesystem")
    }
}

pub struct Activation {
    pub executable: PathBuf,
    pub durable: bool,
}

pub struct UpdateLock(PathBuf);
impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub struct VerifiedRelease {
    manifest: Manifest,
    binary: Vec<u8>,
    target: String,
}

impl VerifiedRelease {
    pub fn version(&self) -> &str {
        &self.manifest.version
    }
    pub fn protocol(&self) -> u32 {
        self.manifest.protocol
    }
}

pub fn verify_release(
    bytes: &[u8],
    signature: &[u8],
    key: &VerifyingKey,
    version: &str,
    target: &str,
    archive: &[u8],
) -> Result<VerifiedRelease> {
    let manifest = verify_manifest(bytes, signature, key, version)?;
    let binary = unpack(archive, artifact(&manifest, target)?)?;
    Ok(VerifiedRelease {
        manifest,
        binary,
        target: target.into(),
    })
}

#[cfg(test)]
mod tests;

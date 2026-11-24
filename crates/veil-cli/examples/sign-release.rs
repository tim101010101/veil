//! Release-signing operations.
//!
//! - `keygen <seed-file>`: create a new seed file (mode 0600) and print its public key.
//! - `public-key <seed-file>`: print the public key of a seed file.
//!
//! A seed file of `-` reads standard input.
//! - `delegate <root-seed-file> <release-public-key> <days>`: write the root-signed
//!   `releases/release-key.json` and `releases/release-key.sig`.
//! - `sign <dist-directory> <version>`: with `VEIL_RELEASE_SIGNING_KEY_FILE`, sign the release
//!   manifest and copy the delegation into the directory.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use veil_cli::update::{self, Artifact, Delegation, Manifest};

/// Warn the operator when the delegation that signs a release expires sooner than this.
const RENEW_WARNING_DAYS: i64 = 60;

fn releases() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../releases")
}

/// Reads a seed file, or standard input for `-`, so a decrypted root never touches the disk.
fn read_seed(path: &Path) -> Result<SigningKey> {
    let encoded = if path == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("Cannot read signing seed from stdin")?
    } else {
        fs::read_to_string(path).context("Cannot read signing seed file")?
    };
    let bytes: [u8; 32] = STANDARD
        .decode(encoded.trim())
        .map_err(|_| anyhow::anyhow!("Invalid signing seed encoding"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signing seed must contain 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keygen", path] => keygen(Path::new(path)),
        ["public-key", path] => {
            println!(
                "{}",
                update::encode_key(&read_seed(Path::new(path))?.verifying_key())
            );
            Ok(())
        }
        ["delegate", root, key, days] => delegate(Path::new(root), key, days.parse()?),
        ["sign", dist, version] => sign(Path::new(dist), version),
        _ => bail!(
            "Usage: sign-release keygen <seed-file> | public-key <seed-file> | delegate <root-seed-file> <release-public-key> <days> | sign <dist-directory> <version>"
        ),
    }
}

fn keygen(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Cannot create {}; refusing to overwrite", path.display()))?;
    writeln!(file, "{}", STANDARD.encode(key.to_bytes()))?;
    file.sync_all()?;
    println!("{}", update::encode_key(&key.verifying_key()));
    Ok(())
}

fn delegate(root_path: &Path, release_key: &str, days: i64) -> Result<()> {
    ensure!(
        (1..=update::MAX_DELEGATION_DAYS).contains(&days),
        "A delegation lasts 1 to {} days",
        update::MAX_DELEGATION_DAYS
    );
    let root = read_seed(root_path)?;
    let trust = update::trust()?;
    ensure!(
        trust.roots.contains(&root.verifying_key()),
        "This root key is not in releases/trust-root.json of this build"
    );
    let key = update::public_key(release_key)?;
    let now = jiff::Timestamp::now();
    let delegation = Delegation {
        schema: 1,
        purpose: update::DELEGATION_PURPOSE.into(),
        key: update::encode_key(&key),
        not_before: now.round(jiff::Unit::Second)?.to_string(),
        expires: now
            .checked_add(jiff::SignedDuration::from_hours(days * 24))?
            .round(jiff::Unit::Second)?
            .to_string(),
    };
    let mut bytes = serde_json::to_vec_pretty(&delegation)?;
    bytes.push(b'\n');
    let signature = STANDARD.encode(root.sign(&bytes).to_bytes());
    trust.release_key(&bytes, signature.as_bytes(), now)?;
    fs::write(releases().join("release-key.json"), &bytes)?;
    fs::write(releases().join("release-key.sig"), format!("{signature}\n"))?;
    println!(
        "Delegated release signing to {} until {}",
        delegation.key, delegation.expires
    );
    Ok(())
}

fn sign(dist: &Path, version: &str) -> Result<()> {
    ensure!(
        version == env!("CARGO_PKG_VERSION"),
        "Signing version must match the workspace version"
    );
    let key_path = std::env::var_os("VEIL_RELEASE_SIGNING_KEY_FILE")
        .context("VEIL_RELEASE_SIGNING_KEY_FILE must name the protected seed file")?;
    let signing = read_seed(Path::new(&key_path))?;
    let delegation = fs::read(releases().join("release-key.json"))
        .context("releases/release-key.json is missing; a root must delegate a release key")?;
    let delegation_signature = fs::read(releases().join("release-key.sig"))?;
    let now = jiff::Timestamp::now();
    let (key, parsed) = update::trust()?.release_key(&delegation, &delegation_signature, now)?;
    ensure!(
        key == signing.verifying_key(),
        "The signing key is not the delegated release key"
    );
    let expires: jiff::Timestamp = parsed.expires.parse()?;
    if expires.as_second() - now.as_second() < RENEW_WARNING_DAYS * 86_400 {
        eprintln!("warning: the release key delegation expires at {expires}; renew it");
    }
    let mut artifacts = Vec::new();
    for target in ["linux-x86_64", "linux-aarch64"] {
        let file = format!("veil-{version}-{target}.tar.gz");
        let bytes = update::bounded_read(fs::File::open(dist.join(&file))?, update::MAX_ARCHIVE)?;
        let artifact = Artifact {
            target: target.into(),
            file,
            size: bytes.len() as u64,
            sha256: update::digest(&bytes),
        };
        update::unpack(&bytes, &artifact).context("Refusing to sign an invalid release archive")?;
        artifacts.push(artifact);
    }
    let manifest = Manifest {
        schema: 1,
        version: version.into(),
        protocol: veil_proto::PROTOCOL_VERSION,
        artifacts,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let signature = STANDARD.encode(signing.sign(&bytes).to_bytes());
    update::verify_manifest(&bytes, signature.as_bytes(), &key, version)?;
    fs::write(dist.join("manifest.json"), bytes)?;
    fs::write(dist.join("manifest.sig"), format!("{signature}\n"))?;
    fs::write(dist.join("release-key.json"), &delegation)?;
    fs::write(dist.join("release-key.sig"), &delegation_signature)?;
    println!("Signed release {version} with the delegated release key");
    Ok(())
}

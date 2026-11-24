# Installation

## Download and install the CLI

Use macOS or Linux. Choose your architecture from the table below. The server is not included
in these archives. To run your own server without installing Rust on the host, follow
[self-hosting](deployment.md#start-your-own-server).

| Platform | Archive target |
| --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` |
| macOS, Intel | `x86_64-apple-darwin` |
| Linux, x86_64 | `x86_64-unknown-linux-musl` |
| Linux, ARM64 | `aarch64-unknown-linux-musl` |

In a browser, download the matching `veil-X.Y.Z-<target>.tar.gz` and `.tar.gz.sha256` from
[GitHub Releases](https://github.com/tim101010101/veil/releases). Only extract an archive after verification.

Alternatively, use [GitHub CLI](https://cli.github.com/). Private repository downloads require
an authorized GitHub account. Run `gh auth login` first if you have not authenticated.
The following commands select the target for the current shell's operating system and architecture:

```sh
version=0.4.2
case "$(uname -s):$(uname -m)" in
	Darwin:arm64) target=aarch64-apple-darwin ;;
	Darwin:x86_64) target=x86_64-apple-darwin ;;
	Linux:x86_64) target=x86_64-unknown-linux-musl ;;
	Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-musl ;;
	*) printf 'No release for this operating system and architecture.\n' >&2; exit 1 ;;
esac
download_dir="$(mktemp -d)"
cd "$download_dir" || exit 1
archive="veil-$version-$target.tar.gz"
gh release download "v$version" --repo tim101010101/veil --pattern "$archive*"
```

Verify the checksum using the command for your operating system. For browser downloads,
first change to the download directory and set `archive` to the downloaded archive's filename.

On macOS:

```sh
shasum -a 256 -c "$archive.sha256"
```

On Linux:

```sh
sha256sum -c "$archive.sha256"
```

The result must end in `OK`. Stop if verification fails. Then extract and install:

```sh
tar -xzf "$archive"
./veil version
mkdir -p "$HOME/.local/bin"
install -m 0755 veil "$HOME/.local/bin/veil"
export PATH="$HOME/.local/bin:$PATH"
veil version
```

Both version commands must report `0.4.2` when using the commands above. Add the same `export`
line to your shell's startup file to keep it in new terminals, such as `~/.zshrc` for zsh or
`~/.bashrc` for interactive bash. Run `command -v veil` to check which executable is selected.
Continue with the [quick start](../README.md#quick-start).

Every archive contains `veil`, `LICENSE`, `BUILD-INFO.json`, and `THIRD-PARTY-NOTICES.txt`.
The metadata identifies the source commit and binary digest. The notices contain dependency
licenses and corresponding-source links. `SHA256SUMS` also lists all four archives' checksums.

macOS binaries are not Developer ID-signed or notarized. macOS may block browser downloads.
Do not disable system security controls to run them. Build from source if necessary.
Linux releases are static musl binaries for their named architecture. Windows is not supported.

Checksums detect corruption. They are not independent release signatures and do not establish
authenticity if the repository or distribution channel is compromised.

## Build from source

Use macOS or Linux with Git and [mise](https://mise.jdx.dev/). Native compilation needs a C
compiler and platform development tools. On macOS, install the Xcode Command Line Tools.
On Linux, install your distribution's C build tools and development headers.

Check out the tag matching your server and CLI version, not the moving default branch.
Review `mise.toml` before trusting the checkout:

```sh
git clone --branch v0.4.2 --depth 1 https://github.com/tim101010101/veil.git veil
cd veil || exit 1
mise trust
mise install rust
mise exec -- cargo build --release --locked --workspace
./target/release/veil version
```

Rust is pinned in `mise.toml`, and dependencies are pinned in `Cargo.lock`.
Install the CLI and, if needed, the server into your user account:

```sh
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/veil "$HOME/.local/bin/veil"
install -m 0755 target/release/veild "$HOME/.local/bin/veild"
export PATH="$HOME/.local/bin:$PATH"
```

To run a source-built server, use a persistent private data directory:

```sh
umask 077
mkdir -p "$HOME/.local/share/veil-server"
veild --bind 127.0.0.1:8080 --db "$HOME/.local/share/veil-server/veil.db"
```

Keep this process running in one terminal. On the same machine, create an account using
[self-hosting step 3](deployment.md#3-create-your-account). Follow the
[TLS and access restrictions](deployment.md#tls-and-access) before connecting from another machine.

## Update an installation

Keep the CLI and server on the same version. Back up the server before upgrading it.
For a release CLI, download the desired version and repeat checksum verification and installation.
For source builds, fetch and check out that version's tag, rebuild with locked dependencies,
and replace the binaries. See [self-hosting upgrades](deployment.md#upgrades) for the tag-fetch
commands needed by a shallow clone and for container server upgrades.

These bundles are manual installations. Do not run `scripts/install.sh` to install them.
They do not use that bootstrap installer's separate managed Linux archive format.
Managed `veil upgrade` requires signed release metadata and pinned trust roots. The initial
trust list remains empty, so managed upgrades fail closed. Do not bypass signature checks
or add test keys.

## CI artifacts

[CI runs](https://github.com/tim101010101/veil/actions/workflows/ci.yml) retain experimental CLI archives for
seven days. These are not the permanent versioned Release assets. A GitHub login is required.
Native smoke tests check help, version, source commit, and archive validity. They do not
verify interactive Keychain dialogs, Touch ID, or older macOS compatibility.

# Veil

A self-hosted secrets vault for command-line tools, CI workloads, and AI agents.
Encrypt secrets on your device, keep references in your project, and deliver values only
when a command needs them. The server stores ciphertext, not decryption keys.

[Quick start](#quick-start) · [Installation](#installation) · [Documentation](#documentation) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

After signing in, import a project's `.env` and run a command with its secrets:

```sh
veil init --vault my-app
veil run -- npm start
```

`veil init` imports your project's `.env` into a vault and writes references to `veil.toml`.
`veil run` resolves those references for the child process and redacts matching values from
its output. The original `.env` remains on disk.

## Features

- Encrypt secret values and names on the client. Run `veild` with a SQLite database and no
  vault decryption path.
- Deliver secrets through environment variables or named pipes. Commit references instead
  of values.
- Grant restricted devices and OIDC workloads access to selected vaults. Require local
  presence or approval on another device before delivery, and inspect deliveries with `veil audit`.
- Connect agents through scoped MCP tools. Value reveal is disabled unless you explicitly
  enable it.
- Read and write the same store with supported Bitwarden clients.

Veil is early, pre-1.0 software. Read the limits below before
storing real secrets. Veil is independent of Bitwarden and is not an official Bitwarden product.
Compatibility covers [pinned, tested clients](tests/bitwarden/README.md), not every Bitwarden
version or feature.

## Installation

Download versioned CLI archives from [GitHub Releases](https://github.com/tim101010101/veil/releases):

| Platform | Target |
| --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` |
| macOS, Intel | `x86_64-apple-darwin` |
| Linux, x86_64 | `x86_64-unknown-linux-musl` |
| Linux, ARM64 | `aarch64-unknown-linux-musl` |

Each archive contains the CLI, license, dependency notices, and build metadata. Its matching
SHA256 file is a separate download. Follow [installation](docs/installation.md) to verify and
install it. macOS binaries are not Developer ID-signed or notarized. Managed self-update is not enabled.

Release archives contain the CLI only. You do not need Rust to use them. To compile either
binary yourself, follow [build from source](docs/installation.md#build-from-source).

## Quick start

Install the CLI using [installation](docs/installation.md), then choose your server:

- **Existing server and account:** use its HTTPS URL and continue below.
- **First self-hosted instance:** follow [start your own server](docs/deployment.md#start-your-own-server)
  to build a container, check readiness, and create your account. No host Rust toolchain is needed.
  Then continue at step 2 below.

### 1. Sign in on your personal computer

Replace the URL and email with your account details:

```sh
veil login --server https://vault.example.com --email you@example.com
```

Enter your master password at the prompt. This registers a personal device with access to
all existing and future vaults. For a shared or headless host, use
[restricted device enrollment](docs/usage.md#add-a-restricted-host) instead.

### 2. Import and use a secret

Create a temporary project with a synthetic value. Use an unused vault name if `demo`
already contains your data:

```sh
project_dir="$(mktemp -d)"
cd "$project_dir" || exit 1
printf 'DEMO_TOKEN=example-value-only\n' > .env
veil init --dry-run --vault demo
veil init --vault demo
veil run -- sh -c 'test "$DEMO_TOKEN" = example-value-only && echo delivered'
veil audit
```

The command prints `delivered`, and the audit lists a delivery. `veil.toml` contains a
`veil://demo/DEMO_TOKEN/password` reference, not the value. `veil init` adds `.env` to
`.gitignore`, but does not delete it or untrack it if it is already in Git.

For a real project, run the same import commands in its directory with its own vault name.
Review the dry run before writing. Commit `veil.toml`, not `.env` or your client state.
See [daily use](docs/usage.md) for updates, key storage, additional devices, recovery,
and troubleshooting. Back up a self-hosted server using [backup and restore](docs/deployment.md#backup-and-restore).

## Security boundaries

- Client-side encryption does not protect a compromised client or operating system.
- A process that receives a secret can copy or transmit it. Output redaction is not a sandbox
  and does not cover encoded values, files, or network traffic.
- Personal devices can read all existing and future vaults. Use restricted devices or
  workloads when you need access to selected vaults only.
- Presence approval requires macOS. Other platforms refuse delivery from vaults that require it.
- Keep the management API private. Bitwarden access does not require exposing the entire API.

Read the [deployment guide](docs/deployment.md)
before using real secrets. For vulnerability reports, follow the [security policy](SECURITY.md),
not the public issue tracker.

## Documentation

Documentation lives in this repository:

- [Installation](docs/installation.md): download, verify, and install the CLI, or build from source.
- [Daily use](docs/usage.md): project references, updates, key storage, devices, recovery, delivery scenarios, and troubleshooting.
- [Self-hosting](docs/deployment.md): start a server, restrict access, back up, restore, and upgrade.
- [Glossary](GLOSSARY.md): vaults, items, devices, and grants.

## Contributing

Report reproducible bugs and feature requests in [GitHub Issues](https://github.com/tim101010101/veil/issues).
Use disposable accounts and synthetic secrets in examples. Include the version and source
commit, and remove personal information from logs before sharing them.

Read [Contributing](CONTRIBUTING.md) for the pull request process and
[Development](docs/development.md) for setup and tests.

## License

Veil is licensed under [AGPL-3.0-only](LICENSE). Distributed CLI archives include dependency
licenses and corresponding-source links in `THIRD-PARTY-NOTICES.txt`.

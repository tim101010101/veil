# Development

Install mise, inspect and trust `mise.toml`, then run:

```sh
mise install
cargo build --workspace --locked
mise run check
```

`mise.toml` is the toolchain source of truth. `mise.lock` records tool downloads and
`Cargo.lock` pins Rust dependencies. Build the workspace before CLI integration tests,
which start a real daemon.

## Tests

- Run `cargo test --workspace --locked` for Rust unit, integration, and scenario tests.
- Run `python3 scripts/test-install.py` for isolated Linux installer tests.
- Run `python3 scripts/test-release.py` for release validation and packaging tests.
- Run `mise run check:boundary` to keep decryption crates out of the server.
- Generate SDK fixture changes with `scripts/regenerate-golden.sh`, then test `veil-core`.
- Run `mise run compat:bitwarden` for the pinned official clients behind local TLS.
  This suite needs its documented browser and client prerequisites.

## CI and caching

The CI workflow checks formatting, Clippy, workspace compilation, Rust tests, installer
tests, release tests, and the daemon cryptography boundary. Four native runners build and
smoke-test macOS ARM64, macOS Intel, Linux x86_64, and Linux ARM64 CLI archives.

Ordinary CI caches Rust dependencies separately for workspace checks and each release target.
Only pushes to `main` save caches. Pull requests restore caches without writing them.
Formal release runs do not restore or save compiled caches. Tool installation uses pinned
versions and verified downloads without a shared tool cache.

Linux CLI builds use Zig and cargo-zigbuild to link against musl. Each Linux binary must run
on its native runner and have no ELF program interpreter or dynamic library dependencies.
macOS builds remove linker debug maps. Rust and native compiler paths are remapped, and
packaging rejects embedded build-machine paths.

The standard workflow does not run the interactive Bitwarden suite or platform approval
dialogs. Native CLI smoke tests do not establish Keychain, Touch ID, or older macOS support.

## Release

1. Update the workspace version and write reviewed notes in `docs/releases/X.Y.Z.md`.
2. Run `mise run check` and merge the intended source into `main`.
3. Push the matching stable tag `vX.Y.Z`.

The release workflow checks that the tag matches the workspace version, has reviewed notes,
and points into `main` history. It runs the complete CI with clean compilation.
Only after every check and all four native builds succeed does a separate job receive
repository-content write permission.

`scripts/release.py` validates the complete target set, checksums, archive contents, file
modes, ownership, binary formats, build commit, source links, licenses, and static Linux linking.
It rejects extra files and archive links. Release archives normalize file timestamps and
ownership. This does not claim byte-for-byte reproducible compiler output.

Publication creates a draft, uploads every verified asset, and then publishes it. Failed
uploads leave a draft rather than a partially published release. Existing releases and assets
are never overwritten. Review and resolve any existing draft before retrying publication.
The workflow never changes repository visibility.

## Release signing

Release archives are manual installations. They do not enable managed self-update or use
Apple Developer ID signing or notarization.

Signed self-update reads releases from the GitHub repository in Cargo package metadata.
Provision independent offline root keys and a delegated release key before enabling it.
Keep every seed outside the repository. The initial empty root list fails closed.
Do not substitute archive checksums for release signature verification.

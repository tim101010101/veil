# Contributing

Include the version and source commit when reporting a bug. Use a disposable account and
synthetic values in reproductions. Never publish secrets, database files, recovery codes,
vault exports, credentials, or signing seeds.

For suspected vulnerabilities, follow the [security policy](SECURITY.md). Do not disclose
security details in public issues or pull requests.

## Development

1. Branch from the version you are changing.
2. Add tests at the level where the behavior lives.
3. Run `mise run check`.
4. Open a pull request with the problem, change, verification, and compatibility impact.

Cryptography, authentication, approval, audit, and client/server boundary changes need their
security rationale in the pull request.

See [development](docs/development.md) for commands and CI coverage. CI runs the workspace
checks and four native CLI builds. Interactive Bitwarden compatibility and platform approval
dialogs require their separate test procedures.

## Release notes

Describe user-visible changes and migration steps in the pull request. Do not create or move
release tags as part of an ordinary contribution.

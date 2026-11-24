# Daily use

Start with the [quick start](../README.md#quick-start). This guide assumes you are signed in
and have a project with `veil.toml`. Run project commands from that directory.

## Check the project's references

```sh
veil list
veil doctor
```

`list` shows names and references, never values. `doctor` checks configuration, local identity,
connectivity, and project references. A failed check returns a nonzero exit status and a hint.

After the README example, `veil.toml` contains:

```toml
vault = "demo"

[env]
DEMO_TOKEN = "veil://demo/DEMO_TOKEN/password"
```

A reference has three components: `veil://vault/item/field`. You can commit this file.
It describes what the project needs, not who can read it. Another device must independently
receive access to those vaults.

`veil init` is a one-time import for a directory without `veil.toml`. Do not rerun it to
update an existing project. Use `veil set`, or edit the reference mapping directly.
The original `.env` remains plaintext on disk. Keep it out of Git and handle existing tracked
copies and backups separately. After verifying delivery and recovery, remove unneeded plaintext
copies according to your retention policy. Import does not remove historical secrets from Git.
An application that reads `.env` itself may still use that file; use the named-pipe delivery
mode in [scenarios](#scenarios) if the application requires a file.

## Update or add a value

Update an existing variable using a hidden prompt:

```sh
veil set DEMO_TOKEN
```

To test an update with another synthetic value instead:

```sh
printf 'updated-example-only' | veil set DEMO_TOKEN --stdin
veil run -- sh -c 'test "$DEMO_TOKEN" = updated-example-only && echo updated'
```

The child prints `updated`. Restart long-running applications after a change: already running
processes retain the old value. There is no value-history or undo command.

Add a new variable to the default vault named at the top of `veil.toml`:

```sh
veil set NEW_TOKEN
veil list
```

`set` adds the reference to this project's `[env]` table. It requires a default vault that
already exists. To use an existing secret shared with another project, put its full reference
in `[env]` instead of creating a duplicate value.

For scripts, `set --stdin` and `set --file <path>` accept UTF-8 and preserve trailing newlines.
They are mutually exclusive. Do not put real values in `--value` arguments or shell history.

## Deliver or deliberately reveal a value

For a project with an npm start script:

```sh
veil run -- npm start
```

Only the child receives the configured environment values. Matching output is redacted, but
the child can still copy or transmit its environment. Redaction is not a sandbox and does not
cover encoded values or strings shorter than four bytes.

When you deliberately need to inspect one value, use:

```sh
veil get DEMO_TOKEN
```

The command asks for reveal confirmation and then prints the value. Do not run it in a
recorded or shared terminal. `veil get DEMO_TOKEN --copy` uses the clipboard instead, but
does not automatically clear it. `--yes` confirms reveal; it does not bypass vault approval.

Inspect delivery records without revealing values:

```sh
veil audit
```

See [scenarios](#scenarios) for named pipes, templates, scoped MCP, and workloads.
These are optional integrations, not prerequisites for ordinary CLI use.

## Scenarios

| Situation | Mechanism | Usage |
| --- | --- | --- |
| Run tests or a service | Inject into a child process | `veil run -- npm test` |
| An app that reads files | Named pipe, removed on exit | `veil run --mount .env -- php artisan serve` |
| A key read a fixed number of times | Same, with a read limit | `veil run --mount key --mount-max-reads 2 -- ssh -i key …` |
| Any config format | Render to stdout or a `0600` file | `veil inject nginx.tpl --out nginx.conf` |
| A manifest in Git | Commit a reference, render at deploy | `password: {{ veil://api/postgres/password }}` |
| Shell variables | Export only text fields, never hidden ones | `eval "$(veil export --format shell)"` |
| One value, once | Reveal after approval | `veil get veil://api/postgres/password --copy` |
| IDE or debugger | Wrap the launch command | `{"program":"veil","args":["run","--","node","app.js"]}` |
| Containers | Inject into the compose process or mount a rendered file | `veil run -- docker compose up` |
| A shared token | One Item, referenced by every service that needs it | `DEMO_TOKEN = "veil://example/demo-service/password"` |
| CI with OIDC | Exchange an OIDC token for a short-lived grant | `veil workload add --name ci --issuer <URL> --audience <AUD> --claim ref=main --vault api` |
| CI without OIDC | Enroll the host as a Device | `veil device add` → `veil device approve` |
| systemd or a single host | Inject at start; key in a `0600` file | `ExecStart=/usr/bin/veil run -- /srv/app` |
| Kubernetes with Flux | Render a SOPS file and commit it | `veil inject secret.tpl --sops --out secret.sops.yaml` |
| An agent running project scripts | Nothing to configure | `npm test` |
| An agent running its own commands | Scoped MCP front end; values stay out of its context | `veil mcp --allow 'veil://example/*'` |
| A Vault an agent must not use alone | Require a human action per delivery | `veil vault policy admin --approval presence` |
| Website accounts | Bitwarden extension and mobile app read the Vault directly | `veil bitwarden enable --vault web` |
| Moving passwords in | Apple Passwords on iOS 26 exports to the Bitwarden app; elsewhere `bw import` | Passwords → Export Data to Another App → Bitwarden; `bw import safaricsv Passwords.csv` |
| Daily login | Renew the management session with the master password; device reads keep their own scope | `veil login` |
| A second machine | Master-password login registers a personal Device with all-Vault reads; hosts use restricted approval | `veil login`; `veil device add` / `veil device approve` for restricted hosts |
| A lost machine | Immediate refusal, Vault key rotation on the next write | `veil device rm old-xps` |
| A lost password | Recovery code plus a new Device | `veil recover` |
| Offline | Cached ciphertext within a 15-minute window | automatic |

## Keep client state and keys

By default, client state lives in `$XDG_CONFIG_HOME/veil`, or `~/.config/veil` when
`XDG_CONFIG_HOME` is unset. `VEIL_HOME` overrides that directory. Keep it persistent for real
accounts. Temporary directories are only for disposable tests.

- `state.json` contains device identity, a management session, and cached ciphertext. Treat
  it as sensitive even though key material is stored separately.
- macOS uses the login Keychain by default. A new unsigned CLI build may require interactive
  authorization. Only approve a build you trust. Keychain authorization is not vault presence approval.
- Linux uses `keys.json` with mode `0600`. These are usable decryption keys, not another
  encrypted backup. Protect the OS account, directory, disk, and backups accordingly.

Choose `VEIL_KEYSTORE=file` or `keychain` before first enrollment if you need to override the
default. Keychain is macOS-only. Changing this setting later does not migrate keys and can
make the existing device unusable. Do not copy a personal device's keys onto a shared host.
A copy of `state.json` alone is not a usable backup of a Keychain-backed device.

Use these commands to inspect configuration without printing secret values:

```sh
veil config
veil doctor
```

The configuration file is `$VEIL_HOME/config.toml`, or the path selected by `VEIL_CONFIG`.
Optional top-level settings look like this:

```toml
server = "https://vault.example.com"
email = "you@example.com"
```

`server` and `email` select the login target. Command flags override environment variables,
which override the file. An existing device remains bound to its account and server. Use a
separate, persistent `VEIL_HOME` for another account rather than editing its identity files.
Never store master passwords, recovery codes, or keys in configuration or project files.

## Add a restricted host

A personal `veil login` gives the machine access to all existing and future vaults. For a
server, shared host, or automation without OIDC, enroll a restricted device instead.
Use a dedicated OS account and persistent, private client directory on that host. It must not
already be enrolled. Replace the URL and email:

```sh
export VEIL_KEYSTORE=file
veil device add --server https://vault.example.com --email you@example.com --name app-host
```

Leave it waiting. On your trusted personal computer, approve the displayed code and explicitly
name the vault to grant:

```sh
veil device approve CODE --vault demo
```

Replace `CODE` with the enrollment code. The host reports approval and can now read that vault.
Copy or check out the project's `veil.toml` on the host, then use `veil run` there. Do not copy
`.env`, `state.json`, or personal keys. Other vaults remain inaccessible unless granted.
Approval expires after about ten minutes if nobody completes it.

To revoke a lost or retired device from a trusted personal computer:

```sh
veil device list
veil device remove DEVICE_ID
```

Replace `DEVICE_ID` with the listed ID. New online requests are refused, and affected vault
keys rotate on the next write. Revocation cannot erase plaintext already copied by the device,
and a fresh offline cache can remain usable within its 15-minute window.

## Recover an account

If you still know the master password, sign in on a new trusted personal computer normally.
If you lost it, use the offline recovery code on a device that is not already enrolled:

```sh
veil recover --server https://vault.example.com --email you@example.com
```

Enter the recovery code, then choose and confirm a new master password. Recovery creates a
new personal device and changes the master password. It does not revoke lost devices or rotate
every vault key. Inspect `veil device list` and revoke lost devices explicitly afterward.
Do not delete working local state just to force recovery. Use a new device or a separate
persistent `VEIL_HOME`, and preserve the old state while diagnosing the problem.

Database restoration is a separate operation. Follow [server backup and restore](deployment.md#backup-and-restore).
A recovery code does not recreate missing server records, and a server backup alone does not
replace the credentials needed to decrypt them.

## Troubleshoot a failure

Start with `veil doctor`, `veil config`, and `veil version`. Before sharing output, remove
personal addresses, server names, device names, and private references. Never attach key files,
recovery codes, `.env`, or a database backup to an issue.

| Symptom | Next step |
| --- | --- |
| `veil: command not found`, or an old version runs | Add the installation directory to `PATH`; check `command -v veil` and open a new shell. |
| Connection refused or TLS failure | Check the server URL, `/readyz`, VPN, certificate trust, and proxy allowlist. Do not disable TLS verification. |
| Login conflicts with this device's account | Check `veil config`, `VEIL_HOME`, and the existing binding. Use a separate home for a different account. |
| Management session expired | On a personal device, run `veil login`. Device reads retain their own scope; do not promote a restricted host to fix a read failure. |
| Keychain needs interaction | Unlock it and authorize the trusted CLI build from an interactive terminal, then retry. Do not switch backends to hide the error. |
| No `veil.toml`, or a reference is missing | Run in the project directory. Inspect `veil list`; initialize a new project or correct its reference mapping. |
| A restricted device cannot read a vault | Ask the owner to check its grant. The project file does not grant permission. |
| Approval unavailable on Linux or in automation | Use an account-appropriate delivery policy. `presence` requires macOS; `--yes` cannot bypass it. |
| Revision conflict after a write | Inspect current state before retrying. Do not assume an automatic rollback. |
| Rollback warning after a deliberate restore | Verify the restored snapshot, then follow the explicit reauthentication step in the restore guide. |
| `veil upgrade` says signing is not configured | Repeat the manual installation procedure. Do not bypass signature checks. |

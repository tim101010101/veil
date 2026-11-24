# Bitwarden compatibility suite

The control point of compatibility suite: pinned official Bitwarden clients against a real `veild`
behind TLS. It grew from the prototype described in the unified-vault proposal.

| Step | Client | Checks |
| --- | --- | --- |
| 1 | `bw` | logs in to a v2 account created by `veil` |
| 2 | `bw` | reads an Item written by `veil`, and nothing from a Vault it was not given |
| 3 | `bw` | creates, edits, trashes, and restores Items and files them in a folder; `veil get` reads the new values |
| 4 | Chrome extension | logs in and lists the Items |
| 5 | `bw` | with two-step login on, is refused with the password alone and logs in with an authenticator code |
| 6 | `bw` | imports an Apple Passwords CSV (`safaricsv`) and a Bitwarden JSON export with a folder; `veil` reads the imported values |

Versions are pinned in `versions.env`. The clients refuse plain HTTP even for `localhost`, so
`veild` runs behind Caddy with an internal CA (`Caddyfile`).

```sh
tests/bitwarden/setup.sh            # once: pinned bw, Playwright Chromium, the extension, Caddy
cargo build -p veil-daemon -p veil-cli
tests/bitwarden/run.sh              # needs a display for the extension; CI uses xvfb-run
```

`run.sh` reads `VEILD`, `VEIL`, `BW`, `CADDY`, `PLAYWRIGHT_DIR`, and `EXTENSION_DIR`, defaulting
to what `setup.sh` installs under `$COMPAT_HOME` (default `~/.cache/veil-compat`).

# Self-hosting

Run one `veild` server for your clients. It stores ciphertext in SQLite and does not decrypt
vault contents. This guide starts a persistent local container, then adds restricted HTTPS
access, backups, and upgrades. Use synthetic data until you have tested backup and recovery.

## Start your own server

### 1. Check prerequisites

Install Git, Docker Engine with Docker Compose, and curl on the server host. Docker must be
running. Install the matching [CLI release](installation.md) on your personal computer.
No host Rust installation is needed for the container build.

The example uses port 8080 on the server's loopback interface. Check that the port is free.
If it is occupied, change the host port in `.docker/compose.yaml` and all URLs below.

### 2. Build and start the server

Check out the same tag as your CLI, then review `.docker/Dockerfile` and `.docker/compose.yaml`:

```sh
git clone --branch v0.4.2 --depth 1 https://github.com/tim101010101/veil.git veil
cd veil || exit 1
docker compose -f .docker/compose.yaml up -d --build veild &&
	curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/readyz
```

The first build downloads a Rust toolchain and compiles the server inside the build container.
It can take several minutes. If package or tool downloads stall, check the Docker builder's
network and proxy settings, not just the host browser's connectivity. The readiness request
must return HTTP 200 with `status` set to `ok`. If it fails, inspect the service before continuing:

```sh
docker compose -f .docker/compose.yaml ps
docker compose -f .docker/compose.yaml logs --tail 100 veild
```

The named Docker volume keeps `/data/veil.db` across container replacement and host restarts.
The container runs as UID/GID `10001:10001`. The restart policy requires Docker itself to
start on the host. Do not delete the volume, run `down --volumes`, or prune it to fix an error.

### 3. Create your account

On the same host, use the installed CLI. Replace the email with your account address:

```sh
veil login --create --server http://127.0.0.1:8080 --email you@example.com
```

Enter a strong master password at the prompt. Save the one-time recovery code offline,
separate from the server and its backups. You are now signed in on this personal device.
Continue with [import and use a secret](../README.md#2-import-and-use-a-secret).

Loopback HTTP is only for a client on this host. From another computer, first configure the
restricted HTTPS endpoint below, then create the account or sign in using that HTTPS URL.
Do not put passwords in command arguments or copy the temporary `VEIL_HOME` from a test
into a real account setup. See [client key storage](usage.md#keep-client-state-and-keys).

To stop or restart this server without deleting its data:

```sh
docker compose -f .docker/compose.yaml stop veild
docker compose -f .docker/compose.yaml up -d veild
```

## TLS and access

Keep this CLI service on a private network or VPN and terminate TLS at a trusted reverse
proxy. The following Caddy configuration assumes Caddy runs directly on the same host as
the loopback-bound server and receives client connections directly. It rejects all service
requests except those from explicitly trusted source addresses:

```caddyfile
vault.example.com {
	@trusted remote_ip 127.0.0.1/32 ::1/128 192.0.2.0/24
	handle @trusted {
		reverse_proxy 127.0.0.1:8080
	}
	handle {
		respond "Forbidden" 403
	}
}
```

Replace the hostname with your own domain and `192.0.2.0/24` with your actual trusted client
or VPN source range. The example range is reserved for documentation and grants no real VPN
access. Configure DNS and certificate issuance for your host. Use a certificate your clients
trust. Do not disable TLS verification.

`remote_ip` checks Caddy's immediate peer, not an arbitrary `X-Forwarded-For` header. Do not
place another proxy in front of this example without preserving and validating client identity.
Do not add a shared proxy or container gateway to the allowlist if it also carries untrusted traffic.
Keep port 8080 bound to loopback and enforce the same boundary in the host firewall.

Before using real secrets, test from both trusted and untrusted networks. Trusted clients
must reach `https://vault.example.com/readyz`; untrusted service requests must receive 403.
Also check `/api/v1/prelogin` from an untrusted network. A request with forged forwarding
headers must still receive 403. Restrict both IPv4 and IPv6.

If you configure `VEIL_TRUSTED_PROXIES`, include only the actual reverse proxy addresses or
ranges. It controls application rate-limit attribution, not permission to access management
routes. Do not trust forwarded addresses from arbitrary clients.

This configuration intentionally keeps Bitwarden routes private too. Public Bitwarden access
requires a separate, reviewed route allowlist while `/api/v1` remains restricted. Do not replace the restricted example with an unrestricted catch-all proxy.

## Backup and restore

A server backup contains ciphertext, account metadata, and a token-signing secret. It does
not replace the master password or recovery code. Keep encrypted off-host copies with
restricted access. Test a restore before relying on the backup.

### Back up the container database

Run these commands from the server checkout while `veild` is running. The explicit `--db`
selects the actual persistent database. Each snapshot must have a new filename:

```sh
(
	set -eu
	umask 077
	backup_dir="$HOME/.local/share/veil-backups"
	mkdir -p "$backup_dir"
	chmod 700 "$backup_dir"
	stamp="$(date -u +%Y%m%dT%H%M%SZ)"
	snapshot="/tmp/veil-$stamp.db"
	backup="$backup_dir/veil-$stamp.db"
	docker compose -f .docker/compose.yaml exec -T veild veild --db /data/veil.db backup "$snapshot"
	docker compose -f .docker/compose.yaml cp "veild:$snapshot" "$backup"
	chmod 600 "$backup"
	docker compose -f .docker/compose.yaml exec -T veild rm "$snapshot"
	printf 'Backup saved: %s\n' "$backup"
)
```

The backup command prints `wrote` and its snapshot path. The local file must exist and be
nonempty. The backup directory stays outside the Git checkout. Never commit database backups.
Stop if any command fails. Copy the verified backup to protected off-host storage.
Do not copy only the live `veil.db` file while the service is writing: WAL data may be missing.

For a source-built server instead, name both paths explicitly:

```sh
umask 077
veild --db "$HOME/.local/share/veil-server/veil.db" backup "$HOME/veil-$(date -u +%Y%m%dT%H%M%SZ).db"
```

### Restore a container backup

Restoration replaces the database and loses all changes made after the snapshot, including
later writes, password changes, grants, and device revocations. Make a fresh backup of the
current state first. Confirm the snapshot belongs to this instance.
Do not restore over a running database.

Set `backup` to the snapshot you intend to restore, then stop the service. The stopped
container may remain; the one-off restore container uses the same data volume and UID/GID.

```sh
backup="$HOME/.local/share/veil-backups/veil-YYYYMMDDTHHMMSSZ.db"
test -s "$backup" && docker compose -f .docker/compose.yaml stop veild
```

Only continue if the file check and stop succeeded. Stage the snapshot before replacing
the database. `restore.db` must not already exist:

```sh
docker compose -f .docker/compose.yaml run --rm --no-deps -T --entrypoint sh veild -ec '
	umask 077
	test ! -e /data/restore.db
	cat > /data/restore.db
	chmod 600 /data/restore.db
	rm -f /data/veil.db-wal /data/veil.db-shm
	mv /data/restore.db /data/veil.db
' < "$backup"
```

Only restart after that command succeeds. A failed copy leaves the original database in
place and may leave `restore.db`; inspect the failure before removing that staging file.

```sh
docker compose -f .docker/compose.yaml up -d --no-build veild &&
	curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/readyz
```

Confirm readiness and inspect logs. Clients that saw a newer revision may reject the restored
state as a rollback. Only after deliberately accepting that rollback, run `veil login` on an
affected personal device to reset its sync watermark, then `veil list` in a known project.
Check that the expected pre-backup records exist. Do not use reauthentication to silence an
unexpected rollback warning.

For a source-built server, stop its process, restore the snapshot to the exact `--db` path,
remove that database's stale `-wal` and `-shm` files, restore its service-account ownership,
and restart it. Keep the pre-restore backup until you have verified the result.

## Upgrades

1. Read the desired version's release notes and make a database backup.
2. Keep the existing checkout and its Compose project name. Fetch and check out the desired tag.
3. Review any Compose or Dockerfile changes, then run `docker compose -f .docker/compose.yaml up -d --build veild`.
4. Verify `/readyz`, install the same CLI version, and test delivery of a known synthetic value.

The initial clone is shallow. To select another release, set `version` to that release's
version and fetch its tag first. The current version is shown below:

```sh
version=0.4.2
git fetch --depth 1 origin "refs/tags/v$version:refs/tags/v$version" &&
	git checkout --detach "v$version"
```

Preserve local configuration changes. Do not force a checkout to discard them.
Do not switch to a fresh volume to work around a migration error. Schema version 4 migrates
version 3 and invalidates old CLI management sessions. Other incompatible schemas are refused.
To roll back an incompatible migration, restore the pre-upgrade backup with the matching old
server version. Merely starting the old binary against a migrated database is not a rollback.

Health is at `/healthz`, readiness at `/readyz`, and OpenAPI at `/openapi.json`.
Probes do not replace authentication or network restrictions. For client-side failures, use
[troubleshooting](usage.md#troubleshoot-a-failure).

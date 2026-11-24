//! The scenario suite (compatibility suite): one end-to-end test per row of the Scenarios table in
//! `docs/usage.md`, named after the row, against a real `veild` and a real `veil`.
//!
//! The redaction invariant runs across the whole suite: every value a test stores is registered
//! as delivered, and the captured stdout and stderr of every `veil` invocation are checked for
//! it, unless the invocation asks to show a value (`veil get`, `veil inject` to stdout,
//! `veil export`, `--no-redact`, `--allow-reveal`).
//!
//! `every_scenario_row_has_a_test` keeps the table and this file in step: a new delivery feature
//! lands with its `usage.md` row and its test.

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio},
    sync::{Mutex, Once},
};

use assert_cmd::cargo::cargo_bin;
use serde_json::{Value, json};

/// Rows a test in this file does not cover, and where they are covered instead.
const ELSEWHERE: &[(&str, &str)] = &[
    (
        "Website accounts",
        "tests/bitwarden: pinned Bitwarden clients against veild (compatibility suite)",
    ),
    (
        "Daily login",
        "`veil login --sso` is planned and not implemented",
    ),
    (
        "Moving passwords in",
        "tests/bitwarden step 6: `bw import` of Apple Passwords CSV and Bitwarden JSON",
    ),
];

const PASSWORD: &str = "correct-horse";
const EMAIL: &str = "me@example.com";

// ---- Harness -------------------------------------------------------------------------------

struct Server {
    child: Child,
    url: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn veild() -> PathBuf {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        // Build in this test's own profile, so a `--release` test never runs a stale veild.
        let mut build = Command::new(env!("CARGO"));
        build.args(["build", "-p", "veil-daemon", "--bin", "veild"]);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        let status = build.status().expect("cargo runs");
        assert!(status.success(), "cannot build veild");
    });
    cargo_bin("veild")
}

fn start_server(db: &Path, bind: &str) -> Server {
    let mut child = Command::new(veild())
        .env("VEIL_BIND", bind)
        .env("VEIL_DB", db)
        .env("VEIL_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("veild starts");
    let stderr = child.stderr.take().expect("stderr");
    let mut lines = BufReader::new(stderr).lines();
    let url = loop {
        let line = lines.next().expect("server logs").expect("line");
        if let Ok(value) = serde_json::from_str::<Value>(&line)
            && value["fields"]["message"] == "listening on http"
        {
            break format!("http://{}", value["fields"]["addr"].as_str().expect("addr"));
        }
    };
    std::thread::spawn(move || for _ in lines {});
    Server { child, url }
}

/// One scenario: a service, an owner machine, and every value delivered so far.
struct World {
    root: PathBuf,
    server: Server,
    delivered: Mutex<Vec<String>>,
}

impl World {
    /// A service with an account and an owner machine called `owner`.
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("veil-scenario-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let server = start_server(&root.join("veil.db"), "127.0.0.1:0");
        let world = Self {
            root,
            server,
            delivered: Mutex::new(Vec::new()),
        };
        world.ok(world
            .veil("owner", &world.dir("owner"))
            .args(["login", "--create"]));
        world
    }

    /// A directory under the scenario root.
    fn dir(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(&path).expect("dir");
        path
    }

    /// `veil` as run on `machine`, in `dir`. Keys stay in a `0600` file, never in the keychain
    /// of the machine running the tests.
    fn veil(&self, machine: &str, dir: &Path) -> Command {
        let mut command = Command::new(cargo_bin("veil"));
        command
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("VEIL_HOME", self.root.join("machines").join(machine))
            .env("VEIL_KEYSTORE", "file")
            // No Touch ID prompt during tests: presence approval refuses, as on a host without it.
            .env("VEIL_PRESENCE", "unavailable")
            .env("VEIL_SERVER", &self.server.url)
            .env("VEIL_EMAIL", EMAIL)
            .env("VEIL_PASSWORD", PASSWORD)
            .env("VEIL_LOG", "error");
        command
    }

    /// Stores a value with the owner's `veil set` and registers it as delivered.
    fn store(&self, reference: &str, value: &str) {
        self.delivered.lock().expect("lock").push(value.to_owned());
        self.ok(self
            .veil("owner", &self.dir("owner"))
            .args(["set", reference, "--value", value]));
    }

    fn output(&self, command: &mut Command) -> Output {
        command.stdin(Stdio::null()).output().expect("veil runs")
    }

    /// Runs a command that must succeed without showing any delivered value.
    fn ok(&self, command: &mut Command) -> String {
        let output = self.output(command);
        self.assert_redacted(&output);
        assert!(output.status.success(), "{}", describe(&output));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Runs a command that must fail without showing any delivered value.
    fn fails(&self, command: &mut Command) -> Output {
        let output = self.output(command);
        self.assert_redacted(&output);
        assert!(!output.status.success(), "{}", describe(&output));
        output
    }

    /// Runs a command that was asked to show a value; the invariant does not apply.
    fn reveal(&self, command: &mut Command) -> String {
        let output = self.output(command);
        assert!(output.status.success(), "{}", describe(&output));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The redaction invariant.
    fn assert_redacted(&self, output: &Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for value in self.delivered.lock().expect("lock").iter() {
            assert!(
                !stdout.contains(value.as_str()) && !stderr.contains(value.as_str()),
                "a delivered value leaked into veil's output\n{}",
                describe(output)
            );
        }
    }
}

fn describe(output: &Output) -> String {
    format!(
        "status {:?}\n--- stdout\n{}\n--- stderr\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const MARKER: &str = "[redacted]";

/// Writes an executable script.
fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

/// A project with `.env` imported into Vault `api`.
fn project(world: &World, name: &str, env: &[(&str, &str)]) -> PathBuf {
    let dir = world.dir(name);
    let mut text = String::new();
    for (key, value) in env {
        world
            .delivered
            .lock()
            .expect("lock")
            .push((*value).to_owned());
        text.push_str(&format!("{key}={value}\n"));
    }
    std::fs::write(dir.join(".env"), text).expect(".env");
    world.ok(world.veil("owner", &dir).args(["init", "--vault", "api"]));
    std::fs::remove_file(dir.join(".env")).expect("remove .env");
    dir
}

// ---- The table and the suite stay in step ---------------------------------------------------

fn test_name(row: &str) -> String {
    row.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

#[test]
fn every_scenario_row_has_a_test() {
    let usage =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/usage.md"))
            .expect("usage.md");
    let table = usage
        .split("## Scenarios")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("a Scenarios section");
    let source = include_str!("scenarios.rs");
    let mut missing = Vec::new();
    for row in table.lines().filter(|line| line.starts_with("| ")).skip(1) {
        let situation = row
            .trim_start_matches("| ")
            .split(" |")
            .next()
            .expect("cell");
        if situation.starts_with("---") || ELSEWHERE.iter().any(|(name, _)| *name == situation) {
            continue;
        }
        let name = test_name(situation);
        if !source.contains(&format!("fn {name}()")) {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "usage.md scenario rows without a test: {missing:?}"
    );
}

// ---- Scenarios ------------------------------------------------------------------------------

#[test]
fn run_tests_or_a_service() {
    let world = World::new("run");
    let dir = project(
        &world,
        "app",
        &[("DATABASE_URL", "postgres://scenario/run")],
    );
    let out = world.ok(world.veil("owner", &dir).args([
        "run",
        "--",
        "sh",
        "-c",
        r#"[ "$DATABASE_URL" = postgres://scenario/run ] && echo delivered; echo "url=$DATABASE_URL""#,
    ]));
    assert!(out.contains("delivered"), "{out}");
    assert!(out.contains(&format!("url={MARKER}")), "{out}");

    // --no-redact turns it off; the invariant does not apply to that run.
    let out = world.reveal(world.veil("owner", &dir).args([
        "run",
        "--no-redact",
        "--",
        "sh",
        "-c",
        "echo $DATABASE_URL",
    ]));
    assert_eq!(out.trim(), "postgres://scenario/run");
}

#[test]
fn an_app_that_reads_files() {
    let world = World::new("mount");
    let dir = project(&world, "app", &[("APP_KEY", "base64:scenario-mount")]);
    let out = world.ok(world.veil("owner", &dir).args([
        "run",
        "--mount",
        ".env",
        "--",
        "sh",
        "-c",
        "grep -qx 'APP_KEY=base64:scenario-mount' .env && echo read",
    ]));
    assert!(out.contains("read"), "{out}");
    assert!(!dir.join(".env").exists(), "the pipe is removed on exit");
}

#[test]
fn a_key_read_a_fixed_number_of_times() {
    let world = World::new("reads");
    let dir = project(&world, "app", &[("TOKEN", "unused-scenario-token")]);
    world.store(
        "veil://api/deploy-key/private_key",
        "-----BEGIN KEY----- scenario",
    );
    let out = world.ok(world.veil("owner", &dir).args([
        "run",
        "--only",
        "veil://api/deploy-key/private_key",
        "--mount",
        "key",
        "--mount-max-reads",
        "2",
        "--",
        "sh",
        "-c",
        "a=$(cat key); b=$(cat key); [ \"$a\" = \"$b\" ] && echo twice; [ -e key ] || echo gone",
    ]));
    assert!(out.contains("twice"), "{out}");
    assert!(out.contains("gone"), "{out}");
}

#[test]
fn any_config_format() {
    let world = World::new("config");
    let dir = project(&world, "app", &[("DB_PASSWORD", "scenario-db-password")]);
    std::fs::write(
        dir.join("nginx.tpl"),
        "auth_basic_user_file {{ veil://api/DB_PASSWORD/password }};\n",
    )
    .expect("template");
    world.ok(world
        .veil("owner", &dir)
        .args(["inject", "nginx.tpl", "--out", "nginx.conf"]));
    let rendered = std::fs::read_to_string(dir.join("nginx.conf")).expect("rendered");
    assert_eq!(rendered, "auth_basic_user_file scenario-db-password;\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("nginx.conf"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_manifest_in_git() {
    let world = World::new("manifest");
    let dir = project(&world, "app", &[("POSTGRES", "scenario-postgres")]);
    std::fs::write(
        dir.join("deployment.yaml"),
        "password: {{ veil://api/POSTGRES/password }}\n",
    )
    .expect("manifest");
    let rendered = world.reveal(
        world
            .veil("owner", &dir)
            .args(["inject", "deployment.yaml"]),
    );
    assert_eq!(rendered, "password: scenario-postgres\n");
}

#[test]
fn shell_variables() {
    let world = World::new("export");
    let dir = project(&world, "app", &[("TOKEN", "scenario-hidden-token")]);
    world.ok(world.veil("owner", &dir).args([
        "set",
        "veil://api/site/uri",
        "--value",
        "https://scenario.example",
    ]));
    let mut declaration = std::fs::read_to_string(dir.join("veil.toml")).expect("toml");
    declaration.push_str("PUBLIC_URL = \"veil://api/site/uri\"\n");
    std::fs::write(dir.join("veil.toml"), declaration).expect("toml");

    let output = world.output(
        world
            .veil("owner", &dir)
            .args(["export", "--format", "shell"]),
    );
    assert!(output.status.success(), "{}", describe(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("export PUBLIC_URL='https://scenario.example'"),
        "{stdout}"
    );
    // Hidden fields are never exported, and the hidden value appears nowhere.
    world.assert_redacted(&output);
    assert!(!stdout.contains("TOKEN"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("TOKEN"),
        "the skipped name is reported"
    );
}

#[test]
fn one_value_once() {
    let world = World::new("copy");
    let dir = project(&world, "app", &[("POSTGRES", "scenario-copy-value")]);
    let clipboard = world.root.join("clipboard");
    world.ok(world
        .veil("owner", &dir)
        .env(
            "VEIL_CLIPBOARD_COMMAND",
            format!("cat > {}", clipboard.display()),
        )
        .args(["get", "veil://api/POSTGRES/password", "--copy", "--yes"]));
    assert_eq!(
        std::fs::read_to_string(&clipboard).expect("clipboard"),
        "scenario-copy-value"
    );
}

#[test]
fn ide_or_debugger() {
    let world = World::new("ide");
    let dir = project(&world, "app", &[("API_KEY", "scenario-ide-key")]);
    let launch: Value = json!({
        "program": "veil",
        "args": ["run", "--", "sh", "-c", "[ \"$API_KEY\" = scenario-ide-key ] && echo attached"],
    });
    let args: Vec<String> = launch["args"]
        .as_array()
        .expect("args")
        .iter()
        .map(|arg| arg.as_str().expect("arg").to_owned())
        .collect();
    let out = world.ok(world.veil("owner", &dir).args(&args));
    assert!(out.contains("attached"), "{out}");
}

#[test]
fn containers() {
    let world = World::new("containers");
    let dir = project(&world, "app", &[("REDIS_PASSWORD", "scenario-redis")]);
    let bin = world.dir("bin");
    script(
        &bin.join("docker"),
        r#"[ "$1 $2" = "compose up" ] && [ "$REDIS_PASSWORD" = scenario-redis ] && echo "compose saw $REDIS_PASSWORD""#,
    );
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = world.ok(world
        .veil("owner", &dir)
        .env("PATH", path)
        .args(["run", "--", "docker", "compose", "up"]));
    assert!(out.contains(&format!("compose saw {MARKER}")), "{out}");
}

#[test]
fn a_shared_token() {
    let world = World::new("shared");
    world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "create", "example"]));
    world.store(
        "veil://example/demo-service/password",
        "demo-scenario:SHARED",
    );
    let services = ["notify", "backup"];
    for service in services {
        let dir = world.dir(service);
        std::fs::write(
            dir.join("veil.toml"),
            "[env]\nDEMO_TOKEN = \"veil://example/demo-service/password\"\n",
        )
        .expect("toml");
        let out = world.ok(world.veil("owner", &dir).args([
            "run",
            "--",
            "sh",
            "-c",
            "[ \"$DEMO_TOKEN\" = demo-scenario:SHARED ] && echo ok",
        ]));
        assert!(out.contains("ok"), "{service}: {out}");
    }

    // Rotate once; every service gets the new value on its next start.
    world.store(
        "veil://example/demo-service/password",
        "demo-scenario:ROTATED",
    );
    for service in services {
        let out = world.ok(world.veil("owner", &world.dir(service)).args([
            "run",
            "--",
            "sh",
            "-c",
            "[ \"$DEMO_TOKEN\" = demo-scenario:ROTATED ] && echo ok",
        ]));
        assert!(out.contains("ok"), "{service}: {out}");
    }

    // And the audit names every delivery of that one Item.
    let audit = world.ok(world.veil("owner", &world.dir("owner")).args([
        "audit",
        "--item",
        "veil://example/demo-service/password",
        "--json",
    ]));
    let events: Value = serde_json::from_str(&audit).expect("json");
    assert_eq!(events.as_array().expect("events").len(), 4, "{audit}");
}

#[test]
fn ci_with_oidc() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rsa::traits::PublicKeyParts;

    let world = World::new("oidc");
    let dir = project(&world, "repo", &[("DEPLOY_TOKEN", "scenario-ci-token")]);

    let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa key");
    let encoding = EncodingKey::from_rsa_der(
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
            .expect("der")
            .as_bytes(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let issuer = format!("http://{}", listener.local_addr().expect("addr"));
    let jwks = json!({ "keys": [{
        "kty": "RSA", "kid": "ci", "alg": "RS256", "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    }]});
    let served = issuer.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let body = if String::from_utf8_lossy(&buffer).starts_with("GET /.well-known") {
                format!(r#"{{"issuer":"{served}","jwks_uri":"{served}/jwks"}}"#)
            } else {
                jwks.to_string()
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });

    let created = world.ok(world.veil("owner", &dir).args([
        "workload",
        "add",
        "--name",
        "ci",
        "--issuer",
        &issuer,
        "--audience",
        "veil",
        "--claim",
        "project_id=42",
        "--claim",
        "ref=main",
        "--json",
    ]));
    let created: Value = serde_json::from_str(&created).expect("json");
    let claims = json!({
        "iss": issuer, "aud": "veil", "project_id": "42", "ref": "main",
        "exp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs() + 600,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ci".to_owned());
    let jwt = jsonwebtoken::encode(&header, &claims, &encoding).expect("jwt");

    // The CI job has no local state: only the server, the workload, its key, and the token.
    let job = world.dir("job");
    std::fs::copy(dir.join("veil.toml"), job.join("veil.toml")).expect("toml");
    let out = world.ok(world
        .veil("ci-runner", &job)
        .env("VEIL_WORKLOAD", created["workload"].as_str().expect("id"))
        .env("VEIL_WORKLOAD_KEY", created["key"].as_str().expect("key"))
        .env("VEIL_ID_TOKEN", jwt)
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "[ \"$DEPLOY_TOKEN\" = scenario-ci-token ] && echo deployed; echo $DEPLOY_TOKEN",
        ]));
    assert!(out.contains("deployed"), "{out}");
    assert!(out.contains(MARKER), "{out}");
}

#[test]
fn ci_without_oidc() {
    let world = World::new("device-ci");
    let dir = project(&world, "repo", &[("DEPLOY_TOKEN", "scenario-runner-token")]);
    let runner = world.dir("runner");
    std::fs::copy(dir.join("veil.toml"), runner.join("veil.toml")).expect("toml");
    enroll(&world, "runner", &runner, &dir, "135790");
    let out = world.ok(world.veil("runner", &runner).args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$DEPLOY_TOKEN\" = scenario-runner-token ] && echo deployed",
    ]));
    assert!(out.contains("deployed"), "{out}");
}

/// Enrolls `machine` with a code, approved by the owner from `approver_dir`.
fn enroll(world: &World, machine: &str, dir: &Path, approver_dir: &Path, code: &str) {
    let mut add = world
        .veil(machine, dir)
        .args(["device", "add", "--name", machine, "--code", code])
        .env("VEIL_ENROLL_ATTEMPTS", "30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("device add");
    std::thread::sleep(std::time::Duration::from_millis(1500));
    world.ok(world
        .veil("owner", approver_dir)
        .args(["device", "approve", code]));
    assert!(add.wait().expect("wait").success());
}

#[test]
fn systemd_or_a_single_host() {
    let world = World::new("systemd");
    let dir = project(
        &world,
        "srv",
        &[("SERVICE_TOKEN", "scenario-systemd-token")],
    );
    let host = world.dir("host");
    std::fs::copy(dir.join("veil.toml"), host.join("veil.toml")).expect("toml");
    enroll(&world, "host", &host, &dir, "246801");

    // ExecStart runs with no password and no terminal; the key sits in a 0600 file.
    let out = world.ok(world.veil("host", &host).env_remove("VEIL_PASSWORD").args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$SERVICE_TOKEN\" = scenario-systemd-token ] && echo started",
    ]));
    assert!(out.contains("started"), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keys = world.root.join("machines/host/keys.json");
        let mode = std::fs::metadata(&keys)
            .expect("key file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{}", keys.display());
    }
}

#[test]
fn kubernetes_with_flux() {
    let world = World::new("sops");
    world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "create", "example"]));
    world.store(
        "veil://example/example_app-oidc/client_secret",
        "scenario-example_app-oidc-secret",
    );
    world.store("veil://example/sso/secret", "scenario-auth-secret");

    // An age key pair stands in for the cluster's; only the public key is used to encrypt.
    let repo = world.dir("infra");
    let keygen = Command::new("age-keygen")
        .arg("-o")
        .arg(repo.join("cluster.agekey"))
        .output()
        .expect("age-keygen runs");
    assert!(keygen.status.success(), "{}", describe(&keygen));
    let recipient = String::from_utf8_lossy(&keygen.stderr)
        .split_whitespace()
        .last()
        .expect("public key")
        .to_owned();
    std::fs::write(
        repo.join(".sops.yaml"),
        format!("creation_rules:\n  - path_regex: \\.sops\\.yaml$\n    age: {recipient}\n"),
    )
    .expect(".sops.yaml");
    std::fs::create_dir_all(repo.join("sso")).expect("dir");
    std::fs::create_dir_all(repo.join("example_app")).expect("dir");
    std::fs::write(
        repo.join("sso/environment.tpl"),
        "DEMO_AUTH_SECRET: {{ veil://example/sso/secret }}\nEXAMPLE_APP_CLIENT_SECRET: {{ veil://example/example_app-oidc/client_secret }}\n",
    )
    .expect("tpl");
    std::fs::write(
        repo.join("example_app/oidc.tpl"),
        "GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: {{ veil://example/example_app-oidc/client_secret }}\n",
    )
    .expect("tpl");

    // The one stored secret renders into both the SSO's and Example app's SOPS files.
    for (template, out) in [
        ("sso/environment.tpl", "sso/environment.sops.yaml"),
        ("example_app/oidc.tpl", "example_app/oidc.sops.yaml"),
    ] {
        world.ok(world
            .veil("owner", &repo)
            .args(["inject", template, "--sops", "--out", out]));
        let sealed = std::fs::read_to_string(repo.join(out)).expect("sops file");
        assert!(sealed.contains("sops:"), "{sealed}");
        assert!(!sealed.contains("scenario-example_app-oidc-secret"));
        let opened = Command::new("sops")
            .args(["-d", out])
            .current_dir(&repo)
            .env("SOPS_AGE_KEY_FILE", repo.join("cluster.agekey"))
            .output()
            .expect("sops runs");
        assert!(opened.status.success(), "{}", describe(&opened));
        assert!(
            String::from_utf8_lossy(&opened.stdout).contains("scenario-example_app-oidc-secret"),
            "{}",
            describe(&opened)
        );
    }
}

#[test]
fn an_agent_running_project_scripts() {
    let world = World::new("agent-scripts");
    let dir = project(&world, "app", &[("OPENAI_KEY", "sk-scenario-agent")]);
    // The project's own script uses veil; an agent only runs `npm test` and reads its output.
    script(
        &dir.join("test.sh"),
        "veil run -- sh -c 'echo \"calling the API with $OPENAI_KEY\"; [ -n \"$OPENAI_KEY\" ] && echo pass'",
    );
    let veil_dir = cargo_bin("veil").parent().expect("bin dir").to_path_buf();
    let agent = Command::new("sh")
        .arg("test.sh")
        .current_dir(&dir)
        .env(
            "PATH",
            format!(
                "{}:{}",
                veil_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("VEIL_HOME", world.root.join("machines/owner"))
        .env("VEIL_KEYSTORE", "file")
        .env("VEIL_PRESENCE", "unavailable")
        .env("VEIL_SERVER", &world.server.url)
        .env("VEIL_LOG", "error")
        .stdin(Stdio::null())
        .output()
        .expect("agent runs");
    world.assert_redacted(&agent);
    let seen = String::from_utf8_lossy(&agent.stdout);
    assert!(seen.contains("pass"), "{}", describe(&agent));
    assert!(seen.contains(MARKER), "{seen}");
}

/// A JSON-RPC session with `veil mcp` over stdio.
struct Mcp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Mcp {
    fn start(world: &World, dir: &Path, args: &[&str]) -> Self {
        let mut child = world
            .veil("owner", dir)
            .arg("mcp")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("veil mcp");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut session = Self {
            child,
            input,
            output,
            next: 1,
        };
        let init = session.call(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "scenario", "version": "1" } }),
        );
        assert!(
            init["result"]["capabilities"]["tools"].is_object(),
            "{init}"
        );
        session.notify("notifications/initialized");
        session
    }

    fn notify(&mut self, method: &str) {
        writeln!(
            self.input,
            "{}",
            json!({ "jsonrpc": "2.0", "method": method })
        )
        .expect("write");
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        writeln!(
            self.input,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )
        .expect("write");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("read");
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON-RPC: {line:?}"))
    }

    fn tools(&mut self) -> Vec<String> {
        self.call("tools/list", json!({}))["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .map(|tool| tool["name"].as_str().expect("name").to_owned())
            .collect()
    }

    fn finish(mut self) -> String {
        drop(self.input);
        let _ = self.child.wait();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        stderr
    }
}

#[test]
fn an_agent_running_its_own_commands() {
    let world = World::new("mcp");
    world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "create", "example"]));
    world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "create", "admin"]));
    world.store("veil://example/demo-service/password", "demo-scenario:MCP");
    world.store("veil://admin/root/password", "scenario-root-password");
    let dir = world.dir("agent");

    let mut mcp = Mcp::start(&world, &dir, &["--allow", "veil://example/*"]);
    assert_eq!(mcp.tools(), vec!["veil_list", "veil_exec"]);

    let listed = mcp.call(
        "tools/call",
        json!({ "name": "veil_list", "arguments": {} }),
    );
    let listed = listed["result"]["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    assert!(
        listed.contains("veil://example/demo-service/password"),
        "{listed}"
    );
    assert!(!listed.contains("admin"), "outside the scope: {listed}");

    let ran = mcp.call(
        "tools/call",
        json!({ "name": "veil_exec", "arguments": {
            "command": ["sh", "-c", "[ \"$DEMO_TOKEN\" = demo-scenario:MCP ] && echo sent; echo token=$DEMO_TOKEN"],
            "env": { "DEMO_TOKEN": "veil://example/demo-service/password" },
        }}),
    );
    let text = ran.to_string();
    assert!(text.contains("sent"), "{text}");
    assert!(text.contains(MARKER), "{text}");
    assert!(
        !text.contains("demo-scenario:MCP"),
        "the token reached the agent: {text}"
    );

    let refused = mcp.call(
        "tools/call",
        json!({ "name": "veil_exec", "arguments": {
            "command": ["sh", "-c", "echo $ROOT"],
            "env": { "ROOT": "veil://admin/root/password" },
        }}),
    );
    assert_eq!(refused["result"]["isError"], json!(true), "{refused}");
    assert!(!refused.to_string().contains("scenario-root-password"));
    let stderr = mcp.finish();
    assert!(!stderr.contains("demo-scenario:MCP") && !stderr.contains("scenario-root-password"));

    // --allow-reveal adds a tool that returns values; the agent asked for exactly that.
    let mut mcp = Mcp::start(
        &world,
        &dir,
        &["--allow", "veil://example/*", "--allow-reveal"],
    );
    assert_eq!(mcp.tools(), vec!["veil_list", "veil_exec", "veil_reveal"]);
    let revealed = mcp.call(
        "tools/call",
        json!({ "name": "veil_reveal", "arguments": { "reference": "veil://example/demo-service/password" } }),
    );
    assert!(
        revealed.to_string().contains("demo-scenario:MCP"),
        "{revealed}"
    );
    mcp.finish();
}

#[test]
fn a_vault_an_agent_must_not_use_alone() {
    let world = World::new("presence");
    world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "create", "admin"]));
    world.store("veil://admin/root/password", "scenario-presence-root");
    world.ok(world.veil("owner", &world.dir("owner")).args([
        "vault",
        "policy",
        "admin",
        "--approval",
        "presence",
    ]));
    let listed = world.ok(world
        .veil("owner", &world.dir("owner"))
        .args(["vault", "list"]));
    assert!(listed.contains("admin\tpresence"), "{listed}");

    // No human at the machine: nothing is delivered, and the exit code says so.
    let refused = world.fails(world.veil("owner", &world.dir("owner")).args([
        "run",
        "--only",
        "veil://admin/root/password",
        "--",
        "sh",
        "-c",
        "echo should-not-run",
    ]));
    assert_eq!(refused.status.code(), Some(4), "{}", describe(&refused));
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("should-not-run"));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("Touch ID"),
        "{}",
        describe(&refused)
    );
    let refused = world.fails(world.veil("owner", &world.dir("owner")).args([
        "get",
        "veil://admin/root/password",
        "--yes",
    ]));
    assert_eq!(refused.status.code(), Some(4));

    // A `get` that could not print anyway refuses before asking for Touch ID.
    let refused = world.fails(
        world
            .veil("owner", &world.dir("owner"))
            .args(["get", "veil://admin/root/password"]),
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("get --yes"), "{}", describe(&refused));
    assert!(!stderr.contains("Touch ID"), "{}", describe(&refused));
}

#[test]
fn a_second_machine() {
    let world = World::new("second");
    let dir = project(&world, "app", &[("TOKEN", "scenario-second-machine")]);
    let laptop = world.dir("laptop");
    std::fs::copy(dir.join("veil.toml"), laptop.join("veil.toml")).expect("toml");
    enroll(&world, "laptop", &laptop, &dir, "112233");
    let out = world.ok(world.veil("laptop", &laptop).args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$TOKEN\" = scenario-second-machine ] && echo same",
    ]));
    assert!(out.contains("same"), "{out}");
}

#[test]
fn a_lost_machine() {
    let world = World::new("lost");
    let dir = project(&world, "app", &[("TOKEN", "scenario-lost-before")]);
    let old = world.dir("old-xps");
    std::fs::copy(dir.join("veil.toml"), old.join("veil.toml")).expect("toml");
    enroll(&world, "old-xps", &old, &dir, "445566");
    world.ok(world.veil("old-xps", &old).args(["run", "--", "true"]));

    world.ok(world.veil("owner", &dir).args(["device", "rm", "old-xps"]));
    // Refused at once.
    world.fails(world.veil("old-xps", &old).args(["run", "--", "true"]));
    // The next write rotates the Vault key; the owner still reads everything.
    world.store("veil://api/TOKEN/password", "scenario-lost-after");
    let out = world.ok(world.veil("owner", &dir).args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$TOKEN\" = scenario-lost-after ] && echo rotated",
    ]));
    assert!(out.contains("rotated"), "{out}");
    let vaults = world.ok(world.veil("owner", &dir).args(["vault", "list", "--json"]));
    let vaults: Value = serde_json::from_str(&vaults).expect("json");
    let api = vaults["vaults"]
        .as_array()
        .expect("vaults")
        .iter()
        .find(|vault| vault["name"] == "api")
        .expect("api");
    assert_eq!(api["key_generation"], 2, "{vaults}");
}

#[test]
fn a_lost_password() {
    let world = World::new("password");
    let created = {
        // A second account on the same service, so the recovery code is known to the test.
        let output = world.output(
            world
                .veil("recoverable", &world.dir("recoverable"))
                .env("VEIL_EMAIL", "lost@example.com")
                .args(["login", "--create", "--json"]),
        );
        assert!(output.status.success(), "{}", describe(&output));
        serde_json::from_slice::<Value>(&output.stdout).expect("json")
    };
    let code = created["recovery_code"].as_str().expect("code").to_owned();
    let dir = world.dir("recoverable");
    world
        .delivered
        .lock()
        .expect("lock")
        .push("scenario-recovered".to_owned());
    world.ok(world
        .veil("recoverable", &dir)
        .env("VEIL_EMAIL", "lost@example.com")
        .args(["vault", "create", "api"]));
    world.ok(world
        .veil("recoverable", &dir)
        .env("VEIL_EMAIL", "lost@example.com")
        .args([
            "set",
            "veil://api/TOKEN/password",
            "--value",
            "scenario-recovered",
        ]));

    let fresh = world.dir("fresh");
    std::fs::write(
        fresh.join("veil.toml"),
        "[env]\nTOKEN = \"veil://api/TOKEN/password\"\n",
    )
    .expect("toml");
    world.ok(world
        .veil("fresh", &fresh)
        .env("VEIL_EMAIL", "lost@example.com")
        .env("VEIL_RECOVERY_CODE", &code)
        .env("VEIL_PASSWORD", "a-new-password")
        .args(["recover"]));
    let out = world.ok(world.veil("fresh", &fresh).args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$TOKEN\" = scenario-recovered ] && echo back",
    ]));
    assert!(out.contains("back"), "{out}");
}

#[test]
fn offline() {
    let mut world = World::new("offline");
    let dir = project(&world, "app", &[("TOKEN", "scenario-offline")]);
    world.ok(world.veil("owner", &dir).args(["run", "--", "true"]));

    // The service goes away; a fresh cache still delivers, and says it is stale.
    let _ = world.server.child.kill();
    let _ = world.server.child.wait();
    world.server.url = "http://127.0.0.1:9".to_owned();
    let output = world.output(world.veil("owner", &dir).args([
        "run",
        "--",
        "sh",
        "-c",
        "[ \"$TOKEN\" = scenario-offline ] && echo cached",
    ]));
    world.assert_redacted(&output);
    assert!(output.status.success(), "{}", describe(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("cached"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cached copy"));
}

/// Not a table row: the terminal half of "redacted by default". `veil` runs on a
/// pseudo-terminal, so it gives the child one too and relays its output through the redactor.
#[test]
fn redaction_on_a_terminal() {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};

    let world = World::new("tty");
    let dir = project(&world, "app", &[("TTY_TOKEN", "scenario-tty-token")]);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("pty");
    let probe = world.veil("owner", &dir);
    let mut builder = CommandBuilder::new(cargo_bin("veil"));
    builder.args([
        "run",
        "--",
        "sh",
        "-c",
        "[ -t 1 ] && echo child-has-a-terminal; echo token=$TTY_TOKEN",
    ]);
    builder.cwd(&dir);
    builder.env_clear();
    for (key, value) in probe.get_envs() {
        if let Some(value) = value {
            builder.env(key, value);
        }
    }
    let mut child = pair.slave.spawn_command(builder).expect("veil on a pty");
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().expect("reader");
    let collected = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = reader.read_to_end(&mut out);
        out
    });
    let status = child.wait().expect("wait");
    drop(pair.master);
    let out = String::from_utf8_lossy(&collected.join().expect("reader thread")).into_owned();
    assert!(status.success(), "{out}");
    assert!(out.contains("child-has-a-terminal"), "{out}");
    assert!(out.contains(&format!("token={MARKER}")), "{out}");
    assert!(!out.contains("scenario-tty-token"), "{out}");
}

//! The acceptance loop: a real `veild`, a real `veil`, a sealed environment.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Once,
};

use assert_cmd::cargo::cargo_bin;
use serde_json::Value;

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

/// Builds the daemon binary once, so the test works even when only the CLI's tests are run.
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

fn start_server(home: &Path) -> Server {
    let db = home.join("veil.db");
    let mut child = Command::new(veild())
        .env("VEIL_BIND", "127.0.0.1:0")
        .env("VEIL_DB", &db)
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
            let addr = value["fields"]["addr"].as_str().expect("addr");
            break format!("http://{addr}");
        }
    };
    std::thread::spawn(move || for _ in lines {});
    Server { child, url }
}

fn veil(home: &Path, server: &str, dir: &Path) -> Command {
    let mut command = Command::new(cargo_bin("veil"));
    command
        .current_dir(dir)
        .env("VEIL_HOME", home)
        .env("VEIL_KEYSTORE", "file")
        .env("VEIL_SERVER", server)
        .env("VEIL_EMAIL", "me@example.com")
        .env("VEIL_PASSWORD", "correct-horse")
        .env("VEIL_LOG", "error");
    command
}

fn run(command: &mut Command) -> String {
    let output = command.output().expect("command runs");
    assert!(
        output.status.success(),
        "command failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn tempdir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("veil-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn a_project_is_created_filled_and_delivered() {
    let home = tempdir("home");
    let project = tempdir("project");
    let server = start_server(&home);

    run(veil(&home, &server.url, &project).args(["login", "--create"]));
    std::fs::write(project.join(".env"), "DATABASE_URL=postgres://local\n").expect("env");

    let init = run(veil(&home, &server.url, &project).args(["init", "--vault", "api", "--json"]));
    assert_eq!(serde_json::from_str::<Value>(&init).unwrap()["items"], 1);

    let listed = run(veil(&home, &server.url, &project).arg("list"));
    assert!(
        listed.contains("DATABASE_URL\tveil://api/DATABASE_URL/password\tok"),
        "{listed}"
    );
    assert!(
        !listed.contains("postgres://local"),
        "list never prints values"
    );

    let delivered = run(veil(&home, &server.url, &project).args([
        "run",
        "--no-redact",
        "--",
        "sh",
        "-c",
        "echo $DATABASE_URL",
    ]));
    assert_eq!(delivered.trim(), "postgres://local");

    run(veil(&home, &server.url, &project).args(["set", "NEW_KEY", "--value", "hello"]));
    let delivered = run(veil(&home, &server.url, &project).args([
        "run",
        "--no-redact",
        "--",
        "sh",
        "-c",
        "echo $NEW_KEY",
    ]));
    assert_eq!(delivered.trim(), "hello");

    // A field of another Item, in another Vault, by reference.
    run(veil(&home, &server.url, &project).args([
        "set",
        "veil://api/example_app/client_secret",
        "--value",
        "oidc-s3cret",
    ]));
    let items = run(veil(&home, &server.url, &project).args(["list", "api"]));
    assert!(items.contains("example_app\tclient_secret"), "{items}");
    let revealed = run(veil(&home, &server.url, &project).args([
        "get",
        "veil://api/example_app/client_secret",
        "--yes",
    ]));
    assert_eq!(revealed.trim(), "oidc-s3cret");

    let mounted = run(veil(&home, &server.url, &project).args([
        "run",
        "--no-redact",
        "--mount",
        "app.env",
        "--",
        "sh",
        "-c",
        "cat app.env",
    ]));
    assert!(
        mounted.contains("DATABASE_URL=postgres://local"),
        "{mounted}"
    );
    assert!(mounted.contains("NEW_KEY=hello"), "{mounted}");
    assert!(!project.join("app.env").exists(), "the pipe is removed");

    std::fs::write(
        project.join("app.tpl"),
        "url={{ veil://api/DATABASE_URL/password }}\n",
    )
    .expect("template");
    let rendered = run(veil(&home, &server.url, &project).args(["inject", "app.tpl"]));
    assert_eq!(rendered, "url=postgres://local\n");

    let declaration = std::fs::read_to_string(project.join("veil.toml")).expect("veil.toml");
    assert!(
        declaration.contains("NEW_KEY = \"veil://api/NEW_KEY/password\""),
        "{declaration}"
    );

    let ignored = std::fs::read_to_string(project.join(".gitignore")).expect("gitignore");
    assert!(ignored.lines().any(|line| line == ".env"), "{ignored}");

    let audit = run(veil(&home, &server.url, &project).args(["audit", "--limit", "100"]));
    assert!(audit.contains("api/DATABASE_URL"), "{audit}");
    assert!(audit.contains("Mount"), "{audit}");
    assert!(audit.contains("Render"), "{audit}");
}

#[test]
fn a_second_machine_enrolls_by_approval_and_reads_only_its_vaults() {
    let home = tempdir("home-device");
    let first = tempdir("first");
    let second = tempdir("second");
    let server = start_server(&home);

    run(veil(&home, &server.url, &first).args(["login", "--create"]));
    std::fs::write(first.join(".env"), "TOKEN=abc\n").expect("env");
    run(veil(&home, &server.url, &first).args(["init", "--vault", "example"]));
    run(veil(&home, &server.url, &first).args(["vault", "create", "private"]));
    run(veil(&home, &server.url, &first).args([
        "set",
        "veil://private/bank/password",
        "--value",
        "never-on-the-host",
    ]));

    let other_home = home.join("other");
    let mut add = veil(&other_home, &server.url, &second)
        .args([
            "device",
            "add",
            "--server",
            &server.url,
            "--email",
            "me@example.com",
            "--code",
            "424242",
        ])
        .env("VEIL_ENROLL_ATTEMPTS", "30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("device add starts");

    // Give the pending enrollment time to land, then approve from the trusted machine. With no
    // --vault, approval grants the Vaults this directory's veil.toml references.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let approved = veil(&home, &server.url, &first)
        .args(["device", "approve", "424242"])
        .output()
        .expect("approve runs");
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );

    let status = add.wait().expect("device add finishes");
    assert!(status.success());

    std::fs::copy(first.join("veil.toml"), second.join("veil.toml")).expect("copy binding");
    let delivered = run(veil(&other_home, &server.url, &second).args([
        "run",
        "--no-redact",
        "--",
        "sh",
        "-c",
        "echo $TOKEN",
    ]));
    assert_eq!(delivered.trim(), "abc");

    // A Vault without a Grant is invisible, even by reference.
    let denied = veil(&other_home, &server.url, &second)
        .args(["get", "veil://private/bank/password", "--yes"])
        .output()
        .expect("get runs");
    assert!(!denied.status.success());
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("never-on-the-host"));

    // A device reads but cannot write without an owner session.
    let write = veil(&other_home, &server.url, &second)
        .args(["set", "TOKEN", "--value", "nope"])
        .output()
        .expect("set runs");
    assert!(!write.status.success());

    run(veil(&other_home, &server.url, &second).arg("login"));
    let denied = veil(&other_home, &server.url, &second)
        .args(["get", "veil://private/bank/password", "--yes"])
        .output()
        .expect("get runs");
    assert!(
        !denied.status.success(),
        "a management session does not expand delivery"
    );
    run(veil(&other_home, &server.url, &second).args([
        "set",
        "veil://private/bank/password",
        "--value",
        "managed-without-promotion",
    ]));
    let denied = veil(&other_home, &server.url, &second)
        .args(["get", "veil://private/bank/password", "--yes"])
        .output()
        .expect("get runs");
    assert!(
        !denied.status.success(),
        "an Owner management view does not pollute the device cache"
    );

    run(veil(&other_home, &server.url, &second).args(["device", "promote"]));
    let value = run(veil(&other_home, &server.url, &second).args([
        "get",
        "veil://private/bank/password",
        "--yes",
    ]));
    assert_eq!(value.trim(), "managed-without-promotion");
}

#[test]
fn personal_login_uses_global_config_and_survives_expiry_until_revoked() {
    let home = tempdir("home-personal");
    let project = tempdir("project-personal");
    let server = start_server(&home);
    run(veil(&home, &server.url, &project).args(["login", "--create"]));
    run(veil(&home, &server.url, &project).args(["vault", "create", "first"]));
    run(veil(&home, &server.url, &project).args([
        "set",
        "veil://first/token/password",
        "--value",
        "before-login",
    ]));

    let fresh = home.join("personal");
    std::fs::create_dir_all(&fresh).expect("home");
    std::fs::write(
        fresh.join("config.toml"),
        format!(
            "server = {:?}\nemail = \"  ME@EXAMPLE.COM  \"\nkeystore = \"file\"\n",
            server.url,
        ),
    )
    .expect("config");
    let mut command = veil(&fresh, &server.url, &project);
    command
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_EMAIL")
        .env_remove("VEIL_KEYSTORE")
        .env_remove("VEIL_CONFIG")
        .env("VEIL_PASSWORD", "wrong-password")
        .arg("login");
    let output = command.output().expect("login");
    assert!(!output.status.success());
    let pending = std::fs::read_to_string(fresh.join("state.json")).expect("pending state");
    let pending_json: Value = serde_json::from_str(&pending).expect("json");
    assert_eq!(pending_json["pending_registration"], true);

    let mut command = veil(&fresh, &server.url, &project);
    command
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_EMAIL")
        .env_remove("VEIL_KEYSTORE")
        .env_remove("VEIL_CONFIG")
        .arg("login");
    run(&mut command);
    std::fs::write(fresh.join("state.json"), &pending).expect("simulate lost final state save");
    run(&mut command);
    let saved = std::fs::read_to_string(fresh.join("state.json")).expect("state");
    let mut state: Value = serde_json::from_str(&saved).expect("json");
    assert_eq!(state["device_id"], pending_json["device_id"]);
    assert_eq!(state["pending_registration"], false);
    let devices: Value = serde_json::from_str(&run(
        veil(&home, &server.url, &project).args(["--json", "device", "list"])
    ))
    .expect("devices");
    assert_eq!(devices.as_array().expect("devices").len(), 2);

    let external = home.join("login-config.toml");
    std::fs::write(
        &external,
        format!(
            "server = {:?}\nemail = \"me@example.com\"\nkeystore = \"file\"\n",
            server.url,
        ),
    )
    .expect("external config");
    run(veil(&fresh, &server.url, &project)
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_EMAIL")
        .env("VEIL_CONFIG", &external)
        .arg("login"));
    std::fs::write(
        &external,
        "server = \"http://127.0.0.1:1\"\nemail = \"wrong@example.com\"\n",
    )
    .expect("overridden config");
    run(veil(&fresh, &server.url, &project)
        .env("VEIL_CONFIG", &external)
        .arg("login"));
    run(veil(&fresh, &server.url, &project)
        .env("VEIL_CONFIG", &external)
        .env("VEIL_SERVER", "http://127.0.0.1:1")
        .env("VEIL_EMAIL", "wrong@example.com")
        .args([
            "login",
            "--server",
            &server.url,
            "--email",
            "me@example.com",
        ]));

    let value = run(veil(&fresh, &server.url, &project).args([
        "get",
        "veil://first/token/password",
        "--yes",
    ]));
    assert_eq!(value.trim(), "before-login");
    state["session"]["expires_at"] = serde_json::json!(1);
    std::fs::write(fresh.join("state.json"), state.to_string()).expect("expire");
    run(veil(&home, &server.url, &project).args(["vault", "create", "future"]));
    run(veil(&home, &server.url, &project).args([
        "set",
        "veil://future/token/password",
        "--value",
        "after-login",
    ]));
    let value = run(veil(&fresh, &server.url, &project).args([
        "get",
        "veil://future/token/password",
        "--yes",
    ]));
    assert_eq!(value.trim(), "after-login");
    let write = veil(&fresh, &server.url, &project)
        .args(["set", "veil://future/token/password", "--value", "denied"])
        .output()
        .expect("write");
    assert!(!write.status.success());

    let state_before = std::fs::read(fresh.join("state.json")).expect("state");
    let conflict = veil(&fresh, &server.url, &project)
        .args(["login", "--server", "http://127.0.0.1:1"])
        .output()
        .expect("login");
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("separate VEIL_HOME"));
    assert_eq!(
        std::fs::read(fresh.join("state.json")).expect("state"),
        state_before
    );
    std::fs::write(
        fresh.join("config.toml"),
        "server = \"http://127.0.0.1:1\"\nemail = \"other@example.com\"\nkeystore = \"file\"\n",
    )
    .expect("conflicting config");
    let conflict = veil(&fresh, &server.url, &project)
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_EMAIL")
        .arg("login")
        .output()
        .expect("login");
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("separate VEIL_HOME"));
    run(veil(&fresh, &server.url, &project).arg("login"));

    run(veil(&home, &server.url, &project).args([
        "device",
        "remove",
        state["device_id"].as_str().expect("id"),
    ]));
    for args in [
        vec!["get", "veil://future/token/password", "--yes"],
        vec!["set", "veil://future/token/password", "--value", "denied"],
        vec!["login"],
    ] {
        let output = veil(&fresh, &server.url, &project)
            .args(args)
            .output()
            .expect("revoked operation");
        assert!(
            !output.status.success(),
            "revoked device must not use its session or cache"
        );
    }
}

#[test]
fn a_lost_machine_is_recovered_with_its_data() {
    let home = tempdir("home-recover");
    let project = tempdir("project-recover");
    let server = start_server(&home);

    let created = run(veil(&home, &server.url, &project).args(["login", "--create", "--json"]));
    let created: Value = serde_json::from_str(&created).expect("json");
    let code = created["recovery_code"]
        .as_str()
        .expect("recovery code")
        .to_owned();

    std::fs::write(project.join(".env"), "TOKEN=recovered\n").expect("env");
    run(veil(&home, &server.url, &project).arg("init"));

    // A machine that never had a device, using only the recovery code.
    let fresh = home.join("recovered");
    let recovered = run(veil(&fresh, &server.url, &project)
        .args([
            "recover",
            "--json",
            "--server",
            &server.url,
            "--email",
            "me@example.com",
        ])
        .env("VEIL_RECOVERY_CODE", &code)
        .env("VEIL_PASSWORD", "new-correct-horse"));
    assert_eq!(
        serde_json::from_str::<Value>(&recovered).unwrap()["recovered"],
        true
    );

    let delivered = run(veil(&fresh, &server.url, &project)
        .env("VEIL_PASSWORD", "new-correct-horse")
        .args(["run", "--no-redact", "--", "sh", "-c", "echo $TOKEN"]));
    assert_eq!(delivered.trim(), "recovered");

    // The new password signs in; the old one no longer does.
    run(veil(&fresh, &server.url, &project)
        .env("VEIL_PASSWORD", "new-correct-horse")
        .arg("login"));
    let old = veil(&fresh, &server.url, &project)
        .env("VEIL_PASSWORD", "correct-horse")
        .arg("login")
        .output()
        .expect("login runs");
    assert!(!old.status.success());
}

#[test]
fn import_reports_confirmed_writes_when_the_service_fails_mid_batch() {
    use std::io::{Read as _, Write as _};
    let home = tempdir("ux-partial-home");
    let first = tempdir("ux-partial-first");
    let second = tempdir("ux-partial-second");
    let server = start_server(&home);
    run(veil(&home, &server.url, &first).args(["login", "--create", "--json"]));
    std::fs::write(first.join(".env"), "A=old-private-a\nB=old-private-b\n").unwrap();
    run(veil(&home, &server.url, &first).args(["init", "--vault", "api"]));
    std::fs::write(second.join(".env"), "A=new-private-a\nB=new-private-b\n").unwrap();
    let saved = std::fs::read(home.join("state.json")).unwrap();
    let mut state: Value = serde_json::from_slice(&saved).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    state["server"] = format!("http://{}", listener.local_addr().unwrap()).into();
    std::fs::write(home.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    let upstream = server.url.clone();
    let proxy = std::thread::spawn(move || {
        for index in 0..3 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "expected request {index}"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            let request = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>();
            let mut forward = ureq::request(request[0], &format!("{upstream}{}", request[1]))
                .timeout(std::time::Duration::from_secs(5));
            let mut length = 0;
            for line in headers.lines().skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    if name.eq_ignore_ascii_case("authorization")
                        || name.eq_ignore_ascii_case("content-type")
                        || name.eq_ignore_ascii_case("x-veil-protocol")
                    {
                        forward = forward.set(name, value.trim());
                    }
                }
            }
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            let (status, body) = if index == 2 {
                (503, "{}".to_owned())
            } else {
                let response = if body.is_empty() {
                    forward.call()
                } else {
                    forward.send_bytes(&body)
                }
                .unwrap();
                (response.status(), response.into_string().unwrap())
            };
            write!(socket, "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let output = veil(&home, &server.url, &second)
        .args(["init", "--vault", "api", "--yes", "--json"])
        .output()
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("1/2 writes confirmed"), "{stderr}");
    assert!(stderr.contains("No rollback"));
    assert!(!stderr.contains("private-a") && !stderr.contains("private-b"));
    assert!(!second.join("veil.toml").exists());
    assert!(!second.join(".gitignore").exists());
    std::fs::write(home.join("state.json"), saved).unwrap();
    assert_eq!(
        run(veil(&home, &server.url, &first).args(["get", "A", "--yes"])).trim(),
        "new-private-a"
    );
    assert_eq!(
        run(veil(&home, &server.url, &first).args(["get", "B", "--yes"])).trim(),
        "old-private-b"
    );
}

#[test]
fn import_preview_and_refusal_do_not_write_and_overwrite_is_explicit() {
    let home = tempdir("ux-import-home");
    let first = tempdir("ux-import-first");
    let second = tempdir("ux-import-second");
    let server = start_server(&home);
    run(veil(&home, &server.url, &first).args(["login", "--create", "--json"]));
    std::fs::write(first.join(".env"), "TOKEN=original-private-value\n").unwrap();
    run(veil(&home, &server.url, &first).args(["init", "--vault", "api"]));
    std::fs::write(
        second.join(".env"),
        "TOKEN=replacement-private-value\nNEW=new-private-value\n",
    )
    .unwrap();
    let before = std::fs::read(home.join("state.json")).unwrap();
    let preview = veil(&home, &server.url, &second)
        .args(["init", "--vault", "api", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let plan: Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["dry_run"], true);
    assert!(
        plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["name"] == "TOKEN" && change["action"] == "replace")
    );
    assert_eq!(std::fs::read(home.join("state.json")).unwrap(), before);
    assert!(!second.join("veil.toml").exists());
    assert!(!second.join(".gitignore").exists());
    assert!(!String::from_utf8_lossy(&preview.stdout).contains("private-value"));
    assert!(!String::from_utf8_lossy(&preview.stderr).contains("private-value"));
    let refused = veil(&home, &server.url, &second)
        .args(["init", "--vault", "api", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert_eq!(std::fs::read(home.join("state.json")).unwrap(), before);
    assert!(!second.join("veil.toml").exists());
    let original = run(veil(&home, &server.url, &first).args(["get", "TOKEN", "--yes"]));
    assert_eq!(original.trim(), "original-private-value");
    run(veil(&home, &server.url, &first).args([
        "set",
        "veil://api/AUX/password",
        "--value",
        "fixture",
    ]));
    let prior: Value =
        serde_json::from_slice(&std::fs::read(home.join("state.json")).unwrap()).unwrap();
    let result =
        run(veil(&home, &server.url, &second).args(["init", "--vault", "api", "--yes", "--json"]));
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["replaced"], 1);
    assert_eq!(result["items"], 2);
    let committed: Value =
        serde_json::from_slice(&std::fs::read(home.join("state.json")).unwrap()).unwrap();
    assert!(
        committed["sync_revision"].as_u64().unwrap() > prior["sync_revision"].as_u64().unwrap()
    );
    assert!(second.join(".env").exists());
    assert_eq!(
        run(veil(&home, &server.url, &second).args(["get", "TOKEN", "--yes"])).trim(),
        "replacement-private-value"
    );
}

#[test]
fn explicit_value_inputs_preserve_newlines_and_child_exit_status_is_not_reclassified() {
    use std::io::Write as _;
    let home = tempdir("ux-input-home");
    let project = tempdir("ux-input-project");
    let server = start_server(&home);
    run(veil(&home, &server.url, &project).args(["login", "--create", "--json"]));
    std::fs::write(project.join(".env"), "TOKEN=initial-value\n").unwrap();
    run(veil(&home, &server.url, &project).args(["init", "--vault", "api"]));
    let value = "first-private-line\nsecond-private-line\n";
    let mut child = veil(&home, &server.url, &project)
        .args(["set", "TOKEN", "--stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-line"));
    let revealed =
        run(veil(&home, &server.url, &project).args(["get", "TOKEN", "--yes", "--json"]));
    assert_eq!(
        serde_json::from_str::<Value>(&revealed).unwrap()["value"],
        value
    );
    std::fs::write(project.join("value.txt"), "file-private-value\n").unwrap();
    run(veil(&home, &server.url, &project).args(["set", "TOKEN", "--file", "value.txt"]));
    let revealed =
        run(veil(&home, &server.url, &project).args(["get", "TOKEN", "--yes", "--json"]));
    assert_eq!(
        serde_json::from_str::<Value>(&revealed).unwrap()["value"],
        "file-private-value\n"
    );
    let output = veil(&home, &server.url, &project)
        .args([
            "--json",
            "run",
            "--",
            "sh",
            "-c",
            "printf child-output; printf child-error >&2; exit 3",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, b"child-output");
    assert_eq!(output.stderr, b"child-error");
    #[cfg(unix)]
    {
        let output = veil(&home, &server.url, &project)
            .args(["run", "--no-redact", "--", "sh", "-c", "kill -INT $$"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(130));
    }
}

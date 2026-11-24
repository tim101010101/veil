use std::{fs, path::PathBuf, process::Output};

use assert_cmd::Command;
use serde_json::Value;

struct World(PathBuf);

impl World {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("veil-ux-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(dir.join("home")).unwrap();
        Self(dir)
    }

    fn veil(&self) -> Command {
        let mut cmd = Command::cargo_bin("veil").unwrap();
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.0.join("home"))
            .env("VEIL_HOME", self.0.join("home"))
            .env("VEIL_KEYSTORE", "file")
            .env("TERM", "xterm-256color")
            .current_dir(&self.0);
        cmd
    }

    fn config(&self, text: &str) {
        fs::write(self.0.join("home/config.toml"), text).unwrap();
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn upgrade_is_independent_of_vault_config_and_does_not_take_ownership() {
    let world = World::new();
    world.config("not valid TOML = [");
    let out = world
        .veil()
        .args(["upgrade", "--check", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(error(&out)["error"]["code"], "upgrade_failed");
    assert!(!stderr(&out).contains("config.toml"));
    assert!(!world.0.join("home/state.json").exists());
    let out = world
        .veil()
        .args(["upgrade", "--allow-downgrade", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = world
        .veil()
        .args(["upgrade", "--version", "not-a-version", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!stderr(&out).contains("not-a-version"));
}

#[cfg(target_os = "linux")]
#[test]
fn a_managed_cli_without_release_configuration_fails_closed() {
    use veil_cli::update::{self, Receipt};
    let world = World::new();
    let directory = world.0.join("bin/.veil/test-build");
    fs::create_dir_all(&directory).unwrap();
    let executable = directory.join("veil");
    let original = assert_cmd::cargo::cargo_bin("veil");
    fs::copy(original, &executable).unwrap();
    let digest = update::file_digest(&executable).unwrap();
    let receipt = Receipt {
        schema: 1,
        source: update::INSTALLER.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        target: update::platform().unwrap(),
        sha256: digest.clone(),
    };
    fs::write(
        directory.join("install.toml"),
        toml::to_string(&receipt).unwrap(),
    )
    .unwrap();
    let launcher = world.0.join("bin/veil");
    std::os::unix::fs::symlink(&executable, &launcher).unwrap();
    let out = std::process::Command::new(&launcher)
        .env_clear()
        .env("VEIL_HOME", world.0.join("home"))
        .args(["upgrade", "--check", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert_eq!(error(&out)["error"]["code"], "upgrade_failed");
    assert!(update::trust().is_err());
    assert!(stderr(&out).contains("signing is not configured"));
    assert_eq!(fs::canonicalize(&launcher).unwrap(), executable);
    assert_eq!(update::file_digest(&executable).unwrap(), digest);
    assert!(!world.0.join("bin/.veil/upgrade.lock").exists());
}

#[test]
fn project_environment_names_cannot_become_shell_syntax() {
    let world = World::new();
    for name in ["$(touch injected)", "A;echo", "1NAME", "A=B"] {
        fs::write(
            world.0.join("veil.toml"),
            format!("[env]\n\'{name}\' = \'veil://api/item/text\'\n"),
        )
        .unwrap();
        let out = world
            .veil()
            .args(["export", "--format", "shell"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
        assert!(out.stdout.is_empty());
        assert!(stderr(&out).contains("project_invalid"));
        assert!(!stderr(&out).contains(name));
    }
    fs::remove_file(world.0.join("veil.toml")).unwrap();
    let out = world
        .veil()
        .args([
            "set",
            "$(touch injected)",
            "--value",
            "secret-value",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error(&out)["error"]["code"], "variable_name_invalid");
    assert!(!stderr(&out).contains("secret-value"));
    assert!(out.stdout.is_empty());
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
fn error(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).expect("one JSON error")
}

#[test]
fn errors_do_not_depend_on_logging_and_pipes_have_no_ansi() {
    let world = World::new();
    for log in ["off", "error", "veil=trace"] {
        let out = world
            .veil()
            .env("VEIL_LOG", log)
            .arg("list")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
        assert!(out.stdout.is_empty());
        assert!(stderr(&out).contains("not_signed_in"));
        assert!(stderr(&out).contains("veil login"));
        assert!(!stderr(&out).contains('\x1b'));
    }
}

#[test]
fn json_errors_cover_usage_settings_and_commands_without_echoing_values() {
    let world = World::new();
    let secret = "secret-must-not-appear";
    let out = world
        .veil()
        .args(["set", "KEY", "--value", secret, "--stdin", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(error(&out)["error"]["code"], "usage");
    assert!(!stderr(&out).contains(secret));
    world.config(&format!("server = [\"{secret}\"]\n"));
    let out = world.veil().args(["--json", "list"]).output().unwrap();
    assert_eq!(error(&out)["error"]["code"], "config_invalid");
    assert!(!stderr(&out).contains(secret));
    world.config("");
    let out = world.veil().args(["--json", "list"]).output().unwrap();
    assert_eq!(error(&out)["error"]["exit_code"], 3);
    assert!(out.stdout.is_empty());
}

#[test]
fn version_and_doctor_survive_broken_configuration() {
    let world = World::new();
    world.config("sever = 'https://example.invalid'\n");
    fs::write(world.0.join("veil.toml"), "[env\n").unwrap();
    let version = world.veil().args(["version", "--json"]).output().unwrap();
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    let out = world.veil().args(["doctor", "--json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    for name in ["config", "project"] {
        assert!(
            checks
                .iter()
                .any(|check| check["name"] == name && check["status"] == "error")
        );
    }
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "device" && check["status"] == "skipped")
    );
    assert_eq!(error(&out)["error"]["code"], "checks_failed");
    assert!(!world.0.join("home/state.json").exists());
}

#[test]
fn noninteractive_password_input_fails_before_registration() {
    let world = World::new();
    let out = world
        .veil()
        .args([
            "login",
            "--server",
            "http://127.0.0.1:1",
            "--email",
            "ux@example.invalid",
            "--no-input",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(stderr(&out).contains("VEIL_PASSWORD"));
    assert!(!world.0.join("home/state.json").exists());
}

#[test]
fn invalid_imports_fail_before_authentication_or_writes() {
    let world = World::new();
    let secret = "never-print-this-value";
    for text in [
        format!("BROKEN-{secret}"),
        format!("A=ok\nA={secret}\n"),
        format!("A=\"{secret}\n"),
        format!("1BAD={secret}\n"),
    ] {
        fs::write(world.0.join(".env"), text).unwrap();
        let out = world.veil().args(["init", "--json"]).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(error(&out)["error"]["code"], "env_invalid");
        assert!(!stderr(&out).contains(secret));
        assert!(!world.0.join("veil.toml").exists());
        assert!(!world.0.join(".gitignore").exists());
        assert!(!world.0.join("home/state.json").exists());
    }
    fs::remove_file(world.0.join(".env")).unwrap();
    let out = world.veil().args(["init", "--json"]).output().unwrap();
    assert_eq!(error(&out)["error"]["code"], "env_missing");
    fs::create_dir(world.0.join(".env")).unwrap();
    let out = world.veil().arg("init").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Cannot read .env"));
}

#[test]
fn raw_stream_commands_reject_a_misleading_json_contract() {
    let world = World::new();
    for args in [
        vec!["inject", "template"],
        vec!["export"],
        vec!["mcp", "--allow", "veil://api/*"],
    ] {
        let out = world.veil().arg("--json").args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(error(&out)["error"]["code"], "usage");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn run_reports_when_the_child_was_not_started() {
    let world = World::new();
    let out = world
        .veil()
        .args(["--json", "run", "--", "sh", "-c", "touch should-not-exist"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(error(&out)["command_started"], false);
    assert!(!world.0.join("should-not-exist").exists());
}

#[test]
fn help_is_grouped_and_examples_describe_boundaries() {
    let world = World::new();
    let out = world.veil().arg("--help").output().unwrap();
    assert!(out.status.success());
    for heading in [
        "Daily use:",
        "Setup and access:",
        "Diagnostics:",
        "Examples:",
    ] {
        assert!(stdout(&out).contains(heading));
    }
    assert!(!stdout(&out).contains('\x1b'));
    let out = world.veil().args(["run", "--help"]).output().unwrap();
    assert!(stdout(&out).contains("FIFO"));
    assert!(stdout(&out).contains("child"));
}

#[test]
fn color_is_opt_in_for_pipes_and_json_never_has_ansi() {
    let world = World::new();
    let out = world
        .veil()
        .args(["--color", "always", "list"])
        .output()
        .unwrap();
    assert!(stderr(&out).contains('\x1b'));
    let out = world
        .veil()
        .env("NO_COLOR", "1")
        .arg("list")
        .output()
        .unwrap();
    assert!(!stderr(&out).contains('\x1b'));
    let out = world
        .veil()
        .args(["--color", "always", "--json", "list"])
        .output()
        .unwrap();
    assert!(!stderr(&out).contains('\x1b'));
    assert_eq!(error(&out)["error"]["code"], "not_signed_in");
}

#[test]
fn enrollment_distinguishes_pending_from_service_failures() {
    use std::io::{Read as _, Write as _};
    for (status, expected_code, exit) in [
        (403, "access_denied", 3),
        (503, "service_error", 1),
        (404, "enrollment_timeout", 1),
    ] {
        let world = World::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for response_status in [201, status] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let headers = String::from_utf8_lossy(&request);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|length| length.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let body = r#"{"title":"failure","detail":"do-not-echo-server-secret"}"#;
                write!(socket, "HTTP/1.1 {response_status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let out = world
            .veil()
            .timeout(std::time::Duration::from_secs(8))
            .env("VEIL_ENROLL_ATTEMPTS", "1")
            .args([
                "device",
                "add",
                "--server",
                &format!("http://{address}"),
                "--email",
                "ux@example.invalid",
                "--code",
                "123456",
                "--json",
            ])
            .output()
            .unwrap();
        server.join().unwrap();
        assert_eq!(out.status.code(), Some(exit), "{}", stderr(&out));
        let messages = stderr(&out)
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(messages[0]["type"], "enrollment");
        assert_eq!(messages[0]["code"], "123456");
        assert_eq!(messages.last().unwrap()["error"]["code"], expected_code);
        assert!(!stderr(&out).contains("do-not-echo-server-secret"));
        assert!(!world.0.join("home/state.json").exists());
    }
}

#[test]
fn narrow_terminal_diagnostics_remain_readable_without_color() {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::Read as _;
    let world = World::new();
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 40,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut builder = CommandBuilder::new(assert_cmd::cargo::cargo_bin("veil"));
    builder.args(["doctor"]);
    builder.env_clear();
    builder.cwd(&world.0);
    builder.env("HOME", world.0.join("home"));
    builder.env("VEIL_HOME", world.0.join("home"));
    builder.env("VEIL_KEYSTORE", "file");
    builder.env("NO_COLOR", "1");
    builder.env("TERM", "xterm-256color");
    let mut child = pair.slave.spawn_command(builder).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let collect = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        bytes
    });
    let status = child.wait().unwrap();
    drop(pair.master);
    let bytes = collect.join().unwrap();
    let output = String::from_utf8_lossy(&bytes);
    assert_eq!(status.exit_code(), 1);
    assert!(!output.contains('\x1b'));
    assert!(output.contains("STATUS"));
    assert!(output.contains("checks_failed"));
    assert!(output.contains("veil login"));
    for line in output.lines().filter(|line| {
        line.starts_with("STATUS") || line.starts_with("ok ") || line.starts_with("error ")
    }) {
        assert!(line.chars().count() <= 40, "{line}");
    }
}

//! CLI contract tests: stdout, stderr, and exit codes are the interface.

use assert_cmd::Command;

fn veil() -> Command {
    Command::cargo_bin("veil").expect("binary is built for tests")
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

#[test]
fn version_prints_to_stdout_only() {
    let output = veil().arg("version").output().expect("binary runs");

    assert!(output.status.success(), "status: {}", output.status);
    assert!(
        stdout_of(&output).contains(env!("CARGO_PKG_VERSION")),
        "stdout: {}",
        stdout_of(&output)
    );
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn version_json_is_machine_readable() {
    let output = veil()
        .args(["--json", "version"])
        .output()
        .expect("binary runs");

    assert!(output.status.success(), "status: {}", output.status);
    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&output)).expect("stdout is JSON");
    assert_eq!(value["name"], "veil");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn missing_subcommand_is_a_usage_error() {
    let output = veil().output().expect("binary runs");

    assert_eq!(output.status.code(), Some(2), "clap usage errors exit 2");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Usage"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "usage errors write nothing to stdout"
    );
}

fn config_home(text: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("veil-config-{}-{}", std::process::id(), text.len()));
    std::fs::create_dir_all(&dir).expect("home");
    std::fs::write(dir.join("config.toml"), text).expect("config");
    dir
}

#[test]
fn config_reads_the_file_and_the_environment_overrides_it() {
    let home = config_home("server = \"https://from-file.example\"\nkeystore = \"file\"\n");
    let output = veil()
        .args(["--json", "config"])
        .env("VEIL_HOME", &home)
        .env_remove("VEIL_CONFIG")
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_KEYSTORE")
        .env("VEIL_EMAIL", "from-env@example.com")
        .output()
        .expect("binary runs");
    assert!(output.status.success(), "status: {}", output.status);
    let value: serde_json::Value =
        serde_json::from_str(&stdout_of(&output)).expect("stdout is JSON");
    assert_eq!(value["exists"], true);
    assert_eq!(
        value["settings"]["server"]["value"],
        "https://from-file.example"
    );
    assert_eq!(value["settings"]["server"]["source"], "config.toml");
    assert_eq!(value["settings"]["email"]["source"], "VEIL_EMAIL");
    assert_eq!(value["settings"]["log"], serde_json::Value::Null);
    std::fs::remove_dir_all(home).expect("cleanup");
}

#[test]
fn login_reports_missing_or_invalid_global_configuration_before_network_access() {
    let home = std::env::temp_dir().join(format!("veil-login-config-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&home).expect("home");
    let file = home.join("config.toml");
    for (text, expected) in [
        ("email = \"me@example.com\"\n", "no service URL"),
        ("server = \"http://127.0.0.1:1\"\n", "no email"),
        ("server = [\n", "cannot parse"),
        ("unknown = \"typo\"\n", "unknown"),
    ] {
        std::fs::write(&file, text).expect("config");
        let output = veil()
            .arg("login")
            .env("VEIL_HOME", &home)
            .env_remove("VEIL_CONFIG")
            .env_remove("VEIL_SERVER")
            .env_remove("VEIL_EMAIL")
            .env("VEIL_KEYSTORE", "file")
            .env("VEIL_PASSWORD", "not-a-secret")
            .output()
            .expect("login");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!home.join("state.json").exists());
    }
    std::fs::remove_file(&file).expect("remove config");
    std::fs::create_dir(&file).expect("unreadable config");
    let output = veil()
        .arg("login")
        .env("VEIL_HOME", &home)
        .env_remove("VEIL_CONFIG")
        .env_remove("VEIL_SERVER")
        .env_remove("VEIL_EMAIL")
        .output()
        .expect("login");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read"));
    std::fs::remove_dir_all(home).expect("cleanup");
}

#[test]
fn an_unknown_config_key_stops_every_command() {
    let home = config_home("sever = \"https://typo.example\"\n");
    let output = veil()
        .arg("list")
        .env("VEIL_HOME", &home)
        .env_remove("VEIL_CONFIG")
        .output()
        .expect("binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config.toml") && stderr.contains("sever"),
        "{stderr}"
    );
    std::fs::remove_dir_all(home).expect("cleanup");
}

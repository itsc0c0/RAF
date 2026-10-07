//! Command-line behavior that needs no terminal and no network.

use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raf-os"))
        .args(args)
        .env_remove("RAF_OS_API")
        .env_remove("RAF_OS_TOKEN")
        .output()
        .expect("run raf-os")
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .to_string()
}

#[test]
fn version_and_help() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("raf-os {}", env!("CARGO_PKG_VERSION"))
    );
    let out = run(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "--dump PAGE",
        "--render FILE",
        "--no-mouse",
        "RAF_OS_TOKEN",
        "raf tui",
    ] {
        assert!(help.contains(needle), "help lacks {needle}");
    }
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["--bogus"][..],
        &["--width", "wide"],
        &["--dump"],
        &["--render", "a.json", "--dump", "home"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("raf-os:"));
    }
}

#[test]
fn render_rejects_missing_and_non_screen_files() {
    let out = run(&["--render", "/nonexistent/screen.json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
    let out = run(&["--render", &fixture("pages.json")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a screen"));
}

#[test]
fn render_defaults_to_width_100_without_a_terminal() {
    let out = run(&["--render", &fixture("home.json")]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().nth(1).unwrap(), "━".repeat(100));
}

#[test]
fn graph_list_flag_switches_layout() {
    let out = run(&[
        "--render",
        &fixture("graph.json"),
        "--graph-list",
        "--width",
        "100",
    ]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("LOGGED_INTO → ■ DEV-01  host"), "{text}");
    assert!(!text.contains("╔══"), "{text}");
}

#[test]
fn unknown_start_page_lists_the_pages() {
    let out = Command::new(env!("CARGO_BIN_EXE_raf-os"))
        .args(["--page", "nonexistent", "--no-boot"])
        .env("RAF_OS_API", "http://127.0.0.1:9/api/v1")
        .output()
        .expect("run raf-os");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown page \"nonexistent\""), "{err}");
    assert!(
        err.contains("home, timeline, trace, iam, blast, exposure"),
        "{err}"
    );
    // A known page passes validation (and then needs a terminal).
    let out = run(&["--page", "GRAPH", "--param", "alice", "--no-boot"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive terminal"));
}

#[test]
fn interactive_mode_requires_a_terminal() {
    // stdout is a pipe here.
    let out = run(&["--no-boot"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive terminal"));
}

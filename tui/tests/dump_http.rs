//! `raf-os --dump` against a tiny in-process HTTP server that plays the R$F API: request
//! paths and query encoding, the bearer token and workspace headers, proxy bypass, error
//! bodies and an unreachable API.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
struct Seen {
    target: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .expect("fixture")
}

/// Serves the fixtures like the R$F API would; returns the base URL and the request log.
fn mock_api() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let target = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.trim_end().split_once(':') {
                    headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                }
            }
            log.lock().unwrap().push(Seen {
                target: target.clone(),
                headers,
            });
            let path = target.split('?').next().unwrap_or("");
            let (status, body) = match path {
                "/api/v1/tui/pages" => (200, fixture("pages.json")),
                "/api/v1/tui/screen/timeline" => (200, fixture("timeline.json")),
                "/api/v1/tui/screen/oracle" => (200, fixture("oracle.json")),
                "/api/v1/tui/inspect" => {
                    if target.contains("ref=host%3Adev-01") || target.contains("ref=host:dev-01") {
                        (200, fixture("inspect-host.json"))
                    } else {
                        let v: serde_json::Value =
                            serde_json::from_str(&fixture("error-404.json")).unwrap();
                        (404, v["body"].to_string())
                    }
                }
                "/api/v1/health" => (200, r#"{"status":"ok","version":"0.1.0"}"#.to_string()),
                _ => (
                    404,
                    r#"{"error":{"code":"raf.not_found","message":"no such page"}}"#.to_string(),
                ),
            };
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (format!("http://{addr}/api/v1"), seen)
}

fn dump(base: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raf-os"))
        .arg("--dump")
        .args(args)
        .env("RAF_OS_API", base)
        .env("RAF_OS_TOKEN", "t0ken-xyz")
        .env("RAF_OS_WORKSPACE", "raven lab")
        // A proxy that does not exist: R$F OS must talk to the local API directly.
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .output()
        .expect("run raf-os")
}

#[test]
fn dump_fetches_the_screen_with_parameter_and_headers() {
    let (base, seen) = mock_api();
    let out = dump(&base, &["timeline", "--param", "INC-001", "--width", "90"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("R$F TIMELINE — INC-001\n"));
    assert!(text.contains("22:47:00.000  AUTH\n"));
    assert!(text.lines().all(|l| raf_os::text::width(l) <= 90));
    let seen = seen.lock().unwrap().clone();
    let targets: Vec<&str> = seen.iter().map(|s| s.target.as_str()).collect();
    assert_eq!(
        targets,
        [
            "/api/v1/tui/pages",
            "/api/v1/tui/screen/timeline?ref=INC-001"
        ]
    );
    for s in &seen {
        assert_eq!(s.header("authorization"), Some("Bearer t0ken-xyz"));
        assert_eq!(s.header("x-raf-workspace"), Some("raven lab"));
        assert_eq!(s.header("accept"), Some("application/json"));
    }
    // The token never appears in the output.
    assert!(!text.contains("t0ken-xyz"));
}

#[test]
fn dump_without_parameter_uses_the_server_default() {
    let (base, seen) = mock_api();
    let out = dump(&base, &["oracle"]);
    assert!(out.status.success());
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/api/v1/tui/screen/oracle");
}

#[test]
fn dump_encodes_free_text_parameters() {
    let (base, seen) = mock_api();
    let out = dump(
        &base,
        &["oracle", "--param", "Who can reach production & why? 100%"],
    );
    assert!(out.status.success());
    let seen = seen.lock().unwrap().clone();
    let target = &seen.last().unwrap().target;
    assert!(
        target.starts_with("/api/v1/tui/screen/oracle?question="),
        "{target}"
    );
    assert!(!target.contains(' ') && !target.contains("& "), "{target}");
    assert!(target.contains("%26") && target.contains("%25"), "{target}");
}

#[test]
fn dump_inspect_and_error_bodies() {
    let (base, _) = mock_api();
    let out = dump(
        &base,
        &["inspect", "--param", "host:dev-01", "--width", "80"],
    );
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("HOST DEV-01\n"), "{text}");

    let out = dump(&base, &["inspect", "--param", "no-such-thing"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("No object named 'no-such-thing' exists in this workspace."),
        "{err}"
    );
    assert!(err.contains("raf.not_found"), "{err}");
    assert!(err.contains("hint: Import data first"), "{err}");

    let out = dump(&base, &["nonexistent", "--param", "x"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown page"));
}

#[test]
fn start_page_ids_are_checked_against_the_api() {
    let (base, _) = mock_api();
    let run = |page: &str| {
        Command::new(env!("CARGO_BIN_EXE_raf-os"))
            .args(["--page", page, "--no-boot"])
            .env("RAF_OS_API", &base)
            .output()
            .expect("run raf-os")
    };
    let out = run("hologram");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown page \"hologram\" (pages: home, timeline"),
        "{err}"
    );
    assert!(err.contains("findings, evidence)"), "{err}");
    // Valid: validation passes, then the console needs a terminal.
    let out = run("evidence");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive terminal"));
}

#[test]
fn dump_reports_an_unreachable_api() {
    // Bind and drop a listener to get a port that is very likely closed.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out = dump(&format!("http://127.0.0.1:{port}/api/v1"), &["home"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("R$F API unreachable"), "{err}");
}

//! HTTP client for the local R$F API and the worker threads that keep the UI responsive.
//!
//! The client speaks plain HTTP/1.1 (ureq, no TLS, no proxy: R$F OS only ever talks to the
//! API that `raf tui` started on the loopback interface). Requests run on a small pool of worker
//! threads; results are delivered through a callback (the UI thread receives them over a
//! channel), so the interface never blocks on the network.

use std::io::ErrorKind;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;

use crate::model::{ErrorBody, Health, PagesDoc, Screen};
use crate::text::{clean, truncate};

/// API used when neither `--api` nor `RAF_OS_API` is given (the default of `raf serve`).
pub const DEFAULT_API: &str = "http://127.0.0.1:8765/api/v1";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PAGES_TIMEOUT: Duration = Duration::from_secs(20);
/// Screens can take a while (Oracle, Ghost on large workspaces): never give up before 60 s.
const SCREEN_TIMEOUT: Duration = Duration::from_secs(90);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(4);

/// Where and how to reach the API.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// Base URL including `/api/v1`, without a trailing slash.
    pub base: String,
    /// Bearer token (from `RAF_OS_TOKEN` only; never printed).
    pub token: Option<String>,
    /// Workspace name sent as `X-RAF-Workspace`.
    pub workspace: Option<String>,
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("workspace", &self.workspace)
            .finish()
    }
}

impl ApiConfig {
    pub fn new(base: &str, token: Option<String>, workspace: Option<String>) -> ApiConfig {
        let base = base.trim().trim_end_matches('/');
        ApiConfig {
            base: if base.is_empty() {
                DEFAULT_API.to_string()
            } else {
                base.to_string()
            },
            token: token.filter(|t| !t.trim().is_empty()),
            workspace: workspace.filter(|w| !w.trim().is_empty()),
        }
    }

    /// Host and port of the base URL (for status displays).
    pub fn authority(&self) -> &str {
        let rest = self
            .base
            .split_once("://")
            .map_or(self.base.as_str(), |(_, r)| r);
        rest.split('/').next().unwrap_or(rest)
    }
}

/// Everything that can go wrong talking to the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// No HTTP response (connection refused, timeout, DNS, bad URL).
    Unreachable { url: String, detail: String },
    /// HTTP status ≥ 400 with the R$F error body (or a synthesized one).
    Http {
        status: u16,
        code: String,
        message: String,
        reason: Option<String>,
        hint: Option<String>,
        suggestions: Vec<String>,
    },
    /// A 2xx response that is not what the protocol promises.
    Invalid { detail: String },
}

impl ApiError {
    /// True for transport failures (worth retrying when the API comes back).
    pub fn is_network(&self) -> bool {
        matches!(self, ApiError::Unreachable { .. })
    }

    /// Short title for error panels.
    pub fn title(&self) -> String {
        match self {
            ApiError::Unreachable { .. } => "R$F API UNREACHABLE".to_string(),
            ApiError::Http { status, code, .. } => format!("ERROR {status} · {code}"),
            ApiError::Invalid { .. } => "UNEXPECTED RESPONSE".to_string(),
        }
    }

    /// One-line description.
    pub fn summary(&self) -> String {
        match self {
            ApiError::Unreachable { detail, .. } => format!("R$F API unreachable: {detail}"),
            ApiError::Http {
                status,
                code,
                message,
                ..
            } => format!("{message} ({code}, HTTP {status})"),
            ApiError::Invalid { detail } => format!("unexpected response: {detail}"),
        }
    }

    /// Label/value rows for an error panel.
    pub fn rows(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        match self {
            ApiError::Unreachable { url, detail } => {
                rows.push(("reason".to_string(), detail.clone()));
                rows.push(("api".to_string(), url.clone()));
            }
            ApiError::Http {
                message,
                reason,
                hint,
                suggestions,
                ..
            } => {
                rows.push(("message".to_string(), message.clone()));
                if let Some(r) = reason {
                    rows.push(("reason".to_string(), r.clone()));
                }
                if let Some(h) = hint {
                    rows.push(("hint".to_string(), h.clone()));
                }
                for (i, s) in suggestions.iter().enumerate() {
                    let label = if i == 0 { "try" } else { "" };
                    rows.push((label.to_string(), s.clone()));
                }
            }
            ApiError::Invalid { detail } => rows.push(("detail".to_string(), detail.clone())),
        }
        rows
    }
}

/// Percent-encodes one URL path segment.
pub fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad request",
        401 => "Unauthorized (check RAF_OS_TOKEN)",
        403 => "Forbidden",
        404 => "Not found",
        409 => "Conflict",
        422 => "Unprocessable request",
        429 => "Too many requests",
        500 => "Internal server error",
        502 => "Bad gateway",
        503 => "Service unavailable",
        504 => "Gateway timeout",
        _ => "Request failed",
    }
}

/// Builds the error for a status ≥ 400 from the response body.
pub fn error_from_body(status: u16, body: &str) -> ApiError {
    let detail = serde_json::from_str::<ErrorBody>(body)
        .ok()
        .and_then(|b| b.error);
    match detail {
        Some(d) => ApiError::Http {
            status,
            code: d.code.unwrap_or_else(|| format!("http_{status}")),
            message: d
                .message
                .unwrap_or_else(|| reason_phrase(status).to_string()),
            reason: d.reason,
            hint: d.hint,
            suggestions: d.suggestions,
        },
        None => {
            let text = clean(body.trim());
            ApiError::Http {
                status,
                code: format!("http_{status}"),
                message: if text.is_empty() || text.starts_with('<') {
                    reason_phrase(status).to_string()
                } else {
                    truncate(&text, 240)
                },
                reason: None,
                hint: None,
                suggestions: Vec::new(),
            }
        }
    }
}

fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused => "connection refused".to_string(),
            ErrorKind::TimedOut => "timed out".to_string(),
            ErrorKind::ConnectionReset => "connection reset".to_string(),
            ErrorKind::ConnectionAborted => "connection aborted".to_string(),
            ErrorKind::UnexpectedEof => "connection closed".to_string(),
            _ => clean(&io.to_string()),
        },
        ureq::Error::Timeout(t) => format!("timed out ({})", clean(&t.to_string())),
        ureq::Error::HostNotFound => "host not found".to_string(),
        ureq::Error::BadUri(u) => format!("invalid API URL: {}", clean(u)),
        ureq::Error::ConnectionFailed => "connection failed".to_string(),
        other => clean(&other.to_string()),
    }
}

/// Blocking HTTP client (used from worker threads and the non-interactive modes).
pub struct Client {
    cfg: ApiConfig,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(cfg: ApiConfig) -> Client {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            // Local API only: never route through HTTP(S)_PROXY from the environment.
            .proxy(None)
            .http_status_as_error(false)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(SCREEN_TIMEOUT))
            // Never follow redirects: the bearer token must not travel to another origin.
            .max_redirects(0)
            .user_agent(format!("raf-os/{}", crate::VERSION))
            .build()
            .into();
        Client { cfg, agent }
    }

    pub fn config(&self) -> &ApiConfig {
        &self.cfg
    }

    fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<T, ApiError> {
        let url = format!("{}{}", self.cfg.base, path);
        let unreachable = |detail: String| ApiError::Unreachable {
            url: self.cfg.base.clone(),
            detail,
        };
        let mut req = self.agent.get(&url).header("Accept", "application/json");
        if let Some(token) = &self.cfg.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(ws) = &self.cfg.workspace {
            req = req.header("X-RAF-Workspace", ws.as_str());
        }
        for (k, v) in query {
            req = req.query(k, v);
        }
        let req = req.config().timeout_global(Some(timeout)).build();
        let mut resp = req.call().map_err(|e| unreachable(describe(&e)))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|v| truncate(&clean(v), 120))
                .unwrap_or_default();
            let target = if location.is_empty() {
                String::new()
            } else {
                format!(" to {location}")
            };
            return Err(ApiError::Http {
                status,
                code: "redirect".to_string(),
                message: format!(
                    "The API answered with a redirect{target}; R$F OS does not follow redirects."
                ),
                reason: None,
                hint: Some("Point --api / RAF_OS_API at the final API address.".to_string()),
                suggestions: Vec::new(),
            });
        }
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| unreachable(describe(&e)))?;
        if status >= 400 {
            return Err(error_from_body(status, &body));
        }
        serde_json::from_str(&body).map_err(|e| ApiError::Invalid {
            detail: format!("{path}: {}", clean(&e.to_string())),
        })
    }

    /// `GET /tui/pages`.
    pub fn pages(&self) -> Result<PagesDoc, ApiError> {
        self.get("/tui/pages", &[], PAGES_TIMEOUT)
    }

    /// `GET /tui/screen/{page}?{name}={value}` (no query parameter for the default).
    pub fn screen(&self, page: &str, param: Option<(&str, &str)>) -> Result<Screen, ApiError> {
        let path = format!("/tui/screen/{}", encode_segment(page));
        match param {
            Some((name, value)) if !name.is_empty() && !value.trim().is_empty() => {
                self.get(&path, &[(name, value)], SCREEN_TIMEOUT)
            }
            _ => self.get(&path, &[], SCREEN_TIMEOUT),
        }
    }

    /// `GET /tui/inspect?ref=...`.
    pub fn inspect(&self, reference: &str) -> Result<Screen, ApiError> {
        self.get("/tui/inspect", &[("ref", reference)], SCREEN_TIMEOUT)
    }

    /// `GET /health`.
    pub fn health(&self) -> Result<Health, ApiError> {
        self.get("/health", &[], HEALTH_TIMEOUT)
    }
}

/// A unit of work for the worker pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Pages,
    Screen {
        page: String,
        /// `(name, value)` of the page parameter; `None` asks for the server default.
        param: Option<(String, String)>,
    },
    Inspect {
        reference: String,
    },
    Health,
}

/// A successful result.
#[derive(Debug, Clone)]
pub enum Payload {
    Pages(Box<PagesDoc>),
    Screen(Screen),
    Health(Health),
}

/// A finished request.
#[derive(Debug, Clone)]
pub struct Response {
    pub id: u64,
    pub request: Request,
    pub result: Result<Payload, ApiError>,
    pub elapsed: Duration,
}

/// Runs one request synchronously.
pub fn execute(client: &Client, req: &Request) -> Result<Payload, ApiError> {
    match req {
        Request::Pages => client.pages().map(|p| Payload::Pages(Box::new(p))),
        Request::Screen { page, param } => client
            .screen(page, param.as_ref().map(|(n, v)| (n.as_str(), v.as_str())))
            .map(Payload::Screen),
        Request::Inspect { reference } => client.inspect(reference).map(Payload::Screen),
        Request::Health => client.health().map(Payload::Health),
    }
}

/// Submits requests to worker threads.
pub struct Worker {
    tx: Option<Sender<(u64, Request)>>,
    next_id: u64,
    /// Requests submitted to a detached worker (tests).
    pub sent: Vec<(u64, Request)>,
}

impl Worker {
    /// Starts `threads` workers sharing one queue; every result is passed to `deliver`.
    pub fn spawn<F>(client: Client, threads: usize, deliver: F) -> Worker
    where
        F: Fn(Response) + Send + Sync + 'static,
    {
        let (tx, rx) = mpsc::channel::<(u64, Request)>();
        let rx = Arc::new(Mutex::new(rx));
        let client = Arc::new(client);
        let deliver = Arc::new(deliver);
        for i in 0..threads.max(1) {
            let rx = Arc::clone(&rx);
            let client = Arc::clone(&client);
            let deliver = Arc::clone(&deliver);
            let _ = thread::Builder::new()
                .name(format!("raf-os-api-{i}"))
                .spawn(move || {
                    loop {
                        let job = match rx.lock() {
                            Ok(queue) => queue.recv(),
                            Err(_) => break,
                        };
                        let Ok((id, request)) = job else { break };
                        let started = Instant::now();
                        let result = execute(&client, &request);
                        deliver(Response {
                            id,
                            request,
                            result,
                            elapsed: started.elapsed(),
                        });
                    }
                });
        }
        Worker {
            tx: Some(tx),
            next_id: 1,
            sent: Vec::new(),
        }
    }

    /// A worker that only records requests (for tests and offline rendering).
    pub fn detached() -> Worker {
        Worker {
            tx: None,
            next_id: 1,
            sent: Vec::new(),
        }
    }

    /// Queues a request and returns its id.
    pub fn submit(&mut self, req: Request) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        match &self.tx {
            Some(tx) => {
                let _ = tx.send((id, req));
            }
            None => self.sent.push((id, req)),
        }
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_normalizes_and_redacts() {
        let cfg = ApiConfig::new(
            " http://127.0.0.1:41234/api/v1/ ",
            Some("s3cr3t".into()),
            Some(String::new()),
        );
        assert_eq!(cfg.base, "http://127.0.0.1:41234/api/v1");
        assert_eq!(cfg.workspace, None);
        assert_eq!(cfg.authority(), "127.0.0.1:41234");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert!(dbg.contains("<redacted>"));
        assert_eq!(ApiConfig::new("", None, None).base, DEFAULT_API);
    }

    #[test]
    fn path_segments_are_encoded() {
        assert_eq!(encode_segment("timeline"), "timeline");
        assert_eq!(encode_segment("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(encode_segment("ölçü"), "%C3%B6l%C3%A7%C3%BC");
    }

    #[test]
    fn error_bodies_are_parsed() {
        let body = r#"{"error":{"code":"raf.not_found","message":"No object named 'x' exists in this workspace.","hint":"Import data first.","suggestions":["raf search x"]}}"#;
        let e = error_from_body(404, body);
        assert_eq!(
            e,
            ApiError::Http {
                status: 404,
                code: "raf.not_found".into(),
                message: "No object named 'x' exists in this workspace.".into(),
                reason: None,
                hint: Some("Import data first.".into()),
                suggestions: vec!["raf search x".into()],
            }
        );
        assert_eq!(e.title(), "ERROR 404 · raf.not_found");
        let rows = e.rows();
        assert_eq!(rows[0].0, "message");
        assert_eq!(
            rows[1],
            ("hint".to_string(), "Import data first.".to_string())
        );
        assert_eq!(rows[2], ("try".to_string(), "raf search x".to_string()));
        // Non-JSON bodies still produce a readable message.
        match error_from_body(502, "<html>bad gateway</html>") {
            ApiError::Http { message, code, .. } => {
                assert_eq!(message, "Bad gateway");
                assert_eq!(code, "http_502");
            }
            other => panic!("{other:?}"),
        }
        // Hostile bodies are sanitized.
        match error_from_body(500, "boom\u{1b}[2J") {
            ApiError::Http { message, .. } => assert_eq!(message, "boom\u{FFFD}[2J"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unreachable_api_is_reported_not_panicking() {
        // Port 9 on loopback ("discard") is closed in test environments.
        let client = Client::new(ApiConfig::new("http://127.0.0.1:9/api/v1", None, None));
        let err = client.pages().unwrap_err();
        assert!(err.is_network(), "{err:?}");
        assert_eq!(err.title(), "R$F API UNREACHABLE");
        assert!(err.summary().starts_with("R$F API unreachable: "));
    }

    #[test]
    fn redirects_are_never_followed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        // `target` must never be contacted; `origin` answers every request with a redirect.
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_port = target.local_addr().unwrap().port();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let request = String::from_utf8_lossy(&buf).to_string();
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/api/v1/tui/pages\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(reply.as_bytes()).unwrap();
            request
        });
        let client = Client::new(ApiConfig::new(
            &format!("http://127.0.0.1:{origin_port}/api/v1"),
            Some("s3cr3t".into()),
            None,
        ));
        let err = client.pages().unwrap_err();
        let request = server.join().unwrap();
        assert!(request.contains("Bearer s3cr3t"), "{request}");
        match &err {
            ApiError::Http {
                status: 302,
                code,
                message,
                ..
            } => {
                assert_eq!(code, "redirect");
                assert!(
                    message.contains(&format!("127.0.0.1:{target_port}")),
                    "{message}"
                );
            }
            other => panic!("{other:?}"),
        }
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            target.accept().is_err(),
            "the redirect target was contacted"
        );
    }

    #[test]
    fn detached_worker_records_requests() {
        let mut w = Worker::detached();
        let a = w.submit(Request::Pages);
        let b = w.submit(Request::Health);
        assert_eq!((a, b), (1, 2));
        assert_eq!(w.sent.len(), 2);
    }
}

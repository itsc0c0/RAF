//! Application state, input handling and the event loop.
//!
//! Everything happens on the UI thread except HTTP requests, which run on worker threads
//! ([`crate::api::Worker`]) and come back as [`AppEvent::Api`]. Terminal input is read on its
//! own thread and arrives as [`AppEvent::Input`], so the loop sleeps on a single channel and
//! wakes up for input, results or the next animation frame, whichever comes first.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

use crate::api::{ApiConfig, ApiError, Payload, Request, Response, Worker};
use crate::boot::Boot;
use crate::model::{PageInfo, PagesDoc, Screen};
use crate::rain::Rain;
use crate::render::{self, Doc, RenderOptions};
use crate::theme;
use crate::ui;

/// Everything the loop reacts to.
#[derive(Debug)]
pub enum AppEvent {
    Input(Event),
    Api(Box<Response>),
    /// The input thread stopped (terminal closed).
    InputClosed,
}

/// Startup options.
#[derive(Debug, Clone)]
pub struct Options {
    pub api: ApiConfig,
    pub boot: bool,
    pub mouse: bool,
    pub low_cpu: bool,
    /// Page to open first (`--page`), by id.
    pub start_page: Option<String>,
    /// Initial parameter of the start page (`--param`).
    pub start_param: Option<String>,
}

/// Pages shown before (or without) `/tui/pages`.
pub const DEFAULT_PAGES: [(&str, &str); 12] = [
    ("home", "HOME"),
    ("timeline", "TIMELINE"),
    ("trace", "TRACE"),
    ("iam", "IAM"),
    ("blast", "BLAST"),
    ("exposure", "EXPOSURE"),
    ("policy", "POLICY"),
    ("ghost", "GHOST"),
    ("graph", "GRAPH"),
    ("oracle", "ORACLE"),
    ("findings", "FINDINGS"),
    ("evidence", "EVIDENCE"),
];

const FRAME: Duration = Duration::from_millis(50);
const HEALTH_EVERY: Duration = Duration::from_secs(15);
const DOUBLE_CLICK: Duration = Duration::from_millis(400);
const MESSAGE_TTL: Duration = Duration::from_secs(4);

/// Cache key of a screen.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScreenKey {
    pub page: String,
    pub param: Option<String>,
}

/// Load state of a page or an inspector entry.
#[derive(Debug, Clone)]
pub enum Status {
    Idle,
    Loading(Instant),
    Ready,
    Failed(ApiError),
}

impl Status {
    pub fn is_loading(&self) -> bool {
        matches!(self, Status::Loading(_))
    }
}

/// Scroll/cursor state of a rendered document.
#[derive(Debug, Default)]
pub struct DocView {
    pub doc: Option<Doc>,
    /// (width, vertical graph layout, generation) the doc was rendered for.
    key: Option<(usize, bool, u64)>,
    pub cursor: usize,
    pub scroll: usize,
    pub hscroll: usize,
}

impl DocView {
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.scroll = 0;
        self.hscroll = 0;
        self.doc = None;
        self.key = None;
    }

    fn len(&self) -> usize {
        self.doc.as_ref().map_or(0, Doc::len)
    }

    /// Keeps the cursor inside the document and visible in a viewport of `height` lines.
    pub fn follow(&mut self, height: usize) {
        let n = self.len();
        if n == 0 {
            self.cursor = 0;
            self.scroll = 0;
            return;
        }
        self.cursor = self.cursor.min(n - 1);
        let height = height.max(1);
        let margin = if height > 8 { 2 } else { 0 };
        if self.cursor < self.scroll + margin {
            self.scroll = self.cursor.saturating_sub(margin);
        }
        if self.cursor + margin >= self.scroll + height {
            self.scroll = self.cursor + margin + 1 - height;
        }
        self.clamp(height);
    }

    /// Keeps the scroll offset in range.
    pub fn clamp(&mut self, height: usize) {
        let n = self.len();
        self.scroll = self.scroll.min(n.saturating_sub(height.max(1)));
        if n > 0 {
            self.cursor = self.cursor.min(n - 1);
        }
    }

    /// Moves the cursor by `delta` non-blank lines.
    pub fn move_cursor(&mut self, delta: isize, height: usize) {
        let Some(doc) = &self.doc else { return };
        let n = doc.len();
        if n == 0 {
            return;
        }
        let mut c = self.cursor.min(n - 1) as isize;
        let step = delta.signum();
        for _ in 0..delta.unsigned_abs() {
            let mut next = c + step;
            while next >= 0 && (next as usize) < n && doc.is_blank(next as usize) {
                next += step;
            }
            if next < 0 || next as usize >= n {
                break;
            }
            c = next;
        }
        self.cursor = c as usize;
        self.follow(height);
    }

    /// Moves the cursor by a page.
    pub fn page(&mut self, down: bool, height: usize) {
        let n = self.len();
        if n == 0 {
            return;
        }
        let jump = height.saturating_sub(1).max(1);
        if down {
            self.cursor = (self.cursor + jump).min(n - 1);
            self.scroll += jump;
        } else {
            self.cursor = self.cursor.saturating_sub(jump);
            self.scroll = self.scroll.saturating_sub(jump);
        }
        self.clamp(height);
        self.follow(height);
    }

    pub fn home(&mut self, height: usize) {
        self.cursor = 0;
        self.scroll = 0;
        self.follow(height);
    }

    pub fn end(&mut self, height: usize) {
        self.cursor = self.len().saturating_sub(1);
        self.follow(height);
    }

    /// Scrolls the viewport (mouse wheel); the cursor is pulled along to stay visible.
    pub fn scroll_by(&mut self, delta: isize, height: usize) {
        let n = self.len();
        let max = n.saturating_sub(height.max(1));
        self.scroll = (self.scroll as isize + delta).clamp(0, max as isize) as usize;
        if self.cursor < self.scroll {
            self.cursor = self.scroll;
        }
        if self.cursor >= self.scroll + height {
            self.cursor = (self.scroll + height).saturating_sub(1);
        }
        self.clamp(height);
    }

    pub fn hscroll_by(&mut self, delta: isize, viewport_w: usize) {
        let wide = self.doc.as_ref().map_or(0, Doc::wide_width);
        let max = wide.saturating_sub(viewport_w);
        self.hscroll = (self.hscroll as isize + delta).clamp(0, max as isize) as usize;
    }

    /// Jumps to the next (or previous) line that carries a reference.
    pub fn next_ref(&mut self, forward: bool, height: usize) -> bool {
        let Some(doc) = &self.doc else { return false };
        let n = doc.len();
        let mut i = self.cursor;
        let current = doc.reference(i).map(str::to_owned);
        loop {
            if forward {
                if i + 1 >= n {
                    return false;
                }
                i += 1;
            } else {
                if i == 0 {
                    return false;
                }
                i -= 1;
            }
            if let Some(r) = doc.reference(i)
                && current.as_deref() != Some(r)
            {
                self.cursor = i;
                self.follow(height);
                return true;
            }
        }
    }

    /// Reference under the cursor.
    pub fn cursor_ref(&self) -> Option<&str> {
        self.doc.as_ref()?.reference(self.cursor)
    }
}

/// A screen being shown (a page or an inspector entry).
#[derive(Debug)]
pub struct Pane {
    pub status: Status,
    pub screen: Option<Arc<Screen>>,
    /// Bumped whenever `status` or `screen` change (the doc must be rebuilt).
    pub generation: u64,
    pub view: DocView,
    pub request: Option<u64>,
}

impl Default for Pane {
    fn default() -> Pane {
        Pane {
            status: Status::Idle,
            screen: None,
            generation: 0,
            view: DocView::default(),
            request: None,
        }
    }
}

impl Pane {
    fn touch(&mut self) {
        self.generation += 1;
    }

    fn set_screen(&mut self, screen: Arc<Screen>) {
        self.screen = Some(screen);
        self.status = Status::Ready;
        self.request = None;
        self.touch();
    }

    /// Makes sure `view.doc` matches the current content at `width`. Returns false while
    /// there is nothing to show yet (loading).
    pub fn ensure_doc(&mut self, width: usize, vertical: bool, height: usize) -> bool {
        let key = (width, vertical, self.generation);
        if self.view.key == Some(key) && self.view.doc.is_some() {
            return true;
        }
        let opts = RenderOptions {
            width,
            graph_vertical: vertical,
        };
        let doc = match (&self.status, &self.screen) {
            (Status::Failed(err), _) => Some(error_doc(err, width)),
            (_, Some(screen)) => Some(render::render_screen(screen, opts)),
            _ => None,
        };
        let previous = self.view.key;
        let previous_wide = self.view.doc.as_ref().map_or(0, Doc::wide_width);
        let had_doc = self.view.doc.is_some();
        self.view.doc = doc;
        self.view.key = self.view.doc.as_ref().map(|_| key);
        let Some(doc) = &self.view.doc else {
            return false;
        };
        // A wide drawing shown for the first time (new page/parameter, other width or graph
        // layout, or after a loading/error panel) starts at its preferred offset (root box
        // centered); a reload at the same width keeps where the user scrolled to.
        let max_h = doc.wide_width().saturating_sub(width);
        let fresh = !had_doc
            || previous_wide == 0
            || previous.is_none_or(|(w, v, _)| w != width || v != vertical);
        self.view.hscroll = if fresh {
            doc.initial_hscroll.unwrap_or(0).min(max_h)
        } else {
            self.view.hscroll.min(max_h)
        };
        if had_doc {
            self.view.clamp(height);
        } else {
            self.view.follow(height);
        }
        true
    }
}

/// The error panel shown in place of a screen.
pub fn error_doc(err: &ApiError, width: usize) -> Doc {
    let style = match err {
        ApiError::Unreachable { .. } => theme::severity(crate::model::Severity::High),
        ApiError::Http { status, .. } if *status >= 500 => {
            theme::severity(crate::model::Severity::High)
        }
        _ => theme::severity(crate::model::Severity::Medium),
    };
    let mut hints = vec!["press r to retry".to_string()];
    match err {
        ApiError::Unreachable { .. } => hints.push(
            "start the console with `raf tui` (it starts the API), or point --api / RAF_OS_API at a running `raf serve`"
                .to_string(),
        ),
        ApiError::Http { status: 401, .. } | ApiError::Http { status: 403, .. } => {
            hints.push("check RAF_OS_TOKEN".to_string())
        }
        ApiError::Http { .. } => hints.push("press / to change the parameter".to_string()),
        ApiError::Invalid { .. } => {}
    }
    render::message_doc(
        &format!("✖ {}", err.title()),
        style,
        &err.rows(),
        &hints,
        width,
    )
}

/// An inspector entry (the popup keeps a stack for back navigation).
#[derive(Debug)]
pub struct InspectEntry {
    pub reference: String,
    pub pane: Pane,
}

/// The inline parameter editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBox {
    pub chars: Vec<char>,
    pub cursor: usize,
    pub page: usize,
}

impl InputBox {
    pub fn new(value: &str, page: usize) -> InputBox {
        let chars: Vec<char> = value.chars().collect();
        InputBox {
            cursor: chars.len(),
            chars,
            page,
        }
    }

    pub fn value(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn insert(&mut self, s: &str) {
        for c in s.chars().filter(|c| !crate::text::is_forbidden(*c)) {
            if self.chars.len() >= 400 {
                break;
            }
            self.chars.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars.len());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.chars.len();
    }

    /// Display column of the cursor.
    pub fn cursor_col(&self) -> usize {
        let before: String = self.chars[..self.cursor].iter().collect();
        crate::text::width(&before)
    }

    /// Places the cursor at display column `col`.
    pub fn set_cursor_col(&mut self, col: usize) {
        let mut w = 0;
        self.cursor = self.chars.len();
        for (i, c) in self.chars.iter().enumerate() {
            if w >= col {
                self.cursor = i;
                break;
            }
            w += crate::text::width(c.encode_utf8(&mut [0u8; 4]));
        }
    }
}

/// One entry of the SIGNAL panel (recent API traffic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub label: String,
    pub ok: bool,
    pub detail: String,
}

const SIGNAL_KEEP: usize = 8;

/// Transient status-bar message.
#[derive(Debug, Clone)]
pub struct Message {
    pub text: String,
    pub error: bool,
    until: Instant,
}

/// Geometry of a document viewport from the last frame (for mouse hit-testing).
#[derive(Debug, Clone, Copy, Default)]
pub struct Viewport {
    /// Text area (gutter excluded).
    pub text: Rect,
    /// Scrollbar column (if the document is longer than the viewport).
    pub scrollbar: Option<Rect>,
}

/// What a sidebar focus entry opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusTarget {
    Inspect(String),
    /// The current page parameter (starts editing).
    EditParam,
}

/// Clickable regions of the last frame.
#[derive(Debug, Default, Clone)]
pub struct HitMap {
    pub tabs: Vec<(Rect, usize)>,
    pub sidebar: Vec<(Rect, usize)>,
    pub focus: Vec<(Rect, FocusTarget)>,
    pub param: Option<Rect>,
    /// Column where the parameter text starts.
    pub param_text_x: u16,
    pub content: Option<Viewport>,
    pub popup: Option<Rect>,
    pub popup_view: Option<Viewport>,
    pub help: Option<Rect>,
}

#[derive(Debug, Clone)]
enum Pending {
    Pages,
    Screen(ScreenKey),
    Inspect(String),
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drag {
    Content,
    Popup,
}

/// The application.
pub struct App {
    pub opts: Options,
    worker: Worker,
    pending: HashMap<u64, Pending>,
    pub meta: Option<PagesDoc>,
    pub meta_status: Status,
    meta_request: Option<u64>,
    pub pages: Vec<PageInfo>,
    /// User-chosen parameter per page (`None` = server default).
    pub params: Vec<Option<String>>,
    pub panes: Vec<Pane>,
    pub current: usize,
    cache: HashMap<ScreenKey, Arc<Screen>>,
    inspect_cache: HashMap<String, Arc<Screen>>,
    pub inspector: Vec<InspectEntry>,
    pub input: Option<InputBox>,
    pub help: bool,
    /// `m` toggle; `None` = automatic (on when the terminal is at least 140 columns wide).
    pub rain_pref: Option<bool>,
    pub graph_vertical: bool,
    pub message: Option<Message>,
    pub boot: Option<Boot>,
    boot_started: Instant,
    pub side_rain: Rain,
    last_rain_step: Instant,
    pub frame: u64,
    pub online: Option<bool>,
    pub latency: Option<Duration>,
    pub hit: HitMap,
    pub focused: bool,
    pub quit: bool,
    pub dirty: bool,
    /// Repaint every cell on the next frame (Ctrl-L, end of the boot sequence).
    pub full_repaint: bool,
    last_click: Option<(Instant, u16, u16)>,
    drag: Option<Drag>,
    last_health: Instant,
    health_request: Option<u64>,
    last_second: u64,
    last_frame: Instant,
    pub truecolor: bool,
    /// Viewport heights from the last frame (keyboard paging).
    pub content_height: usize,
    pub popup_height: usize,
    pub content_width: usize,
    pub popup_width: usize,
    /// Terminal size at the last frame.
    pub term_size: (u16, u16),
    /// Recent API traffic, newest first.
    pub signal: std::collections::VecDeque<Signal>,
    /// `--param` given: the start page waits for /tui/pages before loading.
    start_param_pending: bool,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn default_pages() -> Vec<PageInfo> {
    DEFAULT_PAGES
        .iter()
        .map(|(id, title)| PageInfo {
            id: (*id).to_string(),
            title: (*title).to_string(),
            param: None,
        })
        .collect()
}

impl App {
    /// Creates the application and queues the first requests.
    pub fn new(opts: Options, worker: Worker, terminal_desc: &str) -> App {
        let now = Instant::now();
        let mut pages = default_pages();
        // A start page the built-in list does not know yet (validated against the API).
        if let Some(id) = &opts.start_page
            && !pages.iter().any(|p| &p.id == id)
        {
            pages.push(PageInfo {
                id: id.clone(),
                title: id.to_uppercase(),
                param: None,
            });
        }
        let n = pages.len();
        let start = opts
            .start_page
            .as_ref()
            .and_then(|id| pages.iter().position(|p| &p.id == id))
            .unwrap_or(0);
        let boot = opts
            .boot
            .then(|| Boot::new(opts.api.authority(), terminal_desc));
        let mut app = App {
            worker,
            pending: HashMap::new(),
            meta: None,
            meta_status: Status::Idle,
            meta_request: None,
            params: vec![None; n],
            panes: (0..n).map(|_| Pane::default()).collect(),
            pages,
            current: 0,
            cache: HashMap::new(),
            inspect_cache: HashMap::new(),
            inspector: Vec::new(),
            input: None,
            help: false,
            rain_pref: None,
            graph_vertical: false,
            message: None,
            boot,
            boot_started: now,
            side_rain: Rain::new(0x0B5E_55ED),
            last_rain_step: now,
            frame: 0,
            online: None,
            latency: None,
            hit: HitMap::default(),
            focused: true,
            quit: false,
            dirty: true,
            full_repaint: false,
            last_click: None,
            drag: None,
            last_health: now,
            health_request: None,
            last_second: 0,
            last_frame: now,
            truecolor: theme::truecolor_supported(),
            content_height: 20,
            popup_height: 10,
            content_width: 80,
            popup_width: 60,
            term_size: (0, 0),
            signal: std::collections::VecDeque::new(),
            start_param_pending: false,
            opts,
        };
        app.current = start;
        if let Some(value) = app
            .opts
            .start_param
            .clone()
            .filter(|v| !v.trim().is_empty())
        {
            app.params[start] = Some(value.trim().to_string());
            app.start_param_pending = true;
        }
        app.request_pages();
        // With a start parameter the request waits for /tui/pages (its query name).
        app.load_page(start, false);
        app
    }

    // -----------------------------------------------------------------------------------
    // Requests

    fn submit(&mut self, req: Request, pending: Pending) -> u64 {
        let id = self.worker.submit(req);
        self.pending.insert(id, pending);
        self.dirty = true;
        id
    }

    fn request_pages(&mut self) {
        if self.meta_request.is_some() {
            return;
        }
        let id = self.submit(Request::Pages, Pending::Pages);
        self.meta_request = Some(id);
        self.meta_status = Status::Loading(Instant::now());
    }

    /// Key of the screen page `idx` currently shows.
    pub fn page_key(&self, idx: usize) -> ScreenKey {
        ScreenKey {
            page: self.pages[idx].id.clone(),
            param: self.params[idx].clone(),
        }
    }

    /// Loads page `idx` (from the cache unless `force`).
    pub fn load_page(&mut self, idx: usize, force: bool) {
        if idx >= self.pages.len() {
            return;
        }
        if self.params[idx].is_some()
            && self.pages[idx].param.is_none()
            && !matches!(self.meta_status, Status::Ready)
        {
            // The parameter's query name comes with /tui/pages: wait for it.
            let pane = &mut self.panes[idx];
            if !matches!(pane.status, Status::Failed(_)) {
                pane.status = Status::Loading(Instant::now());
                pane.touch();
            }
            return;
        }
        let key = self.page_key(idx);
        if !force {
            if let Some(screen) = self.cache.get(&key).cloned() {
                let pane = &mut self.panes[idx];
                if pane.request.is_none() && !matches!(pane.status, Status::Ready) {
                    pane.set_screen(screen);
                    self.dirty = true;
                }
                return;
            }
            let pane = &self.panes[idx];
            if pane.request.is_some() || matches!(pane.status, Status::Ready) {
                return;
            }
        } else {
            self.cache.remove(&key);
        }
        let param = match (&key.param, &self.pages[idx].param) {
            (Some(value), Some(spec)) if !spec.name.is_empty() => {
                Some((spec.name.clone(), value.clone()))
            }
            _ => None,
        };
        let id = self.submit(
            Request::Screen {
                page: key.page.clone(),
                param,
            },
            Pending::Screen(key),
        );
        let pane = &mut self.panes[idx];
        pane.request = Some(id);
        pane.status = Status::Loading(Instant::now());
        pane.touch();
    }

    /// Opens the inspector on `reference` (pushes onto the inspector stack).
    pub fn inspect(&mut self, reference: &str) {
        let reference = reference.trim().to_string();
        if reference.is_empty() {
            return;
        }
        let mut entry = InspectEntry {
            reference: reference.clone(),
            pane: Pane::default(),
        };
        if let Some(screen) = self.inspect_cache.get(&reference).cloned() {
            entry.pane.set_screen(screen);
        } else {
            let id = self.submit(
                Request::Inspect {
                    reference: reference.clone(),
                },
                Pending::Inspect(reference),
            );
            entry.pane.request = Some(id);
            entry.pane.status = Status::Loading(Instant::now());
        }
        self.inspector.push(entry);
        self.input = None;
        self.dirty = true;
    }

    fn reload_inspector(&mut self) {
        let Some(top) = self.inspector.last() else {
            return;
        };
        let reference = top.reference.clone();
        self.inspect_cache.remove(&reference);
        let id = self.submit(
            Request::Inspect {
                reference: reference.clone(),
            },
            Pending::Inspect(reference),
        );
        if let Some(top) = self.inspector.last_mut() {
            top.pane.request = Some(id);
            top.pane.status = Status::Loading(Instant::now());
            top.pane.touch();
        }
    }

    /// `r`: refetch what is on screen (and the page list if it failed).
    pub fn reload(&mut self) {
        if !matches!(self.meta_status, Status::Ready) {
            self.request_pages();
        }
        if self.inspector.is_empty() {
            self.load_page(self.current, true);
        } else {
            self.reload_inspector();
        }
        self.flash("reloading…", false);
    }

    // -----------------------------------------------------------------------------------
    // Responses

    /// Applies a finished request.
    pub fn on_response(&mut self, resp: Response) {
        self.dirty = true;
        let Some(pending) = self.pending.remove(&resp.id) else {
            return;
        };
        match &resp.result {
            Err(e) if e.is_network() => self.online = Some(false),
            _ => {
                self.online = Some(true);
                self.latency = Some(resp.elapsed);
            }
        }
        self.record_signal(&resp);
        match (pending, resp.result) {
            (Pending::Pages, result) => {
                self.meta_request = None;
                match result {
                    Ok(Payload::Pages(doc)) => self.apply_pages(*doc),
                    Ok(_) => {}
                    Err(err) => {
                        if let Some(boot) = &mut self.boot {
                            boot.set_pages(Err(&err));
                        }
                        // A page waiting for its parameter name shows the error instead.
                        let idx = self.current;
                        let pane = &mut self.panes[idx];
                        if pane.request.is_none()
                            && pane.screen.is_none()
                            && pane.status.is_loading()
                        {
                            pane.status = Status::Failed(err.clone());
                            pane.touch();
                        }
                        self.meta_status = Status::Failed(err);
                    }
                }
            }
            (Pending::Screen(key), result) => {
                let idx = (0..self.pages.len()).find(|&i| self.panes[i].request == Some(resp.id));
                match result {
                    Ok(Payload::Screen(screen)) => {
                        let screen = Arc::new(screen);
                        self.cache.insert(key, Arc::clone(&screen));
                        if let Some(i) = idx {
                            self.panes[i].set_screen(screen);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        if let Some(i) = idx {
                            let pane = &mut self.panes[i];
                            pane.request = None;
                            pane.status = Status::Failed(err);
                            pane.touch();
                        }
                    }
                }
            }
            (Pending::Inspect(reference), result) => {
                let entry = self
                    .inspector
                    .iter_mut()
                    .find(|e| e.pane.request == Some(resp.id));
                match result {
                    Ok(Payload::Screen(screen)) => {
                        let screen = Arc::new(screen);
                        self.inspect_cache.insert(reference, Arc::clone(&screen));
                        if let Some(e) = entry {
                            e.pane.set_screen(screen);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        if let Some(e) = entry {
                            e.pane.request = None;
                            e.pane.status = Status::Failed(err);
                            e.pane.touch();
                        }
                    }
                }
            }
            (Pending::Health, result) => {
                self.health_request = None;
                if result.is_ok() {
                    self.recover();
                }
            }
        }
    }

    fn record_signal(&mut self, resp: &Response) {
        let label = match &resp.request {
            Request::Pages => "pages".to_string(),
            Request::Screen { page, .. } => page.clone(),
            Request::Inspect { .. } => "inspect".to_string(),
            Request::Health => "health".to_string(),
        };
        let (ok, detail) = match &resp.result {
            Ok(_) => (true, format!("{}ms", resp.elapsed.as_millis())),
            Err(ApiError::Unreachable { detail, .. }) => (
                false,
                detail
                    .strip_prefix("connection ")
                    .unwrap_or(detail)
                    .to_string(),
            ),
            Err(ApiError::Http { status, .. }) => (false, status.to_string()),
            Err(ApiError::Invalid { .. }) => (false, "invalid".to_string()),
        };
        self.signal.push_front(Signal { label, ok, detail });
        self.signal.truncate(SIGNAL_KEEP);
    }

    /// The API answers again: retry what failed because it was unreachable.
    fn recover(&mut self) {
        if matches!(&self.meta_status, Status::Failed(e) if e.is_network()) {
            self.request_pages();
        }
        let idx = self.current;
        if matches!(&self.panes[idx].status, Status::Failed(e) if e.is_network()) {
            self.load_page(idx, true);
        }
    }

    fn apply_pages(&mut self, doc: PagesDoc) {
        if let Some(boot) = &mut self.boot {
            boot.set_pages(Ok(&doc));
        }
        let mut list: Vec<PageInfo> = Vec::new();
        for p in &doc.pages {
            if !p.id.trim().is_empty() && !list.iter().any(|q| q.id == p.id) {
                list.push(p.clone());
            }
        }
        if list.is_empty() {
            list = default_pages();
        }
        let current_id = self.pages.get(self.current).map(|p| p.id.clone());
        let mut old_panes: HashMap<String, (Pane, Option<String>)> = self
            .pages
            .iter()
            .map(|p| p.id.clone())
            .zip(self.panes.drain(..).zip(self.params.drain(..)))
            .collect();
        for p in &list {
            let (pane, param) = old_panes.remove(&p.id).unwrap_or_default();
            self.panes.push(pane);
            self.params.push(param);
        }
        self.pages = list;
        self.current = current_id
            .and_then(|id| self.pages.iter().position(|p| p.id == id))
            .unwrap_or(0);
        self.meta = Some(doc);
        self.meta_status = Status::Ready;
        if self.start_param_pending {
            self.start_param_pending = false;
            let idx = self.current;
            if self.pages[idx].param.is_none() && self.params[idx].take().is_some() {
                let msg = format!(
                    "{} takes no parameter; --param ignored",
                    self.pages[idx].display_title()
                );
                self.flash(&msg, true);
            }
            let pane = &mut self.panes[idx];
            if pane.request.is_none() && pane.screen.is_none() {
                pane.status = Status::Idle;
            }
        }
        self.load_page(self.current, false);
    }

    // -----------------------------------------------------------------------------------
    // Navigation

    pub fn switch_page(&mut self, idx: usize) {
        if idx >= self.pages.len() {
            return;
        }
        if idx != self.current {
            self.input = None;
        }
        self.current = idx;
        self.load_page(idx, false);
        self.dirty = true;
    }

    fn step_page(&mut self, forward: bool) {
        let n = self.pages.len();
        if n == 0 {
            return;
        }
        let idx = if forward {
            (self.current + 1) % n
        } else {
            (self.current + n - 1) % n
        };
        self.switch_page(idx);
    }

    /// Sets the parameter of page `idx` and loads it (`None` or blank = server default).
    pub fn set_param(&mut self, idx: usize, value: Option<String>) {
        let value = value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        if self.params[idx] == value && !matches!(self.panes[idx].status, Status::Failed(_)) {
            self.load_page(idx, false);
            return;
        }
        self.params[idx] = value;
        let pane = &mut self.panes[idx];
        pane.screen = None;
        pane.status = Status::Idle;
        pane.request = None;
        pane.view.reset();
        pane.touch();
        self.load_page(idx, false);
    }

    /// Switches to page `page_id` with `value` as its parameter (from the inspector).
    pub fn open_page_with(&mut self, page_id: &str, value: &str) {
        match self.pages.iter().position(|p| p.id == page_id) {
            Some(idx) if self.pages[idx].param.is_some() => {
                self.inspector.clear();
                self.set_param(idx, Some(value.to_string()));
                self.switch_page(idx);
            }
            Some(_) => self.flash(&format!("{page_id} does not take a parameter"), true),
            None => self.flash(&format!("no {page_id} page in this console"), true),
        }
    }

    /// Current value of a page's parameter (as shown in the parameter bar).
    pub fn param_value(&self, idx: usize) -> Option<String> {
        self.params[idx]
            .clone()
            .or_else(|| {
                self.panes[idx]
                    .screen
                    .as_ref()
                    .and_then(|s| s.param.clone())
            })
            .or_else(|| {
                self.pages[idx]
                    .param
                    .as_ref()
                    .and_then(|p| p.default.clone())
            })
    }

    fn start_edit(&mut self) {
        let idx = self.current;
        if self.pages[idx].param.is_none() {
            let msg = if matches!(self.meta_status, Status::Ready) {
                "this page has no parameter"
            } else {
                "parameters are known once the page list has loaded"
            };
            self.flash(msg, true);
            return;
        }
        let value = self.param_value(idx).unwrap_or_default();
        self.input = Some(InputBox::new(&value, idx));
        self.message = None;
        self.dirty = true;
    }

    fn submit_input(&mut self) {
        if let Some(input) = self.input.take() {
            let page = input.page.min(self.pages.len().saturating_sub(1));
            self.set_param(page, Some(input.value()));
        }
        self.dirty = true;
    }

    pub fn flash(&mut self, text: &str, error: bool) {
        self.message = Some(Message {
            text: text.to_string(),
            error,
            until: Instant::now() + MESSAGE_TTL,
        });
        self.dirty = true;
    }

    /// The pane the keyboard currently drives.
    fn active_pane(&mut self) -> &mut Pane {
        match self.inspector.last_mut() {
            Some(e) => &mut e.pane,
            None => &mut self.panes[self.current],
        }
    }

    fn active_height(&self) -> usize {
        if self.inspector.is_empty() {
            self.content_height
        } else {
            self.popup_height
        }
    }

    fn active_width(&self) -> usize {
        if self.inspector.is_empty() {
            self.content_width
        } else {
            self.popup_width
        }
    }

    fn inspect_cursor(&mut self) {
        let reference = self.active_pane().view.cursor_ref().map(str::to_owned);
        match reference {
            Some(r) => self.inspect(&r),
            None => self.flash("no reference on this line (lines marked › have one)", false),
        }
    }

    /// True when the side rain column is shown at terminal width `w`.
    pub fn rain_visible(&self, w: u16) -> bool {
        self.rain_pref.unwrap_or(w >= 140)
    }

    /// True while anything is loading (spinner).
    pub fn loading(&self) -> bool {
        self.panes
            .get(self.current)
            .is_some_and(|p| p.status.is_loading())
            || self.inspector.iter().any(|e| e.pane.status.is_loading())
            || self.meta_status.is_loading()
    }

    // -----------------------------------------------------------------------------------
    // Input

    /// Dispatches one event.
    pub fn handle(&mut self, ev: AppEvent) {
        match ev {
            AppEvent::Api(resp) => self.on_response(*resp),
            AppEvent::InputClosed => self.quit = true,
            AppEvent::Input(Event::Key(key)) => {
                if key.kind != KeyEventKind::Release {
                    self.on_key(key);
                }
            }
            AppEvent::Input(Event::Mouse(m)) => self.on_mouse(m),
            AppEvent::Input(Event::Paste(text)) => {
                if let Some(input) = &mut self.input {
                    input.insert(&text.replace(['\n', '\r', '\t'], " "));
                    self.dirty = true;
                }
            }
            AppEvent::Input(Event::Resize(..)) => self.dirty = true,
            AppEvent::Input(Event::FocusLost) => self.focused = false,
            AppEvent::Input(Event::FocusGained) => {
                self.focused = true;
                self.dirty = true;
            }
        }
    }

    /// Handles a key press.
    pub fn on_key(&mut self, key: KeyEvent) {
        self.dirty = true;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            self.quit = true;
            return;
        }
        if ctrl && key.code == KeyCode::Char('l') {
            self.full_repaint = true;
            return;
        }
        if let Some(boot) = &mut self.boot {
            boot.skip();
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        if self.input.is_some() {
            self.on_input_key(key);
            return;
        }
        if !self.inspector.is_empty() {
            self.on_inspector_key(key);
            return;
        }
        let h = self.content_height;
        let w = self.content_width;
        let n = self.pages.len();
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Left | KeyCode::Char('h') | KeyCode::BackTab => self.step_page(false),
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => self.step_page(true),
            KeyCode::Char(c @ '1'..='9') => {
                let idx = c as usize - '1' as usize;
                if idx < n {
                    self.switch_page(idx);
                }
            }
            KeyCode::Char('0') if n >= 10 => self.switch_page(9),
            KeyCode::Up | KeyCode::Char('k') => self.panes[self.current].view.move_cursor(-1, h),
            KeyCode::Down | KeyCode::Char('j') => self.panes[self.current].view.move_cursor(1, h),
            KeyCode::PageUp => self.panes[self.current].view.page(false, h),
            KeyCode::PageDown | KeyCode::Char(' ') => self.panes[self.current].view.page(true, h),
            KeyCode::Home | KeyCode::Char('g') => self.panes[self.current].view.home(h),
            KeyCode::End | KeyCode::Char('G') => self.panes[self.current].view.end(h),
            KeyCode::Char('[') => self.panes[self.current].view.hscroll_by(-8, w),
            KeyCode::Char(']') => self.panes[self.current].view.hscroll_by(8, w),
            KeyCode::Char('n') => {
                if !self.panes[self.current].view.next_ref(true, h) {
                    self.flash("no further references", false);
                }
            }
            KeyCode::Char('N') => {
                if !self.panes[self.current].view.next_ref(false, h) {
                    self.flash("no earlier references", false);
                }
            }
            KeyCode::Char('/') | KeyCode::Char('s') => self.start_edit(),
            KeyCode::Enter | KeyCode::Char('i') => self.inspect_cursor(),
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('m') => {
                let visible = self.rain_visible(self.term_size.0);
                self.rain_pref = Some(!visible);
            }
            KeyCode::Char('v') => {
                self.graph_vertical = !self.graph_vertical;
                let msg = if self.graph_vertical {
                    "graph: list layout"
                } else {
                    "graph: layered diagram"
                };
                self.flash(msg, false);
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.help = true,
            _ => {}
        }
    }

    fn on_input_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let Some(input) = &mut self.input else { return };
        match key.code {
            KeyCode::Enter => self.submit_input(),
            KeyCode::Esc => self.input = None,
            KeyCode::Backspace => input.backspace(),
            KeyCode::Delete => input.delete(),
            KeyCode::Left => input.left(),
            KeyCode::Right => input.right(),
            KeyCode::Home => input.home(),
            KeyCode::End => input.end(),
            KeyCode::Char('a') if ctrl => input.home(),
            KeyCode::Char('e') if ctrl => input.end(),
            KeyCode::Char('u') if ctrl => {
                input.chars.clear();
                input.cursor = 0;
            }
            KeyCode::Char(c) if !ctrl => input.insert(c.encode_utf8(&mut [0u8; 4])),
            _ => {}
        }
    }

    fn on_inspector_key(&mut self, key: KeyEvent) {
        let h = self.popup_height;
        let w = self.popup_width;
        let target = self
            .inspector
            .last()
            .map(|e| {
                e.pane
                    .screen
                    .as_ref()
                    .and_then(|s| s.param.clone())
                    .unwrap_or_else(|| e.reference.clone())
            })
            .unwrap_or_default();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.inspector.clear(),
            KeyCode::Backspace | KeyCode::Left => {
                if self.inspector.len() > 1 {
                    self.inspector.pop();
                } else {
                    self.inspector.clear();
                }
            }
            KeyCode::Enter | KeyCode::Char('i') => self.inspect_cursor(),
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('g') => self.open_page_with("graph", &target),
            KeyCode::Char('b') => self.open_page_with("blast", &target),
            KeyCode::Char('t') => self.open_page_with("timeline", &target),
            KeyCode::Char('I') => self.open_page_with("iam", &target),
            KeyCode::Char('?') => self.help = true,
            code => {
                let Some(top) = self.inspector.last_mut() else {
                    return;
                };
                let view = &mut top.pane.view;
                match code {
                    KeyCode::Up | KeyCode::Char('k') => view.move_cursor(-1, h),
                    KeyCode::Down | KeyCode::Char('j') => view.move_cursor(1, h),
                    KeyCode::PageUp => view.page(false, h),
                    KeyCode::PageDown | KeyCode::Char(' ') => view.page(true, h),
                    KeyCode::Home => view.home(h),
                    KeyCode::End | KeyCode::Char('G') => view.end(h),
                    KeyCode::Char('[') => view.hscroll_by(-8, w),
                    KeyCode::Char(']') => view.hscroll_by(8, w),
                    KeyCode::Char('n') => {
                        view.next_ref(true, h);
                    }
                    KeyCode::Char('N') => {
                        view.next_ref(false, h);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handles a mouse event (using the regions of the last frame).
    pub fn on_mouse(&mut self, m: MouseEvent) {
        let shift = m.modifiers.contains(KeyModifiers::SHIFT);
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => self.on_click(m.column, m.row),
            MouseEventKind::Drag(MouseButton::Left) => self.on_drag(m.row),
            MouseEventKind::Up(_) => self.drag = None,
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = m.kind == MouseEventKind::ScrollDown;
                if self.boot.is_some() || self.help {
                    return;
                }
                let (h, w) = (self.active_height(), self.active_width());
                let view = &mut self.active_pane().view;
                match (shift, down) {
                    (true, true) => view.hscroll_by(8, w),
                    (true, false) => view.hscroll_by(-8, w),
                    (false, true) => view.scroll_by(3, h),
                    (false, false) => view.scroll_by(-3, h),
                }
                self.dirty = true;
            }
            MouseEventKind::ScrollLeft | MouseEventKind::ScrollRight => {
                let w = self.active_width();
                let delta = if m.kind == MouseEventKind::ScrollRight {
                    8
                } else {
                    -8
                };
                self.active_pane().view.hscroll_by(delta, w);
                self.dirty = true;
            }
            _ => {}
        }
    }

    fn on_click(&mut self, x: u16, y: u16) {
        self.dirty = true;
        let pos = Position::new(x, y);
        let now = Instant::now();
        let double = matches!(self.last_click, Some((t, lx, ly))
            if now.duration_since(t) < DOUBLE_CLICK && lx == x && ly == y);
        self.last_click = Some((now, x, y));
        if let Some(boot) = &mut self.boot {
            boot.skip();
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        if let Some(popup) = self.hit.popup {
            if !popup.contains(pos) {
                self.inspector.clear();
                return;
            }
            if let Some(vp) = self.hit.popup_view {
                self.click_doc(vp, pos, double, true);
            }
            return;
        }
        if let Some(param) = self.hit.param {
            if param.contains(pos) {
                if self.input.is_none() {
                    self.start_edit();
                }
                let text_x = self.hit.param_text_x;
                if let Some(input) = &mut self.input {
                    input.set_cursor_col(x.saturating_sub(text_x) as usize);
                }
                return;
            }
            self.input = None;
        }
        if let Some(&(_, idx)) = self.hit.tabs.iter().find(|(r, _)| r.contains(pos)) {
            self.switch_page(idx);
            return;
        }
        if let Some(&(_, idx)) = self.hit.sidebar.iter().find(|(r, _)| r.contains(pos)) {
            self.switch_page(idx);
            return;
        }
        if let Some((_, target)) = self
            .hit
            .focus
            .iter()
            .find(|(r, _)| r.contains(pos))
            .cloned()
        {
            match target {
                FocusTarget::Inspect(r) => self.inspect(&r),
                FocusTarget::EditParam => self.start_edit(),
            }
            return;
        }
        if let Some(vp) = self.hit.content {
            self.click_doc(vp, pos, double, false);
        }
    }

    fn click_doc(&mut self, vp: Viewport, pos: Position, double: bool, popup: bool) {
        let height = if popup {
            self.popup_height
        } else {
            self.content_height
        };
        if let Some(sb) = vp.scrollbar
            && sb.contains(pos)
        {
            self.drag = Some(if popup { Drag::Popup } else { Drag::Content });
            self.scroll_to_ratio(pos.y, sb, popup);
            return;
        }
        // Gutter clicks count as clicks on the line.
        let in_rows = pos.y >= vp.text.y && pos.y < vp.text.bottom();
        let in_cols = pos.x + 1 >= vp.text.x && pos.x < vp.text.right();
        if !(in_rows && in_cols) {
            return;
        }
        let pane = if popup {
            match self.inspector.last_mut() {
                Some(e) => &mut e.pane,
                None => return,
            }
        } else {
            &mut self.panes[self.current]
        };
        let Some(doc) = &pane.view.doc else { return };
        let line = pane.view.scroll + (pos.y - vp.text.y) as usize;
        if line >= doc.len() {
            return;
        }
        let mut col = pos.x.saturating_sub(vp.text.x) as usize;
        if doc.lines[line].wide {
            col += pane.view.hscroll;
        }
        let mut reference = doc.reference_at(line, col).map(str::to_owned);
        if reference.is_none() && double {
            // A double click on an unmarked line opens the reference of its block (the
            // closest marked line above it, within the same paragraph).
            reference = (0..line)
                .rev()
                .take_while(|&i| !doc.is_blank(i))
                .find_map(|i| doc.reference(i))
                .map(str::to_owned);
        }
        pane.view.cursor = line;
        pane.view.follow(height);
        if let Some(r) = reference {
            self.inspect(&r);
        }
    }

    fn scroll_to_ratio(&mut self, y: u16, bar: Rect, popup: bool) {
        let height = if popup {
            self.popup_height
        } else {
            self.content_height
        };
        let pane = if popup {
            match self.inspector.last_mut() {
                Some(e) => &mut e.pane,
                None => return,
            }
        } else {
            &mut self.panes[self.current]
        };
        let n = pane.view.len();
        let max = n.saturating_sub(height);
        let rel = y.saturating_sub(bar.y) as usize;
        let span = (bar.height as usize).saturating_sub(1).max(1);
        pane.view.scroll = (rel * max + span / 2) / span;
        pane.view.cursor = pane.view.scroll;
        pane.view.clamp(height);
        self.dirty = true;
    }

    fn on_drag(&mut self, y: u16) {
        match self.drag {
            Some(Drag::Content) => {
                if let Some(sb) = self.hit.content.and_then(|v| v.scrollbar) {
                    self.scroll_to_ratio(y, sb, false);
                }
            }
            Some(Drag::Popup) => {
                if let Some(sb) = self.hit.popup_view.and_then(|v| v.scrollbar) {
                    self.scroll_to_ratio(y, sb, true);
                }
            }
            None => {}
        }
    }

    // -----------------------------------------------------------------------------------
    // Time

    /// True while something on screen animates (boot, rain, spinners).
    pub fn animating(&self) -> bool {
        if self.boot.is_some() {
            return true;
        }
        if !self.focused {
            return false;
        }
        let rain = self.rain_visible(self.term_size.0) && !self.opts.low_cpu;
        rain || self.loading()
    }

    /// Advances animations and timers.
    pub fn update(&mut self, now: Instant) {
        if let Some(boot) = &mut self.boot {
            boot.tick(now.duration_since(self.boot_started).as_secs_f32());
            if boot.finished() {
                self.boot = None;
                self.full_repaint = true;
                self.dirty = true;
            }
        }
        if now.duration_since(self.last_rain_step) >= FRAME {
            let animate = self.focused && !self.opts.low_cpu;
            if animate && self.boot.is_none() {
                self.side_rain.step();
            }
            self.last_rain_step = now;
        }
        if let Some(msg) = &self.message
            && now >= msg.until
        {
            self.message = None;
            self.dirty = true;
        }
        let second = unix_now();
        if second != self.last_second {
            self.last_second = second;
            self.dirty = true;
        }
        if self.health_request.is_none() && now.duration_since(self.last_health) >= HEALTH_EVERY {
            self.last_health = now;
            let id = self.submit(Request::Health, Pending::Health);
            self.health_request = Some(id);
        }
    }

    fn next_timeout(&self, now: Instant) -> Duration {
        if self.animating() {
            return FRAME
                .saturating_sub(now.duration_since(self.last_frame))
                .max(Duration::from_millis(1));
        }
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_millis());
        Duration::from_millis(u64::from(1000 - ms.min(999)) + 5)
    }

    /// Runs until the user quits.
    pub fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        rx: Receiver<AppEvent>,
    ) -> io::Result<()> {
        loop {
            let now = Instant::now();
            self.update(now);
            if self.full_repaint {
                // Repainted through the next draw (every cell marked for update): ratatui's
                // `Terminal::clear` queries the cursor position, which would race with the
                // input thread for the terminal's reply.
                self.dirty = true;
            }
            let frame_due = self.animating() && now.duration_since(self.last_frame) >= FRAME;
            if self.dirty || frame_due {
                self.frame += 1;
                self.last_frame = now;
                self.dirty = false;
                terminal.draw(|f| ui::draw(f, self))?;
            }
            if self.quit {
                return Ok(());
            }
            match rx.recv_timeout(self.next_timeout(Instant::now())) {
                Ok(ev) => {
                    self.handle(ev);
                    while let Ok(ev) = rx.try_recv() {
                        self.handle(ev);
                        if self.quit {
                            break;
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::api::Response;

    pub fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    }

    /// An app with a detached worker (requests are recorded, never sent).
    pub fn test_app() -> App {
        test_app_with(None, None)
    }

    /// Like [`test_app`], starting on `page` with `param` (`--page`, `--param`).
    pub fn test_app_with(page: Option<&str>, param: Option<&str>) -> App {
        let opts = Options {
            api: ApiConfig::new("http://127.0.0.1:9/api/v1", None, None),
            boot: false,
            mouse: true,
            low_cpu: true,
            start_page: page.map(str::to_string),
            start_param: param.map(str::to_string),
        };
        let mut app = App::new(opts, Worker::detached(), "test");
        app.truecolor = true;
        app
    }

    pub fn respond(app: &mut App, id: u64, request: Request, result: Result<Payload, ApiError>) {
        app.handle(AppEvent::Api(Box::new(Response {
            id,
            request,
            result,
            elapsed: Duration::from_millis(12),
        })));
    }

    /// Answers every outstanding request from the fixtures (inspect → inspect-host.json).
    pub fn serve_fixtures(app: &mut App) {
        let sent: Vec<(u64, Request)> = std::mem::take(&mut app.worker.sent);
        for (id, req) in sent {
            let result = match &req {
                Request::Pages => Ok(Payload::Pages(Box::new(
                    serde_json::from_str(&fixture("pages.json")).unwrap(),
                ))),
                Request::Screen { page, .. } => {
                    let screen: Screen =
                        serde_json::from_str(&fixture(&format!("{page}.json"))).unwrap();
                    Ok(Payload::Screen(screen))
                }
                Request::Inspect { .. } => Ok(Payload::Screen(
                    serde_json::from_str(&fixture("inspect-host.json")).unwrap(),
                )),
                Request::Health => Ok(Payload::Health(Default::default())),
            };
            respond(app, id, req, result);
        }
    }

    /// Serves fixtures until no request is outstanding.
    pub fn serve_all(app: &mut App) {
        for _ in 0..8 {
            if app.worker.sent.is_empty() {
                break;
            }
            serve_fixtures(app);
        }
    }

    pub fn sent(app: &App) -> Vec<Request> {
        app.worker.sent.iter().map(|(_, r)| r.clone()).collect()
    }

    pub fn last_sent(app: &App) -> Option<Request> {
        app.worker.sent.last().map(|(_, r)| r.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use ratatui::crossterm::event::{KeyEventState, MouseEvent};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn startup_requests_pages_and_home() {
        let mut app = test_app();
        let sent: Vec<Request> = sent(&app);
        assert_eq!(
            sent,
            vec![
                Request::Pages,
                Request::Screen {
                    page: "home".into(),
                    param: None
                }
            ]
        );
        serve_fixtures(&mut app);
        assert!(matches!(app.meta_status, Status::Ready));
        assert_eq!(app.pages.len(), 12);
        assert!(matches!(app.panes[0].status, Status::Ready));
        assert_eq!(app.online, Some(true));
    }

    #[test]
    fn arrows_wrap_around_and_digits_jump() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.current, 11);
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.current, 0);
        app.on_key(key(KeyCode::Char('3')));
        assert_eq!(app.current, 2);
        app.on_key(key(KeyCode::Char('0')));
        assert_eq!(app.current, 9);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.current, 10);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.current, 9);
        // Visiting a page requests its screen once; the cache serves it afterwards.
        let requests = sent(&app)
            .iter()
            .filter(|r| matches!(r, Request::Screen { page, .. } if page == "oracle"))
            .count();
        assert_eq!(requests, 1);
    }

    #[test]
    fn param_editing_requests_the_named_parameter() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        app.switch_page(1); // timeline
        serve_fixtures(&mut app);
        app.on_key(key(KeyCode::Char('/')));
        let input = app.input.clone().expect("editing");
        assert_eq!(input.value(), "INC-001");
        for _ in 0..7 {
            app.on_key(key(KeyCode::Backspace));
        }
        for c in "bob".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Home));
        app.on_key(key(KeyCode::Delete));
        app.on_key(key(KeyCode::Char('B')));
        app.on_key(key(KeyCode::End));
        assert_eq!(app.input.as_ref().unwrap().value(), "Bob");
        app.on_key(key(KeyCode::Enter));
        assert!(app.input.is_none());
        let last = last_sent(&app).unwrap();
        assert_eq!(
            last,
            Request::Screen {
                page: "timeline".into(),
                param: Some(("ref".into(), "Bob".into()))
            }
        );
        // Esc cancels without a request.
        let before = sent(&app).len();
        app.on_key(key(KeyCode::Char('s')));
        app.on_key(key(KeyCode::Char('x')));
        app.on_key(key(KeyCode::Esc));
        assert!(app.input.is_none());
        assert_eq!(sent(&app).len(), before);
        assert!(!app.quit);
    }

    #[test]
    fn errors_become_error_panels_and_r_retries() {
        let mut app = test_app();
        let outstanding: Vec<(u64, Request)> = std::mem::take(&mut app.worker.sent);
        for (id, req) in outstanding {
            let err = ApiError::Unreachable {
                url: "http://127.0.0.1:9/api/v1".into(),
                detail: "connection refused".into(),
            };
            respond(&mut app, id, req, Err(err));
        }
        assert_eq!(app.online, Some(false));
        assert!(matches!(app.panes[0].status, Status::Failed(_)));
        assert!(app.panes[0].ensure_doc(80, false, 20));
        let plain = app.panes[0].view.doc.as_ref().unwrap().to_plain();
        assert!(plain.contains("R$F API UNREACHABLE"), "{plain}");
        assert!(plain.contains("connection refused"));
        app.on_key(key(KeyCode::Char('r')));
        let kinds: Vec<Request> = sent(&app);
        assert!(kinds.contains(&Request::Pages));
        assert!(
            kinds
                .iter()
                .any(|r| matches!(r, Request::Screen { page, .. } if page == "home"))
        );
    }

    #[test]
    fn inspector_opens_navigates_and_jumps_to_pages() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        app.inspect("host:dev-01");
        serve_fixtures(&mut app);
        assert_eq!(app.inspector.len(), 1);
        assert!(app.inspector[0].pane.ensure_doc(60, false, 20));
        // Move to a line with a reference and open it (nested).
        app.on_key(key(KeyCode::Char('n')));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.inspector.len(), 2);
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.inspector.len(), 1);
        // `g` opens GRAPH with the inspected object.
        app.on_key(key(KeyCode::Char('g')));
        assert!(app.inspector.is_empty());
        assert_eq!(app.pages[app.current].id, "graph");
        assert_eq!(app.params[app.current].as_deref(), Some("host:dev-01"));
        let last = last_sent(&app).unwrap();
        assert_eq!(
            last,
            Request::Screen {
                page: "graph".into(),
                param: Some(("ref".into(), "host:dev-01".into()))
            }
        );
    }

    #[test]
    fn start_page_and_param_wait_for_the_parameter_name() {
        let mut app = test_app_with(Some("graph"), Some("alice"));
        assert_eq!(app.pages[app.current].id, "graph");
        // Only the page list is requested: the query name of the parameter is not known yet.
        assert_eq!(sent(&app), vec![Request::Pages]);
        assert!(app.panes[app.current].status.is_loading());
        serve_fixtures(&mut app);
        assert_eq!(
            last_sent(&app),
            Some(Request::Screen {
                page: "graph".into(),
                param: Some(("ref".into(), "alice".into()))
            })
        );
        assert_eq!(app.pages[app.current].id, "graph");
        // Oracle's parameter is called "question".
        let mut app = test_app_with(Some("oracle"), Some("Who can reach production?"));
        serve_fixtures(&mut app);
        assert_eq!(
            last_sent(&app),
            Some(Request::Screen {
                page: "oracle".into(),
                param: Some(("question".into(), "Who can reach production?".into()))
            })
        );
    }

    #[test]
    fn start_param_on_a_page_without_parameter_is_ignored() {
        let mut app = test_app_with(None, Some("x"));
        serve_fixtures(&mut app);
        assert_eq!(app.current, 0);
        assert_eq!(app.params[0], None);
        assert!(
            app.message
                .as_ref()
                .unwrap()
                .text
                .contains("takes no parameter")
        );
        assert_eq!(
            last_sent(&app),
            Some(Request::Screen {
                page: "home".into(),
                param: None
            })
        );
    }

    #[test]
    fn start_param_shows_the_page_list_error_when_the_api_is_down() {
        let mut app = test_app_with(Some("blast"), Some("bob"));
        let outstanding: Vec<(u64, Request)> = std::mem::take(&mut app.worker.sent);
        for (id, req) in outstanding {
            let err = ApiError::Unreachable {
                url: "http://127.0.0.1:9/api/v1".into(),
                detail: "connection refused".into(),
            };
            respond(&mut app, id, req, Err(err));
        }
        let idx = app.current;
        assert!(matches!(app.panes[idx].status, Status::Failed(_)));
        // r retries the page list; the screen follows once the parameter name is known.
        app.on_key(key(KeyCode::Char('r')));
        assert_eq!(sent(&app), vec![Request::Pages]);
        serve_fixtures(&mut app);
        assert_eq!(
            last_sent(&app),
            Some(Request::Screen {
                page: "blast".into(),
                param: Some(("ref".into(), "bob".into()))
            })
        );
    }

    #[test]
    fn graph_starts_with_the_root_centered_and_keeps_user_scrolling() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        let idx = app.pages.iter().position(|p| p.id == "graph").unwrap();
        app.switch_page(idx);
        serve_fixtures(&mut app);
        let width = 53;
        app.content_width = width;
        let pane = &mut app.panes[idx];
        assert!(pane.ensure_doc(width, false, 18));
        let doc = pane.view.doc.as_ref().unwrap();
        let wide = doc.wide_width();
        assert!(wide > width, "the bob graph is wider than 53 columns");
        let expected = doc.initial_hscroll.expect("graph offset");
        assert!(expected > 0);
        assert_eq!(pane.view.hscroll, expected);
        // The root box (first hotspot) is inside the viewport.
        let root = doc.hotspots.first().unwrap();
        assert!(root.col >= expected && root.col + root.width <= expected + width);
        // `]` scrolls from there; a reload at the same width keeps the position.
        app.on_key(key(KeyCode::Char(']')));
        let pane = &mut app.panes[idx];
        assert_eq!(pane.view.hscroll, expected + 8);
        pane.generation += 1;
        assert!(pane.ensure_doc(width, false, 18));
        assert_eq!(pane.view.hscroll, expected + 8);
        // A resize re-centers the root for the new width.
        assert!(pane.ensure_doc(70, false, 18));
        let doc = pane.view.doc.as_ref().unwrap();
        assert_eq!(pane.view.hscroll, doc.initial_hscroll.unwrap());
        // A new parameter starts centered again.
        app.set_param(idx, Some("alice".into()));
        serve_fixtures(&mut app);
        let pane = &mut app.panes[idx];
        assert!(pane.ensure_doc(width, false, 18));
        assert_eq!(pane.view.hscroll, expected);
    }

    #[test]
    fn quit_keys() {
        let mut app = test_app();
        app.on_key(key(KeyCode::Char('q')));
        assert!(app.quit);
        let mut app = test_app();
        app.on_key(KeyEvent {
            modifiers: KeyModifiers::CONTROL,
            ..key(KeyCode::Char('c'))
        });
        assert!(app.quit);
        // Esc closes the help overlay instead of quitting.
        let mut app = test_app();
        app.on_key(key(KeyCode::Char('?')));
        assert!(app.help);
        app.on_key(key(KeyCode::Esc));
        assert!(!app.help && !app.quit);
    }

    #[test]
    fn cursor_skips_blank_lines_and_scroll_follows() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        app.content_height = 10;
        let pane = &mut app.panes[0];
        assert!(pane.ensure_doc(80, false, 10));
        let doc_len = pane.view.doc.as_ref().unwrap().len();
        for _ in 0..200 {
            pane.view.move_cursor(1, 10);
            let doc = pane.view.doc.as_ref().unwrap();
            assert!(!doc.is_blank(pane.view.cursor));
            assert!(pane.view.cursor >= pane.view.scroll);
            assert!(pane.view.cursor < pane.view.scroll + 10);
        }
        assert!(pane.view.cursor > doc_len / 2);
        pane.view.home(10);
        assert_eq!((pane.view.cursor, pane.view.scroll), (0, 0));
        pane.view.end(10);
        assert_eq!(pane.view.cursor, doc_len - 1);
    }

    #[test]
    fn mouse_clicks_switch_tabs_and_open_references() {
        let mut app = test_app();
        serve_fixtures(&mut app);
        app.hit.tabs = vec![(Rect::new(10, 1, 6, 1), 4)];
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 12,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.current, 4);
        serve_fixtures(&mut app);
        // A click on a content line with a reference opens the inspector.
        app.switch_page(0);
        let pane = &mut app.panes[0];
        assert!(pane.ensure_doc(80, false, 200));
        let doc = pane.view.doc.as_ref().unwrap();
        let line = (0..doc.len())
            .find(|&i| doc.reference(i).is_some())
            .unwrap();
        let expected = doc.reference(line).unwrap().to_string();
        app.hit = HitMap {
            content: Some(Viewport {
                text: Rect::new(30, 3, 80, 200),
                scrollbar: None,
            }),
            ..HitMap::default()
        };
        app.content_height = 200;
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 35,
            row: 3 + line as u16,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.inspector.len(), 1);
        assert_eq!(app.inspector[0].reference, expected);
        assert_eq!(app.panes[0].view.cursor, line);
        // Clicking outside the popup closes it.
        app.hit.popup = Some(Rect::new(20, 5, 40, 10));
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert!(app.inspector.is_empty());
    }

    #[test]
    fn input_box_editing() {
        let mut input = InputBox::new("bob → prod", 0);
        assert_eq!(input.cursor, 10);
        input.left();
        input.backspace();
        input.insert("x\u{1b}y");
        assert_eq!(input.value(), "bob → prxyd");
        input.home();
        input.delete();
        assert_eq!(input.value(), "ob → prxyd");
        input.set_cursor_col(4);
        assert_eq!(input.cursor, 4);
        assert_eq!(input.cursor_col(), 4);
    }
}

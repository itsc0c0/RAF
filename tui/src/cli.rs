//! Command line: argument parsing, the interactive console and the non-interactive modes
//! (`--dump`, `--render`).

use std::io::{self, IsTerminal, Write};
use std::sync::mpsc;
use std::thread;

use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange, EnableMouseCapture,
};
use ratatui::crossterm::{cursor, execute};

use crate::api::{ApiConfig, Client, DEFAULT_API, Worker};
use crate::app::{App, AppEvent, Options};
use crate::model::Screen;
use crate::render::{RenderOptions, render_screen};
use crate::theme;

pub const USAGE: &str = "\
R$F OS: full-screen terminal control panel for the R$F security platform.

Usage:
  raf-os [--page PAGE] [--param VALUE] [--api URL] [--workspace NAME] [--no-boot] [--no-mouse] [--low-cpu]
  raf-os --dump PAGE [--param VALUE] [--width N] [--graph-list] [--api URL] [--workspace NAME]
  raf-os --render FILE.json [--width N] [--graph-list]
  raf-os --version | --help

Normally started by `raf tui`, which runs the API and sets the environment.

Options:
  --page PAGE        open the console on this page (home, timeline, trace, iam, blast, exposure,
                     policy, ghost, graph, oracle, findings, evidence); default home
  --param VALUE      parameter of the start page (or of --dump PAGE), e.g. an object or a question
  --api URL          API base URL including /api/v1 (env RAF_OS_API, default http://127.0.0.1:8765/api/v1)
  --workspace NAME   workspace to work in (env RAF_OS_WORKSPACE)
  --no-boot          skip the boot sequence (env RAF_OS_NO_BOOT=1)
  --no-mouse         do not capture the mouse
  --low-cpu          freeze the side rain after the boot
  --dump PAGE        print one screen as plain text and exit (PAGE `inspect` + --param REF
                     prints the inspector screen of an object)
  --render FILE      render a Screen JSON file as plain text (no network) and exit
  --width N          text width for --dump/--render (default: terminal width, or 100)
  --graph-list       draw graph blocks as an indented list in --dump/--render

Environment: RAF_OS_TOKEN (bearer token, never printed), RAF_OS_API, RAF_OS_WORKSPACE,
RAF_OS_NO_BOOT, RAF_OS_COLOR=256 (force the 256-color palette).

Keys: ←/→ pages, ↑/↓ lines, Enter inspect, / parameter, r reload, v graph layout, m rain,
? help, q quit. Mouse: click tabs, pages and lines; wheel scrolls.";

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Interactive,
    Dump(String),
    Render(String),
    Help,
    Version,
}

/// Parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    pub page: Option<String>,
    pub api: Option<String>,
    pub workspace: Option<String>,
    pub param: Option<String>,
    pub width: Option<usize>,
    pub no_boot: bool,
    pub no_mouse: bool,
    pub low_cpu: bool,
    pub graph_list: bool,
}

/// Parses arguments (without the program name).
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        mode: Mode::Interactive,
        page: None,
        api: None,
        workspace: None,
        param: None,
        width: None,
        no_boot: false,
        no_mouse: false,
        low_cpu: false,
        graph_list: false,
    };
    let mut i = 0;
    let set_mode = |out: &mut Args, m: Mode| -> Result<(), String> {
        if out.mode != Mode::Interactive && !matches!(m, Mode::Help | Mode::Version) {
            return Err("--dump and --render cannot be combined".to_string());
        }
        if !matches!(out.mode, Mode::Help | Mode::Version) {
            out.mode = m;
        }
        Ok(())
    };
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => set_mode(&mut out, Mode::Help)?,
            "-V" | "--version" => set_mode(&mut out, Mode::Version)?,
            "--api" => out.api = Some(value("--api")?),
            "--workspace" => out.workspace = Some(value("--workspace")?),
            "--param" => out.param = Some(value("--param")?),
            "--page" => out.page = Some(value("--page")?.trim().to_ascii_lowercase()),
            "--width" => {
                let v = value("--width")?;
                let w: usize = v
                    .parse()
                    .map_err(|_| format!("--width expects a number, got {v:?}"))?;
                if !(20..=1000).contains(&w) {
                    return Err("--width must be between 20 and 1000".to_string());
                }
                out.width = Some(w);
            }
            "--dump" => {
                let v = value("--dump")?;
                set_mode(&mut out, Mode::Dump(v))?;
            }
            "--render" => {
                let v = value("--render")?;
                set_mode(&mut out, Mode::Render(v))?;
            }
            "--no-boot" => out.no_boot = true,
            "--no-mouse" => out.no_mouse = true,
            "--low-cpu" => out.low_cpu = true,
            "--graph-list" => out.graph_list = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += 1;
    }
    if out.page.is_some() && matches!(out.mode, Mode::Dump(_) | Mode::Render(_)) {
        return Err("--page applies to the interactive console (use --dump PAGE)".to_string());
    }
    Ok(out)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_flag(name: &str) -> bool {
    env(name).is_some_and(|v| !matches!(v.trim(), "0" | "false" | "no" | "off"))
}

/// API configuration from flags and environment (flags win; the token comes only from the
/// environment).
pub fn api_config(args: &Args) -> ApiConfig {
    let base = args
        .api
        .clone()
        .or_else(|| env("RAF_OS_API"))
        .unwrap_or_else(|| DEFAULT_API.to_string());
    let workspace = args.workspace.clone().or_else(|| env("RAF_OS_WORKSPACE"));
    ApiConfig::new(&base, env("RAF_OS_TOKEN"), workspace)
}

fn output_width(args: &Args) -> usize {
    args.width.unwrap_or_else(|| {
        if io::stdout().is_terminal() {
            ratatui::crossterm::terminal::size()
                .map(|(w, _)| w as usize)
                .unwrap_or(100)
                .max(20)
        } else {
            100
        }
    })
}

fn print_doc(screen: &Screen, args: &Args) -> i32 {
    let doc = render_screen(
        screen,
        RenderOptions {
            width: output_width(args),
            graph_vertical: args.graph_list,
        },
    );
    let mut out = io::stdout().lock();
    match out.write_all(doc.to_plain().as_bytes()) {
        Ok(()) => 0,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(e) => {
            eprintln!("raf-os: {e}");
            1
        }
    }
}

/// `--render FILE`: renders a Screen JSON file without any network.
pub fn render_file(path: &str, args: &Args) -> i32 {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("raf-os: cannot read {path}: {e}");
            return 1;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("raf-os: {path} is not a screen document: {e}");
            return 1;
        }
    };
    if !value.get("blocks").is_some_and(serde_json::Value::is_array) {
        eprintln!("raf-os: {path} is not a screen document (no \"blocks\" list)");
        return 1;
    }
    match serde_json::from_value::<Screen>(value) {
        Ok(screen) => print_doc(&screen, args),
        Err(e) => {
            eprintln!("raf-os: {path} is not a screen document: {e}");
            1
        }
    }
}

/// `--dump PAGE`: fetches one screen and prints it.
pub fn dump(page: &str, args: &Args) -> i32 {
    let client = Client::new(api_config(args));
    let result = if page == "inspect" {
        match &args.param {
            Some(r) => client.inspect(r),
            None => {
                eprintln!("raf-os: --dump inspect needs --param REF");
                return 2;
            }
        }
    } else {
        let param = match &args.param {
            None => None,
            Some(value) => match client.pages() {
                Ok(doc) => match doc.pages.iter().find(|p| p.id == page) {
                    Some(p) => match &p.param {
                        Some(spec) => Some((spec.name.clone(), value.clone())),
                        None => {
                            eprintln!("raf-os: page {page:?} does not take a parameter");
                            return 2;
                        }
                    },
                    None => {
                        let ids: Vec<&str> = doc.pages.iter().map(|p| p.id.as_str()).collect();
                        eprintln!("raf-os: unknown page {page:?} (pages: {})", ids.join(", "));
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("raf-os: {}", e.summary());
                    return 1;
                }
            },
        };
        client.screen(page, param.as_ref().map(|(n, v)| (n.as_str(), v.as_str())))
    };
    match result {
        Ok(screen) => print_doc(&screen, args),
        Err(e) => {
            eprintln!("raf-os: {}", e.summary());
            for (k, v) in e.rows().into_iter().skip(1) {
                if !k.is_empty() {
                    eprintln!("  {k}: {v}");
                } else {
                    eprintln!("       {v}");
                }
            }
            1
        }
    }
}

fn restore_terminal(mouse: bool) {
    let mut out = io::stdout();
    if mouse {
        let _ = execute!(out, DisableMouseCapture);
    }
    let _ = execute!(out, DisableBracketedPaste, DisableFocusChange, cursor::Show);
    ratatui::restore();
}

/// Checks a `--page` id: the built-in pages are always valid; anything else must be listed
/// by the API's `/tui/pages`. Returns the error message for an unknown id.
pub fn check_page(page: &str, cfg: &ApiConfig) -> Result<(), String> {
    use crate::app::DEFAULT_PAGES;
    if DEFAULT_PAGES.iter().any(|(id, _)| *id == page) {
        return Ok(());
    }
    let known: Vec<String> = match Client::new(cfg.clone()).pages() {
        Ok(doc) if !doc.pages.is_empty() => doc.pages.into_iter().map(|p| p.id).collect(),
        _ => DEFAULT_PAGES
            .iter()
            .map(|(id, _)| (*id).to_string())
            .collect(),
    };
    if known.iter().any(|id| id == page) {
        Ok(())
    } else {
        Err(format!(
            "unknown page {page:?} (pages: {})",
            known.join(", ")
        ))
    }
}

/// Runs the interactive console.
pub fn run_console(args: &Args) -> i32 {
    if let Some(page) = &args.page
        && let Err(msg) = check_page(page, &api_config(args))
    {
        eprintln!("raf-os: {msg}");
        return 2;
    }
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        eprintln!(
            "raf-os: the control panel needs an interactive terminal \
             (use --dump PAGE or --render FILE for plain text)"
        );
        return 2;
    }
    let cfg = api_config(args);
    let mouse = !args.no_mouse;
    let opts = Options {
        api: cfg.clone(),
        boot: !args.no_boot && !env_flag("RAF_OS_NO_BOOT"),
        mouse,
        low_cpu: args.low_cpu,
        start_page: args.page.clone(),
        start_param: args.param.clone(),
    };

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let api_tx = tx.clone();
    let worker = Worker::spawn(Client::new(cfg), 3, move |resp| {
        let _ = api_tx.send(AppEvent::Api(Box::new(resp)));
    });

    let mut terminal = match ratatui::try_init() {
        Ok(t) => t,
        Err(e) => {
            ratatui::restore();
            eprintln!("raf-os: cannot initialize the terminal: {e}");
            return 1;
        }
    };
    // Disable mouse capture before ratatui's own hook restores the screen on panic.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut out = io::stdout();
        let _ = execute!(
            out,
            DisableMouseCapture,
            DisableBracketedPaste,
            DisableFocusChange,
            cursor::Show
        );
        previous(info);
    }));
    {
        let mut out = io::stdout();
        if mouse {
            let _ = execute!(out, EnableMouseCapture);
        }
        let _ = execute!(out, EnableBracketedPaste, EnableFocusChange);
    }

    let input_tx = tx;
    let _ = thread::Builder::new()
        .name("raf-os-input".to_string())
        .spawn(move || {
            loop {
                match event::read() {
                    Ok(ev) => {
                        if input_tx.send(AppEvent::Input(ev)).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = input_tx.send(AppEvent::InputClosed);
                        break;
                    }
                }
            }
        });

    let size = terminal.size().unwrap_or_default();
    let colors = if theme::truecolor_supported() {
        "truecolor"
    } else {
        "256 colors"
    };
    let desc = format!(
        "{}×{} · {colors}{}",
        size.width,
        size.height,
        if mouse { " · mouse" } else { "" }
    );
    let mut app = App::new(opts, worker, &desc);
    let result = app.run(&mut terminal, rx);
    restore_terminal(mouse);
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("raf-os: {e}");
            1
        }
    }
}

/// Entry point; returns the process exit code.
pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("raf-os: {e}\n\n{USAGE}");
            return 2;
        }
    };
    match &args.mode {
        Mode::Help => {
            println!("{USAGE}");
            0
        }
        Mode::Version => {
            println!("raf-os {}", crate::VERSION);
            0
        }
        Mode::Render(path) => render_file(path, &args),
        Mode::Dump(page) => dump(page, &args),
        Mode::Interactive => run_console(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &[&str]) -> Result<Args, String> {
        parse_args(&s.iter().map(|x| x.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_modes_and_flags() {
        let a = parse(&["--dump", "timeline", "--param", "INC-001", "--width=90"]).unwrap();
        assert_eq!(a.mode, Mode::Dump("timeline".into()));
        assert_eq!(a.param.as_deref(), Some("INC-001"));
        assert_eq!(a.width, Some(90));
        let a = parse(&["--render", "x.json", "--graph-list"]).unwrap();
        assert_eq!(a.mode, Mode::Render("x.json".into()));
        assert!(a.graph_list);
        let a = parse(&[
            "--api",
            "http://h:1/api/v1",
            "--workspace=ws",
            "--no-boot",
            "--no-mouse",
            "--low-cpu",
        ])
        .unwrap();
        assert_eq!(a.mode, Mode::Interactive);
        assert_eq!(a.api.as_deref(), Some("http://h:1/api/v1"));
        assert_eq!(a.workspace.as_deref(), Some("ws"));
        assert!(a.no_boot && a.no_mouse && a.low_cpu);
        let a = parse(&["--page", "Oracle", "--param", "Who can reach production?"]).unwrap();
        assert_eq!(a.mode, Mode::Interactive);
        assert_eq!(a.page.as_deref(), Some("oracle"));
        assert_eq!(a.param.as_deref(), Some("Who can reach production?"));
        assert_eq!(parse(&["--version"]).unwrap().mode, Mode::Version);
        assert_eq!(
            parse(&["--render", "a", "--help"]).unwrap().mode,
            Mode::Help
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--width", "abc"]).is_err());
        assert!(parse(&["--width", "5"]).is_err());
        assert!(parse(&["--dump"]).is_err());
        assert!(parse(&["--dump", "a", "--render", "b"]).is_err());
        assert!(parse(&["positional"]).is_err());
        assert!(parse(&["--dump", "home", "--page", "graph"]).is_err());
        assert!(parse(&["--page"]).is_err());
    }
}

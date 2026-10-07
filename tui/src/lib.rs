//! R$F OS: a full-screen, mouse-enabled terminal control panel for the R$F security platform.
//!
//! The binary (`raf-os`, normally started by `raf tui`) talks to the local R$F HTTP API, which
//! serves every page as a *Screen*: a title plus a list of typed blocks (key/value rows, event
//! timelines, causal chains, trees, tables, graphs, ...). This crate turns those blocks into
//! terminal lines ([`render`]), draws them inside a Matrix-styled frame ([`ui`]) and handles
//! keyboard and mouse input ([`app`]). Network access happens on worker threads ([`api`]) so the
//! interface never blocks.
//!
//! Everything that comes from the API is treated as untrusted text: control characters, bidi
//! overrides and zero-width characters are replaced before anything reaches the terminal
//! ([`text::sanitize`]).

pub mod api;
pub mod app;
pub mod boot;
pub mod cli;
pub mod model;
pub mod rain;
pub mod render;
pub mod text;
pub mod theme;
pub mod ui;

/// Version of this binary (also shown in the header and the boot log).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

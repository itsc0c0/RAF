//! `raf-os --render` over every fixture (real `/tui/screen` and `/tui/inspect` responses of the
//! Raven Industries demo, plus hand-written edge cases), and golden snapshots at width 100.
//!
//! Regenerate the snapshots with `RAF_OS_BLESS=1 cargo test --test render_fixtures`.

use std::path::{Path, PathBuf};
use std::process::Command;

use raf_os::model::{Block, PagesDoc, Screen};
use raf_os::render::{RenderOptions, render_screen};
use raf_os::text::{is_forbidden, width};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every screen fixture (everything but the page list and the error body).
fn screen_fixtures() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(root().join("tests/fixtures"))
        .expect("fixtures dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name != "pages.json" && name != "error-404.json"
        })
        .collect();
    v.sort();
    v
}

fn render_cli(path: &Path, width: usize) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_raf-os"))
        .arg("--render")
        .arg(path)
        .arg("--width")
        .arg(width.to_string())
        .output()
        .expect("run raf-os");
    assert!(
        out.status.success(),
        "--render {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 output")
}

fn has_graph(path: &Path) -> bool {
    let s: Screen = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    s.blocks.iter().any(|b| matches!(b, Block::Graph(_)))
}

#[test]
fn all_twelve_pages_and_inspect_screens_are_present() {
    let names: Vec<String> = screen_fixtures()
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().to_string())
        .collect();
    for page in [
        "home",
        "timeline",
        "trace",
        "iam",
        "blast",
        "exposure",
        "policy",
        "ghost",
        "graph",
        "oracle",
        "findings",
        "evidence",
        "inspect-host",
        "inspect-user",
        "inspect-event",
        "inspect-finding",
        "inspect-relationship",
    ] {
        assert!(names.contains(&page.to_string()), "missing fixture {page}");
    }
}

#[test]
fn every_fixture_renders_at_common_widths() {
    for path in screen_fixtures() {
        let graph = has_graph(&path);
        for w in [80usize, 100, 140] {
            let out = render_cli(&path, w);
            assert!(out.lines().count() > 3, "{}: almost empty", path.display());
            for c in out.chars() {
                assert!(
                    c == '\n' || !is_forbidden(c),
                    "{} at {w}: control character {c:?} in output",
                    path.display()
                );
            }
            if !graph {
                for line in out.lines() {
                    assert!(
                        width(line) <= w,
                        "{} at {w}: line too wide ({}): {line}",
                        path.display(),
                        width(line)
                    );
                }
            }
        }
    }
}

#[test]
fn screen_titles_come_first() {
    for path in screen_fixtures() {
        let s: Screen = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let out = render_cli(&path, 100);
        let mut lines = out.lines();
        let first = lines.next().unwrap();
        if !s.title.is_empty() {
            assert!(s.title.starts_with(first.trim_end_matches('…')) || first.contains("R$F"));
        }
        assert_eq!(lines.next().unwrap(), "━".repeat(100), "{}", path.display());
    }
}

#[test]
fn snapshots_at_width_100() {
    let bless = std::env::var_os("RAF_OS_BLESS").is_some();
    let dir = root().join("tests/snapshots");
    let mut failures = Vec::new();
    for path in screen_fixtures() {
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let out = render_cli(&path, 100);
        let snap = dir.join(format!("{stem}.txt"));
        if bless {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&snap, &out).unwrap();
            continue;
        }
        match std::fs::read_to_string(&snap) {
            Ok(expected) if expected == out => {}
            Ok(_) => failures.push(format!("{stem}: output differs from {}", snap.display())),
            Err(_) => failures.push(format!("{stem}: missing snapshot {}", snap.display())),
        }
    }
    assert!(
        failures.is_empty(),
        "{}\n(run with RAF_OS_BLESS=1 to update)",
        failures.join("\n")
    );
}

#[test]
fn pages_fixture_lists_the_twelve_pages_in_order() {
    let p: PagesDoc = serde_json::from_str(
        &std::fs::read_to_string(root().join("tests/fixtures/pages.json")).unwrap(),
    )
    .unwrap();
    let ids: Vec<&str> = p.pages.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "home", "timeline", "trace", "iam", "blast", "exposure", "policy", "ghost", "graph",
            "oracle", "findings", "evidence"
        ]
    );
    assert_eq!(p.stats.objects, Some(426));
    assert_eq!(p.focus.subject_id.as_deref(), Some("user:bob"));
    assert_eq!(p.focus.incident_id.as_deref(), Some("incident:inc-001"));
    // "" defaults mean "no parameter".
    let exposure = p.pages.iter().find(|p| p.id == "exposure").unwrap();
    assert_eq!(exposure.param.as_ref().unwrap().default, None);
    let oracle = p.pages.iter().find(|p| p.id == "oracle").unwrap();
    assert_eq!(oracle.param.as_ref().unwrap().name, "question");
}

#[test]
fn error_fixture_becomes_an_error_panel() {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root().join("tests/fixtures/error-404.json")).unwrap(),
    )
    .unwrap();
    let status = v["status"].as_u64().unwrap() as u16;
    let body = v["body"].to_string();
    let err = raf_os::api::error_from_body(status, &body);
    assert_eq!(err.title(), "ERROR 404 · raf.not_found");
    let doc = raf_os::app::error_doc(&err, 100);
    let plain = doc.to_plain();
    assert!(plain.contains("No object named 'no-such-thing' exists in this workspace."));
    assert!(plain.contains("Import data first"));
    assert!(plain.contains("raf search no-such-thing"));
    assert!(plain.contains("press r to retry"));
}

#[test]
fn ref_map_covers_fixture_references() {
    let load = |name: &str| -> Screen {
        serde_json::from_str(
            &std::fs::read_to_string(root().join("tests/fixtures").join(name)).unwrap(),
        )
        .unwrap()
    };
    // Timeline: every event's lines carry the event reference.
    let s = load("timeline.json");
    let doc = render_screen(&s, RenderOptions::new(100));
    for block in &s.blocks {
        if let Block::Event(e) = block {
            let r = e.reference.as_deref().unwrap();
            // Header plus every (possibly wrapped) detail line.
            let n = doc.refs().iter().filter(|x| **x == Some(r)).count();
            assert!(n > e.lines.len(), "{r}: {n} lines");
        }
    }
    // Oracle: citations are clickable rows; inline [ids] are hotspots.
    let s = load("oracle.json");
    let doc = render_screen(&s, RenderOptions::new(100));
    assert!(doc.refs().contains(&Some("incident:inc-001")));
    assert!(
        doc.hotspots
            .iter()
            .any(|h| h.reference == "rel:1f1434863428c6030311131b")
    );
    // Graph: boxes are hotspots pointing at node ids; drawing lines scroll sideways.
    let s = load("graph.json");
    let Block::Graph(g) = &s.blocks[0] else {
        panic!("graph block first")
    };
    for width in [100, 160, 400] {
        let doc = render_screen(&s, RenderOptions::new(width));
        assert!(doc.lines.iter().any(|l| l.wide));
        assert!(
            doc.hotspots.len() >= 20,
            "{} hotspots at {width}",
            doc.hotspots.len()
        );
        for h in &doc.hotspots {
            assert!(
                g.nodes.iter().any(|n| n.id == h.reference),
                "{}",
                h.reference
            );
        }
    }
    // The vertical layout lists every node with its reference.
    let doc = render_screen(
        &s,
        RenderOptions {
            width: 100,
            graph_vertical: true,
        },
    );
    for n in &g.nodes {
        assert!(doc.refs().contains(&Some(n.id.as_str())), "{}", n.id);
    }
}

#[test]
fn graph_fits_the_requested_width_when_possible() {
    let s: Screen = serde_json::from_str(
        &std::fs::read_to_string(root().join("tests/fixtures/graph.json")).unwrap(),
    )
    .unwrap();
    // Compaction makes the bob graph fit common console widths; narrower panels scroll
    // sideways, starting with the root box centered.
    for width in [140, 200] {
        let doc = render_screen(&s, RenderOptions::new(width));
        let widest = doc.wide_width();
        assert!(widest <= width, "graph drawing {widest} wider than {width}");
        assert_eq!(doc.initial_hscroll, None);
    }
    for width in [53, 100] {
        let doc = render_screen(&s, RenderOptions::new(width));
        let off = doc.initial_hscroll.expect("scroll offset for a wide graph");
        let root = doc.hotspots.first().expect("root box hotspot");
        assert!(
            root.col >= off && root.col + root.width <= off + width,
            "root not in view at {width}"
        );
        assert!(off + width <= doc.wide_width());
    }
}

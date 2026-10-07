//! Unit tests for the block renderers (plain-text output at fixed widths).

use super::*;
use crate::model::Screen;

fn screen(blocks: &str) -> Screen {
    serde_json::from_str(&format!(r#"{{"title":"T","blocks":[{blocks}]}}"#)).expect("valid screen")
}

/// Renders blocks and returns the plain lines after the title header (title, rule, blank).
fn body(blocks: &str, width: usize) -> Vec<String> {
    let doc = render_screen(&screen(blocks), RenderOptions::new(width));
    let plain = doc.to_plain();
    plain.lines().skip(3).map(str::to_string).collect()
}

fn doc(blocks: &str, width: usize) -> Doc {
    render_screen(&screen(blocks), RenderOptions::new(width))
}

#[test]
fn title_rule_and_subtitle() {
    let s: Screen = serde_json::from_str(
        r#"{"page":"timeline","title":"R$F TIMELINE — INC-001","subtitle":"Suspicious production data access","blocks":[]}"#,
    )
    .unwrap();
    let out = render_screen(&s, RenderOptions::new(30)).to_plain();
    assert_eq!(
        out,
        "R$F TIMELINE — INC-001\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nSuspicious production data\naccess\n"
    );
}

#[test]
fn event_and_gap_shape() {
    let lines = body(
        r#"{"t":"event","time":"22:47:00.000","category":"AUTH","lines":["6× failed login for bob on VPN-01 from 203.0.113.45"],"severity":"LOW","ref":"event:a"},
           {"t":"gap","text":"+5m 11s"},
           {"t":"event","time":"22:52:11.000","category":"AUTH","lines":["bob logged into VPN-01 from 203.0.113.45","result=SUCCESS"],"severity":"MEDIUM","ref":"event:b"}"#,
        80,
    );
    let expected = [
        "22:47:00.000  AUTH",
        "               6× failed login for bob on VPN-01 from 203.0.113.45",
        "",
        "       +5m 11s",
        "",
        "22:52:11.000  AUTH",
        "               bob logged into VPN-01 from 203.0.113.45",
        "               result=SUCCESS",
    ];
    assert_eq!(lines, expected);
}

#[test]
fn consecutive_events_are_separated_and_dates_announced() {
    let d = doc(
        r#"{"t":"event","time":"23:59:00.000","date":"2026-10-06","category":"AUTH","lines":["a"],"severity":"INFO","ref":"event:1"},
           {"t":"event","time":"23:59:30.000","date":"2026-10-06","category":"DNS","lines":["b"],"severity":"INFO","ref":"event:2"},
           {"t":"gap","text":"+1m"},
           {"t":"event","time":"00:00:30.000","date":"2026-10-07","category":"HTTP","lines":["c"],"severity":null,"ref":null}"#,
        40,
    );
    let plain = doc_lines(&d);
    let expected = [
        "T",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        "─── 2026-10-06 ─────────────────────────",
        "",
        "23:59:00.000  AUTH",
        "               a",
        "",
        "23:59:30.000  DNS",
        "               b",
        "",
        "       +1m",
        "",
        "─── 2026-10-07 ─────────────────────────",
        "",
        "00:00:30.000  HTTP",
        "               c",
    ];
    assert_eq!(plain, expected);
    // Every line of an event carries its reference.
    assert_eq!(d.reference(5), Some("event:1"));
    assert_eq!(d.reference(6), Some("event:1"));
    assert_eq!(d.reference(8), Some("event:2"));
    assert_eq!(d.reference(15), None);
}

fn doc_lines(d: &Doc) -> Vec<String> {
    d.to_plain().lines().map(str::to_string).collect()
}

#[test]
fn event_detail_lines_wrap_with_hanging_indent() {
    let lines = body(
        r#"{"t":"event","time":"23:06:05.000","category":"PROCESS","lines":["svc-deploy started deploy.sh [9120] on CI-01: deploy.sh --target prod --skip-review"],"severity":"HIGH","ref":null}"#,
        50,
    );
    assert_eq!(lines[0], "23:06:05.000  PROCESS");
    assert_eq!(
        lines[1],
        "               svc-deploy started deploy.sh [9120]"
    );
    assert_eq!(lines[2], "               on CI-01: deploy.sh --target prod");
    assert_eq!(lines[3], "               --skip-review");
}

#[test]
fn chain_shape() {
    let lines = body(
        r#"{"t":"chain","nodes":[
            {"label":"203.0.113.45","type":null,"ref":"ip:203.0.113.45","note":null},
            {"label":"VPN-01","type":"","ref":"host:vpn-01","note":null},
            {"label":"bob","ref":"user:bob"}],
           "edges":[
            {"label":"network observation","kind":"observed","note":"22:52:11 auth.login"},
            {"label":"authenticated as","kind":"modeled","note":null}]}"#,
        80,
    );
    let expected = [
        "      203.0.113.45",
        "           │",
        "           │ network observation   ● observed 22:52:11 auth.login",
        "           ▼",
        "         VPN-01",
        "           │",
        "           │ authenticated as      ◌ modeled",
        "           ▼",
        "          bob",
    ];
    assert_eq!(lines, expected);
}

#[test]
fn chain_type_tags_correlated_edges_and_refs() {
    let d = doc(
        r#"{"t":"chain","nodes":[{"label":"WS-02","type":"host","ref":"host:ws-02","note":"first seen"},{"label":"DEV-01","type":"host","ref":"host:dev-01"}],
           "edges":[{"label":"ssh","kind":"correlated","note":"same minute"}]}"#,
        80,
    );
    let lines = doc_lines(&d);
    // Axis at margin 6 + (6 - 1) / 2 for the widest label (DEV-01).
    assert_eq!(lines[3], "      WS-02 [host] · first seen");
    assert_eq!(lines[4], "        │");
    assert_eq!(lines[5], "        │ ssh   ◐ correlated same minute");
    assert_eq!(lines[6], "        ▼");
    assert_eq!(lines[7], "      DEV-01 [host]");
    assert_eq!(d.reference(3), Some("host:ws-02"));
    assert_eq!(d.reference(5), None);
    assert_eq!(d.reference(7), Some("host:dev-01"));
}

#[test]
fn chain_edges_with_relationship_ids_are_clickable() {
    let d = doc(
        r#"{"t":"chain","nodes":[{"label":"bob","type":"user","ref":"user:bob"},{"label":"DEV-01","type":"host","ref":"host:dev-01"}],
           "edges":[{"label":"LOGGED_INTO","kind":"observed","note":"22:58:03.000 auth.login","ref":"rel:1f14"}]}"#,
        80,
    );
    // Node, │, annotation, ▼, node.
    assert_eq!(
        d.refs()[3..8],
        [
            Some("user:bob"),
            Some("rel:1f14"),
            Some("rel:1f14"),
            Some("rel:1f14"),
            Some("host:dev-01")
        ]
    );
}

#[test]
fn section_heading_and_rule() {
    let lines = body(
        r#"{"t":"text","lines":["Starting assumption:"],"style":"dim"},{"t":"section","text":"REACHABILITY"}"#,
        24,
    );
    assert_eq!(
        lines,
        [
            "Starting assumption:",
            "",
            "REACHABILITY",
            "────────────────────────"
        ]
    );
}

#[test]
fn kv_rows_align_and_wrap() {
    let lines = body(
        r#"{"t":"kv","rows":[{"k":"Reachable objects","v":"37","style":null,"ref":null},
                              {"k":"Controllable hosts","v":"3","style":"warn","ref":"host:x"},
                              {"k":"Why","v":"a long value that has to wrap onto the next line","style":null,"ref":null}]}"#,
        50,
    );
    assert_eq!(lines[0], "Reachable objects    37");
    assert_eq!(lines[1], "Controllable hosts   3");
    assert_eq!(
        lines[2],
        "Why                  a long value that has to wrap"
    );
    assert_eq!(lines[3], "                     onto the next line");
    // Minimum label column of 18.
    assert_eq!(
        body(r#"{"t":"kv","rows":[{"k":"+50","v":"x"}]}"#, 40)[0],
        "+50               x"
    );
}

#[test]
fn kv_ref_map() {
    let d = doc(
        r#"{"t":"kv","rows":[{"k":"Incident","v":"INC-001","style":"accent","ref":"incident:inc-001"},{"k":"Window","v":"40m","ref":null}]}"#,
        60,
    );
    assert_eq!(
        d.refs(),
        vec![None, None, None, Some("incident:inc-001"), None]
    );
    assert!(d.is_clickable(3));
    assert!(!d.is_clickable(4));
}

#[test]
fn text_wraps_and_keeps_indentation() {
    let lines = body(
        r#"{"t":"text","lines":["  source      network:dev","","  a fairly long indented sentence that wraps"],"style":"normal"}"#,
        30,
    );
    assert_eq!(
        lines,
        [
            "  source      network:dev",
            "",
            "  a fairly long indented",
            "  sentence that wraps"
        ]
    );
}

#[test]
fn list_items_hang_under_their_text() {
    let lines = body(
        r#"{"t":"text","lines":["1. remove bob LOGGED_INTO VPN-01 (credential exposure)"],"style":"normal"}"#,
        30,
    );
    assert_eq!(
        lines,
        [
            "1. remove bob LOGGED_INTO",
            "   VPN-01 (credential",
            "   exposure)"
        ]
    );
}

#[test]
fn inline_citations_become_clickable() {
    let d = doc(
        r#"{"t":"text","lines":["path to production [user:bob] [cloud_resource:production] (see [notes])"],"style":"normal"}"#,
        100,
    );
    let line = 3;
    assert_eq!(d.reference(line), Some("user:bob"));
    assert_eq!(d.reference_at(line, 21), Some("user:bob"));
    assert_eq!(d.reference_at(line, 32), Some("cloud_resource:production"));
    // "[notes]" is not an object id; plain text there falls back to the line reference.
    assert_eq!(d.hotspots.len(), 2);
    assert_eq!(
        inline_refs("x [host:dev-01] y"),
        vec![(2, 15, "host:dev-01".to_string())]
    );
    assert!(inline_refs("[Bob] [a b:c] [:x] [x:]").is_empty());
}

#[test]
fn tree_guides() {
    let lines = body(
        r#"{"t":"tree","arrows":false,"root":{"label":"bob","type":"user","ref":"user:bob","note":null,"style":null,"children":[
            {"label":"finance","type":"group","ref":null,"note":"MEMBER_OF","style":null,"children":[
                {"label":"finance-approver","type":null,"ref":null,"note":null,"style":null,"children":[]}]},
            {"label":"all-staff","type":null,"ref":null,"note":null,"style":"dim","children":[]}]}}"#,
        60,
    );
    assert_eq!(
        lines,
        [
            "bob  [user]",
            "├─ finance  [group]  MEMBER_OF",
            "│  └─ finance-approver",
            "└─ all-staff",
        ]
    );
}

#[test]
fn tree_arrow_staircase() {
    let lines = body(
        r#"{"t":"tree","arrows":true,"root":{"label":"bob","children":[{"label":"DEV-01","children":[{"label":"DEPLOY_TOKEN","children":[{"label":"svc-deploy","children":[]}]}]}]}}"#,
        60,
    );
    assert_eq!(
        lines,
        [
            "bob",
            " └─► DEV-01",
            "      └─► DEPLOY_TOKEN",
            "           └─► svc-deploy",
        ]
    );
}

#[test]
fn table_header_rule_rows_and_truncation() {
    let d = doc(
        r#"{"t":"table","columns":["ASSET","SCORE","LEVEL","PRIMARY FACTORS"],"align":["l","r","l","l"],"rows":[
            {"cells":["VPN-01","97","CRITICAL","internet + identity path and a very long explanation"],"style":"danger","ref":"host:vpn-01"},
            {"cells":["DEV-01","84","HIGH","credential + prod path"],"style":null,"ref":null}]}"#,
        60,
    );
    let lines = doc_lines(&d);
    assert_eq!(lines[3], "ASSET    SCORE   LEVEL      PRIMARY FACTORS");
    assert_eq!(lines[4], "─".repeat(60));
    assert_eq!(
        lines[5],
        "VPN-01      97   CRITICAL   internet + identity path and a…"
    );
    assert_eq!(
        lines[6],
        "DEV-01      84   HIGH       credential + prod path"
    );
    assert!(lines.iter().all(|l| text::width(l) <= 60));
    assert_eq!(d.reference(5), Some("host:vpn-01"));
    // Severity words get the severity color, the rest of the row its row style.
    let row = &d.lines[5].line.spans;
    let level = row.iter().find(|s| s.content.contains("CRITICAL")).unwrap();
    assert_eq!(level.style, theme::severity(Severity::Critical));
    assert_eq!(row[0].style, theme::named(StyleName::Danger));
}

#[test]
fn fit_columns_shrinks_last_then_widest() {
    assert_eq!(fit_columns(&[5, 5, 40], 30), vec![5, 5, 20]);
    assert_eq!(fit_columns(&[20, 5, 14], 30), vec![13, 5, 12]);
    assert_eq!(fit_columns(&[3, 3], 100), vec![3, 3]);
}

#[test]
fn finding_block_shape() {
    let d = doc(
        r#"{"t":"finding","severity":"HIGH","title":"Overly broad rule r40-dev-to-prod","id":"r40-dev-to-prod",
            "lines":["ALLOW","  source      network:dev"],"ref":"finding:policy:x"}"#,
        40,
    );
    let lines = doc_lines(&d);
    assert_eq!(
        &lines[3..],
        [
            "HIGH  r40-dev-to-prod",
            &"─".repeat(40),
            "Overly broad rule r40-dev-to-prod",
            "ALLOW",
            "  source      network:dev",
            "",
        ]
    );
    assert!((3..8).all(|i| d.reference(i) == Some("finding:policy:x")));
    assert_eq!(d.reference(8), None);
}

#[test]
fn compare_block_layout_and_verdicts() {
    let lines = body(
        r#"{"t":"compare","left":"BEFORE","right":"AFTER","rows":[
            {"label":"bob → production","before":"REACHABLE","after":"BLOCKED","verdict":"better"},
            {"label":"Blast score","before":"100","after":"31","verdict":"better"},
            {"label":"Open findings","before":"42","after":"44","verdict":"worse"},
            {"label":"Incidents","before":"1","after":"1","verdict":"same"},
            {"label":"Impact","before":"","after":"3 relationships removed","verdict":"info"}]}"#,
        70,
    );
    assert_eq!(lines[0], "                   BEFORE       AFTER");
    assert_eq!(lines[1], "━".repeat(70));
    assert_eq!(
        lines[2],
        "bob → production   REACHABLE  → BLOCKED  ✔ better"
    );
    assert_eq!(
        lines[3],
        "Blast score        100        → 31       ▼ better"
    );
    assert_eq!(lines[4], "Open findings      42         → 44       ▲ worse");
    assert_eq!(lines[5], "Incidents          1          → 1        = same");
    assert_eq!(
        lines[6],
        "Impact                          3 relationships removed"
    );
    // Narrow panels keep only the verdict symbol.
    let narrow = body(
        r#"{"t":"compare","left":"BEFORE","right":"AFTER","rows":[{"label":"Blast score","before":"100","after":"31","verdict":"better"}]}"#,
        30,
    );
    assert_eq!(narrow[2], "Blast score 100    → 31     ▼");
}

#[test]
fn bars_use_partial_blocks() {
    assert_eq!(bar_string(0.5, 4), "██");
    assert_eq!(bar_string(1.0 / 32.0, 4), "▏");
    assert_eq!(bar_string(0.3, 10), "███");
    assert_eq!(bar_string(0.35, 10), "███▌");
    assert_eq!(bar_string(0.0, 10), "");
    assert_eq!(bar_string(0.001, 10), "▏");
    let lines = body(
        r#"{"t":"bars","rows":[{"label":"CRITICAL","value":7,"max":28,"style":"danger"},{"label":"HIGH","value":28,"max":28,"style":"danger"},{"label":"INFO","value":0,"max":28,"style":"dim"}]}"#,
        30,
    );
    assert_eq!(lines[0], "CRITICAL  ████············   7");
    assert_eq!(lines[1], "HIGH      ████████████████  28");
    assert_eq!(lines[2], "INFO      ················   0");
    assert_eq!(fmt_num(2.5), "2.5");
    assert_eq!(fmt_num(20.0), "20");
}

#[test]
fn grid_lays_out_items_in_columns() {
    let lines = body(
        r#"{"t":"grid","columns":2,"items":[{"label":"Graph","status":"BETA","style":"ok"},{"label":"Lab","status":"EXPERIMENTAL","style":"warn"},{"label":"Oracle","status":"BETA","style":"ok"}]}"#,
        60,
    );
    assert_eq!(
        lines,
        [
            "● Graph  BETA                 ● Lab    EXPERIMENTAL",
            "● Oracle BETA"
        ]
    );
}

#[test]
fn citations_and_diagram() {
    let d = doc(
        r#"{"t":"citations","items":[{"id":"host:dev-01","label":"DEV-01","type":"host"},{"id":"user:bob","label":"bob","type":"user"}]}"#,
        40,
    );
    let lines = doc_lines(&d);
    assert_eq!(lines[3], "[host:dev-01]  DEV-01");
    assert_eq!(lines[4], "[user:bob]     bob");
    assert_eq!(d.reference(3), Some("host:dev-01"));
    assert_eq!(d.reference(4), Some("user:bob"));
    let lines = body(
        r#"{"t":"diagram","lines":["RAW LOGS","   ↓","A VERY LONG DIAGRAM LINE THAT IS CLIPPED"],"style":"accent"}"#,
        24,
    );
    assert_eq!(lines, ["RAW LOGS", "   ↓", "A VERY LONG DIAGRAM LINE"]);
}

#[test]
fn spacer_and_unknown_blocks() {
    let lines = body(
        r#"{"t":"text","lines":["a"]},{"t":"spacer"},{"t":"hologram","x":1},{"t":"tree","root":"oops"},{"t":"kv","rows":[{"k":"b","v":"c"}]}"#,
        60,
    );
    assert_eq!(lines[0], "a");
    assert_eq!(lines[1], "");
    assert_eq!(lines[2], "[unsupported block: hologram]");
    assert!(
        lines[3].starts_with("[unsupported block: tree ("),
        "{}",
        lines[3]
    );
    assert!(lines.last().unwrap().starts_with('b'));
}

#[test]
fn hostile_strings_never_reach_the_output() {
    let s: Screen = serde_json::from_str(
        "{\"title\":\"\\u001b]0;pwned\\u0007R$F\",\"subtitle\":\"\\u202egnp.exe\",\"blocks\":[\
         {\"t\":\"text\",\"lines\":[\"\\u001b[2J\\u001b[31mred\\u009b1m \\u200bhidden\\u2066iso\\u2069\"]},\
         {\"t\":\"kv\",\"rows\":[{\"k\":\"\\u001b[1mk\",\"v\":\"v\\r\\nInjected: yes\",\"ref\":\"host:\\u001bx\"}]},\
         {\"t\":\"table\",\"columns\":[\"A\\tB\"],\"rows\":[{\"cells\":[\"\\u0000\\u007f\"]}]},\
         {\"t\":\"graph\",\"nodes\":[{\"id\":\"n\\u001b\",\"label\":\"\\u001b[5mblink\",\"type\":\"h\\u0085\"}],\"links\":[]},\
         {\"t\":\"\\u001b[31mevil\"}]}",
    )
    .unwrap();
    for width in [24, 60, 100] {
        let doc = render_screen(&s, RenderOptions::new(width));
        let plain = doc.to_plain();
        for c in plain.chars() {
            assert!(
                c == '\n' || !crate::text::is_forbidden(c),
                "forbidden {c:?} in output at width {width}:\n{plain}"
            );
        }
        for l in &doc.lines {
            if let Some(r) = &l.reference {
                assert!(!r.chars().any(crate::text::is_forbidden));
            }
        }
        assert!(plain.contains("\u{FFFD}]0;pwned\u{FFFD}R$F"));
        if width >= 60 {
            assert!(
                plain.contains("[unsupported block: \u{FFFD}[31mevil]"),
                "{plain}"
            );
        }
    }
}

#[test]
fn every_line_fits_the_width() {
    let blocks = r#"{"t":"text","lines":["word word word word word word word word word word"]},
        {"t":"kv","rows":[{"k":"a very very long label that exceeds the column","v":"value value value value"}]},
        {"t":"event","time":"2026-10-06 22:47:00","category":"AUTHENTICATION-FAILURE","lines":["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]},
        {"t":"chain","nodes":[{"label":"a label far too long for any narrow terminal width at all"},{"label":"b"}],"edges":[{"label":"an edge label","kind":"observed","note":"with a long note that must wrap somewhere"}]},
        {"t":"table","columns":["A","B","C"],"rows":[{"cells":["xxxxxxxxxxxxxxxxxxxx","yyyyyyyyyyyyyyyyyyyyyyy","zzzzzzzzzzzzzzzzzzzzzzzzzzzz"]}]},
        {"t":"compare","left":"BEFORE","right":"AFTER","rows":[{"label":"a long label","before":"something long","after":"something longer still","verdict":"better"}]},
        {"t":"bars","rows":[{"label":"label","value":3,"max":4}]},
        {"t":"grid","items":[{"label":"Dependency","status":"EXPERIMENTAL"}]},
        {"t":"finding","severity":"LOW","title":"t t t t t t t t t t t t t t t t t t t","id":"id","lines":["l l l l l l l l l l l l l l l l l"]},
        {"t":"citations","items":[{"id":"finding:iam:credential-exposure-path:6409415f44c1","label":"Credentials of svc-deploy exposed"}]}"#;
    for width in [MIN_WIDTH, 30, 41, 80] {
        let d = doc(blocks, width);
        for l in &d.lines {
            let w = text::line_width(&l.line);
            assert!(
                w <= width,
                "line wider than {width}: {:?}",
                text::plain(&l.line)
            );
        }
    }
}

#[test]
fn graph_block_renders_drawing_links_and_hotspots() {
    let d = doc(
        r#"{"t":"graph","root":"user:bob","nodes":[
            {"id":"user:bob","label":"bob","type":"user","criticality":null,"highlight":true,"parent":null,"edge":null,"dir":null},
            {"id":"host:dev-01","label":"DEV-01","type":"host","criticality":"medium","highlight":true,"parent":"user:bob","edge":"LOGGED_INTO","dir":"out"},
            {"id":"file:env","label":".env","type":"file","criticality":null,"highlight":false,"parent":"host:dev-01","edge":"READ","dir":"out"},
            {"id":"service:app","label":"APP","type":"service","criticality":null,"highlight":false,"parent":"host:dev-01","edge":"RUNS","dir":"out"},
            {"id":"vuln:18","label":"VULN-18","type":"vulnerability","criticality":"critical","highlight":false,"parent":"host:dev-01","edge":"HAS","dir":"out"}],
           "links":[{"source":"service:app","target":"file:env","label":"READS"}]}"#,
        80,
    );
    let plain = d.to_plain();
    for needle in [
        "╔══════╗",
        "║ bob  ║",
        "║ ■ DEV-01 ║",
        "LOGGED_INTO",
        "READ",
        "RUNS",
        "HAS",
        "◆ VULN-18",
        "APP ─READS→ .env",
        "OTHER RELATIONSHIPS",
    ] {
        assert!(plain.contains(needle), "missing {needle:?} in\n{plain}");
    }
    // Four connectors (plus the legend's own arrow).
    assert_eq!(plain.matches('▼').count(), 5, "{plain}");
    // Mouse hotspots: one per box; the root line resolves to bob.
    assert_eq!(d.hotspots.len(), 5);
    let bob = d
        .hotspots
        .iter()
        .find(|h| h.reference == "user:bob")
        .unwrap();
    assert_eq!(d.reference_at(bob.line + 1, bob.col + 2), Some("user:bob"));
    assert_eq!(d.reference(bob.line + 1), Some("user:bob"));
    // Drawing lines are horizontally scrollable.
    assert!(d.lines[bob.line].wide);
    // Vertical layout: one line per node, each with its reference.
    let v = render_screen(
        &screen(
            r#"{"t":"graph","nodes":[{"id":"a","label":"A","highlight":true},{"id":"b","label":"B","parent":"a","edge":"E","dir":"in"}],"links":[]}"#,
        ),
        RenderOptions {
            width: 40,
            graph_vertical: true,
        },
    );
    let vl = doc_lines(&v);
    assert_eq!(vl[5], "A");
    assert_eq!(vl[6], "└── ← E B");
    assert_eq!(v.reference(6), Some("b"));
}

#[test]
fn notes_are_rendered_dim_at_the_end() {
    let s: Screen = serde_json::from_str(
        r#"{"title":"T","blocks":[{"t":"text","lines":["x"]}],"notes":["60 objects within 2 hops; 40 drawn"]}"#,
    )
    .unwrap();
    let out = render_screen(&s, RenderOptions::new(40)).to_plain();
    assert!(
        out.ends_with("x\n\n※ 60 objects within 2 hops; 40 drawn\n"),
        "{out}"
    );
}

#[test]
fn message_doc_frames_title() {
    let d = message_doc(
        "R$F API UNREACHABLE",
        theme::severity(Severity::High),
        &[("url".to_string(), "http://127.0.0.1:1/api/v1".to_string())],
        &["press r to retry".to_string()],
        40,
    );
    let lines = doc_lines(&d);
    assert_eq!(lines[0], format!("╔{}╗", "═".repeat(38)));
    assert!(lines[1].starts_with("║  R$F API UNREACHABLE"));
    assert!(lines[1].ends_with('║'));
    assert_eq!(text::width(&lines[1]), 40);
    assert!(lines.iter().any(|l| l == "› press r to retry"));
}

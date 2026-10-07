//! Serde model of the R$F OS screen protocol (`/tui/pages`, `/tui/screen/{page}`,
//! `/tui/inspect`, `/health`).
//!
//! Deserialization is deliberately lenient and forward compatible: unknown fields are ignored,
//! optional values may be missing or `null`, scalars are accepted where strings are expected,
//! unknown block types and malformed blocks become [`Block::Unsupported`] instead of failing the
//! whole screen. Every string is sanitized ([`crate::text::sanitize`]) while it is decoded, so
//! nothing downstream ever sees a raw control character.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::text::clean;

/// Lenient field decoders (used through `#[serde(deserialize_with = ...)]`).
pub mod de {
    use super::*;

    fn scalar(v: &Value) -> Option<String> {
        match v {
            Value::Null => None,
            Value::String(s) => Some(clean(s)),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(n.to_string()),
            other => Some(clean(&other.to_string())),
        }
    }

    /// Any scalar as a string; `null`/missing → `""`.
    pub fn string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(scalar(&Value::deserialize(d)?).unwrap_or_default())
    }

    /// Any scalar as a string; `null` → `None`.
    pub fn opt_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        Ok(scalar(&Value::deserialize(d)?))
    }

    /// Like [`opt_string`], but blank strings are `None` too.
    pub fn opt_nonempty<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        Ok(scalar(&Value::deserialize(d)?).filter(|s| !s.trim().is_empty()))
    }

    /// An array of scalars (a single scalar becomes a one-element list; `null` → empty).
    pub fn strings<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Array(items) => items
                .iter()
                .map(|v| scalar(v).unwrap_or_default())
                .collect(),
            Value::Null => Vec::new(),
            other => scalar(&other).into_iter().collect(),
        })
    }

    fn number_of(v: &Value) -> Option<f64> {
        match v {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
        .filter(|x: &f64| x.is_finite())
    }

    /// A number (or numeric string); anything else → 0.
    pub fn number<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        Ok(number_of(&Value::deserialize(d)?).unwrap_or(0.0))
    }

    /// An optional number (or numeric string).
    pub fn opt_number<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
        Ok(number_of(&Value::deserialize(d)?))
    }

    /// An optional non-negative integer (or numeric string).
    pub fn opt_count<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        Ok(number_of(&Value::deserialize(d)?)
            .filter(|x| *x >= 0.0)
            .map(|x| x.round() as u64))
    }

    /// A boolean (`true`, non-zero numbers, `"true"`/`"yes"`/`"1"`).
    pub fn boolean<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Bool(b) => b,
            Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
            Value::String(s) => matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "true" | "yes" | "1" | "on"
            ),
            _ => false,
        })
    }

    /// `null` → `T::default()`.
    pub fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default,
    {
        Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
    }

    /// A list whose malformed elements are skipped instead of failing the whole list.
    pub fn list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned,
    {
        Ok(match Value::deserialize(d)? {
            Value::Array(items) => items
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect(),
            _ => Vec::new(),
        })
    }

    /// An optional object that falls back to `None` when malformed.
    pub fn opt_object<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned,
    {
        Ok(match Value::deserialize(d)? {
            Value::Null => None,
            v => serde_json::from_value(v).ok(),
        })
    }
}

/// Named text style of a block, row or node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StyleName {
    #[default]
    Normal,
    Dim,
    Accent,
    Ok,
    Info,
    Warn,
    Danger,
    Note,
}

impl StyleName {
    /// Parses a style name; unknown names are `Normal`.
    pub fn parse(s: &str) -> StyleName {
        match s.trim().to_ascii_lowercase().as_str() {
            "dim" => StyleName::Dim,
            "accent" => StyleName::Accent,
            "ok" => StyleName::Ok,
            "info" => StyleName::Info,
            "warn" | "warning" => StyleName::Warn,
            "danger" | "error" => StyleName::Danger,
            "note" => StyleName::Note,
            _ => StyleName::Normal,
        }
    }
}

impl<'de> Deserialize<'de> for StyleName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::String(s) => StyleName::parse(&s),
            _ => StyleName::Normal,
        })
    }
}

/// Severity levels, lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parses a severity word (case-insensitive).
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_uppercase().as_str() {
            "INFO" | "INFORMATIONAL" => Some(Severity::Info),
            "LOW" => Some(Severity::Low),
            "MEDIUM" | "MODERATE" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Severity named by the first word of `s` (e.g. `"CRITICAL 97"`, `"HIGH (0.80)"`).
    pub fn leading(s: &str) -> Option<Severity> {
        s.split_whitespace().next().and_then(Severity::parse)
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

fn de_severity<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Severity>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) => Severity::parse(&s),
        _ => None,
    })
}

// ---------------------------------------------------------------------------------------------
// /tui/pages

/// `GET /tui/pages`: system summary, statistics, focus and the page list.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PagesDoc {
    #[serde(deserialize_with = "de::nullable")]
    pub system: SystemInfo,
    #[serde(deserialize_with = "de::nullable")]
    pub stats: Stats,
    #[serde(deserialize_with = "de::nullable")]
    pub focus: Focus,
    #[serde(deserialize_with = "de::list")]
    pub pages: Vec<PageInfo>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SystemInfo {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub version: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub workspace: Option<String>,
    #[serde(deserialize_with = "de::opt_count")]
    pub products: Option<u64>,
    #[serde(deserialize_with = "de::opt_count")]
    pub available: Option<u64>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub oracle: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Stats {
    #[serde(deserialize_with = "de::opt_count")]
    pub objects: Option<u64>,
    #[serde(deserialize_with = "de::opt_count")]
    pub relationships: Option<u64>,
    #[serde(deserialize_with = "de::opt_count")]
    pub events: Option<u64>,
    #[serde(deserialize_with = "de::opt_count")]
    pub findings_open: Option<u64>,
    #[serde(deserialize_with = "de::opt_count")]
    pub incidents: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Focus {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub incident: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub incident_id: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub subject: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub subject_id: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub target: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub target_id: Option<String>,
}

/// One page of the control panel.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct PageInfo {
    #[serde(deserialize_with = "de::string")]
    pub id: String,
    #[serde(deserialize_with = "de::string")]
    pub title: String,
    #[serde(deserialize_with = "de::opt_object")]
    pub param: Option<ParamSpec>,
}

impl PageInfo {
    /// Title to show (falls back to the upper-cased id).
    pub fn display_title(&self) -> String {
        if self.title.trim().is_empty() {
            self.id.to_uppercase()
        } else {
            self.title.clone()
        }
    }
}

/// The parameter a page accepts (`?{name}={value}`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ParamSpec {
    #[serde(deserialize_with = "de::string")]
    pub name: String,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub label: Option<String>,
    /// Default value; `None` (or `""` on the wire) means "no parameter".
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub default: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Screens

/// A screen: what one page (or the inspector) shows.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Screen {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub page: Option<String>,
    #[serde(deserialize_with = "de::string")]
    pub title: String,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub subtitle: Option<String>,
    /// The effective parameter value the server used.
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub param: Option<String>,
    #[serde(deserialize_with = "de::nullable")]
    pub blocks: Vec<Block>,
    #[serde(deserialize_with = "de::strings")]
    pub notes: Vec<String>,
}

/// One block of a screen.
#[derive(Debug, Clone)]
pub enum Block {
    Section(SectionBlock),
    Text(TextBlock),
    Kv(KvBlock),
    Event(EventBlock),
    Gap(GapBlock),
    Chain(ChainBlock),
    Tree(TreeBlock),
    Table(TableBlock),
    Finding(FindingBlock),
    Compare(CompareBlock),
    Graph(GraphBlock),
    Diagram(DiagramBlock),
    Citations(CitationsBlock),
    Bars(BarsBlock),
    Grid(GridBlock),
    Spacer,
    /// An unknown block type (`detail` is `None`) or a known type that failed to decode.
    Unsupported {
        kind: String,
        detail: Option<String>,
    },
}

impl Block {
    /// Decodes one block from JSON; never fails.
    pub fn from_value(v: Value) -> Block {
        let kind = match v.get("t") {
            Some(Value::String(s)) => clean(s),
            Some(other) => clean(&other.to_string()),
            None => String::from("?"),
        };
        fn parse<T: DeserializeOwned>(v: Value, kind: &str, wrap: fn(T) -> Block) -> Block {
            match serde_json::from_value::<T>(v) {
                Ok(b) => wrap(b),
                Err(e) => Block::Unsupported {
                    kind: kind.to_string(),
                    detail: Some(clean(&e.to_string())),
                },
            }
        }
        match kind.as_str() {
            "section" => parse(v, &kind, Block::Section),
            "text" => parse(v, &kind, Block::Text),
            "kv" => parse(v, &kind, Block::Kv),
            "event" => parse(v, &kind, Block::Event),
            "gap" => parse(v, &kind, Block::Gap),
            "chain" => parse(v, &kind, Block::Chain),
            "tree" => parse(v, &kind, Block::Tree),
            "table" => parse(v, &kind, Block::Table),
            "finding" => parse(v, &kind, Block::Finding),
            "compare" => parse(v, &kind, Block::Compare),
            "graph" => parse(v, &kind, Block::Graph),
            "diagram" => parse(v, &kind, Block::Diagram),
            "citations" => parse(v, &kind, Block::Citations),
            "bars" => parse(v, &kind, Block::Bars),
            "grid" => parse(v, &kind, Block::Grid),
            "spacer" => Block::Spacer,
            _ => Block::Unsupported { kind, detail: None },
        }
    }

    /// The block type name (`t`).
    pub fn kind(&self) -> &str {
        match self {
            Block::Section(_) => "section",
            Block::Text(_) => "text",
            Block::Kv(_) => "kv",
            Block::Event(_) => "event",
            Block::Gap(_) => "gap",
            Block::Chain(_) => "chain",
            Block::Tree(_) => "tree",
            Block::Table(_) => "table",
            Block::Finding(_) => "finding",
            Block::Compare(_) => "compare",
            Block::Graph(_) => "graph",
            Block::Diagram(_) => "diagram",
            Block::Citations(_) => "citations",
            Block::Bars(_) => "bars",
            Block::Grid(_) => "grid",
            Block::Spacer => "spacer",
            Block::Unsupported { kind, .. } => kind,
        }
    }
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Block::from_value(Value::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SectionBlock {
    #[serde(deserialize_with = "de::string")]
    pub text: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TextBlock {
    #[serde(deserialize_with = "de::strings")]
    pub lines: Vec<String>,
    pub style: StyleName,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KvBlock {
    #[serde(deserialize_with = "de::list")]
    pub rows: Vec<KvRow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KvRow {
    #[serde(deserialize_with = "de::string")]
    pub k: String,
    #[serde(deserialize_with = "de::string")]
    pub v: String,
    pub style: StyleName,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EventBlock {
    #[serde(deserialize_with = "de::string")]
    pub time: String,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub date: Option<String>,
    #[serde(deserialize_with = "de::string")]
    pub category: String,
    #[serde(deserialize_with = "de::strings")]
    pub lines: Vec<String>,
    #[serde(deserialize_with = "de_severity")]
    pub severity: Option<Severity>,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GapBlock {
    #[serde(deserialize_with = "de::string")]
    pub text: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ChainBlock {
    #[serde(deserialize_with = "de::list")]
    pub nodes: Vec<ChainNode>,
    #[serde(deserialize_with = "de::list")]
    pub edges: Vec<ChainEdge>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ChainNode {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(rename = "type", deserialize_with = "de::opt_nonempty")]
    pub kind: Option<String>,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ChainEdge {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(deserialize_with = "de::string")]
    pub kind: String,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub note: Option<String>,
    /// Not part of the contract yet; accepted for forward compatibility.
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TreeBlock {
    #[serde(deserialize_with = "de::nullable")]
    pub root: TreeNode,
    #[serde(deserialize_with = "de::boolean")]
    pub arrows: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TreeNode {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(rename = "type", deserialize_with = "de::opt_nonempty")]
    pub kind: Option<String>,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub note: Option<String>,
    #[serde(deserialize_with = "de::nullable")]
    pub style: Option<StyleName>,
    #[serde(deserialize_with = "de::list")]
    pub children: Vec<TreeNode>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TableBlock {
    #[serde(deserialize_with = "de::strings")]
    pub columns: Vec<String>,
    #[serde(deserialize_with = "de::strings")]
    pub align: Vec<String>,
    #[serde(deserialize_with = "de::list")]
    pub rows: Vec<TableRow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TableRow {
    #[serde(deserialize_with = "de::strings")]
    pub cells: Vec<String>,
    pub style: StyleName,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FindingBlock {
    #[serde(deserialize_with = "de_severity")]
    pub severity: Option<Severity>,
    #[serde(deserialize_with = "de::string")]
    pub title: String,
    #[serde(deserialize_with = "de::string")]
    pub id: String,
    #[serde(deserialize_with = "de::strings")]
    pub lines: Vec<String>,
    #[serde(rename = "ref", deserialize_with = "de::opt_nonempty")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CompareBlock {
    #[serde(deserialize_with = "de::string")]
    pub left: String,
    #[serde(deserialize_with = "de::string")]
    pub right: String,
    #[serde(deserialize_with = "de::list")]
    pub rows: Vec<CompareRow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CompareRow {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(deserialize_with = "de::string")]
    pub before: String,
    #[serde(deserialize_with = "de::string")]
    pub after: String,
    #[serde(deserialize_with = "de::string")]
    pub verdict: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GraphBlock {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub root: Option<String>,
    #[serde(deserialize_with = "de::list")]
    pub nodes: Vec<GraphNode>,
    #[serde(deserialize_with = "de::list")]
    pub links: Vec<GraphLink>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GraphNode {
    #[serde(deserialize_with = "de::string")]
    pub id: String,
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(rename = "type", deserialize_with = "de::opt_nonempty")]
    pub kind: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub criticality: Option<String>,
    #[serde(deserialize_with = "de::boolean")]
    pub highlight: bool,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub parent: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub edge: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub dir: Option<String>,
}

impl GraphNode {
    /// Label to draw (falls back to the id).
    pub fn display_label(&self) -> &str {
        if self.label.trim().is_empty() {
            &self.id
        } else {
            &self.label
        }
    }

    /// True when the relationship points from the child to its parent.
    pub fn is_incoming(&self) -> bool {
        self.dir
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case("in"))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GraphLink {
    #[serde(deserialize_with = "de::string")]
    pub source: String,
    #[serde(deserialize_with = "de::string")]
    pub target: String,
    #[serde(deserialize_with = "de::string")]
    pub label: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DiagramBlock {
    #[serde(deserialize_with = "de::strings")]
    pub lines: Vec<String>,
    pub style: StyleName,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CitationsBlock {
    #[serde(deserialize_with = "de::list")]
    pub items: Vec<Citation>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Citation {
    #[serde(deserialize_with = "de::string")]
    pub id: String,
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(rename = "type", deserialize_with = "de::opt_nonempty")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BarsBlock {
    #[serde(deserialize_with = "de::list")]
    pub rows: Vec<BarRow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BarRow {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(deserialize_with = "de::number")]
    pub value: f64,
    #[serde(deserialize_with = "de::opt_number")]
    pub max: Option<f64>,
    pub style: StyleName,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GridBlock {
    #[serde(deserialize_with = "de::opt_count")]
    pub columns: Option<u64>,
    #[serde(deserialize_with = "de::list")]
    pub items: Vec<GridItem>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GridItem {
    #[serde(deserialize_with = "de::string")]
    pub label: String,
    #[serde(deserialize_with = "de::string")]
    pub status: String,
    pub style: StyleName,
}

// ---------------------------------------------------------------------------------------------
// Errors and health

/// Error body of any response with status ≥ 400: `{"error": {...}}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ErrorBody {
    #[serde(deserialize_with = "de::opt_object")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ErrorDetail {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub code: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub message: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub hint: Option<String>,
    #[serde(deserialize_with = "de::strings")]
    pub suggestions: Vec<String>,
}

/// `GET /health`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Health {
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub status: Option<String>,
    #[serde(deserialize_with = "de::opt_nonempty")]
    pub version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_malformed_blocks_are_kept_as_unsupported() {
        let s: Screen = serde_json::from_str(
            r#"{"title":"T","blocks":[
                {"t":"hologram","beam":1},
                {"t":"section","text":"OK"},
                {"t":"tree","root":"not an object"},
                {"no_type":true}
            ]}"#,
        )
        .unwrap();
        assert_eq!(s.blocks.len(), 4);
        assert!(
            matches!(&s.blocks[0], Block::Unsupported { kind, detail: None } if kind == "hologram")
        );
        assert!(matches!(&s.blocks[1], Block::Section(b) if b.text == "OK"));
        assert!(
            matches!(&s.blocks[2], Block::Unsupported { kind, detail: Some(_) } if kind == "tree")
        );
        assert!(matches!(&s.blocks[3], Block::Unsupported { kind, .. } if kind == "?"));
    }

    #[test]
    fn lenient_scalars_and_nulls() {
        let s: Screen = serde_json::from_str(
            r#"{"title":null,"subtitle":"","param":"","notes":null,"blocks":[
                {"t":"kv","rows":[{"k":"Score","v":97,"style":"DANGER","ref":null},{"k":1.5,"v":true}]},
                {"t":"bars","rows":[{"label":"HIGH","value":"20","max":null,"style":"bogus"}]},
                {"t":"event","time":"22:47:00.000","category":"AUTH","lines":"single","severity":"medium","ref":""}
            ],"future":{"x":1}}"#,
        )
        .unwrap();
        assert_eq!(s.title, "");
        assert_eq!(s.subtitle, None);
        assert_eq!(s.param, None);
        let Block::Kv(kv) = &s.blocks[0] else {
            panic!()
        };
        assert_eq!(kv.rows[0].v, "97");
        assert_eq!(kv.rows[0].style, StyleName::Danger);
        assert_eq!(kv.rows[1].k, "1.5");
        assert_eq!(kv.rows[1].v, "true");
        let Block::Bars(bars) = &s.blocks[1] else {
            panic!()
        };
        assert_eq!(bars.rows[0].value, 20.0);
        assert_eq!(bars.rows[0].style, StyleName::Normal);
        let Block::Event(ev) = &s.blocks[2] else {
            panic!()
        };
        assert_eq!(ev.lines, vec!["single"]);
        assert_eq!(ev.severity, Some(Severity::Medium));
        assert_eq!(ev.reference, None);
    }

    #[test]
    fn strings_are_sanitized_while_decoding() {
        let s: Screen = serde_json::from_str(
            "{\"title\":\"evil\\u001b[2J\\u202etxt.exe\",\"blocks\":[{\"t\":\"text\",\"lines\":[\"a\\u0007b\\u009bc\"]}]}",
        )
        .unwrap();
        assert_eq!(s.title, "evil\u{FFFD}[2J\u{FFFD}txt.exe");
        let Block::Text(t) = &s.blocks[0] else {
            panic!()
        };
        assert_eq!(t.lines[0], "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn pages_doc_tolerates_nulls_and_empty_defaults() {
        let p: PagesDoc = serde_json::from_str(
            r#"{"system":null,"stats":{"objects":"426","events":562.0},"focus":{"incident":"","subject":"bob"},
                "pages":[{"id":"home","title":"HOME","param":null},
                         {"id":"exposure","title":"","param":{"name":"ref","label":"asset","default":""}},
                         "garbage"]}"#,
        )
        .unwrap();
        assert_eq!(p.stats.objects, Some(426));
        assert_eq!(p.stats.events, Some(562));
        assert_eq!(p.focus.incident, None);
        assert_eq!(p.focus.subject.as_deref(), Some("bob"));
        assert_eq!(p.pages.len(), 2);
        assert_eq!(p.pages[1].display_title(), "EXPOSURE");
        assert_eq!(p.pages[1].param.as_ref().unwrap().default, None);
    }

    #[test]
    fn severity_parsing() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(Severity::leading("CRITICAL 97"), Some(Severity::Critical));
        assert_eq!(Severity::leading("HIGH (0.80)"), Some(Severity::High));
        assert_eq!(Severity::leading("investigating"), None);
    }
}

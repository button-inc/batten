//! Mutant schemata: every mutant of a sweep compiled into ONE build, each
//! behind a runtime switch, so a mutant costs its covering cases and no
//! build of its own (CLOUD-2253).
//!
//! # Why
//!
//! cargo-mutants builds once per mutant. On #1276 that was 2,865 incremental
//! builds of one crate at a median 25 s, against a median 2.5 s of covering
//! cases: the build was 85% of every mutant and the whole of the sweep's
//! length. Untch, Offutt and Harrold's mutant schemata (1993) compile every
//! mutant at once and select one at run time; the `mutest-rs` tool (ICST
//! 2023) does it for Rust inside rustc, which ties it to a nightly
//! compiler. This does it at the source, from cargo-mutants' own listing,
//! on the stable toolchain the tree builds with.
//!
//! # The rewrite
//!
//! A mutant `N` becomes a branch on `crate::__batten_mutant(N)`, which reads
//! `BATTEN_MUTANT` once:
//!
//! * a function body: `if m(N) { replacement } else { original }`;
//! * an operator: the expression it joins, `(if m(N) { a != b } else { a == b })`;
//! * a guard: `(if m(N) { true } else { guard })`;
//! * a deleted match arm: the arm's guard gains `&& !m(N)`.
//!
//! Several mutants of one site nest as `else if`, and a mutant inside another's
//! site is rendered inside both of its branches, innermost first.
//!
//! # What stays classic
//!
//! A site the rewrite cannot express is handed back to cargo-mutants rather
//! than rendered: a const context (a runtime switch does not compile there), a
//! body returning `impl Trait` (two branches would be two types), a struct
//! field, and anything the parser does not place.

use super::trace;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;

use ra_ap_syntax::{AstNode as _, SourceFile, SyntaxKind, SyntaxNode, TextRange, TextSize, ast};

/// The environment variable that selects the active mutant.
pub const ACTIVE: &str = "BATTEN_MUTANT";

/// The switch every mutated crate root gains, for a schema of `probes`
/// function probes.
///
/// RECORDING TOO: under `BATTEN_MUTANT_RECORD` each process appends every
/// mutant site it reaches (`<id>`) and every function it executes (`f<id>`),
/// once each, to a file named by its pid in that directory, written
/// unbuffered so a process killed mid-case still leaves its record. A
/// function's probe costs one relaxed load once it has fired.
#[must_use]
pub fn prelude(probes: usize) -> String {
    format!(
        "\n#[doc(hidden)]\n#[allow(dead_code, unreachable_pub, clippy::all)]\n\
pub(crate) fn __batten_record(line: std::fmt::Arguments<'_>) {{\n    \
static REACHED: std::sync::OnceLock<Option<std::sync::Mutex<std::fs::File>>> = std::sync::OnceLock::new();\n    \
if let Some(file) = REACHED.get_or_init(|| {{\n        \
let dir = std::env::var_os(\"BATTEN_MUTANT_RECORD\")?;\n        \
let file = std::fs::OpenOptions::new().create(true).append(true).open(std::path::Path::new(&dir).join(std::process::id().to_string())).ok()?; // stream: probe lines, committed by the case record's done file\n        \
Some(std::sync::Mutex::new(file))\n    \
}}) && let Ok(mut file) = file.lock() {{\n        \
let _ = std::io::Write::write_fmt(&mut *file, format_args!(\"{{line}}\\n\"));\n    \
}}\n}}\n\
#[doc(hidden)]\n#[allow(dead_code, unreachable_pub, clippy::all)]\n\
pub(crate) fn __batten_mutant(id: u32) -> bool {{\n    \
static ACTIVE: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();\n    \
static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u32>>> = std::sync::OnceLock::new();\n    \
if let Ok(mut seen) = SEEN.get_or_init(Default::default).lock() && seen.insert(id) {{\n        \
__batten_record(format_args!(\"{{id}}\"));\n    \
}}\n    \
*ACTIVE.get_or_init(|| std::env::var(\"BATTEN_MUTANT\").ok().and_then(|v| v.parse().ok())) \
== Some(id)\n}}\n\
#[doc(hidden)]\n#[allow(dead_code, unreachable_pub, clippy::all)]\n\
pub(crate) fn __batten_fn(id: usize) {{\n    \
static SEEN: [std::sync::atomic::AtomicBool; {probes}] = \
[const {{ std::sync::atomic::AtomicBool::new(false) }}; {probes}];\n    \
if let Some(seen) = SEEN.get(id) && !seen.load(std::sync::atomic::Ordering::Relaxed) \
&& !seen.swap(true, std::sync::atomic::Ordering::Relaxed) {{\n        \
__batten_record(format_args!(\"f{{id}}\"));\n    \
}}\n}}\n"
    )
}

/// The directory a recording case's processes write their reached sites to.
pub const RECORD: &str = "BATTEN_MUTANT_RECORD";

/// The directory every case's reach is recorded under.
pub const REACH: &str = "BATTEN_SCHEMA_REACH";

/// The first argument that makes this binary nextest's recording wrapper.
pub const RECORD_ARG: &str = "__schema-record";

/// The schema tree a recording case runs in, which its touched paths are
/// taken relative to.
pub const TREE_ENV: &str = "BATTEN_SCHEMA_TREE";

/// The file in a case's record listing the tree paths it touched; absent when
/// the case was not traced.
const READ: &str = "read";

/// The tracer's raw output in a case's record, removed once read.
const TRACE: &str = "trace";

/// The tree paths a trace shows touched, relative to `tree`, or `None` when
/// the trace cannot be read whole ([`trace::touched`]) or it read the tree's
/// `.git`, which depends on every tracked file. Paths outside the tree and
/// under its `target/` are a run's own, not its inputs.
fn read_trace(trace: &str, tree: &[std::path::PathBuf]) -> Option<BTreeSet<String>> {
    let mut read = BTreeSet::new();
    for path in trace::touched(trace, None)? {
        let Some(relative) = tree.iter().find_map(|root| path.strip_prefix(root).ok()) else {
            continue;
        };
        let relative = relative.to_string_lossy().into_owned();
        if relative == ".git" || relative.starts_with(".git/") {
            return None;
        }
        if relative == "target" || relative.starts_with("target/") {
            continue;
        }
        read.insert(relative);
    }
    Some(read)
}

/// One mutant as `cargo mutants --list --json` names it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Listed {
    /// cargo-mutants' name for it, which `-F` matches.
    pub name: String,
    /// The file, relative to the tree.
    pub file: String,
    /// The package it is compiled into.
    pub package: String,
    /// What kind of change it is.
    pub genre: String,
    /// The text that replaces the span.
    pub replacement: String,
    /// What it replaces.
    pub span: Span,
    /// The function it is in.
    pub function: Option<Function>,
}

/// A 1-based line and 1-based character column range.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct Span {
    /// Where it starts.
    pub start: Position,
    /// Where it ends, exclusive.
    pub end: Position,
}

/// A 1-based line and character column.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct Position {
    /// The line.
    pub line: usize,
    /// The character column.
    pub column: usize,
}

/// The function a mutant is in.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Function {
    /// Its name.
    pub function_name: String,
    /// Its return type as written, `-> T`, or empty.
    pub return_type: String,
    /// Where the whole function is.
    #[serde(default)]
    pub span: Option<Span>,
}

/// The byte offset of `position` in `text`, or `None` past its end.
#[must_use]
pub fn offset(text: &str, position: Position) -> Option<usize> {
    let mut line_start = 0;
    for _ in 1..position.line {
        line_start += text[line_start..].find('\n')? + 1;
    }
    let rest = &text[line_start..];
    let line = &rest[..rest.find('\n').unwrap_or(rest.len())];
    let column = position.column.checked_sub(1)?;
    if column == 0 {
        return Some(line_start);
    }
    line.char_indices()
        .nth(column)
        .map(|(at, _)| line_start + at)
        .or_else(|| (line.chars().count() == column).then(|| line_start + line.len()))
}

/// How a site is switched.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Wrap {
    /// An operator token replaced, per mutant: the site is its expression.
    Op {
        op: Range<usize>,
        alts: Vec<(u32, String)>,
    },
    /// A function body's contents replaced, per mutant.
    Body(Vec<(u32, String)>),
    /// A guard's condition replaced, per mutant.
    Guard(Vec<(u32, String)>),
    /// A match arm switched off, per mutant: the site is its guard's condition,
    /// or the point after its pattern where it has none.
    ArmOff(Vec<u32>),
    /// A `const fn`'s `const` dropped, so a switch can run in its body. Renders
    /// as nothing and owns nothing: a const caller it breaks is answered by
    /// [`unviable`] through [`Rendered::deconst`].
    Erase,
    /// A function probe, inserted at the start of a body: the statement that
    /// records the function as executed. Owns no mutant.
    Probe(String),
}

/// One switched site and everything that switches it.
#[derive(Debug, Clone)]
struct Site {
    range: Range<usize>,
    wraps: Vec<Wrap>,
    children: Vec<Site>,
}

/// The rendered file, and which mutant owns each stretch of it.
#[derive(Debug, Default)]
pub struct Rendered {
    /// The switched source.
    pub text: String,
    /// Byte ranges of the output, each with the mutants a compile error inside
    /// it belongs to. The innermost range holding an error decides.
    pub regions: Vec<(Range<usize>, Vec<u32>)>,
    /// Mutants handed back to cargo-mutants.
    pub classic: Vec<u32>,
    /// Each `const fn` whose `const` the rendering dropped: its name as
    /// cargo-mutants lists it, and the mutants placed in its body.
    pub deconst: Vec<(String, Vec<u32>)>,
    /// Each probed function's source digest, in probe-id order from the id
    /// the rendering was given.
    pub probes: Vec<String>,
    /// The output ranges the probes were written at, so a compile error at
    /// one unprobes the file rather than reading as a mutant's.
    pub probe_regions: Vec<Range<usize>>,
    /// The digest of the source with every probed body cut out: types,
    /// consts, `const fn`s, macros and signatures, which no probe records
    /// but every run depends on. The whole source where nothing is probed.
    pub skeleton: String,
    /// Each probed function's names, in probe-id order ([`names_in`]).
    pub names: Vec<BTreeSet<String>>,
    /// Each located mutant's innermost probed function, by digest.
    pub mutant_fns: Vec<(u32, String)>,
    /// Each skeleton item's mentioned names, under every name it answers to.
    pub mentions: Vec<(String, BTreeSet<String>)>,
    /// Each skeleton item's digest under every name it answers to.
    pub items: Vec<(String, String)>,
    /// Each probed function's own name, in probe-id order: what a call by
    /// that name may reach ([`test_digests`]'s same-name term).
    pub fn_names: Vec<String>,
    /// Each probed function's byte range in the source, in probe-id order.
    pub fn_spans: Vec<Range<usize>>,
}

impl Rendered {
    /// The mutants a compile error at byte `at` of the output belongs to.
    #[must_use]
    pub fn owners(&self, at: usize) -> Option<&[u32]> {
        self.regions
            .iter()
            .filter(|(range, _)| range.start <= at && at < range.end.max(range.start + 1))
            .min_by_key(|(range, _)| range.end - range.start)
            .map(|(_, ids)| ids.as_slice())
    }
}

/// Where a node is evaluated.
#[derive(Debug, PartialEq, Eq)]
enum Context {
    /// At run time only.
    Runtime,
    /// Inside a const item, static, const argument or array length, where no
    /// switch can run: handed back.
    ConstItem,
    /// Inside a `const fn`: switched, with the `const` (and the space after
    /// it) at this range dropped. A `const fn` also runs at run time, and
    /// only a caller in a const context needs it const.
    ConstFn(Range<usize>),
}

fn const_context(node: &SyntaxNode) -> Context {
    let mut context = Context::Runtime;
    for ancestor in node.ancestors() {
        match ancestor.kind() {
            SyntaxKind::CONST
            | SyntaxKind::STATIC
            | SyntaxKind::CONST_ARG
            | SyntaxKind::ARRAY_TYPE => return Context::ConstItem,
            SyntaxKind::FN if context == Context::Runtime => {
                if let Some(token) = ast::Fn::cast(ancestor).and_then(|f| f.const_token()) {
                    let end = token
                        .next_token()
                        .filter(|next| next.kind() == SyntaxKind::WHITESPACE)
                        .map_or(token.text_range().end(), |next| next.text_range().end());
                    context =
                        Context::ConstFn(usize::from(token.text_range().start())..usize::from(end));
                }
            }
            _ => {}
        }
    }
    context
}

fn node_at(root: &SyntaxNode, range: Range<usize>) -> Option<SyntaxNode> {
    let start = TextSize::try_from(range.start).ok()?;
    let end = TextSize::try_from(range.end).ok()?;
    let element = root.covering_element(TextRange::new(start, end));
    Some(match element {
        ra_ap_syntax::NodeOrToken::Node(node) => node,
        ra_ap_syntax::NodeOrToken::Token(token) => token.parent()?,
    })
}

fn span_of(node: &SyntaxNode) -> Range<usize> {
    let range = node.text_range();
    usize::from(range.start())..usize::from(range.end())
}

fn guard_condition(arm: &ast::MatchArm) -> Option<ast::Expr> {
    arm.guard()?.syntax().children().find_map(ast::Expr::cast)
}

/// A placed mutant: its site, its wrap, and the `const` its function must
/// drop for the switch to run, if any.
type Placed = (Range<usize>, Wrap, Option<Range<usize>>);

/// The site and wrap for one mutant, or `None` to hand it back.
fn place(root: &SyntaxNode, text: &str, id: u32, mutant: &Listed) -> Option<Placed> {
    let start = offset(text, mutant.span.start)?;
    let end = offset(text, mutant.span.end)?;
    let node = node_at(root, start..end)?;
    let erase = match const_context(&node) {
        Context::ConstItem => return None,
        Context::ConstFn(range) => Some(range),
        Context::Runtime => None,
    };
    let (site, wrap) = switched(&node, start..end, id, mutant)?;
    Some((site, wrap, erase))
}

/// The site and wrap that switch `mutant` at `node`, spanning `start..end`.
fn switched(
    node: &SyntaxNode,
    Range { start, end }: Range<usize>,
    id: u32,
    mutant: &Listed,
) -> Option<(Range<usize>, Wrap)> {
    match mutant.genre.as_str() {
        "FnValue" => {
            let returns = mutant
                .function
                .as_ref()
                .map_or("", |f| f.return_type.as_str());
            if returns.contains("impl ") || returns.contains('!') {
                return None;
            }
            Some((
                start..end,
                Wrap::Body(vec![(id, mutant.replacement.clone())]),
            ))
        }
        "BinaryOperator" | "UnaryOperator" => {
            // The innermost operator expression holding the span: every
            // ancestor of the covering node holds it, so the kind decides, and
            // the token check below hands back a span that is not its operator.
            let expr = node
                .ancestors()
                .find(|n| matches!(n.kind(), SyntaxKind::BIN_EXPR | SyntaxKind::PREFIX_EXPR))?;
            let op = match expr.kind() {
                SyntaxKind::BIN_EXPR => ast::BinExpr::cast(expr.clone())?.op_token()?,
                _ => ast::PrefixExpr::cast(expr.clone())?.op_token()?,
            };
            let op = usize::from(op.text_range().start())..usize::from(op.text_range().end());
            if op != (start..end) {
                return None;
            }
            let alt = if mutant.genre == "UnaryOperator" {
                String::new()
            } else {
                mutant.replacement.clone()
            };
            Some((
                span_of(&expr),
                Wrap::Op {
                    op,
                    alts: vec![(id, alt)],
                },
            ))
        }
        "MatchArmGuard" => {
            let arm = node.ancestors().find_map(ast::MatchArm::cast)?;
            let condition = guard_condition(&arm)?;
            (span_of(condition.syntax()) == (start..end)).then(|| {
                (
                    start..end,
                    Wrap::Guard(vec![(id, mutant.replacement.clone())]),
                )
            })
        }
        "MatchArm" => {
            let arm = node.ancestors().find_map(ast::MatchArm::cast)?;
            // THE ARM WITHOUT ITS COMMA: the parser's arm node holds the
            // trailing `,`, and cargo-mutants' span stops before it.
            let whole = span_of(arm.syntax());
            let bare = arm.comma_token().map_or(whole.clone(), |comma| {
                whole.start..usize::from(comma.text_range().start())
            });
            if bare != (start..end) && whole != (start..end) {
                return None;
            }
            let site = if let Some(condition) = guard_condition(&arm) {
                span_of(condition.syntax())
            } else {
                let at = span_of(arm.pat()?.syntax()).end;
                at..at
            };
            Some((site, Wrap::ArmOff(vec![id])))
        }
        _ => None,
    }
}

/// Fold `wrap` into the wraps already at a site: same kind merges.
fn merge(wraps: &mut Vec<Wrap>, wrap: Wrap) {
    for held in wraps.iter_mut() {
        // ONE SITE, ONE OPERATOR: a site is its expression's span, which holds
        // exactly one operator token, so two `Op`s at one site swap the same one.
        match (held, &wrap) {
            (Wrap::Op { alts, .. }, Wrap::Op { alts: more, .. })
            | (Wrap::Body(alts), Wrap::Body(more))
            | (Wrap::Guard(alts), Wrap::Guard(more)) => {
                alts.extend(more.iter().cloned());
                return;
            }
            (Wrap::ArmOff(ids), Wrap::ArmOff(more)) => {
                ids.extend(more.iter().copied());
                return;
            }
            _ => {}
        }
    }
    wraps.push(wrap);
    // INNERMOST FIRST: an operator's switch sits inside a guard's, which sits
    // inside an arm's.
    wraps.sort_by_key(|wrap| match wrap {
        Wrap::Op { .. } => 0,
        Wrap::Body(_) => 1,
        Wrap::Guard(_) => 2,
        Wrap::ArmOff(_) => 3,
        Wrap::Erase => 4,
        Wrap::Probe(_) => 5,
    });
}

/// Nest `sites` (sorted by start, then widest first) by containment.
fn nest(mut sites: Vec<Site>) -> Vec<Site> {
    sites.sort_by(|a, b| {
        a.range
            .start
            .cmp(&b.range.start)
            .then(b.range.end.cmp(&a.range.end))
    });
    let mut roots: Vec<Site> = Vec::new();
    for site in sites {
        insert(&mut roots, site);
    }
    roots
}

fn insert(level: &mut Vec<Site>, site: Site) {
    if let Some(last) = level.last_mut()
        && last.range.start <= site.range.start
        && site.range.end <= last.range.end
        && last.range != site.range
    {
        insert(&mut last.children, site);
        return;
    }
    level.push(site);
}

struct Writer<'a> {
    source: &'a str,
    out: String,
    regions: Vec<(Range<usize>, Vec<u32>)>,
    probe_regions: Vec<Range<usize>>,
}

fn switch(ids: &[u32]) -> String {
    ids.iter()
        .map(|id| format!("crate::__batten_mutant({id})"))
        .collect::<Vec<_>>()
        .join(" || ")
}

impl Writer<'_> {
    /// `range` of the source with `children` rendered and `swap` (a token
    /// range and its replacement) applied in the gaps between them.
    fn inner(
        &mut self,
        range: Range<usize>,
        children: &[Site],
        swap: Option<(&Range<usize>, &str)>,
    ) {
        let mut at = range.start;
        for child in children {
            self.gap(at..child.range.start, swap);
            self.site(child);
            at = child.range.end;
        }
        self.gap(at..range.end, swap);
    }

    fn gap(&mut self, range: Range<usize>, swap: Option<(&Range<usize>, &str)>) {
        match swap {
            Some((op, alt)) if range.start <= op.start && op.end <= range.end => {
                self.out.push_str(&self.source[range.start..op.start]);
                self.out.push_str(alt);
                self.out.push_str(&self.source[op.end..range.end]);
            }
            _ => self.out.push_str(&self.source[range]),
        }
    }

    /// One branch owned by `id`, recorded as its region.
    fn branch(&mut self, id: u32, body: impl FnOnce(&mut Self)) {
        let start = self.out.len();
        body(self);
        self.regions.push((start..self.out.len(), vec![id]));
    }

    fn site(&mut self, site: &Site) {
        let start = self.out.len();
        self.layer(site, site.wraps.len());
        let ids: Vec<u32> = site.wraps.iter().flat_map(ids_of).collect();
        // A SITE OWNING NO MUTANT CLAIMS NO ERROR: an erased `const` renders
        // as nothing, and a region of it would swallow an error placed there.
        if !ids.is_empty() {
            self.regions.push((start..self.out.len(), ids));
        }
    }

    /// The site with its first `depth` wraps applied, innermost first.
    fn layer(&mut self, site: &Site, depth: usize) {
        let Some(wrap) = depth.checked_sub(1).and_then(|at| site.wraps.get(at)) else {
            self.inner(site.range.clone(), &site.children, None);
            return;
        };
        match wrap {
            Wrap::Op { op, alts } => {
                self.out.push('(');
                for (id, alt) in alts {
                    let _ = write!(self.out, "if crate::__batten_mutant({id}) {{ ");
                    self.branch(*id, |w| {
                        w.inner(site.range.clone(), &site.children, Some((op, alt)));
                    });
                    self.out.push_str(" } else ");
                }
                self.out.push_str("{ ");
                self.layer(site, depth - 1);
                self.out.push_str(" })");
            }
            Wrap::Body(alts) | Wrap::Guard(alts) => {
                let guard = matches!(wrap, Wrap::Guard(_));
                if guard {
                    self.out.push('(');
                }
                for (id, alt) in alts {
                    let _ = write!(self.out, "if crate::__batten_mutant({id}) {{ ");
                    self.branch(*id, |w| w.out.push_str(alt));
                    self.out.push_str(" } else ");
                }
                self.out.push_str("{ ");
                self.layer(site, depth - 1);
                self.out.push_str(" }");
                if guard {
                    self.out.push(')');
                }
            }
            Wrap::Erase => {}
            Wrap::Probe(statement) => {
                let start = self.out.len();
                self.out.push_str(statement);
                self.probe_regions.push(start..self.out.len());
            }
            Wrap::ArmOff(ids) => {
                if site.range.is_empty() {
                    let start = self.out.len();
                    let _ = write!(self.out, " if !({})", switch(ids));
                    self.regions.push((start..self.out.len(), ids.clone()));
                } else {
                    self.out.push('(');
                    self.layer(site, depth - 1);
                    let start = self.out.len();
                    let _ = write!(self.out, ") && !({})", switch(ids));
                    self.regions.push((start..self.out.len(), ids.clone()));
                }
            }
        }
    }
}

fn ids_of(wrap: &Wrap) -> Vec<u32> {
    match wrap {
        Wrap::Op { alts, .. } | Wrap::Body(alts) | Wrap::Guard(alts) => {
            alts.iter().map(|(id, _)| *id).collect()
        }
        Wrap::ArmOff(ids) => ids.clone(),
        Wrap::Erase | Wrap::Probe(_) => Vec::new(),
    }
}

/// Render `source` with every mutant of `mutants` switched, except those in
/// `skip`, and, from `probe_from`, a probe in every runtime function body. A
/// mutant the rewrite cannot place is returned in `classic`.
#[must_use]
pub fn render(
    source: &str,
    mutants: &[(u32, &Listed)],
    skip: &BTreeSet<u32>,
    probe_from: Option<usize>,
) -> Rendered {
    let parse = SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024);
    let root = parse.tree().syntax().clone();
    let mut classic = Vec::new();
    let mut placed: Vec<(u32, Range<usize>)> = Vec::new();
    let mut sites: Vec<Site> = Vec::new();
    let mut erased: std::collections::BTreeMap<(usize, usize), (String, Vec<u32>)> =
        std::collections::BTreeMap::new();
    for (id, mutant) in mutants {
        if skip.contains(id) {
            continue;
        }
        let Some((range, wrap, erase)) = place(&root, source, *id, mutant) else {
            classic.push(*id);
            if let (Some(start), Some(end)) = (
                offset(source, mutant.span.start),
                offset(source, mutant.span.end),
            ) {
                placed.push((*id, start..end));
            }
            continue;
        };
        if let Some(erase) = erase {
            // A MUTANT WITH NO FUNCTION NAME could not be answered for if its
            // dropped `const` broke a caller, so it is handed back instead.
            let Some(function) = mutant.function.as_ref() else {
                classic.push(*id);
                continue;
            };
            erased
                .entry((erase.start, erase.end))
                .or_insert_with(|| (function.function_name.clone(), Vec::new()))
                .1
                .push(*id);
        }
        placed.push((*id, range.clone()));
        match sites.iter_mut().find(|site| site.range == range) {
            Some(site) => merge(&mut site.wraps, wrap),
            None => sites.push(Site {
                range,
                wraps: vec![wrap],
                children: Vec::new(),
            }),
        }
    }
    let probed = probe_sites(&root, probe_from, &mut sites);
    for &(start, end) in erased.keys() {
        sites.push(Site {
            range: start..end,
            wraps: vec![Wrap::Erase],
            children: Vec::new(),
        });
    }
    let roots = nest(sites);
    let mut writer = Writer {
        source,
        out: String::with_capacity(source.len() * 2),
        regions: Vec::new(),
        probe_regions: Vec::new(),
    };
    writer.inner(0..source.len(), &roots, None);
    Rendered {
        text: writer.out,
        regions: writer.regions,
        classic,
        deconst: erased.into_values().collect(),
        probes: probed.probes,
        names: probed.names,
        items: probed.items,
        probe_regions: writer.probe_regions,
        mutant_fns: innermost(&placed, &probed.functions),
        mentions: probed.mentions,
        skeleton: probed.skeleton,
        fn_names: probed.fn_names,
        fn_spans: probed.functions.into_iter().map(|(span, _)| span).collect(),
    }
}

/// Each placed mutant's innermost enclosing probed function, by its digest:
/// what a reach record of a case that ran that function could not have seen
/// if the mutant is new. A mutant in no probed function is left out.
fn innermost(
    placed: &[(u32, Range<usize>)],
    functions: &[(Range<usize>, String)],
) -> Vec<(u32, String)> {
    placed
        .iter()
        .filter_map(|(id, range)| {
            functions
                .iter()
                .filter(|(function, _)| function.start <= range.start && range.end <= function.end)
                .min_by_key(|(function, _)| function.end - function.start)
                .map(|(_, digest)| (*id, digest.clone()))
        })
        .collect()
}
/// What [`probe_sites`] reads off one file besides the sites it places.
#[derive(Debug, Default)]
struct Probed {
    /// Each probed function's source digest, in probe-id order.
    probes: Vec<String>,
    /// Each probed function's names, in probe-id order ([`names_in`]).
    names: Vec<BTreeSet<String>>,
    /// Each skeleton item's mentioned names under every name it answers to.
    mentions: Vec<(String, BTreeSet<String>)>,
    /// Each probed function's byte range in the source with its digest.
    functions: Vec<(Range<usize>, String)>,
    /// Each skeleton item's digest under every name it answers to
    /// ([`item_names`]); `""` for tokens outside any item.
    items: Vec<(String, String)>,
    /// The digest of the whole skeleton.
    skeleton: String,
    /// Each probed function's own name, in probe-id order.
    fn_names: Vec<String>,
}

/// One skeleton item as [`probe_sites`] gathers it: the names it answers
/// to, its tokens' hasher and the names those tokens mention.
type Grouped = (Vec<String>, blake3::Hasher, BTreeSet<String>);

/// A probe site in every function body that runs at run time, ids counted
/// from `probe_from` (none when it is `None`), each with its function's
/// source digest; and the skeleton digest (see [`Rendered::skeleton`]).
///
/// THE FUNCTION IS THE UNIT (RTS++, Fu et al. 2019; `RustyRTS`, Hundsdorfer et
/// al., ICST 2025): a test's verdict depends on the functions it executes, so
/// those are recorded per case, while what is decided at compile time (const
/// items and `const fn`s, types, macros, impl headers, imports) is in the
/// skeleton every key carries. Source text, never the binary: one line shifts
/// every address.
///
/// A PROBED FUNCTION LEAVES THE SKELETON WHOLE, signature and attributes with
/// its body: its probe digest is the whole item, and reach is recorded afresh
/// on every run, so a function that is new, renamed or re-typed moves exactly
/// the cases that now execute it. Kept in the skeleton, every added test or
/// helper moved every key in the crate, and #1276's sweep reused nothing.
///
/// TOKENS, NOT TEXT (Ekstazi's smart checksum, Gligoric et al. ISSTA 2015):
/// whitespace and comments, doc comments included, change no compiled
/// behaviour, so the skeleton hashes the non-trivia tokens alone.
///
/// EACH SKELETON ITEM ITS OWN DIGEST, under every name it answers to, and each
/// probed function the names it mentions. `RustyRTS` (ICST 2025) sees a `const`
/// through the MIR of every function that inlines it; source has no such edge,
/// so the edge is the name: a case depends on the items its executed functions
/// name. An edited const, type or impl header moves exactly the cases whose
/// functions name it, and an item ADDED moves none, which is the commit a
/// mutant-fixing lap makes. A tree-wide skeleton in every key re-judged all
/// 2386 viable mutants on #1276 after one commit of new tests.
fn probe_sites(root: &SyntaxNode, probe_from: Option<usize>, sites: &mut Vec<Site>) -> Probed {
    let mut probed = Probed::default();
    let mut cuts: Vec<Range<usize>> = Vec::new();
    if let Some(mut next) = probe_from {
        for function in root.descendants().filter_map(ast::Fn::cast) {
            if function.const_token().is_some()
                || const_context(function.syntax()) != Context::Runtime
            {
                continue;
            }
            let Some(list) = function.body().and_then(|body| body.stmt_list()) else {
                continue;
            };
            let (Some(open), Some(_)) = (list.l_curly_token(), list.r_curly_token()) else {
                continue;
            };
            let at = usize::from(open.text_range().end());
            sites.push(Site {
                range: at..at,
                wraps: vec![Wrap::Probe(format!("crate::__batten_fn({next});"))],
                children: Vec::new(),
            });
            probed.probes.push(
                blake3::hash(function.syntax().to_string().as_bytes())
                    .to_hex()
                    .to_string(),
            );
            probed.names.push(names_in(function.syntax()));
            probed.fn_names.push(
                ast::HasName::name(&function)
                    .map_or_else(String::new, |name| name.text().to_string()),
            );
            let item = function.syntax().text_range();
            cuts.push(usize::from(item.start())..usize::from(item.end()));
            probed.functions.push((
                usize::from(item.start())..usize::from(item.end()),
                probed.probes.last().cloned().unwrap_or_default(),
            ));
            next += 1;
        }
    }
    cuts.sort_by_key(|cut| cut.start);
    let mut skeleton = blake3::Hasher::new();
    // EACH ITEM ITS OWN DIGEST, keyed by where it starts so its tokens gather
    // in one hasher wherever the walk meets them.
    let mut items: std::collections::BTreeMap<usize, Grouped> = std::collections::BTreeMap::new();
    let mut cut = cuts.iter().peekable();
    for token in root
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
    {
        if matches!(token.kind(), SyntaxKind::WHITESPACE | SyntaxKind::COMMENT) {
            continue;
        }
        let start = usize::from(token.text_range().start());
        // A function inside a cut function went with it: cuts are walked in
        // order, and one ending before this token is behind every later token.
        while cut.peek().is_some_and(|c| c.end <= start) {
            cut.next();
        }
        if cut.peek().is_some_and(|c| c.start <= start) {
            continue;
        }
        skeleton.update(token.text().as_bytes());
        skeleton.update(b"\x1f");
        let owner = owning_item(&token);
        let at = owner.as_ref().map_or(usize::MAX, |item| {
            usize::from(item.syntax().text_range().start())
        });
        let (_, hasher, mentions) = items.entry(at).or_insert_with(|| {
            (
                owner
                    .as_ref()
                    .map_or_else(|| vec![String::new()], item_names),
                blake3::Hasher::new(),
                BTreeSet::new(),
            )
        });
        hasher.update(token.text().as_bytes());
        hasher.update(b"\x1f");
        token_names(&token, mentions);
    }
    for (names, hasher, mentions) in items.into_values() {
        let digest = hasher.finalize().to_hex().to_string();
        probed
            .items
            .extend(names.iter().map(|name| (name.clone(), digest.clone())));
        probed
            .mentions
            .extend(names.into_iter().map(|name| (name, mentions.clone())));
    }
    probed.skeleton = skeleton.finalize().to_hex().to_string();
    probed
}

/// The skeleton item `token` belongs to: its innermost item, past a macro
/// call in an expression, which is that item's own code. Grouped apart, a
/// `const` whose value is a macro call kept the call out of its digest and its
/// mentions, so an edit to the call moved no case that names the `const`.
fn owning_item(token: &ra_ap_syntax::SyntaxToken) -> Option<ast::Item> {
    token.parent_ancestors().find_map(|node| {
        let item = ast::Item::cast(node)?;
        let in_expression = matches!(&item, ast::Item::MacroCall(_))
            && item
                .syntax()
                .parent()
                .is_some_and(|parent| parent.kind() == SyntaxKind::MACRO_EXPR);
        (!in_expression).then_some(item)
    })
}

/// The names a skeleton item answers to: its own where it has one, and for an
/// impl, an import or an item-position macro every identifier in it (the
/// type and trait an impl is for; what a `use` or a `thread_local!` binds).
/// Over-inclusion is the safe direction: a name too many only re-runs a case.
fn item_names(item: &ast::Item) -> Vec<String> {
    use ast::HasName as _;
    let named = match item {
        ast::Item::Const(it) => it.name(),
        ast::Item::Static(it) => it.name(),
        ast::Item::Struct(it) => it.name(),
        ast::Item::Enum(it) => it.name(),
        ast::Item::Union(it) => it.name(),
        ast::Item::Trait(it) => it.name(),
        ast::Item::TypeAlias(it) => it.name(),
        ast::Item::MacroRules(it) => it.name(),
        ast::Item::MacroDef(it) => it.name(),
        ast::Item::Module(it) => it.name(),
        ast::Item::Fn(it) => it.name(),
        _ => None,
    };
    named.map_or_else(
        || names_in(item.syntax()).into_iter().collect(),
        |name| vec![name.text().to_string()],
    )
}

/// Every identifier `node` names: its `IDENT` tokens, and each name a string
/// literal captures in a format argument (`"{LIMIT}"`), which no token carries.
fn names_in(node: &SyntaxNode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for token in node
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
    {
        token_names(&token, &mut names);
    }
    names
}

/// The names one token carries into `names` ([`names_in`]).
fn token_names(token: &ra_ap_syntax::SyntaxToken, names: &mut BTreeSet<String>) {
    match token.kind() {
        SyntaxKind::IDENT => {
            names.insert(token.text().to_owned());
        }
        SyntaxKind::STRING => {
            for captured in token.text().split('{').skip(1) {
                let name: String = captured
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
                {
                    names.insert(name);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The driver: one persistent tree, one build, every mutant judged by switch.
// ---------------------------------------------------------------------------

/// Every mutant `cargo mutants --list --json` printed, from its output.
///
/// # Errors
///
/// The output holds no listing.
pub fn listing(text: &str) -> anyhow::Result<Vec<Listed>> {
    use serde::Deserialize as _;
    let at = text
        .find('[')
        .ok_or_else(|| anyhow::anyhow!("no mutant listing"))?;
    let mut decoder = serde_json::Deserializer::from_str(&text[at..]);
    Ok(Vec::<Listed>::deserialize(&mut decoder)?)
}

/// Make `work` hold `root`'s files, `target/` aside, writing only what
/// differs: an untouched file keeps its time, so the build stays incremental.
/// A file gone from `root` goes from `work` too, so a test listing a
/// directory sees the tree it was listed from. The paths in `rendered` are
/// left to [`build`], which writes them only when their rendering changes:
/// copied here first, each one's time moved on every sweep and cargo rebuilt
/// every crate the schema touches, though nothing in it had changed.
///
/// # Errors
///
/// A directory cannot be read or a file cannot be written.
pub fn sync(
    root: &std::path::Path,
    work: &std::path::Path,
    rendered: &BTreeSet<String>,
) -> anyhow::Result<()> {
    // THE CASES' FIXTURE SCRATCH IS A RUN'S OWN, NEVER KEPT. Each case writes
    // its fixtures under the target's `tmp/`, and the build output beside it is
    // kept so the next sweep compiles only what moved; the scratch was kept with
    // it and grew to 6.5 GB on #1276, which put the disk under the pruner's
    // floor and made every build start cold. Cleared at the start, so a run
    // killed mid-sweep leaves nothing the next one carries.
    match std::fs::remove_dir_all(work.join("target").join("tmp")) {
        Err(gone) if gone.kind() != std::io::ErrorKind::NotFound => return Err(gone.into()),
        _ => {}
    }
    sync_dir(root, work, std::path::Path::new(""), rendered)
}

fn sync_dir(
    from: &std::path::Path,
    to: &std::path::Path,
    at: &std::path::Path,
    rendered: &BTreeSet<String>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(to)?;
    let top = at.as_os_str().is_empty();
    let mut present = BTreeSet::new();
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if top && name == "target" {
            continue;
        }
        present.insert(name.clone());
        let source = entry.path();
        let dest = to.join(&name);
        let relative = at.join(&name);
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_dir(&source, &dest, &relative, rendered)?;
        } else if kind.is_symlink() {
            let link = std::fs::read_link(&source)?;
            if std::fs::read_link(&dest).ok() != Some(link.clone()) {
                let _ = std::fs::remove_file(&dest);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&link, &dest)?;
            }
        } else if rendered.contains(relative.to_string_lossy().as_ref()) && dest.exists() {
            // The build writes it, only when its rendering changes.
        } else if crate::fsio::read(&dest).ok() != crate::fsio::read(&source).ok() {
            std::fs::copy(&source, &dest)?;
        }
    }
    for entry in std::fs::read_dir(to)? {
        let entry = entry?;
        let name = entry.file_name();
        if (top && name == "target") || present.contains(&name) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Write `text` to `path` only if it differs, keeping an unchanged file's time.
fn write_if_changed(path: &std::path::Path, text: &str) -> anyhow::Result<()> {
    if crate::fsio::read_to_string(path).ok().as_deref() != Some(text) {
        crate::durable::replace(path, text)?;
    }
    Ok(())
}

/// The crate roots of the packages `mutants` live in: each package's
/// `src/lib.rs` and `src/main.rs` that exist.
fn crate_roots(work: &std::path::Path, mutants: &[Listed]) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for mutant in mutants {
        if let Some(at) = mutant
            .file
            .find("/src/")
            .or_else(|| mutant.file.starts_with("src/").then_some(0))
        {
            let dir = &mutant.file[..at];
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            for root in ["src/lib.rs", "src/main.rs"] {
                let path = format!("{prefix}{root}");
                if work.join(&path).is_file() {
                    roots.insert(path);
                }
            }
        }
    }
    roots
}

/// The schema as rendered into `work`: per file, its rendering, and what the
/// verdict keys read from it.
#[derive(Debug, Default)]
pub struct Schema {
    /// Each rendered file's rendering, by path.
    pub files: std::collections::BTreeMap<String, Rendered>,
    /// Every probed function's source digest, by probe id.
    pub probes: Vec<String>,
    /// The digest of every rendered file's skeleton ([`Rendered::skeleton`]).
    pub skeleton: String,
    /// Every probed function's names, by probe id.
    pub names: Vec<BTreeSet<String>>,
    /// Every skeleton item's digests, by each name it answers to, across
    /// every rendered file: a name shared by two items keys on both.
    pub items: std::collections::BTreeMap<String, BTreeSet<String>>,
    /// Each located mutant's innermost probed function, by digest.
    pub mutant_fns: std::collections::BTreeMap<u32, String>,
    /// Every skeleton item's mentioned names, by each name it answers to.
    pub mentions: std::collections::BTreeMap<String, BTreeSet<String>>,
    /// The files rendered with a probe in every runtime function: what a
    /// reach record's functions can come from ([`Format::probed`]).
    pub probed: BTreeSet<String>,
}

impl Schema {
    /// Every mutant the schema hands back: each rendering's own, and .
    #[must_use]
    pub fn classic(&self, handed: impl IntoIterator<Item = u32>) -> BTreeSet<u32> {
        self.files
            .values()
            .flat_map(|rendered| rendered.classic.iter().copied())
            .chain(handed)
            .collect()
    }
}

/// Every Rust source under the `src/` of each package `mutants` live in: the
/// files a probe goes into, mutated or not.
fn package_sources(root: &std::path::Path, mutants: &[Listed]) -> BTreeSet<String> {
    let mut sources: BTreeSet<String> = mutants.iter().map(|m| m.file.clone()).collect();
    for dir in package_dirs(mutants).values() {
        let src = root.join(dir).join("src");
        for entry in ignore::WalkBuilder::new(&src)
            .hidden(false)
            .build()
            .flatten()
        {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "rs")
                && let Ok(relative) = path.strip_prefix(root)
            {
                sources.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    sources
}

/// The sources a package's `build.rs` includes by `#[path]`: compiled into
/// the build script too, which has no probe to call.
fn build_script_includes(root: &std::path::Path, mutants: &[Listed]) -> BTreeSet<String> {
    let mut included = BTreeSet::new();
    for dir in package_dirs(mutants).values() {
        let Ok(script) = crate::fsio::read_to_string(root.join(dir).join("build.rs")) else {
            continue;
        };
        for line in script.lines() {
            if let Some(rest) = line.trim().strip_prefix("#[path = \"")
                && let Some((path, _)) = rest.split_once('"')
            {
                included.insert(format!("{dir}/{path}"));
            }
        }
    }
    included
}

/// Render every mutant but `skip` from `root`'s sources into `work`, a probe
/// in every package source but `unprobed`, and the switch in every crate
/// root. Returns the renderings, for error attribution and the keys.
///
/// # Errors
///
/// A source cannot be read or a rendering cannot be written.
pub fn write_schema(
    root: &std::path::Path,
    work: &std::path::Path,
    mutants: &[Listed],
    skip: &BTreeSet<u32>,
    unprobed: &BTreeSet<String>,
) -> anyhow::Result<Schema> {
    let mut by_file: std::collections::BTreeMap<&str, Vec<(u32, &Listed)>> =
        std::collections::BTreeMap::new();
    for (id, mutant) in mutants.iter().enumerate() {
        let id = u32::try_from(id)?;
        by_file
            .entry(mutant.file.as_str())
            .or_default()
            .push((id, mutant));
    }
    let roots = crate_roots(work, mutants);
    let included = build_script_includes(root, mutants);
    let mut schema = Schema::default();
    let mut skeleton = blake3::Hasher::new();
    for file in package_sources(root, mutants) {
        let source = crate::fsio::read_to_string(root.join(&file))?;
        let listed = by_file.get(file.as_str()).map_or(&[][..], Vec::as_slice);
        let probe_from =
            (!unprobed.contains(&file) && !included.contains(&file)).then_some(schema.probes.len());
        let rendered = render(&source, listed, skip, probe_from);
        if probe_from.is_some() {
            schema.probed.insert(file.clone());
        }
        schema.probes.extend(rendered.probes.iter().cloned());
        schema.names.extend(rendered.names.iter().cloned());
        schema
            .mutant_fns
            .extend(rendered.mutant_fns.iter().cloned());
        for (name, digest) in &rendered.items {
            schema
                .items
                .entry(name.clone())
                .or_default()
                .insert(digest.clone());
        }
        for (name, mentioned) in &rendered.mentions {
            schema
                .mentions
                .entry(name.clone())
                .or_default()
                .extend(mentioned.iter().cloned());
        }
        skeleton.update(format!("\x1d{file}\x1f{}", rendered.skeleton).as_bytes());
        schema.files.insert(file, rendered);
    }
    schema.skeleton = skeleton.finalize().to_hex().to_string();
    let prelude = prelude(schema.probes.len());
    for (file, rendered) in &schema.files {
        let mut text = rendered.text.clone();
        if roots.contains(file) {
            text.push_str(&prelude);
        }
        write_if_changed(&work.join(file), &text)?;
    }
    for crate_root in roots.iter().filter(|r| !schema.files.contains_key(*r)) {
        let mut source = crate::fsio::read_to_string(root.join(crate_root))?;
        source.push_str(&prelude);
        write_if_changed(&work.join(crate_root), &source)?;
    }
    Ok(schema)
}

/// What a refused build's errors say about the mutants.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Refused {
    /// The mutants an error belongs to: they do not compile.
    pub owned: BTreeSet<u32>,
    /// The mutants of each `const fn` whose dropped `const` a const caller
    /// needed: they compile, but not switched, so they are handed back.
    pub reconst: BTreeSet<u32>,
    /// The files whose probes an error landed on: rebuilt without probes,
    /// their whole text then in the skeleton.
    pub unprobe: BTreeSet<String>,
    /// Each error no mutant owns.
    pub stray: Vec<String>,
}

/// Whether rustc's `message` is a const context refusing a call to the
/// function cargo-mutants lists as `name` (E0015), however it qualifies it.
fn refuses_const_call(message: &str, name: &str) -> bool {
    message.contains("non-const")
        && (message.contains(&format!("`{name}`")) || message.contains(&format!("::{name}`")))
}

/// The mutants the compiler's errors in `messages` (cargo's JSON lines)
/// belong to, those handed back because a const caller needs their function
/// const, and the errors no mutant owns.
#[must_use]
pub fn unviable(schema: &Schema, messages: &str) -> Refused {
    let mut refused = Refused::default();
    for line in messages.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let message = &value["message"];
        if value["reason"] != "compiler-message" || message["level"] != "error" {
            continue;
        }
        let text = message["message"].as_str().unwrap_or_default();
        // A CONST CALLER FIRST, wherever it sits: its error is the dropped
        // `const`'s, even inside another mutant's branch.
        let reconst: Vec<u32> = schema
            .files
            .values()
            .flat_map(|rendered| &rendered.deconst)
            .filter(|(name, _)| refuses_const_call(text, name))
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        if !reconst.is_empty() {
            refused.reconst.extend(reconst);
            continue;
        }
        let primary = message["spans"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|span| span["is_primary"] == true);
        let at = primary.and_then(|span| {
            let file = span["file_name"].as_str()?;
            let at = usize::try_from(span["byte_start"].as_u64()?).ok()?;
            Some((file, at))
        });
        // AN ERROR ON A PROBE IS THE PROBE'S: the file is compiled somewhere
        // the switch is not (a build script's `#[path]`), whatever mutant's
        // branch the probe sits in.
        if let Some((file, at)) = at
            && schema.files.get(file).is_some_and(|rendered| {
                rendered
                    .probe_regions
                    .iter()
                    .any(|region| region.start <= at && at < region.end)
            })
        {
            refused.unprobe.insert(file.to_owned());
            continue;
        }
        let ids = at.and_then(|(file, at)| schema.files.get(file)?.owners(at));
        match ids {
            Some(ids) => refused.owned.extend(ids.iter().copied()),
            None => refused.stray.push(text.to_owned()),
        }
    }
    refused
}

/// Build the schema in `work` into `target` until it compiles, switching off
/// each mutant an error belongs to. Returns those unviable mutants and the
/// schema that built.
///
/// # Errors
///
/// An error no mutant owns, or no clean build within the round bound.
pub fn build(
    root: &std::path::Path,
    work: &std::path::Path,
    target: &std::path::Path,
    mutants: &[Listed],
    known: Known,
    on_round: &mut dyn FnMut(&Refused) -> anyhow::Result<()>,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Built> {
    let packages: BTreeSet<&str> = mutants.iter().map(|m| m.package.as_str()).collect();
    let mut args: Vec<String> = [
        "test",
        "--no-run",
        "--profile",
        "test",
        "--message-format",
        "json",
    ]
    .map(String::from)
    .to_vec();
    for package in &packages {
        args.extend([String::from("-p"), (*package).to_owned()]);
    }
    args.extend(cargo_dirs(target));
    let env: Vec<(String, String)> = Vec::new();
    let Known {
        unviable: mut skip,
        mut handed,
        mut unprobed,
    } = known;
    skip.extend(handed.iter().copied());
    for round in 1..=12 {
        let schema = write_schema(root, work, mutants, &skip, &unprobed)?;
        let ran = super::spawn(
            work,
            super::Program::Cargo,
            &args,
            &env,
            super::runner_bound(),
        )?;
        if ran.passed() {
            writeln!(
                out,
                "mutate schema: build {round} clean, {} unviable",
                skip.len() - handed.len()
            )?;
            return Ok(Built {
                unviable: skip.difference(&handed).copied().collect(),
                handed,
                schema,
                unprobed,
            });
        }
        let refused = unviable(&schema, &ran.stdout);
        writeln!(
            out,
            "mutate schema: build {round} refused {} mutant(s), handed back {} for a const caller, unprobed {} file(s), {} error(s) unowned",
            refused.owned.len(),
            refused.reconst.len(),
            refused.unprobe.len(),
            refused.stray.len()
        )?;
        for message in &refused.stray {
            writeln!(out, "mutate schema:   unowned: {message}")?;
        }
        // AN ERROR NO MUTANT OWNS IS THE SCHEMA'S OWN FAULT, never retried:
        // on #1276 two of them were sources edited mid-sweep, which the
        // pristine snapshot now rules out, and anything else is a rendering bug.
        anyhow::ensure!(
            !refused.owned.is_empty() || !refused.reconst.is_empty() || !refused.unprobe.is_empty(),
            "the schema build failed on error(s) no mutant owns: {}",
            refused.stray.join("; ")
        );
        // KEPT THE MOMENT THE BUILD REFUSED: a round is a full schema build,
        // and a sweep killed in the next one, or the next sweep, would pay it
        // again to rediscover what this one already found.
        on_round(&refused)?;
        unprobed.extend(refused.unprobe);
        skip.extend(refused.owned);
        // HANDED BACK, NOT UNVIABLE: the mutants compile, only not switched,
        // and with every one of them skipped the function keeps its `const`.
        skip.extend(refused.reconst.iter().copied());
        handed.extend(refused.reconst);
    }
    anyhow::bail!("the schema build was not clean within 12 rounds")
}

/// What earlier runs already found a build refuses: the mutants that do not
/// compile, those handed back for a const caller, and the files built without
/// probes. Each skips the build round that would only rediscover it.
#[derive(Debug, Default)]
pub struct Known {
    /// Mutants an earlier build found do not compile.
    pub unviable: BTreeSet<u32>,
    /// Mutants an earlier build handed back for a const caller.
    pub handed: BTreeSet<u32>,
    /// Files an earlier build had to build without probes.
    pub unprobed: BTreeSet<String>,
}

/// A schema that built: the mutants that do not compile, those handed back
/// because a const caller needs their function const, and the renderings.
#[derive(Debug)]
pub struct Built {
    /// Mutants an error belonged to.
    pub unviable: BTreeSet<u32>,
    /// Mutants whose `const fn` a const caller needs const.
    pub handed: BTreeSet<u32>,
    /// The renderings that built.
    pub schema: Schema,
    /// The files built without probes ([`Known::unprobed`] and every round's).
    pub unprobed: BTreeSet<String>,
}

/// What one mutant's covering cases said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A covering case failed.
    Caught,
    /// Every covering case passed.
    Missed,
    /// No case covers it, so none ran.
    Uncovered,
    /// A covering case hung.
    Timeout,
    /// The run itself failed.
    Error,
}

impl Verdict {
    /// The verdict's name as the report prints it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Caught => "caught",
            Self::Missed => "missed",
            Self::Uncovered => "uncovered",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

/// The package a nextest binary id names: `batten::it` is `batten`'s.
fn package_of(binary: &str) -> &str {
    binary
        .split_once("::")
        .map_or(binary, |(package, _)| package)
}

/// A case: its name and the binary that holds it.
type Case = (String, String);

/// Seconds of measured case time the first phase may spend before the rest
/// wait on it. The sites' median reach costs 3.3 s in all (#1276), so most
/// mutants are judged in one run; a hub's hundreds of cases are not paid for
/// unless the cheap ones all survive.
const FIRST_PHASE_SECONDS: f64 = 4.0;

/// What a case the reach run did not time is taken to cost.
const UNMEASURED_SECONDS: f64 = 1.0;

/// How many times its cases' measured time one mutant's run may take, and the
/// least it is ever given: cargo-mutants' own rule (mutants.rs, "Timeouts":
/// 5x the baseline, never under 20 s), applied to the cases this run selects.
const TIMEOUT_MULTIPLIER: f64 = 5.0;
const MINIMUM_TIMEOUT_SECONDS: f64 = 20.0;

/// What one run spends before any case starts: cargo's freshness check and
/// nextest listing each selected binary, which no case's time includes.
const STARTUP_SECONDS: f64 = 30.0;

/// How long one mutant's run over `cases` may take before it is a timeout.
///
/// MEASURED ON #1276: the bound was the classic runner's six hours, sized for a
/// build per mutant, and one mutant hung its run before a case started — the
/// test binary blocked listing itself — so the sweep sat 70 minutes on its
/// last run with every other verdict in.
fn case_bound(
    cases: &BTreeSet<Case>,
    seconds: &std::collections::BTreeMap<Case, f64>,
) -> std::time::Duration {
    let measured: f64 = cases
        .iter()
        .map(|case| seconds.get(case).copied().unwrap_or(UNMEASURED_SECONDS))
        .sum();
    std::time::Duration::from_secs_f64(
        STARTUP_SECONDS + (TIMEOUT_MULTIPLIER * measured).max(MINIMUM_TIMEOUT_SECONDS),
    )
}

/// Each case's measured seconds, from a nextest `JUnit` report: the `name`,
/// `classname` (the binary) and `time` of every `<testcase>`.
fn durations(junit: &str) -> std::collections::BTreeMap<Case, f64> {
    // AS XML, as the judge reads its report (#1276), never split on text.
    let Ok(doc) = roxmltree::Document::parse(junit) else {
        return std::collections::BTreeMap::new();
    };
    doc.descendants()
        .filter(|node| node.has_tag_name("testcase"))
        .filter_map(|case| {
            let time = case.attribute("time")?.parse::<f64>().ok()?;
            Some((
                (
                    case.attribute("name")?.to_owned(),
                    case.attribute("classname")?.to_owned(),
                ),
                time,
            ))
        })
        .collect()
}

/// The two runs a mutant is judged by. The first holds the cases that killed a
/// sibling in the same function, then the cheapest of the rest until
/// [`FIRST_PHASE_SECONDS`] are spent; the second holds everything else and runs
/// only when the first kills nothing — prioritised cases, stopped at the first
/// kill (Zhang, Marinov & Khurshid, ISSTA 2013), with no case ever skipped for
/// a survivor.
fn phases(
    cases: &BTreeSet<Case>,
    hints: &BTreeSet<Case>,
    seconds: &std::collections::BTreeMap<Case, f64>,
) -> (BTreeSet<Case>, BTreeSet<Case>) {
    let cost = |case: &Case| seconds.get(case).copied().unwrap_or(UNMEASURED_SECONDS);
    let mut first: BTreeSet<Case> = cases.intersection(hints).cloned().collect();
    let mut spent: f64 = first.iter().map(cost).sum();
    let mut rest: Vec<&Case> = cases.iter().filter(|case| !first.contains(*case)).collect();
    rest.sort_by(|a, b| cost(a).total_cmp(&cost(b)).then_with(|| a.cmp(b)));
    let mut second = BTreeSet::new();
    for case in rest {
        if first.is_empty() || spent < FIRST_PHASE_SECONDS {
            spent += cost(case);
            first.insert(case.clone());
        } else {
            second.insert(case.clone());
        }
    }
    (first, second)
}

/// The nextest argv that runs exactly `cases` against `mutant`: the cases'
/// own packages and targets, and a filter naming each case.
fn nextest_args(mutant: &Listed, cases: &BTreeSet<Case>) -> Vec<String> {
    let tests: BTreeSet<&str> = cases.iter().map(|(name, _)| name.as_str()).collect();
    let binaries: BTreeSet<&str> = cases.iter().map(|(_, binary)| binary.as_str()).collect();
    let mut args: Vec<String> = [
        "nextest",
        "run",
        "--cargo-profile",
        "test",
        "--profile",
        "mutants",
        "--color",
        "never",
    ]
    .map(String::from)
    .to_vec();
    // THE CASES' PACKAGES, NOT THE MUTANT'S: a `batten-fsio` site reached only
    // by `batten`'s cases is judged by those.
    let packages: BTreeSet<&str> = binaries
        .iter()
        .map(|binary| package_of(binary))
        .filter(|package| !package.is_empty())
        .collect();
    if packages.is_empty() || binaries.contains("") {
        // A CASE WHOSE BINARY WENT UNRECORDED narrows nothing: its own package
        // and every target, rather than a `-p ""` cargo refuses.
        args.extend([String::from("-p"), mutant.package.clone()]);
    } else {
        for package in packages {
            args.extend([String::from("-p"), package.to_owned()]);
        }
        args.extend(super::cover::target_args(&binaries, &mutant.file));
    }
    args.extend([
        String::from("-E"),
        super::cover::filterset(&tests),
        String::from("--no-tests=pass"),
    ]);
    args
}

/// Run `cases` once with mutant `id` switched on, and answer its verdict, the
/// case that killed it, and every case that passed. `cases` must not be empty.
///
/// # Errors
///
/// The run could not be started.
fn run_cases(
    judging: &Judging<'_>,
    id: u32,
    mutant: &Listed,
    cases: &BTreeSet<Case>,
) -> anyhow::Result<(Verdict, Option<Case>, Vec<Case>)> {
    let mut args = nextest_args(mutant, cases);
    args.extend(cargo_dirs(judging.target));
    let own = judging.scratch.join(id.to_string());
    let _ = std::fs::create_dir_all(own.join("tmp"));
    let _ = std::fs::create_dir_all(own.join("fixtures"));
    // THE VERDICT IS READ FROM THE RUN'S OWN JUNIT REPORT, written under this
    // run's scratch so no two workers share one (#1276).
    let store = own.join("store");
    let config = own.join("nextest.toml");
    crate::durable::replace(&config, judge_config(judging.work, &store)?)?;
    args.extend([
        String::from("--config-file"),
        config.to_string_lossy().into_owned(),
    ]);
    let mut env: Vec<(String, String)> = Vec::new();
    env.extend([
        // EACH RUN ITS OWN TEMP AND FIXTURE ROOTS, under the sweep's scratch:
        // a fixture at a fixed path is then never shared by two workers
        // running one case, so no run waits on another's cases, and what a
        // run leaves is the sweep's to collect at its barrier.
        (
            String::from("TMPDIR"),
            own.join("tmp").to_string_lossy().into_owned(),
        ),
        (
            String::from(TEST_TMPDIR),
            own.join("fixtures").to_string_lossy().into_owned(),
        ),
        (String::from(ACTIVE), id.to_string()),
    ]);
    // KEPT, NEVER ECHOED: the verdict is the report and an error keeps its
    // words below, so the run's output is shown nowhere ([`super::Said::Kept`]).
    let ran = super::spawn_as(
        judging.work,
        super::Program::Cargo,
        &args,
        &env,
        case_bound(cases, judging.seconds).min(super::runner_bound()),
        super::Said::Kept,
    );
    let report = crate::fsio::read_to_string(store.join(JUDGE_PROFILE).join(JUDGE_REPORT))
        .ok()
        .and_then(|xml| junit_cases(&xml));
    // THE RUN'S OWN SCRATCH GOES WITH IT: nothing else ever reads it.
    let _ = std::fs::remove_dir_all(&own);
    let ran = ran?;
    let judged = verdict_of_run(ran.outcome, report.as_deref(), cases);
    if judged.0 == Verdict::Error {
        // THE RUN'S OWN WORDS, KEPT: on #1276 2,213 runs failed before a
        // case started and said nothing anywhere, so an error now leaves
        // its output beside the tree, where the summary points.
        keep_error(judging, id, &ran.output);
    }
    Ok(judged)
}

/// The nextest profile every judging run uses ([`nextest_args`]).
const JUDGE_PROFILE: &str = "mutants";

/// The `JUnit` report each judging run writes under its own store.
const JUDGE_REPORT: &str = "judge.xml";

/// The work tree's nextest config with this run's store and a `JUnit` report on
/// the judging profile.
///
/// # Errors
///
/// The work tree's nextest config does not parse.
fn judge_config(work: &std::path::Path, store: &std::path::Path) -> anyhow::Result<String> {
    let text =
        crate::fsio::read_to_string(work.join(".config").join("nextest.toml")).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|why| anyhow::anyhow!("parse nextest.toml: {why}"))?;
    doc["store"]["dir"] = toml_edit::value(store.to_string_lossy().into_owned());
    doc["profile"][JUDGE_PROFILE]["junit"]["path"] = toml_edit::value(JUDGE_REPORT);
    Ok(doc.to_string())
}

/// How one case ended, as its `JUnit` `<testcase>` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseEnd {
    Passed,
    Failed,
    TimedOut,
}

/// Every case a nextest `JUnit` report names, with how it ended: a `<failure>`
/// or `<error>` child of type `test timeout` timed out, any other failed, and
/// none passed. `None` when the report is not XML.
///
/// READ AS XML, NEVER AS WORDS (#1276). The judge used to scan the run's text
/// output, and a compiler snippet naming `TIMEOUT_MULTIPLIER` filed 220 caught
/// mutants as timeouts. A case's own output sits inside its element and is
/// never a status.
fn junit_cases(xml: &str) -> Option<Vec<(Case, CaseEnd)>> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    Some(
        doc.descendants()
            .filter(|node| node.has_tag_name("testcase"))
            .filter_map(|case| {
                let name = case.attribute("name")?;
                let binary = case.attribute("classname")?;
                let end = case
                    .children()
                    .filter(roxmltree::Node::is_element)
                    .find_map(|child| match child.tag_name().name() {
                        "failure" | "error" => {
                            Some(if child.attribute("type") == Some("test timeout") {
                                CaseEnd::TimedOut
                            } else {
                                CaseEnd::Failed
                            })
                        }
                        _ => None,
                    })
                    .unwrap_or(CaseEnd::Passed);
                Some(((name.to_owned(), binary.to_owned()), end))
            })
            .collect(),
    )
}

/// One judging run's verdict, the case that killed it, and every case it
/// proved passing, from how the process ended and its `JUnit` report.
///
/// COULD-NOT-LOOK IS AN ERROR, NEVER A MISS: a run with no report, a report
/// naming no case, or a passing exit missing one of `cases` from its report
/// decided nothing about the mutant.
fn verdict_of_run(
    outcome: super::Outcome,
    report: Option<&[(Case, CaseEnd)]>,
    cases: &BTreeSet<Case>,
) -> (Verdict, Option<Case>, Vec<Case>) {
    let passed: Vec<Case> = report
        .into_iter()
        .flatten()
        .filter(|(_, end)| *end == CaseEnd::Passed)
        .map(|(case, _)| case.clone())
        .collect();
    if matches!(outcome, super::Outcome::TimedOut) {
        return (Verdict::Timeout, None, passed);
    }
    let Some(rows) = report.filter(|rows| !rows.is_empty()) else {
        return (Verdict::Error, None, Vec::new());
    };
    if let Some((killer, _)) = rows.iter().find(|(_, end)| *end == CaseEnd::Failed) {
        return (Verdict::Caught, Some(killer.clone()), passed);
    }
    if rows.iter().any(|(_, end)| *end == CaseEnd::TimedOut) {
        return (Verdict::Timeout, None, passed);
    }
    let reported: BTreeSet<&Case> = rows.iter().map(|(case, _)| case).collect();
    if matches!(outcome, super::Outcome::Passed) && cases.iter().all(|case| reported.contains(case))
    {
        return (Verdict::Missed, None, passed);
    }
    (Verdict::Error, None, Vec::new())
}

/// Keep what an erring run of mutant `id` said under the sweep's `errors/`,
/// where the summary points.
fn keep_error(judging: &Judging<'_>, id: u32, said: &str) {
    if let Some(state) = judging.work.parent() {
        let errors = state.join("errors");
        let _ = std::fs::create_dir_all(&errors);
        let _ = crate::durable::replace(errors.join(format!("{id}.log")), said);
    }
}

/// The variable that moves an integration suite's fixture root off the path
/// cargo compiled in (`tests/it/common`'s `target_tmp`).
const TEST_TMPDIR: &str = "BATTEN_TEST_TMPDIR";

/// The function a mutant sits in, which its siblings share.
type Sibling = (String, String, Option<usize>);

/// Judge mutant `id` by the cases that reach its site, in two phases (see
/// [`phases`]); none reach it is a survivor no run could kill. A kill teaches
/// its siblings which case to try first.
fn judge(
    judging: &Judging<'_>,
    id: u32,
    mutant: &Listed,
    cases: &BTreeSet<Case>,
    hints: &std::sync::Mutex<std::collections::BTreeMap<Sibling, BTreeSet<Case>>>,
    journal: &std::sync::Mutex<Option<std::path::PathBuf>>,
) -> (Verdict, usize) {
    if cases.is_empty() {
        return (Verdict::Uncovered, 0);
    }
    let sibling: Option<Sibling> = mutant.function.as_ref().map(|function| {
        (
            mutant.file.clone(),
            function.function_name.clone(),
            function.span.as_ref().map(|span| span.start.line),
        )
    });
    // EACH CASE'S OWN RECORDED OUTCOME FIRST ([`pair_key`]): a kill under an
    // unchanged pair decides the mutant with no run; a pass leaves that case
    // out of every run, so only the cases an edit could change are run.
    let pairs: std::collections::BTreeMap<&Case, String> = cases
        .iter()
        .filter_map(|case| Some((case, pair_key(judging.root, mutant, case, judging.digests)?)))
        .collect();
    let recorded = |case: &Case| {
        pairs
            .get(case)
            .and_then(|key| judging.cache.get(key))
            .map(String::as_str)
    };
    if cases.iter().any(|case| recorded(case) == Some("caught")) {
        return (Verdict::Caught, cases.len());
    }
    let open: BTreeSet<Case> = cases
        .iter()
        .filter(|case| recorded(case) != Some(PASSED))
        .cloned()
        .collect();
    let skipped = cases.len() - open.len();
    if open.is_empty() {
        return (Verdict::Missed, skipped);
    }
    let record = |case: &Case, verdict: &str| {
        if let Some(key) = pairs.get(case) {
            append(journal, &journal_line(Some(key), verdict, &mutant.name));
        }
    };
    let hinted = sibling
        .as_ref()
        .and_then(|key| hints.lock().ok()?.get(key).cloned())
        .unwrap_or_default();
    let (first, second) = phases(&open, &hinted, judging.seconds);
    for phase in batches(&first).iter().chain(&batches(&second)) {
        match run_cases(judging, id, mutant, phase) {
            Ok((verdict, killed_by, passed)) => {
                // EVERY CASE'S OUTCOME, AS IT LANDS: a run killed mid-sweep
                // keeps each pass and kill it already proved.
                for case in &passed {
                    record(case, PASSED);
                }
                if verdict == Verdict::Missed {
                    continue;
                }
                if let Some(case) = journaled_kill(verdict, killed_by.as_ref()) {
                    record(case, "caught");
                }
                if let (Some(key), Some(case)) = (sibling, killed_by)
                    && let Ok(mut hints) = hints.lock()
                {
                    hints.entry(key).or_default().insert(case);
                }
                return (verdict, skipped);
            }
            Err(why) => {
                // A RUN THAT COULD NOT START SAYS WHY, beside the runs that
                // failed: on #1276 six such errors left no log at all.
                keep_error(judging, id, &format!("{why:#}\n"));
                return (Verdict::Error, skipped);
            }
        }
    }
    (Verdict::Missed, skipped)
}

/// The case a run's verdict journals as a kill: its killer, and only when
/// the run caught the mutant (a timeout names no killer it could reuse).
fn journaled_kill(verdict: Verdict, killed_by: Option<&Case>) -> Option<&Case> {
    killed_by.filter(|_| verdict == Verdict::Caught)
}

/// Whether the reach record under `base` was sealed by a finished run over
/// the tree `inputs` digests.
fn sealed_over(base: &std::path::Path, inputs: &str) -> bool {
    crate::fsio::read_to_string(base.join(SEALED)).is_ok_and(|held| held == inputs)
}

/// The longest filterset one run is handed, in bytes. The kernel caps ONE
/// argument at 128 KiB (`MAX_ARG_STRLEN`), and on #1276 the sites reached by
/// nearly every case failed to start with `E2BIG`.
const FILTER_BYTES: usize = 96 * 1024;

/// `phase` cut into runs whose filtersets each fit [`FILTER_BYTES`], in case
/// order, so the runs stop at the first kill as one would. Empty for an empty
/// phase.
fn batches(phase: &BTreeSet<Case>) -> Vec<BTreeSet<Case>> {
    let mut runs: Vec<BTreeSet<Case>> = Vec::new();
    let mut bytes = 0;
    for case in phase {
        // `test(=<name>) | ` per case (`cover::filterset`).
        let cost = case.0.len() + 10;
        match runs.last_mut() {
            Some(run) if bytes + cost <= FILTER_BYTES => {
                bytes += cost;
                run.insert(case.clone());
            }
            _ => {
                bytes = cost;
                runs.push([case.clone()].into());
            }
        }
    }
    runs
}

/// As nextest's `run-wrapper` while reach is recorded: run the case with its
/// own record directory, which every process it spawns inherits, and exit as
/// it did. `None` when this process is not the wrapper.
pub fn recorded(args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<String> = args
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .collect();
    if args.first().map(String::as_str) != Some(RECORD_ARG) {
        return None;
    }
    let code = match record(args.get(1..).unwrap_or_default()) {
        Ok(code) => code,
        Err(why) => {
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!("batten: schema record: {why:#}\n"),
            );
            101
        }
    };
    Some(std::process::ExitCode::from(code))
}

fn record(test: &[String]) -> anyhow::Result<u8> {
    let base = std::path::PathBuf::from(
        std::env::var_os(REACH).ok_or_else(|| anyhow::anyhow!("no reach directory"))?,
    );
    record_into(&base, test)
}

/// Record one case's reach under `base`, or nothing when a run over the same
/// tree already recorded it passing.
///
/// RESUMABLE, CASE BY CASE: a case's record is whole only once its process has
/// exited and [`DONE`] holds the exit code, so a run killed mid-suite (twice in
/// one #1276 session, each costing the whole 724 s suite) keeps every case that
/// finished and runs only the rest. A case that failed, or never finished, runs
/// again. The skip is here rather than in a filter, so the resumed run is the
/// same single invocation and no list of names meets the argument limit.
fn record_into(base: &std::path::Path, test: &[String]) -> anyhow::Result<u8> {
    let (program, rest) = test
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no case to run"))?;
    let name = super::cover::test_name(test).unwrap_or(program);
    let binary = super::cover::binary_id(program, &std::env::current_dir()?);
    let key = blake3::hash(test.join("\u{1f}").as_bytes()).to_hex()[..16].to_owned();
    let dir = base.join(key);
    if finished_passing(&dir) {
        return Ok(0);
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    crate::durable::replace(dir.join("case"), format!("{name}\t{binary}"))?;
    if let Ok(over) = crate::fsio::read_to_string(base.join(TREE)) {
        crate::durable::replace(dir.join(OVER), over)?;
    }
    let cwd = std::env::current_dir()?;
    let env = [(String::from(RECORD), dir.to_string_lossy().into_owned())];
    // TRACED WHERE THE HOST CAN, so the case's key reads only the files it
    // touched (Ekstazi's dynamic file dependencies); untraced, it keys on every
    // non-Rust file. The tree the paths are taken against comes from the
    // recorder, which knows it; a case run outside one is not traced.
    let tree = std::env::var_os(TREE_ENV).map(std::path::PathBuf::from);
    let traced = trace::tracer().filter(|_| tree.is_some());
    let trace = dir.join(TRACE);
    let ran = match traced.as_deref() {
        Some(strace) => super::spawn_as(
            &cwd,
            super::Program::Tracer(strace),
            &trace::trace_args(&trace, program, rest),
            &env,
            super::runner_bound(),
            super::Said::Streamed,
        )?,
        None => super::spawn_as(
            &cwd,
            super::Program::Test(program),
            rest,
            &env,
            super::runner_bound(),
            super::Said::Streamed,
        )?,
    };
    let code = match ran.outcome {
        super::Outcome::Passed => 0,
        super::Outcome::Failed(Some(code)) => u8::try_from(code).unwrap_or(101),
        super::Outcome::Failed(None) | super::Outcome::TimedOut => 101,
    };
    if let (Some(_), Some(tree)) = (traced, tree) {
        let roots: Vec<std::path::PathBuf> = std::fs::canonicalize(&tree)
            .ok()
            .into_iter()
            .chain(std::iter::once(tree))
            .collect();
        let read = trace::await_trace(&trace).and_then(|text| read_trace(&text, &roots));
        if let Some(read) = read {
            let listing = read.iter().fold(String::new(), |mut listing, path| {
                listing.push_str(path);
                listing.push('\n');
                listing
            });
            crate::durable::replace(dir.join(READ), listing)?;
        }
        let _ = std::fs::remove_file(&trace);
    }
    crate::durable::replace(dir.join(DONE), code.to_string())?;
    Ok(code)
}

/// The file a case's record holds once its process exited, with its exit code.
const DONE: &str = "done";

/// Whether the case recorded at `dir` finished and passed: the one record a
/// resumed run keeps.
fn finished_passing(dir: &std::path::Path) -> bool {
    crate::fsio::read_to_string(dir.join(DONE)).is_ok_and(|code| code == "0")
}

/// The file naming the schema tree a reach directory is being recorded over.
const TREE: &str = "tree";

/// The file a sealed case record holds ([`seal_reach`]): its dependency
/// digest (`D`), the functions it executed by digest (`F`), the sites it
/// reached by site key (`S`) and its seconds (`T`), so it outlives the ids of
/// the rendering it was recorded on.
const DEPENDS: &str = "depends";

/// The site keys of the listing the reach record was last sealed over.
const LISTED: &str = "listed";

/// What one rendering's positional ids mean: a reach record is written in
/// them, and is carried to another rendering by these.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    /// Each probed function's digest, by probe id.
    pub probes: &'a [String],
    /// Each mutant's site key, by mutant id.
    pub sites: &'a [Option<String>],
    /// Each located mutant's innermost probed function, by digest.
    pub mutant_fns: &'a std::collections::BTreeMap<u32, String>,
    /// The mutants handed back, which no reach run switches.
    pub classic: &'a BTreeSet<u32>,
}

/// A sealed case record ([`DEPENDS`]), read back.
#[derive(Debug, Default, PartialEq)]
struct Carried {
    digest: String,
    functions: BTreeSet<String>,
    sites: BTreeSet<String>,
    seconds: Option<f64>,
}

fn carried(text: &str) -> Option<Carried> {
    let mut record = Carried::default();
    for line in text.lines() {
        let (tag, value) = line.split_at_checked(1)?;
        match tag {
            "D" => value.clone_into(&mut record.digest),
            "F" => {
                record.functions.insert(value.to_owned());
            }
            "S" => {
                record.sites.insert(value.to_owned());
            }
            "T" => record.seconds = value.parse().ok(),
            _ => return None,
        }
    }
    (!record.digest.is_empty()).then_some(record)
}

/// Each value's ids in `by_id`, inverted: one digest or key can name several.
fn ids_by_value<T: AsRef<str>>(
    by_id: impl IntoIterator<Item = (usize, T)>,
) -> std::collections::BTreeMap<String, Vec<usize>> {
    let mut ids: std::collections::BTreeMap<String, Vec<usize>> = std::collections::BTreeMap::new();
    for (id, value) in by_id {
        ids.entry(value.as_ref().to_owned()).or_default().push(id);
    }
    ids
}

/// The live tree a sweep verifies carried records over, for each to take its
/// selection digest there ([`retest_carried`]): the snapshot's root, the
/// checkout's content ids ([`resource_ids`]) and the [`Format`] it is read in.
pub type Over<'a> = (
    &'a std::path::Path,
    &'a std::collections::BTreeMap<String, String>,
    &'a Format,
);

/// The digests a carried case's dependencies would have on this rendering.
pub type Recompute<'r> = dyn Fn(
        &std::collections::BTreeMap<Case, BTreeSet<usize>>,
        &std::collections::BTreeMap<Case, BTreeSet<String>>,
    ) -> std::collections::BTreeMap<Case, String>
    + 'r;

/// Keep each case record under `base` this rendering can still trust, and
/// clear the rest so the reach run records them again; how many it carried
/// across a change and how many it resumed over this same tree.
///
/// INCREMENTAL ACROSS A MOVING HEAD (`ReMT`, Zhang et al. ISSTA 2012; Ekstazi):
/// a sealed record is carried when every function it executed still exists
/// by digest, its dependency digest recomputed on this tree is the one it was
/// sealed with, and no mutant new to this listing sits in a function it ran,
/// which its record could not have seen. A lap that adds a test re-records
/// that test, not the suite. A record not yet sealed (a run killed mid-suite)
/// is kept only over the tree it was recorded on, whose ids it is written in.
///
/// A CARRY IS A VERIFICATION, SO IT BACKFILLS SELECTION: with `over`, every
/// record carried takes its selection digest over the live tree it was just
/// verified on ([`retest_carried`]), so any sweep, an all-carry one included,
/// leaves `test:cargo` a digest for every case it kept.
///
/// # Errors
///
/// The directory cannot be read, cleared or written.
fn carry_forward(
    base: &std::path::Path,
    inputs: &str,
    identity: &Identity<'_>,
    (recompute, over): (&Recompute<'_>, Option<Over<'_>>),
) -> anyhow::Result<(usize, usize)> {
    std::fs::create_dir_all(base)?;
    let same_tree = crate::fsio::read_to_string(base.join(TREE)).is_ok_and(|held| held == inputs);
    let listed: BTreeSet<String> = crate::fsio::read_to_string(base.join(LISTED))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    let mut fresh_fns = BTreeSet::new();
    let mut fresh_unplaced = false;
    for (id, key) in identity.sites.iter().enumerate() {
        let id = u32::try_from(id)?;
        if identity.classic.contains(&id) || key.as_ref().is_some_and(|key| listed.contains(key)) {
            continue;
        }
        match identity.mutant_fns.get(&id) {
            Some(function) => {
                fresh_fns.insert(function.clone());
            }
            None => fresh_unplaced = true,
        }
    }
    let functions = ids_by_value(identity.probes.iter().enumerate());
    let mut candidates: Vec<(std::path::PathBuf, Case, Carried)> = Vec::new();
    let mut resumed = 0;
    for entry in std::fs::read_dir(base)? {
        let dir = entry?.path();
        if !dir.is_dir() {
            continue;
        }
        let record = crate::fsio::read_to_string(dir.join(DEPENDS))
            .ok()
            .and_then(|text| carried(&text));
        let case = crate::fsio::read_to_string(dir.join("case"))
            .ok()
            .map(|head| {
                let (name, binary) = head.split_once('\t').unwrap_or((head.as_str(), ""));
                (name.to_owned(), binary.to_owned())
            });
        match (finished_passing(&dir), record, case) {
            (true, Some(record), Some(case))
                if !fresh_unplaced
                    && record.functions.is_disjoint(&fresh_fns)
                    && record.functions.iter().all(|f| functions.contains_key(f)) =>
            {
                candidates.push((dir, case, record));
            }
            (true, None, Some(_)) if same_tree => resumed += 1,
            _ => {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    let mut executed = std::collections::BTreeMap::new();
    let mut read = std::collections::BTreeMap::new();
    for (dir, case, record) in &candidates {
        let ids: BTreeSet<usize> = record
            .functions
            .iter()
            .flat_map(|f| functions.get(f).into_iter().flatten().copied())
            .collect();
        executed.insert(case.clone(), ids);
        if let Ok(listing) = crate::fsio::read_to_string(dir.join(READ)) {
            read.insert(case.clone(), listing.lines().map(str::to_owned).collect());
        }
    }
    let now = recompute(&executed, &read);
    let mut kept: Vec<(std::path::PathBuf, Case, Ran)> = Vec::new();
    for (dir, case, record) in candidates {
        if now.get(&case) == Some(&record.digest) {
            let touched = read.get(&case).cloned();
            kept.push((dir, case, (record.functions, touched)));
        } else {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    // THE SELECTION DIGEST IS AN ECONOMY: one that cannot be taken leaves the
    // record to the suite's build key, and never fails the carry.
    if let Some(over) = over {
        let _ = retest_carried(base, &kept, over);
    }
    crate::durable::replace(base.join(TREE), inputs)?;
    Ok((kept.len(), resumed))
}

/// Write the selection digest ([`TESTED`]) of every record of `carried` over
/// the live tree `over` names, wherever it holds none or holds one read in the
/// same [`Format`]. A record holding a digest read in
/// another format keeps it: that digest is compared only in its own format.
///
/// SOUND AS A CARRY IS: [`carry_forward`] keeps a record only where every
/// function it ran still exists by digest and its dependency digest over this
/// tree is the one it was sealed with, so what it ran is what this tree runs,
/// and the digest taken here is the one `test:cargo` recomputes on it. A pass
/// is never read under a digest no run passed under: the suite's passes are
/// keyed on the digest itself.
///
/// # Errors
///
/// The tree cannot be indexed, or a digest cannot be written.
fn retest_carried(
    base: &std::path::Path,
    carried: &[(std::path::PathBuf, Case, Ran)],
    (root, resources, format): Over<'_>,
) -> anyhow::Result<()> {
    let key = format.key();
    let due: Vec<&(std::path::PathBuf, Case, Ran)> = carried
        .iter()
        .filter(|(dir, _, _)| {
            crate::fsio::read_to_string(dir.join(TESTED))
                .ok()
                .is_none_or(|held| {
                    held.trim_end()
                        .split_once('\t')
                        .is_none_or(|(read_in, _)| read_in == key)
                })
        })
        .collect();
    if due.is_empty() {
        return Ok(());
    }
    format.store(base)?;
    let index = dependency_index(root, format)?;
    let cases: std::collections::BTreeMap<Case, Ran> = due
        .iter()
        .map(|(_, case, ran)| (case.clone(), ran.clone()))
        .collect();
    let digests = test_digests(root, &index, &format.dirs, &cases, resources);
    for (dir, case, _) in due {
        let Some(Some(digest)) = digests.get(case) else {
            continue;
        };
        let line = format!("{key}\t{digest}");
        let held = crate::fsio::read_to_string(dir.join(TESTED)).ok();
        if held.as_deref().map(str::trim_end) != Some(line.as_str()) {
            crate::durable::replace(dir.join(TESTED), &line)?;
        }
    }
    Ok(())
}

/// Whether a case recorded at `dir` finished and passed: the one record a
/// resumed or carried run keeps.
fn kept_case(dir: &std::path::Path) -> Option<Case> {
    let head = crate::fsio::read_to_string(dir.join("case")).ok()?;
    let (name, binary) = head.split_once('\t').unwrap_or((head.as_str(), ""));
    Some((name.to_owned(), binary.to_owned()))
}

/// What the reach run recorded: per mutant site, the cases that reached it;
/// per case, the probed functions it executed.
#[derive(Debug, Default)]
pub struct Reach {
    /// Each site's reaching cases, by mutant id.
    pub sites: std::collections::BTreeMap<u32, BTreeSet<Case>>,
    /// Each case's executed functions, by probe id.
    pub executed: std::collections::BTreeMap<Case, BTreeSet<usize>>,
    /// Each traced case's touched tree paths ([`READ`]); an untraced case is
    /// absent, never empty.
    pub read: std::collections::BTreeMap<Case, BTreeSet<String>>,
    /// Each carried case's seconds as sealed: this run skipped it, so its own
    /// timing reads as nothing.
    pub seconds: std::collections::BTreeMap<Case, f64>,
    /// The schema tree the record is over ([`tree_digest`]).
    pub tree: String,
}

/// Every mutant site each case reached and every function it executed, from
/// every process of each case, a sealed case's carried by [`Identity`].
///
/// # Errors
///
/// The reach directory cannot be read.
pub fn collect_reach(base: &std::path::Path, identity: &Identity<'_>) -> anyhow::Result<Reach> {
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(base)? {
        dirs.push(entry?.path());
    }
    collect_dirs(dirs, identity)
}

/// [`collect_reach`] over the case directories `dirs` alone, so a sweep can
/// read back only the records a stopped run left ([`seal_leftovers`]).
fn collect_dirs(
    dirs: impl IntoIterator<Item = std::path::PathBuf>,
    identity: &Identity<'_>,
) -> anyhow::Result<Reach> {
    let functions = ids_by_value(identity.probes.iter().enumerate());
    let sites = ids_by_value(
        identity
            .sites
            .iter()
            .enumerate()
            .filter_map(|(id, key)| key.as_deref().map(|key| (id, key))),
    );
    let mut reach = Reach::default();
    for dir in dirs {
        let Some(case) = kept_case(&dir) else {
            continue;
        };
        if let Ok(listing) = crate::fsio::read_to_string(dir.join(READ)) {
            reach
                .read
                .insert(case.clone(), listing.lines().map(str::to_owned).collect());
        }
        if let Some(record) = crate::fsio::read_to_string(dir.join(DEPENDS))
            .ok()
            .and_then(|text| carried(&text))
        {
            let executed = reach.executed.entry(case.clone()).or_default();
            for function in &record.functions {
                executed.extend(functions.get(function).into_iter().flatten().copied());
            }
            for key in &record.sites {
                for id in sites.get(key).into_iter().flatten() {
                    reach
                        .sites
                        .entry(u32::try_from(*id)?)
                        .or_default()
                        .insert(case.clone());
                }
            }
            if let Some(seconds) = record.seconds {
                reach.seconds.insert(case, seconds);
            }
            continue;
        }
        for file in std::fs::read_dir(&dir)? {
            let path = file?.path();
            if path
                .file_name()
                .is_some_and(|f| f == "case" || f == DONE || f == TRACE || f == READ || f == OVER)
            {
                continue;
            }
            let text = crate::fsio::read_to_string(&path).unwrap_or_default();
            for line in text.lines().map(str::trim) {
                if let Some(probe) = line.strip_prefix('f') {
                    if let Ok(probe) = probe.parse::<usize>() {
                        reach
                            .executed
                            .entry(case.clone())
                            .or_default()
                            .insert(probe);
                    }
                } else if let Ok(site) = line.parse::<u32>() {
                    reach.sites.entry(site).or_default().insert(case.clone());
                }
            }
        }
    }
    Ok(reach)
}

/// Seal every case record under `base` in identities that outlive this
/// rendering ([`DEPENDS`]), then the listing's site keys and the tree, so the
/// next sweep carries what it can ([`carry_forward`]). A case reaching a site
/// with no key is left unsealed, and so is recorded again on another tree.
///
/// # Errors
///
/// A record cannot be read or written.
pub fn seal_reach(
    base: &std::path::Path,
    reach: &Reach,
    digests: &std::collections::BTreeMap<Case, String>,
    identity: &Identity<'_>,
    seconds: &std::collections::BTreeMap<Case, f64>,
    whole: bool,
) -> anyhow::Result<()> {
    let mut reached: std::collections::BTreeMap<&Case, BTreeSet<u32>> =
        std::collections::BTreeMap::new();
    for (site, cases) in &reach.sites {
        for case in cases {
            reached.entry(case).or_default().insert(*site);
        }
    }
    for entry in std::fs::read_dir(base)? {
        let dir = entry?.path();
        let Some(case) = kept_case(&dir) else {
            continue;
        };
        let Some(digest) = digests.get(&case) else {
            continue;
        };
        seal_dir(
            &dir,
            digest,
            reach.executed.get(&case),
            reached.get(&case),
            seconds.get(&case).copied(),
            identity,
        )?;
    }
    write_listed(base, identity)?;
    // THE TREE IS SEALED ONLY BY A WHOLE PASS: a seal over the same tree skips
    // the suite, which after a failed baseline would skip the refusal too. Each
    // passing case's `depends` is written either way, which is what carries.
    if whole {
        crate::durable::replace(base.join(SEALED), &reach.tree)?;
    }
    Ok(())
}
/// Write the listing's site keys under `base` ([`LISTED`]): what the records
/// there were made against, so the next run knows which mutants are new.
///
/// WRITTEN WHEN REACH STARTS, NOT WHEN IT ENDS: a record a recorder sealed is
/// carried only against the listing it was made under, and one written only at
/// the end was absent after a kill, so every mutant read as new and every
/// recorder-sealed record was dropped — the crash it exists for.
///
/// # Errors
///
/// The file cannot be written.
fn write_listed(base: &std::path::Path, identity: &Identity<'_>) -> anyhow::Result<()> {
    let listing = identity
        .sites
        .iter()
        .flatten()
        .fold(String::new(), |mut listing, key| {
            listing.push_str(key);
            listing.push('\n');
            listing
        });
    crate::durable::replace(base.join(LISTED), listing)?;
    Ok(())
}

/// Seal one case's record at `dir` in identities ([`DEPENDS`]) and drop its
/// per-process files; a case reaching a keyless site is left unsealed.
///
/// # Errors
///
/// The record cannot be written or the directory read.
fn seal_dir(
    dir: &std::path::Path,
    digest: &str,
    executed: Option<&BTreeSet<usize>>,
    reached: Option<&BTreeSet<u32>>,
    seconds: Option<f64>,
    identity: &Identity<'_>,
) -> anyhow::Result<()> {
    let mut record = format!("D{digest}\n");
    for probe in executed.into_iter().flatten() {
        let Some(function) = identity.probes.get(*probe) else {
            continue;
        };
        let _ = writeln!(record, "F{function}");
    }
    for site in reached.into_iter().flatten() {
        match identity
            .sites
            .get(usize::try_from(*site)?)
            .and_then(Option::as_ref)
        {
            Some(key) => {
                let _ = writeln!(record, "S{key}");
            }
            None => return Ok(()),
        }
    }
    if let Some(took) = seconds {
        let _ = writeln!(record, "T{took}");
    }
    crate::durable::replace(dir.join(DEPENDS), record)?;
    for file in std::fs::read_dir(dir)? {
        let path = file?.path();
        let own = path.file_name().is_some_and(|f| {
            f == "case" || f == DONE || f == READ || f == DEPENDS || f == OVER || f == TESTED
        });
        if !own {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

/// The file under the reach directory holding what a stopped run's records
/// are sealed with ([`SealContext`], [`seal_leftovers`]).
const CONTEXT: &str = "context.json";

/// What a run's records are sealed with: the sweep's identities and every input
/// [`case_digests`] reads, written when reach starts, so a run that never
/// reached its own end-of-run seal can still be sealed by the next one.
///
/// CRASH-ONLY WITHOUT A PER-CASE TAX: sealed only after the whole suite exited,
/// a sweep killed at case 9,000 left 9,000 records that carried nowhere once the
/// head moved, and the next run recorded them all again. Sealing in each
/// recorder would parse this context ~9,960 times a run to cover the one case
/// of a kill; the context and the `pristine/` snapshot its `root` names both
/// outlive the stopped run, so the next sweep seals what it left, once.
#[derive(serde::Serialize, serde::Deserialize)]
struct SealContext {
    root: std::path::PathBuf,
    dirs: std::collections::BTreeMap<String, String>,
    probes: Vec<String>,
    names: Vec<BTreeSet<String>>,
    items: std::collections::BTreeMap<String, BTreeSet<String>>,
    mentions: std::collections::BTreeMap<String, BTreeSet<String>>,
    resources: std::collections::BTreeMap<String, String>,
    untraced: String,
    sites: Vec<Option<String>>,
    mutant_fns: std::collections::BTreeMap<u32, String>,
    classic: BTreeSet<u32>,
    /// What a case's selection digest is read in ([`seal_tested`]): the probed
    /// and unprobed files, the features and the cargo arguments. A context
    /// written before it existed takes no selection digest.
    #[serde(default)]
    format: Option<Format>,
}

impl SealContext {
    fn identity(&self) -> Identity<'_> {
        Identity {
            probes: &self.probes,
            sites: &self.sites,
            mutant_fns: &self.mutant_fns,
            classic: &self.classic,
        }
    }
}

/// [`seal_leftovers`] over the sweep's reach directory under `state`, saying
/// how many a stopped run left.
///
/// # Errors
///
/// As [`seal_leftovers`], or the line cannot be written.
fn keep_leftovers(state: &std::path::Path, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let leftovers = seal_leftovers(&state.join("reach"))?;
    if leftovers > 0 {
        writeln!(
            out,
            "mutate schema: sealed {leftovers} case(s) a stopped run finished"
        )?;
    }
    Ok(())
}

/// Seal every finished, passing record under `base` that a stopped run left
/// unsealed, with the context that run wrote; the count sealed. No context, no
/// leftovers. Run before the sweep re-copies `pristine/`, the snapshot the
/// context's `root` names, so each digest is the one the stopped run's own
/// end-of-run seal would have written. Idempotent: a crash in here reruns it.
///
/// # Errors
///
/// The context does not parse, or a record cannot be read or written.
fn seal_leftovers(base: &std::path::Path) -> anyhow::Result<usize> {
    let Ok(text) = crate::fsio::read_to_string(base.join(CONTEXT)) else {
        return Ok(0);
    };
    let context: SealContext = serde_json::from_str(&text)?;
    let identity = context.identity();
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let dir = entry?.path();
        if dir.is_dir() && finished_passing(&dir) && !dir.join(DEPENDS).exists() {
            dirs.push(dir);
        }
    }
    if dirs.is_empty() {
        return Ok(0);
    }
    let reach = collect_dirs(dirs.clone(), &identity)?;
    let mut executed = reach.executed.clone();
    for dir in &dirs {
        if let Some(case) = kept_case(dir) {
            executed.entry(case).or_default();
        }
    }
    let digests = case_digests(
        &context.root,
        executed.keys(),
        &context.dirs,
        &executed,
        &Depends {
            probes: &context.probes,
            names: &context.names,
            items: &context.items,
            mentions: &context.mentions,
            read: &reach.read,
            resources: &context.resources,
            untraced: &context.untraced,
        },
    );
    let mut reached: std::collections::BTreeMap<&Case, BTreeSet<u32>> =
        std::collections::BTreeMap::new();
    for (site, cases) in &reach.sites {
        for case in cases {
            reached.entry(case).or_default().insert(*site);
        }
    }
    let mut sealed = 0;
    for dir in &dirs {
        let Some(case) = kept_case(dir) else {
            continue;
        };
        let Some(digest) = digests.get(&case) else {
            continue;
        };
        seal_dir(
            dir,
            digest,
            reach.executed.get(&case),
            reached.get(&case),
            None,
            &identity,
        )?;
        if dir.join(DEPENDS).exists() {
            sealed += 1;
        }
    }
    if let Some(format) = &context.format {
        seal_tested(base, &context.root, &context.resources, format)?;
    }
    Ok(sealed)
}

/// Run the suite once on the schema build with no mutant active, recording
/// which sites each case reaches; a case whose record [`carry_forward`] kept
/// is skipped by the recorder, so a lap re-runs only what its change touched.
/// It is also the baseline: a case that fails unmutated makes every verdict
/// meaningless, so it refuses.
///
/// # Errors
///
/// A case failed unmutated, or the run could not be made.
pub fn record_reach(
    work: &std::path::Path,
    target: &std::path::Path,
    state: &std::path::Path,
    packages: &BTreeSet<&str>,
    (identity, recompute, over): (&Identity<'_>, &Recompute<'_>, Option<Over<'_>>),
    out: &mut dyn std::io::Write,
) -> anyhow::Result<(Reach, bool)> {
    let base = state.join("reach");
    // A RESTART OVER THE SAME TREE resumes from the record a finished run
    // sealed instead of re-running the suite (640 s on #1276).
    let inputs = tree_digest(work);
    if sealed_over(&base, &inputs) {
        let mut reach = collect_reach(&base, identity)?;
        reach.tree = inputs;
        return Ok((reach, true));
    }
    let (carried, resumed) = carry_forward(&base, &inputs, identity, (recompute, over))?;
    write_listed(&base, identity)?;
    writeln!(
        out,
        "mutate schema: reach carried {carried} case(s) across the change, resumed {resumed}"
    )?;
    let config = state.join("nextest.toml");
    // A PRIVATE COPY of this binary is the recorder: the suite runs for minutes,
    // and the checkout's own `target/debug/batten` is relinked by any build in
    // between, so a case could run a half-linked one. Renamed into place, so a
    // running copy is never written.
    let recorder = state.join("recorder");
    let staged = state.join(format!("recorder.{}", std::process::id()));
    std::fs::copy(std::env::current_exe()?, &staged)?;
    std::fs::rename(&staged, &recorder)?;
    crate::durable::replace(
        &config,
        super::cover::wrapped_config(work, &recorder, RECORD_ARG, &state.join("nextest"))?,
    )?;
    let mut args: Vec<String> = [
        "nextest",
        "run",
        "--cargo-profile",
        "test",
        "--profile",
        "batten-cover",
        "--no-fail-fast",
        "--config-file",
    ]
    .map(String::from)
    .to_vec();
    args.push(config.to_string_lossy().into_owned());
    for package in packages {
        args.extend([String::from("-p"), (*package).to_owned()]);
    }
    args.extend(cargo_dirs(target));
    let mut env: Vec<(String, String)> = Vec::new();
    env.extend([
        (String::from(REACH), base.to_string_lossy().into_owned()),
        (String::from(TREE_ENV), work.to_string_lossy().into_owned()),
    ]);
    let ran = super::spawn_as(
        work,
        super::Program::Cargo,
        &args,
        &env,
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    // A FAILED BASELINE STILL KEEPS WHAT PASSED: the caller seals every case
    // that finished passing before it refuses, so the next run carries them
    // across the fix instead of re-running the whole suite (9,952 of 9,959
    // cases thrown away on #1276 when seven failed and the tree then moved).
    let passed = ran.passed();
    // THE FINISHED SUITE'S FIXTURES GO: nothing reads them once it has exited,
    // and on #1276 they held 3.7 GB of the tree's target while the judging ran.
    let _ = std::fs::remove_dir_all(target.join("tmp"));
    let mut reach = collect_reach(&base, identity)?;
    reach.tree = inputs;
    Ok((reach, passed))
}

/// The file `record_reach` writes once a record is whole, holding the digest
/// of the tree it was recorded over.
const SEALED: &str = "sealed";

/// The digest of every non-Rust file the checkout at `live` tracks or has
/// changed: fixtures, presets, configs and the lockfile a run may read, which
/// no probe records. Untracked ignored files (a session transcript) are not.
///
/// # Errors
///
/// The checkout's index or status cannot be read.
pub fn resource_digest(live: &std::path::Path) -> anyhow::Result<String> {
    let mut paths = crate::git::tracked_paths(live)?;
    paths.extend(crate::git::changed_paths(live)?);
    let mut hasher = blake3::Hasher::new();
    for path in paths.iter().filter(|path| {
        !std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
    }) {
        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(&crate::fsio::read(live.join(path)).unwrap_or_default());
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Each path of the checkout at `live` by its content id: git's own blob id
/// from the index, which costs no hashing, and a fresh one for each path the
/// working tree changed or git does not track. A deleted path is left out, so
/// it reads as absent.
///
/// # Errors
///
/// The checkout's index or working tree cannot be read.
pub fn resource_ids(
    live: &std::path::Path,
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let mut ids = std::collections::BTreeMap::new();
    for fact in crate::git::index_facts(live, &[String::from(".")])?.into_values() {
        for entry in fact.entries.into_iter().filter(|entry| entry.stage == 0) {
            ids.insert(entry.path, entry.oid);
        }
        for path in fact.diverged.into_iter().chain(fact.untracked) {
            match crate::fsio::read(live.join(&path)) {
                Ok(bytes) => {
                    let id = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(crate::git::blob_id)
                        .unwrap_or_else(|| format!("b3:{}", blake3::hash(&bytes).to_hex()));
                    ids.insert(path, id);
                }
                Err(_) => {
                    ids.remove(&path);
                }
            }
        }
    }
    Ok(ids)
}

/// The content id a case keys a path it touched on: the file's, a directory's
/// listing of the names directly in it, or `-` for a path that is absent, so
/// a file appearing where a case probed for none moves its key.
fn resource_id(resources: &std::collections::BTreeMap<String, String>, path: &str) -> String {
    if let Some(id) = resources.get(path) {
        return id.clone();
    }
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path}/")
    };
    let listing: BTreeSet<&str> = resources
        .range(prefix.clone()..)
        .take_while(|(held, _)| held.starts_with(&prefix))
        .filter_map(|(held, _)| held[prefix.len()..].split('/').next())
        .collect();
    if listing.is_empty() {
        return String::from("-");
    }
    let mut hasher = blake3::Hasher::new();
    for name in listing {
        hasher.update(name.as_bytes());
        hasher.update(b"\x1f");
    }
    format!("dir:{}", hasher.finalize().to_hex())
}

/// A digest of every source and manifest in the schema tree: what the test
/// binaries a reach record ran were built from. The build output is not.
#[must_use]
pub fn tree_digest(work: &std::path::Path) -> String {
    let mut files: Vec<std::path::PathBuf> = ignore::WalkBuilder::new(work)
        .standard_filters(false)
        .filter_entry(|entry| !matches!(entry.file_name().to_str(), Some("target" | ".git")))
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .map(ignore::DirEntry::into_path)
        .collect();
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for file in files {
        hasher.update(
            file.strip_prefix(work)
                .unwrap_or(&file)
                .as_os_str()
                .as_encoded_bytes(),
        );
        hasher.update(&[0]);
        hasher.update(&std::fs::read(&file).unwrap_or_default());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Regression reuse: a verdict stands while nothing it was decided over moved.
// ---------------------------------------------------------------------------

/// The source files a case's verdict depends on, besides the mutated site:
/// an integration case's own `tests/<binary>/<module>.rs` and the shared
/// `common/` beside it, or a unit case's module file. `package_dirs` maps a
/// package name to its directory.
#[must_use]
pub fn case_sources(
    package_dirs: &std::collections::BTreeMap<String, String>,
    name: &str,
    binary: &str,
) -> Vec<String> {
    let (package, target) = binary.split_once("::").unwrap_or((binary, ""));
    let Some(dir) = package_dirs.get(package) else {
        return Vec::new();
    };
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let module: Vec<&str> = name
        .split("::")
        .take_while(|segment| *segment != "tests")
        .collect();
    let module = &module[..module
        .len()
        .saturating_sub(usize::from(!name.contains("::tests::")))];
    if target.is_empty() {
        if module.is_empty() {
            return vec![format!("{prefix}src/lib.rs")];
        }
        let path = module.join("/");
        return vec![
            format!("{prefix}src/{path}.rs"),
            format!("{prefix}src/{path}/mod.rs"),
        ];
    }
    if target.contains('/') {
        return vec![format!("{prefix}src/main.rs")];
    }
    let head = module.first().copied().unwrap_or_default();
    // NOT THE TARGET'S `main.rs`: it declares the modules and nothing a case
    // asserts, so one `mod` line added on #1276 moved the key of every mutant
    // an integration case reaches and the next lap re-judged them all.
    vec![
        format!("{prefix}tests/{target}/{head}.rs"),
        format!("{prefix}tests/{target}/common/mod.rs"),
        format!("{prefix}tests/{target}.rs"),
    ]
}

/// The key an unviable verdict is reused under: the mutated function's text
/// and the mutation without its position. Whether a mutant compiles depends
/// on nothing else. `None` when the function cannot be read.
#[must_use]
pub fn site_key(root: &std::path::Path, mutant: &Listed) -> Option<String> {
    Some(site_hasher(root, mutant)?.finalize().to_hex().to_string())
}

/// The key a run's verdict is reused under: [`site_key`]'s inputs and every
/// reaching case with its [`case_digests`] digest.
#[must_use]
pub fn verdict_key(
    root: &std::path::Path,
    mutant: &Listed,
    cases: &BTreeSet<(String, String)>,
    digests: &std::collections::BTreeMap<Case, String>,
) -> Option<String> {
    let mut hasher = site_hasher(root, mutant)?;
    for case in cases {
        let digest = digests.get(case).map_or("", String::as_str);
        hasher.update(format!("\x1e{}\x1f{}\x1f{digest}", case.0, case.1).as_bytes());
    }
    Some(hasher.finalize().to_hex().to_string())
}

/// The key one case's outcome against one mutant is reused under: the
/// mutant's [`site_key`] inputs and that case alone with its digest.
///
/// THE MUTANT-TEST PAIR IS THE UNIT (Regression Mutation Testing, Zhang,
/// Marinov, Zhang & Khurshid, ISSTA 2012): a verdict keyed by EVERY reaching
/// case moved whenever any one of them did, so a mutant reached by 2,000
/// integration cases ran all 2,000 again for an edit that touched one. Keyed
/// by the pair, an edit re-runs exactly the cases it can change.
///
/// Its limit is the verdict key's: a case's digest is what it executed
/// unmutated, so code only a mutant steers it into is not in the key.
#[must_use]
pub fn pair_key(
    root: &std::path::Path,
    mutant: &Listed,
    case: &Case,
    digests: &std::collections::BTreeMap<Case, String>,
) -> Option<String> {
    let mut hasher = site_hasher(root, mutant)?;
    let digest = digests.get(case).map_or("", String::as_str);
    hasher.update(format!("\x1dpair\x1e{}\x1f{}\x1f{digest}", case.0, case.1).as_bytes());
    Some(hasher.finalize().to_hex().to_string())
}

/// The journal's verdict for one case that ran a mutant and passed.
const PASSED: &str = "passed";

/// Append `line` to the journal, one write so a crash tears at most it.
fn append(journal: &std::sync::Mutex<Option<std::path::PathBuf>>, line: &str) {
    if let Ok(held) = journal.lock()
        && let Some(path) = held.as_ref()
    {
        let _ = crate::durable::append(path, line);
    }
}

/// What a case's key reads besides its own text: per case, its executed
/// functions and the files it read; across the sweep, what each names.
#[derive(Debug, Clone, Copy)]
pub struct Depends<'a> {
    /// Each probed function's source digest, by probe id.
    pub probes: &'a [String],
    /// Each probed function's names, by probe id ([`names_in`]).
    pub names: &'a [BTreeSet<String>],
    /// Every skeleton item's digests, by name ([`Schema::items`]).
    pub items: &'a std::collections::BTreeMap<String, BTreeSet<String>>,
    /// Every skeleton item's mentioned names, by name ([`Schema::mentions`]).
    pub mentions: &'a std::collections::BTreeMap<String, BTreeSet<String>>,
    /// The checkout paths each traced case touched ([`Reach::read`]); a case
    /// absent here was not traced.
    pub read: &'a std::collections::BTreeMap<Case, BTreeSet<String>>,
    /// Each checkout path's content id ([`resource_ids`]).
    pub resources: &'a std::collections::BTreeMap<String, String>,
    /// What an untraced case keys on in place of its reads: every non-Rust
    /// file's content ([`resource_digest`]).
    pub untraced: &'a str,
}

/// Every name reachable from `start` through what each named item mentions:
/// a function naming `LIMIT`, where `const LIMIT: u8 = limit();`, depends on
/// `limit` too, which no token of the function names.
#[cfg(test)]
fn named_closure<'n>(
    start: impl IntoIterator<Item = &'n String>,
    mentions: &std::collections::BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = start.into_iter().cloned().collect();
    while let Some(name) = frontier.pop() {
        if !reached.insert(name.clone()) {
            continue;
        }
        if let Some(mentioned) = mentions.get(&name) {
            frontier.extend(
                mentioned
                    .iter()
                    .filter(|next| !reached.contains(*next))
                    .cloned(),
            );
        }
    }
    reached
}

/// The mentions graph by integer id, built once per sweep: ids are ranked in
/// name order, so a walk listed by id is listed by name.
struct Graph<'g> {
    ids: std::collections::HashMap<&'g str, usize>,
    names: Vec<&'g str>,
    edges: Vec<Vec<usize>>,
    tokens: Vec<Option<blake3::Hash>>,
}

/// One walk's reusable state: the visited map and the ids it set.
#[derive(Default)]
struct Walk {
    seen: Vec<bool>,
    reached: Vec<usize>,
    frontier: Vec<usize>,
}

impl<'g> Graph<'g> {
    /// Every name the mentions graph or a probe names, ranked by name.
    fn new(depends: &Depends<'g>) -> Self {
        let mut all: BTreeSet<&'g str> = BTreeSet::new();
        for (name, mentioned) in depends.mentions {
            all.insert(name);
            all.extend(mentioned.iter().map(String::as_str));
        }
        for names in depends.names {
            all.extend(names.iter().map(String::as_str));
        }
        let names: Vec<&'g str> = all.into_iter().collect();
        let ids: std::collections::HashMap<&'g str, usize> = names
            .iter()
            .enumerate()
            .map(|(id, name)| (*name, id))
            .collect();
        let edges = names
            .iter()
            .map(|name| {
                depends
                    .mentions
                    .get(*name)
                    .into_iter()
                    .flatten()
                    .filter_map(|next| ids.get(next.as_str()).copied())
                    .collect()
            })
            .collect();
        // EACH NAME'S ITEMS HASHED ONCE PER SWEEP, here rather than on first
        // reach: nearly every name is reached by some case.
        let tokens = names
            .iter()
            .map(|name| {
                depends
                    .items
                    .get(*name)
                    .map(|items| name_token(name, items))
            })
            .collect();
        Self {
            ids,
            names,
            edges,
            tokens,
        }
    }

    fn id(&self, name: &str) -> Option<usize> {
        self.ids.get(name).copied()
    }

    /// Every id reachable from `starts`, the starts included, in name order.
    fn reach<'w>(&self, starts: impl Iterator<Item = usize>, walk: &'w mut Walk) -> &'w [usize] {
        walk.seen.resize(self.names.len(), false);
        for id in walk.reached.drain(..) {
            walk.seen[id] = false;
        }
        walk.frontier.clear();
        walk.frontier.extend(starts);
        while let Some(id) = walk.frontier.pop() {
            if std::mem::replace(&mut walk.seen[id], true) {
                continue;
            }
            walk.reached.push(id);
            walk.frontier.extend(
                self.edges[id]
                    .iter()
                    .copied()
                    .filter(|next| !walk.seen[*next]),
            );
        }
        walk.reached.sort_unstable();
        &walk.reached
    }

    /// A reached id's token, computed when the graph was built.
    fn token_of(&self, id: usize) -> Option<blake3::Hash> {
        self.tokens[id]
    }
}

/// One reached name's contribution to a case's digest.
fn name_token(name: &str, items: &BTreeSet<String>) -> blake3::Hash {
    let mut own = blake3::Hasher::new();
    own.update(format!("\x1b{name}\x1f").as_bytes());
    for item in items {
        own.update(b"\x1b");
        own.update(item.as_bytes());
    }
    own.finalize()
}

/// Each case's own text, digested once per sweep (read once per file): in
/// each of its own module files, the test function it names and the helper
/// functions beside it; the whole file where no such test is found; and the
/// shared fixtures (`common/mod.rs`) whole. KEYED BY THE CASE, NOT ITS FILE:
/// on #1276 a file-wide key moved every mutant a `lib.rs` case reaches on any
/// edit to `lib.rs`, so a lap re-judged nearly all of them.
///
/// AND WHAT IT DEPENDS ON, NEVER THE TREE (Ekstazi, Gligoric et al., ISSTA
/// 2015; RTS++; RustyRTS): each probed function the reach run saw the case
/// run, by its digest; every skeleton item those functions name; and each file
/// it touched with that file's content id, absent included. A case the reach
/// run could not trace keys on every non-Rust file instead, which is what
/// every case keyed on before and is never less sound. On #1276 a tree-wide
/// digest in every key moved every pair on a commit that added tests and two
/// `exclude_re` lines, and the next sweep re-judged all 2386 viable mutants.
#[must_use]
pub fn case_digests<'c>(
    root: &std::path::Path,
    cases: impl IntoIterator<Item = &'c Case>,
    package_dirs: &std::collections::BTreeMap<String, String>,
    executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
    depends: &Depends<'_>,
) -> std::collections::BTreeMap<Case, String> {
    type Parsed = Option<(Vec<u8>, std::collections::BTreeMap<String, Vec<String>>)>;
    let mut parsed: std::collections::BTreeMap<String, Parsed> = std::collections::BTreeMap::new();
    let mut digests = std::collections::BTreeMap::new();
    let mut named_parts: std::collections::HashMap<Vec<usize>, blake3::Hash> =
        std::collections::HashMap::new();
    let graph = Graph::new(depends);
    let mut walk = Walk::default();
    for case in cases {
        let (name, binary) = case;
        let test = name.rsplit("::").next().unwrap_or(name);
        let mut hasher = blake3::Hasher::new();
        let ran = executed.get(case);
        for probe in ran.into_iter().flatten() {
            hasher.update(b"\x1c");
            hasher.update(
                depends
                    .probes
                    .get(*probe)
                    .map_or("", String::as_str)
                    .as_bytes(),
            );
        }
        // ONCE PER DISTINCT PROBE SET, OVER A GRAPH INDEXED ONCE PER SWEEP
        // (#1276). Measured: the union of every reached name's items, built and
        // sorted per case, held one core for 20 minutes over 6236 cases before
        // a single mutant was judged; memoised per probe set, the string-keyed
        // closure alone still held it, because nearly every probe set is
        // distinct. The walk is now over integer ids with one reused visited
        // map, ids are ranked in name order so the walk's order is the names',
        // and each name's items are hashed once.
        let key: Vec<usize> = ran.into_iter().flatten().copied().collect();
        let named = *named_parts.entry(key).or_insert_with(|| {
            let starts = ran
                .into_iter()
                .flatten()
                .filter_map(|probe| depends.names.get(*probe))
                .flatten()
                .filter_map(|name| graph.id(name));
            let reached = graph.reach(starts, &mut walk);
            let mut part = blake3::Hasher::new();
            if let Some(token) = depends.items.get("").map(|items| name_token("", items)) {
                part.update(token.as_bytes());
            }
            for id in reached {
                if let Some(token) = graph.token_of(*id) {
                    part.update(token.as_bytes());
                }
            }
            part.finalize()
        });
        hasher.update(b"\x1b");
        hasher.update(named.as_bytes());
        if let Some(paths) = depends.read.get(case) {
            for path in paths {
                hasher.update(format!("\x1a{path}\x1f").as_bytes());
                hasher.update(resource_id(depends.resources, path).as_bytes());
            }
        } else {
            hasher.update(b"\x19");
            hasher.update(depends.untraced.as_bytes());
        }
        for file in case_sources(package_dirs, name, binary) {
            let held = parsed.entry(file.clone()).or_insert_with(|| {
                let bytes = crate::fsio::read(root.join(&file)).ok()?;
                let tests = test_texts(&String::from_utf8_lossy(&bytes));
                Some((bytes, tests))
            });
            hasher.update(format!("\x1d{file}\x1f").as_bytes());
            let Some((bytes, tests)) = held else {
                continue;
            };
            match tests.get(test).filter(|_| !file.ends_with("common/mod.rs")) {
                Some(bodies) => {
                    for text in bodies {
                        hasher.update(text.as_bytes());
                        hasher.update(b"\x1e");
                    }
                }
                None => {
                    hasher.update(bytes);
                }
            }
        }
        digests.insert(case.clone(), hasher.finalize().to_hex().to_string());
    }
    digests
}

/// Every `#[test]` function in `source` by name: its own text, then the
/// non-test functions of the module it sits in, which are its helpers.
fn test_texts(source: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    use ast::{HasAttrs as _, HasName as _};
    let is_test = |function: &ast::Fn| {
        function
            .attrs()
            .any(|attr| attr.syntax().text().to_string().contains("test"))
    };
    let parse = SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024);
    let mut texts: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for function in parse
        .tree()
        .syntax()
        .descendants()
        .filter_map(ast::Fn::cast)
    {
        let Some(name) = function.name() else {
            continue;
        };
        if !is_test(&function) {
            continue;
        }
        let helpers: String = function
            .syntax()
            .parent()
            .into_iter()
            .flat_map(|module| module.children().filter_map(ast::Fn::cast))
            .filter(|sibling| !is_test(sibling))
            .map(|sibling| sibling.syntax().to_string())
            .collect();
        texts
            .entry(name.text().to_string())
            .or_default()
            .push(format!("{}\x1f{helpers}", function.syntax()));
    }
    texts
}

fn site_hasher(root: &std::path::Path, mutant: &Listed) -> Option<blake3::Hasher> {
    let source = crate::fsio::read_to_string(root.join(&mutant.file)).ok()?;
    let function = mutant.function.as_ref()?;
    let span = function.span?;
    let text = source.get(offset(&source, span.start)?..offset(&source, span.end)?)?;
    let mut hasher = blake3::Hasher::new();
    for part in [
        mutant.file.as_str(),
        text,
        mutant.genre.as_str(),
        mutant.replacement.as_str(),
        function.function_name.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\x1f");
    }
    // THE SITE WITHIN THE FUNCTION, as an offset from the function's start, so
    // a function moved whole keeps its key and a second site does not share it.
    let site = offset(&source, mutant.span.start)?.checked_sub(offset(&source, span.start)?)?;
    hasher.update(site.to_string().as_bytes());
    Some(hasher)
}

/// Package name to directory, from where the listing's mutants live.
#[must_use]
pub fn package_dirs(mutants: &[Listed]) -> std::collections::BTreeMap<String, String> {
    mutants
        .iter()
        .filter_map(|m| {
            let at = m.file.find("/src/")?;
            Some((m.package.clone(), m.file[..at].to_owned()))
        })
        .collect()
}

/// Reusable verdicts, by key: `key\tverdict` lines.
#[must_use]
pub fn load_verdicts(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            Some((fields.next()?, fields.next()?))
        })
        // A BUILD'S FINDINGS LOAD TOO: a hand-back and an unprobed file stand
        // in for no run, but each spares the build round that rediscovers it.
        .filter(|(key, verdict)| {
            *key != "-" && (reusable(verdict) || [PASSED, HANDED, UNPROBED].contains(verdict))
        })
        .map(|(key, verdict)| (key.to_owned(), verdict.to_owned()))
        .collect()
}

/// Whether a stored verdict may stand in for a run: every decided verdict,
/// never a run that erred. A SURVIVOR TOO: its key holds the cases that reach
/// its site and their files, so a case added that reaches it, or an edit to
/// one that does, moves the key and it is judged again. Re-judging survivors
/// whose key held cost most of a lap's judging on #1276.
#[must_use]
pub fn reusable(verdict: &str) -> bool {
    matches!(
        verdict,
        "caught" | "timeout" | "unviable" | "missed" | "uncovered"
    )
}

/// The first argument that runs a schema sweep over a listing file.
pub const RUN_ARG: &str = "__mutate-schema";

/// As `batten __mutate-schema <listing.json> [jobs]`: build the schema once
/// and judge every mutant the listing names. `None` when this process is not
/// that.
pub fn ran(args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<String> = args
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .collect();
    if args.first().map(String::as_str) != Some(RUN_ARG) {
        return None;
    }
    let path = args.get(1)?;
    let jobs = args.get(2).and_then(|j| j.parse().ok()).unwrap_or(3);
    let mut out = std::io::stdout();
    let swept = crate::git::repo_root(std::path::Path::new(".")).and_then(|root| {
        let listed_over = super::cover::source_digest(&root)?;
        let mutants = listing(&crate::fsio::read_to_string(path)?)?;
        sweep(&root, &mutants, &listed_over, jobs, None, &mut out)
    });
    let code = match swept {
        Ok(swept) => swept.code,
        Err(why) => {
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!("batten: mutate schema: {why:#}\n"),
            );
            3
        }
    };
    Some(std::process::ExitCode::from(code))
}

/// What judging a mutant reads, shared by every worker.
struct Judging<'a> {
    work: &'a std::path::Path,
    target: &'a std::path::Path,
    /// The sweep's own temp root, collected at each barrier.
    scratch: &'a std::path::Path,
    root: &'a std::path::Path,
    mutants: &'a [Listed],
    reach: &'a std::collections::BTreeMap<u32, BTreeSet<Case>>,
    /// Each case's measured seconds, from the reach run.
    seconds: &'a std::collections::BTreeMap<Case, f64>,
    cache: &'a std::collections::BTreeMap<String, String>,
    /// Each reaching case's own digest ([`case_digests`]).
    digests: &'a std::collections::BTreeMap<Case, String>,
    /// The verdict journal, appended as each verdict is decided: CRASH-ONLY
    /// (Candea & Fox 2003), so a killed sweep keeps every kill it finished and
    /// a restart resumes from them (a restart lost a whole judging pass).
    store: &'a std::path::Path,
}

/// How many verdicts pass between two progress lines.
const PROGRESS_EVERY: usize = 100;

/// Judge every mutant in `todo` on `jobs` workers, reusing a stored kill whose
/// key still holds. NO BARRIER: each run owns its scratch (`run_cases`) and
/// removes it when it ends, so no worker ever waits for another's slow run.
/// Progress is printed from this thread as verdicts arrive.
fn judge_all(
    judging: &Judging<'_>,
    todo: &[u32],
    jobs: usize,
    out: &mut dyn std::io::Write,
) -> Vec<(u32, Verdict)> {
    let started = std::time::Instant::now();
    let nobody = BTreeSet::new();
    let hints = std::sync::Mutex::new(std::collections::BTreeMap::new());
    let journal = std::sync::Mutex::new(Some(judging.store.to_path_buf()));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let reused_count = std::sync::atomic::AtomicUsize::new(0);
    let skipped_runs = std::sync::atomic::AtomicUsize::new(0);
    let (sent, decided) = std::sync::mpsc::channel::<(u32, Verdict)>();
    let mut verdicts = Vec::with_capacity(todo.len());
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            let sent = sent.clone();
            let (next, hints, journal, nobody, reused_count, skipped_runs) = (
                &next,
                &hints,
                &journal,
                &nobody,
                &reused_count,
                &skipped_runs,
            );
            scope.spawn(move || {
                loop {
                    let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(&id) = todo.get(at) else { break };
                    let Some(mutant) = judging.mutants.get(id as usize) else {
                        break;
                    };
                    let cases = judging.reach.get(&id).unwrap_or(nobody);
                    let key = verdict_key(judging.root, mutant, cases, judging.digests);
                    let reused = key
                        .as_ref()
                        .and_then(|key| judging.cache.get(key))
                        .filter(|v| reusable(v));
                    if reused.is_some() {
                        reused_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let verdict = match reused.map(String::as_str) {
                        Some("caught") => Verdict::Caught,
                        Some("timeout") => Verdict::Timeout,
                        Some("missed") => Verdict::Missed,
                        // A stored `uncovered` needs no arm: its key was taken
                        // over no reaching case, so the same key reaches none
                        // now, and `judge` answers it without a run.
                        _ => {
                            let (verdict, skipped) =
                                judge(judging, id, mutant, cases, hints, journal);
                            skipped_runs.fetch_add(skipped, std::sync::atomic::Ordering::Relaxed);
                            verdict
                        }
                    };
                    // EVERY VERDICT, SURVIVORS TOO, the moment it is decided:
                    // one write per line, so a crash tears at most the last.
                    // Every decided verdict is reused under an unchanged key
                    // (`reusable`); a run that erred decided nothing and runs
                    // again.
                    if reused.is_none() {
                        append(
                            journal,
                            &journal_line(key.as_deref(), verdict.name(), &mutant.name),
                        );
                    }
                    if sent.send((id, verdict)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sent);
        for verdict in decided {
            verdicts.push(verdict);
            if verdicts.len() % PROGRESS_EVERY == 0 || verdicts.len() == todo.len() {
                let judged = format!("mutate schema: judged {}/{}", verdicts.len(), todo.len());
                let _ = writeln!(out, "{judged} in {}s", started.elapsed().as_secs());
                // THE LAP SEES THE SWEEP MOVE: one step can outlast the stall bound.
                crate::step::advanced(&judged);
            }
        }
    });
    let _ = writeln!(
        out,
        "mutate schema: reused {} of {} verdict(s), and {} case run(s) a recorded outcome decided",
        reused_count.into_inner(),
        todo.len(),
        skipped_runs.into_inner()
    );
    verdicts
}

/// Append `lines` to the verdict journal in one write. APPEND-ONLY, never
/// rewritten: a crash tears at most the last line, which `load_verdicts`
/// skips, and a survivor's line outlives the sweep that decided it.
fn journal(path: &std::path::Path, lines: &str) -> anyhow::Result<()> {
    if !lines.is_empty() {
        crate::durable::append(path, lines)?;
    }
    Ok(())
}

/// One journal line: the verdict's key (`-` when the site has none), the
/// verdict, and the mutant it was decided for.
fn journal_line(key: Option<&str>, verdict: &str, name: &str) -> String {
    format!("{}\t{verdict}\t{name}\n", key.unwrap_or("-"))
}

/// Record each unviable mutant in `cache`, answering the journal lines for
/// those it did not already hold.
fn newly_unviable(
    unviable: &BTreeSet<u32>,
    site_keys: &[Option<String>],
    mutants: &[Listed],
    cache: &mut std::collections::BTreeMap<String, String>,
) -> String {
    let mut found = String::new();
    for id in unviable {
        if let Some(Some(key)) = site_keys.get(*id as usize)
            && let Some(mutant) = mutants.get(*id as usize)
            && cache
                .insert(key.clone(), String::from("unviable"))
                .is_none()
        {
            found.push_str(&journal_line(Some(key), "unviable", &mutant.name));
        }
    }
    found
}

/// The mutants a stored verdict already found do not compile, by site key.
#[cfg(test)]
fn cached_unviable(
    site_keys: &[Option<String>],
    cache: &std::collections::BTreeMap<String, String>,
) -> BTreeSet<u32> {
    cached_as(site_keys, cache, "unviable")
}

/// The mutants whose site key the journal holds as `verdict`.
fn cached_as(
    site_keys: &[Option<String>],
    cache: &std::collections::BTreeMap<String, String>,
    verdict: &str,
) -> BTreeSet<u32> {
    site_keys
        .iter()
        .enumerate()
        .filter(|(_, key)| {
            key.as_ref()
                .is_some_and(|key| cache.get(key).is_some_and(|v| v == verdict))
        })
        .filter_map(|(id, _)| u32::try_from(id).ok())
        .collect()
}

/// The journal's word for a mutant handed back for a const caller.
const HANDED: &str = "handed";

/// The journal's word for a file a build had to build without probes.
const UNPROBED: &str = "unprobed";

/// A file's journal key for being built without probes: its path and bytes,
/// so an edit to the file asks the build again.
fn unprobe_key(root: &std::path::Path, file: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(file.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(&crate::fsio::read(root.join(file)).unwrap_or_default());
    format!("unprobe-{}", hasher.finalize().to_hex())
}

/// Print every verdict that is not a kill, and the counts, and answer the
/// sweep's exit: 3 when a run erred, 2 when a mutant survived, else 0.
fn report(
    out: &mut dyn std::io::Write,
    mutants: &[Listed],
    verdicts: &[(u32, Verdict)],
    (unviable, classic): (usize, usize),
    state: &std::path::Path,
    seconds: u64,
) -> anyhow::Result<u8> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (id, verdict) in verdicts {
        *counts.entry(verdict.name()).or_default() += 1;
        if !matches!(verdict, Verdict::Caught)
            && let Some(mutant) = mutants.get(*id as usize)
        {
            writeln!(out, "{}\t{}", verdict.name(), mutant.name)?;
        }
    }
    writeln!(
        out,
        "mutate schema: {counts:?}, {unviable} unviable, {classic} classic, in {seconds}s"
    )?;
    // A RUN THAT ERRED DECIDED NOTHING: could-not-look (3), above any verdict,
    // so a sweep whose runs failed never reads as a set of survivors.
    if verdicts.iter().any(|(_, v)| matches!(v, Verdict::Error)) {
        writeln!(
            out,
            "mutate schema: run errors kept under {}",
            state.join("errors").display()
        )?;
        return Ok(3);
    }
    let failed = verdicts
        .iter()
        .any(|(_, v)| matches!(v, Verdict::Missed | Verdict::Uncovered));
    Ok(if failed { 2 } else { 0 })
}

/// This shard's mutants of `listed`: each `k`th of every `n` by listing order,
/// so the shards of one listing partition it. All of them with no shard.
#[must_use]
pub fn shard_of(listed: Vec<Listed>, shard: Option<(usize, usize)>) -> Vec<Listed> {
    let Some((k, n)) = shard else {
        return listed;
    };
    listed
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index % n == k)
        .map(|(_, mutant)| mutant)
        .collect()
}

/// A sweep's exit on the house contract (§6): 0 every switched mutant caught,
/// 2 one survived, and anything else could not look.
#[must_use]
pub const fn exit_of(code: u8) -> crate::exit::ExitCode {
    match code {
        0 => crate::exit::ExitCode::Success,
        2 => crate::exit::ExitCode::Violation,
        _ => crate::exit::ExitCode::Internal,
    }
}

/// The graver of two exits, for a verdict two runners share: could-not-look
/// over a violation over usage over success.
#[must_use]
pub const fn worse(a: crate::exit::ExitCode, b: crate::exit::ExitCode) -> crate::exit::ExitCode {
    if b.code() > a.code() { b } else { a }
}

/// Print and answer each handed-back mutant's name. The schema decided
/// nothing about one, so whatever judges it next needs the list, not the
/// count.
fn handed_back(
    out: &mut dyn std::io::Write,
    mutants: &[Listed],
    classic: &BTreeSet<u32>,
) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for id in classic {
        if let Some(mutant) = mutants.get(*id as usize) {
            writeln!(out, "classic\t{}", mutant.name)?;
            names.push(mutant.name.clone());
        }
    }
    Ok(names)
}

/// What judges the mutants the schema cannot switch: cargo-mutants, in place
/// in a persistent mirror of the checkout, over the change in `diff`.
#[derive(Debug, Clone, Copy)]
pub struct Handback<'a> {
    /// The provisioned cargo-mutants, run as cargo runs a subcommand.
    pub runner: &'a std::path::Path,
    /// The change the listing was made of.
    pub diff: &'a std::path::Path,
}

/// The bare identifier a cargo-mutants function name ends in: `bar` of
/// `Foo::bar` or of `<impl Display for Foo>::bar`.
fn function_ident(name: &str) -> Option<String> {
    let last = name.rsplit("::").next()?.trim();
    let ident: String = last
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!ident.is_empty()).then_some(ident)
}

/// `name` and every name whose item mentions one of them, transitively: what
/// a function must name to depend on `name` ([`named_closure`]'s inverse).
fn mentioners(
    name: &str,
    mentions: &std::collections::BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = [name.to_owned()].into();
    loop {
        let grown: Vec<String> = mentions
            .iter()
            .filter(|(item, mentioned)| !found.contains(*item) && !mentioned.is_disjoint(&found))
            .map(|(item, _)| item.clone())
            .collect();
        if grown.is_empty() {
            return found;
        }
        found.extend(grown);
    }
}

/// The cases that can observe handed-back mutant `id`: each that ran its
/// enclosing function, and each whose functions name its function through
/// any chain of items ([`mentioners`]). `None` when neither can be said (no
/// enclosing probe and no function name), so every case must judge it.
fn handback_cases(
    id: u32,
    mutant: &Listed,
    schema: &Schema,
    reach: &Reach,
) -> Option<BTreeSet<Case>> {
    let enclosing: BTreeSet<usize> = schema
        .mutant_fns
        .get(&id)
        .map(|digest| {
            schema
                .probes
                .iter()
                .enumerate()
                .filter(|(_, probe)| *probe == digest)
                .map(|(at, _)| at)
                .collect()
        })
        .unwrap_or_default();
    let name = mutant
        .function
        .as_ref()
        .and_then(|function| function_ident(&function.function_name));
    if enclosing.is_empty() && name.is_none() {
        return None;
    }
    let observers = name.map_or_else(BTreeSet::new, |name| mentioners(&name, &schema.mentions));
    Some(
        reach
            .executed
            .iter()
            .filter(|(_, ran)| {
                ran.iter().any(|probe| {
                    enclosing.contains(probe)
                        || schema
                            .names
                            .get(*probe)
                            .is_some_and(|names| !names.is_disjoint(&observers))
                })
            })
            .map(|(case, _)| case.clone())
            .collect(),
    )
}

/// A handed-back mutant's verdict from cargo-mutants' exit and its outcome
/// files: a kill only where `caught.txt` names it (an `--re` that matched
/// nothing exits 0 too), and a survivor no case observed is uncovered.
fn handback_verdict(
    outcome: super::Outcome,
    output: &std::path::Path,
    name: &str,
    unobserved: bool,
) -> &'static str {
    let listed = |file: &str| {
        crate::fsio::read_to_string(output.join("mutants.out").join(file))
            .is_ok_and(|text| text.lines().any(|line| line.trim() == name))
    };
    if listed("unviable.txt") {
        return "unviable";
    }
    match outcome {
        super::Outcome::Passed if listed("caught.txt") => "caught",
        super::Outcome::Failed(Some(2)) if unobserved => "uncovered",
        super::Outcome::Failed(Some(2)) => "missed",
        super::Outcome::Failed(Some(3)) | super::Outcome::TimedOut => "timeout",
        _ => "error",
    }
}

/// Judge each handed-back mutant ONCE, IN PLACE, on the cases that can
/// observe it, reusing a journaled verdict whose key holds; answer the
/// verdicts and how many were unviable.
///
/// NO COPY, NO BASELINE, NO FULL SUITE (CLOUD-2253's classic stage paid all
/// three every lap: a fresh copy, a 493 s build and a 708 s baseline run, then
/// the whole suite per mutant). The mirror at `tree` keeps its own target, so
/// a mutant costs the rebuild its mutation forces; the reach run already
/// proved the unmutated suite on this source; and a mutant runs only the cases
/// [`handback_cases`] names. The mirror is synced before the first run, which
/// also undoes a mutation a killed run left in place.
///
/// # Errors
///
/// The mirror cannot be synced, cargo-mutants cannot be spawned, or the
/// journal cannot be written.
fn judge_handbacks(
    judging: &Judging<'_>,
    (handback, live, listed_over, state): (&Handback<'_>, &std::path::Path, &str, &std::path::Path),
    classic: &BTreeSet<u32>,
    (schema, reach): (&Schema, &Reach),
    out: &mut dyn std::io::Write,
) -> anyhow::Result<(Vec<(u32, Verdict)>, usize)> {
    // THE MIRROR COPIES THE LIVE CHECKOUT, an hour after the listing: an edit
    // since would judge these names against text the listing never read.
    anyhow::ensure!(
        super::cover::source_digest(live)? == listed_over,
        "the checkout's Rust sources changed during the sweep, so the handed-back mutants \
         would be judged against text they were not listed from; the schema's verdicts are \
         journaled, so run the sweep again once the tree is still"
    );
    let (tree, output) = (state.join("classic"), state.join("classic-out"));
    let (tree, output) = (tree.as_path(), output.as_path());
    let every: BTreeSet<Case> = reach.executed.keys().cloned().collect();
    let (mut verdicts, mut unviable, mut reused, mut synced) = (Vec::new(), 0, 0, false);
    for &id in classic {
        let Some(mutant) = judging.mutants.get(id as usize) else {
            continue;
        };
        let observing = handback_cases(id, mutant, schema, reach);
        let cases = observing.clone().unwrap_or_else(|| every.clone());
        let key = verdict_key(judging.root, mutant, &cases, judging.digests);
        let stored = key
            .as_ref()
            .and_then(|key| judging.cache.get(key))
            .filter(|verdict| reusable(verdict));
        let verdict = if let Some(stored) = stored {
            reused += 1;
            stored.clone()
        } else {
            if !synced {
                sync(live, tree, &BTreeSet::new())?;
                synced = true;
            }
            let filter = observing.as_ref().map(|cases| {
                super::cover::filterset(&cases.iter().map(|(name, _)| name.as_str()).collect())
            });
            let bound = case_bound(&cases, judging.seconds).min(super::runner_bound());
            let outcome = super::cargo_mutant_in_place(
                (tree, handback.runner, handback.diff),
                &mutant.name,
                filter.as_deref(),
                bound,
                output,
            )?;
            let unobserved = observing.as_ref().is_some_and(BTreeSet::is_empty);
            let name = handback_verdict(outcome, output, &mutant.name, unobserved);
            journal(
                judging.store,
                &journal_line(key.as_deref(), name, &mutant.name),
            )?;
            name.to_owned()
        };
        match verdict.as_str() {
            "unviable" => unviable += 1,
            "caught" => verdicts.push((id, Verdict::Caught)),
            "missed" => verdicts.push((id, Verdict::Missed)),
            "timeout" => verdicts.push((id, Verdict::Timeout)),
            "uncovered" => verdicts.push((id, Verdict::Uncovered)),
            _ => verdicts.push((id, Verdict::Error)),
        }
    }
    writeln!(
        out,
        "mutate schema: {} handed-back mutant(s) judged in place, {reused} reused",
        classic.len()
    )?;
    Ok((verdicts, unviable))
}

/// What a sweep decided: its exit (0 every switched mutant caught, 2 one
/// survived, 3 a run erred) and the mutants it handed back, by name, for
/// cargo-mutants to judge.
#[derive(Debug)]
pub struct Swept {
    /// The exit, as [`report`] answers it.
    pub code: u8,
    /// The handed-back mutants' names.
    pub classic: Vec<String>,
}

/// The schema mirror's state directory for the checkout at `root`.
///
/// # Errors
///
/// The repository state directory cannot be resolved.
fn mirror_state(root: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    Ok(crate::state::repo_state_dir(root)?
        .join("mutate")
        .join("schema"))
}

/// The environment every schema build and run spawns cargo under: the mirror's
/// own target directory for what cargo uplifts, and the CHECKOUT's build
/// directory for every intermediate unit.
///
/// MEASURED ON #1276: the mirror's 738 dependency units matched 734 of
/// `target/debug`'s by name and hash, compiled and stored twice. Built under the
/// `test` profile into the checkout's build directory, a schema build reused all
/// 437 registry units and compiled none: 101 s against ~160 s for a cold round.
/// The target directory stays the mirror's, so an uplifted binary built from
/// mutated sources never lands over the checkout's `target/debug/batten`, and
/// `CARGO_TARGET_TMPDIR` stays inside the mirror tree, where its fixtures need
/// a checkout around them. Outside a sweep no build directory was recorded,
/// and a build uses its target directory alone, as before.
fn cargo_dirs(target: &std::path::Path) -> Vec<String> {
    // AS ARGUMENTS, NEVER EXPORTED (#1276). Exported, every case the suite ran
    // inherited them: a fixture keyed its own build flags with them while the
    // `batten` it started had them cleared, and a case driving cargo over a
    // fixture built into the sweep's directory. A failed baseline judges no
    // mutant, and 13 of 10,086 cases failed for it.
    vec![
        // THE MIRROR'S OWN TARGET, AND NO SHARED BUILD DIRECTORY (#1276).
        // Building into the checkout's saved 909 MB of duplicate units, and
        // cargo then compiled the suite's `CARGO_TARGET_TMPDIR` under it: the
        // baseline's fixtures (4.8 GB) landed in the checkout's `target/tmp`,
        // where no sweep collected them, and cases that read their own
        // repository read the checkout's.
        String::from("--target-dir"),
        target.to_string_lossy().into_owned(),
        // The `test` profile's own setting for the crate under mutation, the
        // one `[profile.mutants]` carried: nothing reads a mutant's debug info,
        // and a dependency's unit hash does not depend on it.
        String::from("--config"),
        String::from("profile.test.debug=0"),
        // NO INCREMENTAL STATE FOR THE SCHEMA BUILD (#1276). It is one build per
        // head of source instrumented afresh, so a session is never reused, and
        // rustc copies the previous session into each new one while it compiles:
        // measured, `target/debug/incremental` went 4.7 -> 8.6 GB inside one lap
        // and fell to 2.2 GB when the build stopped.
        String::from("--config"),
        String::from("build.incremental=false"),
    ]
}

/// The schema mirror's build tree: a cache, one more tree the disk collector
/// ranks (`collect::trees`). It holds a whole incremental build, 6.0 GB measured
/// on #1276, outside `[prune] root`. Unseen by the collector, it left a lap's
/// parallel builds no room and the lap died of a full disk while the collector
/// reported nothing it might remove. Losing it costs one sweep rebuild; a held
/// build lock spares it while a sweep runs.
///
/// # Errors
///
/// The repository state directory cannot be resolved.
pub fn mirror_target(root: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    Ok(mirror_state(root)?.join("tree").join("target"))
}

/// Every one of `mutants` judged in one schema build of the checkout at
/// `root`, on `jobs` workers.
///
/// # Errors
///
/// The tree cannot be staged, the schema does not build, or the unmutated
/// suite fails.
pub fn sweep(
    root: &std::path::Path,
    mutants: &[Listed],
    listed_over: &str,
    jobs: usize,
    handback: Option<&Handback<'_>>,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Swept> {
    let state = mirror_state(root)?;
    let work = state.join("tree");
    // INSIDE THE TREE, where cargo-mutants' copies keep theirs: a case's
    // fixtures land under the target's `tmp/`, and on #1276 one with no `.git`
    // of its own passed only inside a checkout, so a target beside the tree
    // failed the unmutated baseline.
    let target = mirror_target(root)?;
    let started = std::time::Instant::now();
    // WHAT A STOPPED RUN FINISHED IS KEPT, BEFORE ANYTHING MOVES IT: its
    // records are sealed against the snapshot it ran over, which the copy
    // below replaces.
    keep_leftovers(&state, out)?;
    sync(root, &work, &package_sources(root, mutants))?;
    // THE SOURCES AS THE SWEEP FOUND THEM: every rendering, key and case file
    // is read from this snapshot, never the live checkout, which an edit during
    // an hour-long sweep would move under the listing's spans.
    //
    // AND THE SNAPSHOT IS OF THE TREE THE LISTING READ: `listed_over` is the
    // checkout's source digest taken before the change was written, and the
    // copy is compared by the bytes it copied. On #1276 a `cargo fmt` landed
    // between the listing and this copy, every span after it pointed into the
    // wrong text, and five builds refused delimiters no mutant owned.
    let snapshot = state.join("pristine");
    let copied = super::cover::pristine(root, &snapshot)?;
    anyhow::ensure!(
        copied == listed_over,
        "the checkout's Rust sources changed while the mutants were listed, so no span would \
         point where it was listed; run the sweep again once the tree is still"
    );
    let resources = resource_digest(root)?;
    let resource_ids = resource_ids(root)?;
    let live = root;
    let root = snapshot;
    // AN ERROR LOG IS THIS SWEEP'S OR NOTHING: one left by a killed sweep
    // would read as a run of this one erring.
    let _ = std::fs::remove_dir_all(state.join("errors"));
    let cache_path = state.join("verdicts");
    let mut cache = load_verdicts(&crate::fsio::read_to_string(&cache_path).unwrap_or_default());
    let site_keys: Vec<Option<String>> = mutants.iter().map(|m| site_key(&root, m)).collect();
    let Built {
        unviable,
        handed,
        schema,
        unprobed,
    } = build_journaled(
        (&root, &work, &target),
        mutants,
        (&site_keys, &mut cache, &cache_path),
        out,
    )?;
    let classic = schema.classic(handed);
    writeln!(
        out,
        "mutate schema: {} mutant(s), {} unviable, {} classic, built in {}s",
        mutants.len(),
        unviable.len(),
        classic.len(),
        started.elapsed().as_secs()
    )?;
    let trees = (work.as_path(), target.as_path(), state.as_path());
    let ids = (&resource_ids, resources.as_str());
    let format = sweep_format(live, mutants, &schema, unprobed);
    let (reach, digests, seconds) = reached(
        trees,
        &root,
        mutants,
        (&schema, &site_keys, &classic, &format),
        ids,
        out,
    )?;
    let scratch = state.join("scratch");
    std::fs::create_dir_all(&scratch)?;
    let todo: Vec<u32> = (0..u32::try_from(mutants.len())?)
        .filter(|id| !unviable.contains(id) && !classic.contains(id))
        .collect();
    let judging = Judging {
        work: &work,
        target: &target,
        scratch: &scratch,
        root: &root,
        mutants,
        reach: &reach.sites,
        seconds: &seconds,
        cache: &cache,
        digests: &digests,
        store: &cache_path,
    };
    let mut verdicts = judge_all(&judging, &todo, jobs, out);
    let (names, handed_unviable) = match handback {
        Some(handback) => {
            let (judged, unviable) = judge_handbacks(
                &judging,
                (handback, live, listed_over, &state),
                &classic,
                (&schema, &reach),
                out,
            )?;
            verdicts.extend(judged);
            (Vec::new(), unviable)
        }
        None => (handed_back(out, mutants, &classic)?, 0),
    };
    let code = report(
        out,
        mutants,
        &verdicts,
        (
            unviable_total(unviable.len(), handed_unviable),
            classic.len(),
        ),
        &state,
        started.elapsed().as_secs(),
    )?;
    Ok(Swept {
        code,
        classic: names,
    })
}

/// [`build`] seeded with what the journal already knows a build refuses, and
/// journaling each round's discoveries the moment its build refuses them, so
/// no later round or sweep rebuilds to rediscover one.
///
/// # Errors
///
/// The build fails as [`build`] does, or the journal cannot be written.
fn build_journaled(
    (root, work, target): (&std::path::Path, &std::path::Path, &std::path::Path),
    mutants: &[Listed],
    (site_keys, cache, cache_path): (
        &[Option<String>],
        &mut std::collections::BTreeMap<String, String>,
        &std::path::Path,
    ),
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Built> {
    let known = Known {
        unviable: cached_as(site_keys, cache, "unviable"),
        handed: cached_as(site_keys, cache, HANDED),
        unprobed: mutants
            .iter()
            .map(|m| m.file.clone())
            .filter(|file| cache.contains_key(&unprobe_key(root, file)))
            .collect(),
    };
    writeln!(
        out,
        "mutate schema: {} unviable, {} handed back and {} unprobed file(s) known from earlier runs",
        known.unviable.len(),
        known.handed.len(),
        known.unprobed.len()
    )?;
    let mut keep = |refused: &Refused| {
        let mut lines = newly_unviable(&refused.owned, site_keys, mutants, cache);
        for id in &refused.reconst {
            if let (Some(Some(key)), Some(mutant)) =
                (site_keys.get(*id as usize), mutants.get(*id as usize))
                && cache.insert(key.clone(), String::from(HANDED)).is_none()
            {
                lines.push_str(&journal_line(Some(key), HANDED, &mutant.name));
            }
        }
        for file in &refused.unprobe {
            let key = unprobe_key(root, file);
            if cache.insert(key.clone(), String::from(UNPROBED)).is_none() {
                lines.push_str(&journal_line(Some(&key), UNPROBED, file));
            }
        }
        journal(cache_path, &lines)
    };
    build(root, work, target, mutants, known, &mut keep, out)
}

/// Each of `executed`'s cases keyed on what it depends on ([`case_digests`]):
/// the schema's probes, names and items, `read`, and the checkout's content
/// ids with the untraced fallback.
fn digests_with(
    root: &std::path::Path,
    dirs: &std::collections::BTreeMap<String, String>,
    schema: &Schema,
    (resources, untraced): (&std::collections::BTreeMap<String, String>, &str),
    executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
    read: &std::collections::BTreeMap<Case, BTreeSet<String>>,
) -> std::collections::BTreeMap<Case, String> {
    let depends = Depends {
        probes: &schema.probes,
        names: &schema.names,
        items: &schema.items,
        mentions: &schema.mentions,
        read,
        resources,
        untraced,
    };
    case_digests(root, executed.keys(), dirs, executed, &depends)
}

/// What a sweep reads off its reach run: the record, each case's digest and
/// each case's seconds.
type Reached = (
    Reach,
    std::collections::BTreeMap<Case, String>,
    std::collections::BTreeMap<Case, f64>,
);

/// Record reach over the schema, carrying every case the change left alone;
/// key every recorded case on what it depends on; take each case's seconds,
/// a carried one's as sealed; and seal the record for the next sweep.
///
/// # Errors
///
/// The reach run fails, or its record cannot be read or sealed.
fn reached(
    (work, target, state): (&std::path::Path, &std::path::Path, &std::path::Path),
    root: &std::path::Path,
    mutants: &[Listed],
    (schema, site_keys, classic, format): (&Schema, &[Option<String>], &BTreeSet<u32>, &Format),
    ids: (&std::collections::BTreeMap<String, String>, &str),
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Reached> {
    let dirs = package_dirs(mutants);
    let started = std::time::Instant::now();
    let identity = &Identity {
        probes: &schema.probes,
        sites: site_keys,
        mutant_fns: &schema.mutant_fns,
        classic,
    };
    let packages: BTreeSet<&str> = mutants.iter().map(|m| m.package.as_str()).collect();
    let recompute =
        |executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
         read: &std::collections::BTreeMap<Case, BTreeSet<String>>| {
            digests_with(root, &dirs, schema, ids, executed, read)
        };
    let base = state.join("reach");
    std::fs::create_dir_all(&base)?;
    crate::durable::replace(
        base.join(CONTEXT),
        serde_json::to_string(&SealContext {
            root: root.to_path_buf(),
            dirs: dirs.clone(),
            probes: schema.probes.clone(),
            names: schema.names.clone(),
            items: schema.items.clone(),
            mentions: schema.mentions.clone(),
            resources: ids.0.clone(),
            untraced: ids.1.to_owned(),
            sites: site_keys.to_vec(),
            mutant_fns: schema.mutant_fns.clone(),
            classic: classic.clone(),
            format: Some(format.clone()),
        })?,
    )?;
    let (reach, passed) = record_reach(
        work,
        target,
        state,
        &packages,
        (identity, &recompute, Some((root, ids.0, format))),
        out,
    )?;
    let mut recorded = reach.executed.clone();
    for case in reach.sites.values().flatten() {
        recorded.entry(case.clone()).or_default();
    }
    let digests = digests_with(root, &dirs, schema, ids, &recorded, &reach.read);
    let mut seconds = case_seconds(state);
    for (case, took) in &reach.seconds {
        let held = seconds.entry(case.clone()).or_insert(0.0);
        *held = held.max(*took);
    }
    seal_reach(
        &state.join("reach"),
        &reach,
        &digests,
        identity,
        &seconds,
        passed,
    )?;
    // THE SELECTION DIGEST IS AN ECONOMY: one that cannot be taken leaves each
    // record to the suite's build key, and never fails the sweep.
    match seal_tested(&base, root, ids.0, format) {
        Ok(taken) => writeln!(
            out,
            "mutate schema: selection digest taken for {taken} case(s)"
        )?,
        Err(why) => writeln!(out, "mutate schema: no selection digest taken: {why:#}")?,
    }
    anyhow::ensure!(
        passed,
        "the unmutated suite failed on the schema build, so no verdict would mean anything; \
         every case that passed is sealed and carries to the next run"
    );
    writeln!(
        out,
        "mutate schema: reach recorded for {} site(s), {} function(s) probed, in {}s",
        reach.sites.len(),
        schema.probes.len(),
        started.elapsed().as_secs()
    )?;
    Ok((reach, digests, seconds))
}

/// Every unviable mutant a sweep reports: the schema build's and the
/// handbacks' that would not build either.
const fn unviable_total(schema: usize, handed: usize) -> usize {
    schema + handed
}

/// The [`Format`] a sweep of `mutants` from the checkout at `live` reads its
/// records in: the schema's probed files, the unprobed ones, and the cargo
/// arguments, features and flags the reach run builds its suite with
/// ([`record_reach`]).
fn sweep_format(
    live: &std::path::Path,
    mutants: &[Listed],
    schema: &Schema,
    unprobed: BTreeSet<String>,
) -> Format {
    let packages: BTreeSet<&str> = mutants.iter().map(|m| m.package.as_str()).collect();
    let mut cargo_args: Vec<String> = ["--cargo-profile", "test"].map(str::to_owned).to_vec();
    for package in packages {
        cargo_args.extend([String::from("-p"), package.to_owned()]);
    }
    Format {
        dirs: package_dirs(mutants),
        probed: schema.probed.clone(),
        unprobed,
        features: super::overlay_features(live),
        cargo_args,
        flags: build_flags(),
    }
}

/// Each case's measured seconds from the reach run's junit report, or none
/// when it left no report.
fn case_seconds(state: &std::path::Path) -> std::collections::BTreeMap<Case, f64> {
    durations(
        &crate::fsio::read_to_string(
            state
                .join("nextest")
                .join("batten-cover")
                .join(super::cover::JUNIT),
        )
        .unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// Cross-head test selection: a case's pass stands while nothing it ran moved.
// ---------------------------------------------------------------------------

/// The file a sealed case record holds once its selection digest is taken
/// ([`seal_tested`]): the [`Format`]'s key, a tab, and the digest
/// [`test_digests`] gave over the tree the case was recorded on.
const TESTED: &str = "tested";

/// The file a case's record holds from its first moment: the reach
/// directory's [`TREE`] as it read when the case was recorded, so a seal
/// knows which records were made on the tree it seals over.
const OVER: &str = "over";

/// The words a feature gate is spelled with, as an attribute or as the macro
/// that reads one.
const GATES: [&str; 2] = ["cfg", "cfg_attr"];

/// The macros that put another file's bytes into the item that calls them.
const INCLUDES: [&str; 3] = ["include", "include_str", "include_bytes"];

/// What a reach record's functions and keys were read in: the files the sweep
/// probed, and how the suite it recorded was built.
///
/// PER RECORD, NOT PER SWEEP: a record carried across sweeps keeps the digest
/// taken when it was recorded, which only an index read the same way can
/// reproduce, so each record names its format by key.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Format {
    /// Package name to directory ([`package_dirs`]).
    pub dirs: std::collections::BTreeMap<String, String>,
    /// The files rendered with probes ([`Schema::probed`]).
    pub probed: BTreeSet<String>,
    /// The files a build refused probes in ([`Built::unprobed`]).
    pub unprobed: BTreeSet<String>,
    /// The `--features` the sweep's suite carried.
    pub features: Vec<String>,
    /// The cargo arguments the reach run was built with.
    pub cargo_args: Vec<String>,
    /// The code-generation variables the reach run inherited ([`build_flags`]).
    pub flags: std::collections::BTreeMap<String, String>,
}

impl Format {
    /// The key a record names this format by: a digest of all of it.
    #[must_use]
    pub fn key(&self) -> String {
        let text = serde_json::to_string(self).unwrap_or_default();
        blake3::hash(text.as_bytes()).to_hex()[..16].to_owned()
    }

    /// The format a record under `base` names by `key`, or `None` when none
    /// was written or it does not parse.
    #[must_use]
    pub fn load(base: &std::path::Path, key: &str) -> Option<Self> {
        let text = crate::fsio::read_to_string(base.join(format!("format-{key}.json"))).ok()?;
        let format: Self = serde_json::from_str(&text).ok()?;
        (format.key() == key).then_some(format)
    }

    fn store(&self, base: &std::path::Path) -> anyhow::Result<String> {
        let key = self.key();
        let path = base.join(format!("format-{key}.json"));
        if !path.is_file() {
            crate::durable::replace(&path, serde_json::to_string(self)?)?;
        }
        Ok(key)
    }
}

/// The variables of this process that change what a cargo build generates:
/// the compiler, its flags and every profile override. A record made under
/// other values ran other code.
#[must_use]
pub fn build_flags() -> std::collections::BTreeMap<String, String> {
    build_flags_in(std::env::vars_os())
}

/// [`build_flags`] over `vars`.
fn build_flags_in(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> std::collections::BTreeMap<String, String> {
    vars.filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(key, _)| {
            matches!(
                key.as_str(),
                "RUSTC" | "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS"
            ) || key.starts_with("CARGO_PROFILE_")
        })
        .collect()
}

/// What a case's selection digest reads in one tree: every function, probed
/// as the sweep probed it, and every skeleton item, with what each names, the
/// feature gates in each and the files each includes.
#[derive(Debug, Default)]
pub struct DependencyIndex {
    probes: Vec<String>,
    names: Vec<BTreeSet<String>>,
    own_names: std::collections::BTreeMap<String, BTreeSet<usize>>,
    items: std::collections::BTreeMap<String, BTreeSet<String>>,
    mentions: std::collections::BTreeMap<String, BTreeSet<String>>,
    gated_probes: BTreeSet<usize>,
    gated_names: BTreeSet<String>,
    probe_includes: std::collections::BTreeMap<usize, Option<BTreeSet<String>>>,
    name_includes: std::collections::BTreeMap<String, Option<BTreeSet<String>>>,
}

impl DependencyIndex {
    /// The source digests of every probed function named `name`.
    #[must_use]
    pub fn digests_of(&self, name: &str) -> Vec<String> {
        self.own_names
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|id| self.probes.get(*id).cloned())
            .collect()
    }
}

/// Where one feature gate or include sits: the innermost probed function, or
/// else the names of the innermost item ([`item_names`]), `""` for none.
enum Owner {
    Probe(usize),
    Names(Vec<String>),
}

fn owner_of(token: &ra_ap_syntax::SyntaxToken, spans: &[(usize, Range<usize>)]) -> Owner {
    let at = usize::from(token.text_range().start());
    if let Some((id, _)) = spans
        .iter()
        .filter(|(_, span)| span.start <= at && at < span.end)
        .min_by_key(|(_, span)| span.end - span.start)
    {
        return Owner::Probe(*id);
    }
    Owner::Names(owning_item(token).map_or_else(|| vec![String::new()], |item| item_names(&item)))
}

/// Whether the gate word at `token` names a feature: the attribute or macro
/// call it heads, or failing one (a token in a macro's body) the token tree
/// around it. A word that is only a variable's name heads neither.
fn names_a_feature(token: &ra_ap_syntax::SyntaxToken) -> bool {
    token
        .parent_ancestors()
        .find(|node| {
            ast::Meta::can_cast(node.kind())
                || matches!(node.kind(), SyntaxKind::MACRO_CALL | SyntaxKind::TOKEN_TREE)
        })
        .is_some_and(|node| {
            node.descendants_with_tokens()
                .filter_map(ra_ap_syntax::NodeOrToken::into_token)
                .any(|t| t.text() == "feature")
        })
}

/// The package directory a source at `file` belongs to: what precedes its
/// `src/`, `tests/`, `benches/` or `examples/`.
fn package_dir_of(file: &str) -> Option<&str> {
    ["src/", "tests/", "benches/", "examples/"]
        .iter()
        .find_map(|dir| {
            if file.starts_with(dir) {
                return Some("");
            }
            file.find(&format!("/{dir}")).map(|at| &file[..at])
        })
}

/// `relative` joined onto the directory `dir` of the tree, `..` resolved;
/// `None` where it leaves the tree.
fn tree_join(dir: &str, relative: &str) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|part| !part.is_empty()).collect();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// What one call of an include macro reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Included {
    /// A file of the tree, by path.
    File(String),
    /// A file of the build's output, which the build key holds.
    Built,
    /// What no syntax can name: an argument that is not a path.
    Unknown,
}

/// What the include macro `call` in `file` reads.
fn include_target(call: &ast::MacroCall, file: &str) -> Included {
    include_path(call, file).unwrap_or(Included::Unknown)
}

fn include_path(call: &ast::MacroCall, file: &str) -> Option<Included> {
    use ra_ap_syntax::AstToken as _;
    let tree = call.token_tree()?;
    let mut strings = Vec::new();
    let mut idents = Vec::new();
    for token in tree
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
    {
        match token.kind() {
            SyntaxKind::STRING => {
                strings.push(ast::String::cast(token)?.value().ok()?.into_owned());
            }
            SyntaxKind::IDENT => idents.push(token.text().to_owned()),
            SyntaxKind::WHITESPACE
            | SyntaxKind::COMMENT
            | SyntaxKind::L_PAREN
            | SyntaxKind::R_PAREN
            | SyntaxKind::COMMA
            | SyntaxKind::BANG => {}
            _ => return None,
        }
    }
    match (idents.as_slice(), strings.as_slice()) {
        ([], [path]) => {
            let dir = file.rsplit_once('/').map_or("", |(dir, _)| dir);
            Some(Included::File(tree_join(dir, path)?))
        }
        ([concat, env], [var, rest @ ..]) if concat == "concat" && env == "env" => {
            let path: String = rest.concat();
            match var.as_str() {
                "OUT_DIR" => Some(Included::Built),
                "CARGO_MANIFEST_DIR" => {
                    Some(Included::File(tree_join(package_dir_of(file)?, &path)?))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Every Rust source of the tree at `root`: the files git tracks or sees
/// changed in a checkout, every file under a snapshot ([`super::cover::pristine`]).
fn tree_rust_files(root: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let is_rust = |path: &str| {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rs")
    };
    if root.join(".git").exists() {
        let mut paths = crate::git::tracked_paths(root)?;
        paths.extend(crate::git::changed_paths(root)?);
        return Ok(paths
            .into_iter()
            .filter(|path| is_rust(path) && root.join(path).is_file())
            .collect());
    }
    let mut files: Vec<String> = ignore::WalkBuilder::new(root)
        .standard_filters(false)
        .filter_entry(|entry| !matches!(entry.file_name().to_str(), Some("target" | ".git")))
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let relative = entry.path().strip_prefix(root).ok()?;
            Some(relative.to_string_lossy().replace('\\', "/"))
        })
        .filter(|path| is_rust(path))
        .collect();
    files.sort();
    Ok(files)
}

/// The tree at `root` read for selection, syntax alone: every Rust source
/// rendered with no mutant, probed where `format` says the sweep probed it,
/// so a function's digest and a name's items are the ones the sweep read;
/// the rest, tests included, gives its items and the names they mention.
///
/// # Errors
///
/// The tree's sources cannot be listed or read.
pub fn dependency_index(
    root: &std::path::Path,
    format: &Format,
) -> anyhow::Result<DependencyIndex> {
    let mut index = DependencyIndex::default();
    let none = BTreeSet::new();
    for file in tree_rust_files(root)? {
        let source = crate::fsio::read_to_string(root.join(&file))?;
        let first = index.probes.len();
        let probe_from = format.probed.contains(&file).then_some(first);
        let rendered = render(&source, &[], &none, probe_from);
        for (offset, name) in rendered.fn_names.iter().enumerate() {
            index
                .own_names
                .entry(name.clone())
                .or_default()
                .insert(first + offset);
        }
        index.probes.extend(rendered.probes.iter().cloned());
        index.names.extend(rendered.names.iter().cloned());
        for (name, digest) in rendered.items {
            index.items.entry(name).or_default().insert(digest);
        }
        for (name, mentioned) in rendered.mentions {
            index.mentions.entry(name).or_default().extend(mentioned);
        }
        let spans: Vec<(usize, Range<usize>)> = rendered
            .fn_spans
            .into_iter()
            .enumerate()
            .map(|(offset, span)| (first + offset, span))
            .collect();
        read_gates_and_includes(&mut index, &source, &file, &spans);
    }
    Ok(index)
}

/// Record each feature gate and each include in `source` against its owner.
fn read_gates_and_includes(
    index: &mut DependencyIndex,
    source: &str,
    file: &str,
    spans: &[(usize, Range<usize>)],
) {
    let parse = SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024);
    let root = parse.tree().syntax().clone();
    let mut resolved: std::collections::BTreeMap<usize, Included> =
        std::collections::BTreeMap::new();
    for call in root.descendants().filter_map(ast::MacroCall::cast) {
        let Some(ident) = call
            .path()
            .and_then(|path| path.segment())
            .and_then(|segment| segment.name_ref())
            .and_then(|name| name.ident_token())
        else {
            continue;
        };
        if INCLUDES.contains(&ident.text()) {
            resolved.insert(
                usize::from(ident.text_range().start()),
                include_target(&call, file),
            );
        }
    }
    for token in root
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
        .filter(|token| {
            !matches!(
                token.kind(),
                SyntaxKind::STRING | SyntaxKind::COMMENT | SyntaxKind::WHITESPACE
            )
        })
    {
        let text = token.text();
        if GATES.contains(&text) {
            if names_a_feature(&token) {
                match owner_of(&token, spans) {
                    Owner::Probe(id) => {
                        index.gated_probes.insert(id);
                    }
                    Owner::Names(names) => index.gated_names.extend(names),
                }
            }
            continue;
        }
        if token.kind() != SyntaxKind::IDENT || !INCLUDES.contains(&text) {
            continue;
        }
        // AN INCLUDE THE SYNTAX CANNOT PLACE (one in a macro's body or another
        // macro's arguments) makes its owner unknown, never invisible.
        let target = resolved
            .get(&usize::from(token.text_range().start()))
            .cloned()
            .unwrap_or(Included::Unknown);
        let merge = |held: &mut Option<BTreeSet<String>>| match (held.as_mut(), &target) {
            (Some(targets), Included::File(path)) => {
                targets.insert(path.clone());
            }
            (Some(_), Included::Built) | (None, _) => {}
            (Some(_), Included::Unknown) => *held = None,
        };
        match owner_of(&token, spans) {
            Owner::Probe(id) => merge(
                index
                    .probe_includes
                    .entry(id)
                    .or_insert_with(|| Some(BTreeSet::new())),
            ),
            Owner::Names(names) => {
                for name in names {
                    merge(
                        index
                            .name_includes
                            .entry(name)
                            .or_insert_with(|| Some(BTreeSet::new())),
                    );
                }
            }
        }
    }
}

/// The digest of a whole tree by its content ids ([`resource_ids`]), Rust
/// included: what a case keys on that no trace could read.
#[must_use]
pub fn tree_ids_digest(resources: &std::collections::BTreeMap<String, String>) -> String {
    let mut hasher = blake3::Hasher::new();
    for (path, id) in resources {
        hasher.update(path.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(id.as_bytes());
        hasher.update(b"\x1e");
    }
    hasher.finalize().to_hex().to_string()
}

/// What one case's selection digest is taken from: the functions it ran by
/// digest, and the tree paths it touched, `None` when it was not traced.
pub type Ran = (BTreeSet<String>, Option<BTreeSet<String>>);

/// Each case's selection digest over the tree at `root` ([`case_digests`]
/// over `index`, plus what that cannot see), or `None` where it is unknown:
/// a function it ran is gone, or what it reaches is feature-gated or includes
/// a file no syntax can name.
///
/// BEYOND [`case_digests`]:
/// - the names reached from the case's own test function too, so a test's
///   helpers in another test module are in its key;
/// - every probed function sharing a reached name, by digest, so a function
///   added or edited where a call by that name may now land moves the key;
/// - every file an include in what it reaches names, by content id;
/// - for a case no trace could read, the whole tree, Rust included.
///
/// A FEATURE GATE IS UNKNOWN, never keyed: the sweep and the suite may build
/// different feature sets, so what the record saw is not what the suite runs.
#[must_use]
pub fn test_digests(
    root: &std::path::Path,
    index: &DependencyIndex,
    dirs: &std::collections::BTreeMap<String, String>,
    cases: &std::collections::BTreeMap<Case, Ran>,
    resources: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<Case, Option<String>> {
    let by_digest = ids_by_value(index.probes.iter().enumerate());
    let untraced = tree_ids_digest(resources);
    let mut out = std::collections::BTreeMap::new();
    let mut executed = std::collections::BTreeMap::new();
    let mut read = std::collections::BTreeMap::new();
    for (case, (functions, touched)) in cases {
        let ids: Option<BTreeSet<usize>> = functions
            .iter()
            .map(|function| by_digest.get(function))
            .try_fold(BTreeSet::new(), |mut ids, found| {
                ids.extend(found?.iter().copied());
                Some(ids)
            });
        let Some(ids) = ids else {
            out.insert(case.clone(), None);
            continue;
        };
        executed.insert(case.clone(), ids);
        if let Some(touched) = touched {
            read.insert(case.clone(), touched.clone());
        }
    }
    let depends = Depends {
        probes: &index.probes,
        names: &index.names,
        items: &index.items,
        mentions: &index.mentions,
        read: &read,
        resources,
        untraced: &untraced,
    };
    let base = case_digests(root, executed.keys(), dirs, &executed, &depends);
    // ONE INDEXED GRAPH FOR EVERY CASE'S SELECTION WALK, as `case_digests`
    // walks its own: per case a `String` closure over the mentions graph held
    // this stage at one core for minutes on #1276 (sampled under gdb).
    let graph = Graph::new(&depends);
    let mut walk = Walk::default();
    for (case, ids) in &executed {
        out.insert(
            case.clone(),
            selection_digest(
                index,
                (&graph, &mut walk),
                case,
                ids,
                base.get(case),
                resources,
            ),
        );
    }
    out
}

/// [`test_digests`] for one case past [`case_digests`]'s `base`.
fn selection_digest(
    index: &DependencyIndex,
    (graph, walk): (&Graph<'_>, &mut Walk),
    case: &Case,
    ids: &BTreeSet<usize>,
    base: Option<&String>,
    resources: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let test = case.0.rsplit("::").next().unwrap_or(&case.0);
    let starts: Vec<&str> = ids
        .iter()
        .filter_map(|id| index.names.get(*id))
        .flatten()
        .map(String::as_str)
        .chain([test, ""])
        .collect();
    // What `named_closure` reaches, in name order: the graph's walk, plus each
    // start the graph does not hold (no mention names it, so it reaches only
    // itself).
    let mut reached: Vec<&str> = graph
        .reach(starts.iter().filter_map(|name| graph.id(name)), walk)
        .iter()
        .map(|id| graph.names[*id])
        .collect();
    reached.extend(starts.iter().filter(|name| graph.id(name).is_none()));
    reached.sort_unstable();
    reached.dedup();
    let mut probes: BTreeSet<usize> = ids.clone();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tc1\x1f");
    hasher.update(base?.as_bytes());
    let mut includes: BTreeSet<String> = BTreeSet::new();
    let mut include = |held: Option<&Option<BTreeSet<String>>>| match held {
        Some(None) => false,
        Some(Some(targets)) => {
            includes.extend(targets.iter().cloned());
            true
        }
        None => true,
    };
    for name in reached {
        if index.gated_names.contains(name) || !include(index.name_includes.get(name)) {
            return None;
        }
        for digest in index.items.get(name).into_iter().flatten() {
            hasher.update(format!("\x1b{name}\x1f{digest}").as_bytes());
        }
        for id in index.own_names.get(name).into_iter().flatten() {
            probes.insert(*id);
            hasher.update(format!("\x18{name}\x1f").as_bytes());
            hasher.update(index.probes.get(*id).map_or("", String::as_str).as_bytes());
        }
    }
    for id in &probes {
        if index.gated_probes.contains(id) || !include(index.probe_includes.get(id)) {
            return None;
        }
    }
    for path in includes {
        hasher.update(format!("\x17{path}\x1f").as_bytes());
        hasher.update(resource_id(resources, &path).as_bytes());
    }
    Some(hasher.finalize().to_hex().to_string())
}

/// One sealed record a selection can read ([`sealed_cases`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The case: its name and binary id.
    pub case: (String, String),
    /// What its digest is taken from.
    pub ran: Ran,
    /// The key of the [`Format`] it was read in.
    pub format: String,
    /// Its selection digest over the tree it was recorded on.
    pub tested: String,
}

/// Every record under `base` that finished passing and carries a selection
/// digest ([`TESTED`]): what a run's selection may stand on. A record that
/// reads short anywhere (a sweep clearing it mid-read) is left out, which
/// reruns it.
#[must_use]
pub fn sealed_cases(base: &std::path::Path) -> Vec<Sealed> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let read = |name: &str| crate::fsio::read_to_string(dir.join(name)).ok();
        let Some(tested) = read(TESTED) else {
            continue;
        };
        let Some((format, tested)) = tested.trim_end().split_once('\t') else {
            continue;
        };
        let (Some(record), Some(case), true) = (
            read(DEPENDS).and_then(|text| carried(&text)),
            kept_case(&dir),
            finished_passing(&dir),
        ) else {
            continue;
        };
        let touched = read(READ).map(|listing| listing.lines().map(str::to_owned).collect());
        if read(TESTED).as_deref().map(str::trim_end) != Some(&format!("{format}\t{tested}")) {
            continue;
        }
        out.push(Sealed {
            case,
            ran: (record.functions, touched),
            format: format.to_owned(),
            tested: tested.to_owned(),
        });
    }
    out.sort_by(|a, b| a.case.cmp(&b.case));
    out
}

/// Take the selection digest of every passing, sealed record under `base`
/// that was recorded over the tree the reach directory now names ([`OVER`])
/// and has none yet, over the snapshot at `root` with the checkout content
/// ids `resources`, in `format`; how many it took.
///
/// TAKEN ONCE HERE, WHERE THE RECORD WAS MADE: a record made on another tree
/// takes its digest only where a carry verified it ([`retest_carried`]), over
/// the tree that carry verified it on.
///
/// # Errors
///
/// The tree cannot be indexed or a digest cannot be written.
pub fn seal_tested(
    base: &std::path::Path,
    root: &std::path::Path,
    resources: &std::collections::BTreeMap<String, String>,
    format: &Format,
) -> anyhow::Result<usize> {
    let Ok(over) = crate::fsio::read_to_string(base.join(TREE)) else {
        return Ok(0);
    };
    let mut todo: Vec<(std::path::PathBuf, Case, Ran)> = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let dir = entry?.path();
        if !dir.is_dir()
            || dir.join(TESTED).exists()
            || !finished_passing(&dir)
            || crate::fsio::read_to_string(dir.join(OVER)).ok().as_deref() != Some(over.as_str())
        {
            continue;
        }
        let (Some(record), Some(case)) = (
            crate::fsio::read_to_string(dir.join(DEPENDS))
                .ok()
                .and_then(|text| carried(&text)),
            kept_case(&dir),
        ) else {
            continue;
        };
        let touched = crate::fsio::read_to_string(dir.join(READ))
            .ok()
            .map(|listing| listing.lines().map(str::to_owned).collect());
        todo.push((dir, case, (record.functions, touched)));
    }
    if todo.is_empty() {
        return Ok(0);
    }
    let key = format.store(base)?;
    let index = dependency_index(root, format)?;
    let cases: std::collections::BTreeMap<Case, Ran> = todo
        .iter()
        .map(|(_, case, ran)| (case.clone(), ran.clone()))
        .collect();
    let digests = test_digests(root, &index, &format.dirs, &cases, resources);
    let mut sealed = 0;
    for (dir, case, _) in &todo {
        if let Some(Some(digest)) = digests.get(case) {
            crate::durable::replace(dir.join(TESTED), format!("{key}\t{digest}"))?;
            sealed += 1;
        }
    }
    Ok(sealed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_indexed_walk_reaches_what_the_closure_reaches_in_name_order() {
        let set = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let mentions: std::collections::BTreeMap<String, BTreeSet<String>> = [
            ("a", set(&["b", "c"])),
            ("b", set(&["d"])),
            ("c", set(&["d"])),
            ("d", set(&["a"])),
            ("x", set(&["y"])),
        ]
        .into_iter()
        .map(|(name, next)| (name.to_owned(), next))
        .collect();
        let names = vec![set(&["d", "lone"]), set(&["x"])];
        let empty = std::collections::BTreeMap::new();
        let read = std::collections::BTreeMap::new();
        let depends = Depends {
            probes: &[],
            names: &names,
            items: &empty,
            mentions: &mentions,
            read: &read,
            resources: &std::collections::BTreeMap::new(),
            untraced: "",
        };
        let graph = Graph::new(&depends);
        let mut walk = Walk::default();
        for start in [vec!["d", "lone"], vec!["x"], vec!["b", "x"]] {
            let starts: Vec<String> = start.iter().map(|name| (*name).to_owned()).collect();
            let want: Vec<String> = named_closure(starts.iter(), &mentions)
                .into_iter()
                .collect();
            let got: Vec<String> = graph
                .reach(starts.iter().filter_map(|name| graph.id(name)), &mut walk)
                .iter()
                .map(|id| graph.names[*id].to_owned())
                .collect();
            assert_eq!(got, want, "from {start:?}");
        }
    }

    #[test]
    fn a_schema_build_keeps_no_incremental_session() {
        let args = cargo_dirs(std::path::Path::new("/t"));
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--config" && pair[1] == "build.incremental=false"),
            "{args:?}"
        );
        // NOR IS ANY OF IT EXPORTED to the cases the suite runs (#1276).
        assert!(
            !args.iter().any(|arg| arg.starts_with("CARGO_")),
            "{args:?}"
        );
    }

    /// A one-file crate at a fresh scratch root, its `src/lib.rs` probed as a
    /// sweep would probe it, and `more` beside it in `src/more.rs`.
    fn selection_tree(name: &str, lib: &str, more: &str) -> (std::path::PathBuf, Format) {
        let root = crate::scratch::scratch(name);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), lib).unwrap();
        std::fs::write(root.join("src/more.rs"), more).unwrap();
        let format = Format {
            dirs: [(String::from("fix"), String::new())].into(),
            probed: [String::from("src/lib.rs")].into(),
            ..Format::default()
        };
        (root, format)
    }

    /// The selection digest of the case `tests::checks` over the tree at
    /// `root`, as having run `functions` and read `read`.
    fn selection(
        root: &std::path::Path,
        format: &Format,
        functions: &[&str],
        read: Option<&[&str]>,
        resources: &std::collections::BTreeMap<String, String>,
    ) -> Option<String> {
        let index = dependency_index(root, format).unwrap();
        let ran: BTreeSet<String> = functions
            .iter()
            .flat_map(|name| index.digests_of(name))
            .collect();
        assert!(!ran.is_empty(), "the fixture's functions are probed");
        let case = (String::from("tests::checks"), String::from("fix"));
        let read = read.map(|paths| paths.iter().map(|p| (*p).to_owned()).collect());
        let cases = [(case.clone(), (ran, read))].into();
        test_digests(root, &index, &format.dirs, &cases, resources)
            .remove(&case)
            .unwrap()
    }

    const SELECTED: &str = "pub fn run() -> u8 { helper() }\nfn helper() -> u8 { 1 }\n\
        #[cfg(test)]\nmod tests {\n    #[test]\n    fn checks() { assert_eq!(super::run(), 1); }\n}\n";

    /// Fails by: a function added under a name the case's code calls left out
    /// of its key (a call that may now land there skipped), or an unrelated
    /// one moving it (every edit rerunning every case).
    #[test]
    fn a_function_sharing_a_called_name_moves_the_selection_digest() {
        let none = std::collections::BTreeMap::new();
        let ran = ["run", "helper", "checks"];
        let (root, format) = selection_tree("schema-select-shadow", SELECTED, "");
        let held = selection(&root, &format, &ran, Some(&[]), &none).unwrap();
        std::fs::write(root.join("src/more.rs"), "pub fn other() -> u8 { 2 }\n").unwrap();
        assert_eq!(
            selection(&root, &format, &ran, Some(&[]), &none).as_deref(),
            Some(held.as_str()),
            "an unrelated function"
        );
        std::fs::write(root.join("src/more.rs"), "pub fn helper() -> u8 { 2 }\n").unwrap();
        assert_ne!(
            selection(&root, &format, &ran, Some(&[]), &none).as_deref(),
            Some(held.as_str()),
            "a function named as the case's code calls"
        );
    }

    /// Fails by: a case whose code is feature-gated selected (the sweep's
    /// features are not the suite's), a function it ran that is gone keyed
    /// as if present, or an ungated case left unknown.
    #[test]
    fn a_feature_gate_or_a_vanished_function_is_unknown() {
        let none = std::collections::BTreeMap::new();
        let ran = ["run", "helper", "checks"];
        let gated =
            "pub fn run() -> u8 {\n    #[cfg(feature = \"x\")]\n    let _ = 0;\n    helper()\n}\n";
        let (root, format) = selection_tree(
            "schema-select-gate",
            &SELECTED.replace("pub fn run() -> u8 { helper() }\n", gated),
            "",
        );
        assert_eq!(
            selection(&root, &format, &ran, Some(&[]), &none),
            None,
            "a gated function"
        );
        let (root, format) = selection_tree(
            "schema-select-gated-item",
            SELECTED,
            "#[cfg(not(feature = \"x\"))]\npub const LIMIT: u8 = 1;\n",
        );
        let index = dependency_index(&root, &format).unwrap();
        assert!(index.gated_names.contains("LIMIT"), "a gated item");
        assert!(
            selection(&root, &format, &ran, Some(&[]), &none).is_some(),
            "an item nothing names"
        );
        let (root, format) = selection_tree("schema-select-gone", SELECTED, "");
        let index = dependency_index(&root, &format).unwrap();
        let case = (String::from("tests::checks"), String::from("fix"));
        let cases = [(
            case.clone(),
            ([String::from("gone")].into(), Some(BTreeSet::new())),
        )]
        .into();
        assert_eq!(
            test_digests(&root, &index, &format.dirs, &cases, &none).remove(&case),
            Some(None),
            "a function no longer in the tree"
        );
        let cfg_variable =
            "pub fn run() -> u8 { let cfg = 1; let feature = cfg; feature + helper() - 1 }\n";
        let (root, format) = selection_tree(
            "schema-select-variable",
            &SELECTED.replace("pub fn run() -> u8 { helper() }\n", cfg_variable),
            "",
        );
        assert!(
            selection(&root, &format, &ran, Some(&[]), &none).is_some(),
            "a variable is no gate"
        );
    }

    /// Fails by: an included file's edit left out of the key of a case whose
    /// code holds it (a stale pass of a rebuilt constant), an untraced case
    /// keyed on less than the whole tree, or an include no syntax can name
    /// keyed as if read.
    #[test]
    fn an_include_and_an_untraced_case_key_on_what_they_cannot_name() {
        let lib = "const T: &str = include_str!(\"../tpl.txt\");\n\
            pub fn run() -> u8 { u8::from(!T.is_empty()) }\n\
            #[cfg(test)]\nmod tests {\n    #[test]\n    fn checks() { assert_eq!(super::run(), 1); }\n}\n";
        let (root, format) = selection_tree("schema-select-include", lib, "");
        let ran = ["run", "checks"];
        let ids = |tpl: &str, other: &str| -> std::collections::BTreeMap<String, String> {
            [
                (String::from("tpl.txt"), tpl.to_owned()),
                (String::from("x.txt"), other.to_owned()),
            ]
            .into()
        };
        let held = selection(&root, &format, &ran, Some(&[]), &ids("a", "a"));
        assert!(held.is_some());
        assert_eq!(
            held,
            selection(&root, &format, &ran, Some(&[]), &ids("a", "b")),
            "a file it neither read nor holds"
        );
        assert_ne!(
            held,
            selection(&root, &format, &ran, Some(&[]), &ids("b", "a")),
            "the included file"
        );
        let untraced = selection(&root, &format, &ran, None, &ids("a", "a"));
        assert_ne!(
            untraced,
            selection(&root, &format, &ran, None, &ids("a", "b")),
            "an untraced case reads all"
        );
        let wrapped = "macro_rules! held { ($p:literal) => { include_str!($p) }; }\n\
            pub fn run() -> u8 { u8::from(!held!(\"../tpl.txt\").is_empty()) }\n\
            #[cfg(test)]\nmod tests {\n    #[test]\n    fn checks() { assert_eq!(super::run(), 1); }\n}\n";
        let (root, format) = selection_tree("schema-select-wrapped", wrapped, "");
        assert_eq!(
            selection(&root, &format, &ran, Some(&[]), &ids("a", "a")),
            None,
            "an include in a macro's body"
        );
    }

    /// Fails by: a record made on another tree given a selection digest (a
    /// carried record compared with a head its functions were not read on), a
    /// failed or unsealed one given one, or a sealed one not read back.
    #[test]
    fn a_selection_digest_is_taken_once_over_the_tree_a_record_was_made_on() {
        use std::fmt::Write as _;
        let (root, format) = selection_tree("schema-seal-tested", SELECTED, "");
        let index = dependency_index(&root, &format).unwrap();
        let base = crate::scratch::scratch("schema-seal-tested-base");
        std::fs::write(base.join(TREE), "t1").unwrap();
        let mut functions = String::from("D-\n");
        for name in ["run", "helper", "checks"] {
            for digest in index.digests_of(name) {
                let _ = writeln!(functions, "F{digest}");
            }
        }
        for (dir, over, done, depends) in [
            ("made", "t1", "0", true),
            ("carried", "t0", "0", true),
            ("failed", "t1", "101", true),
            ("unsealed", "t1", "0", false),
        ] {
            let dir = base.join(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("case"), "tests::checks\tfix").unwrap();
            std::fs::write(dir.join(OVER), over).unwrap();
            std::fs::write(dir.join(DONE), done).unwrap();
            std::fs::write(dir.join(READ), "").unwrap();
            if depends {
                std::fs::write(dir.join(DEPENDS), &functions).unwrap();
            }
        }
        let none = std::collections::BTreeMap::new();
        assert_eq!(seal_tested(&base, &root, &none, &format).unwrap(), 1);
        for (dir, tested) in [
            ("made", true),
            ("carried", false),
            ("failed", false),
            ("unsealed", false),
        ] {
            assert_eq!(base.join(dir).join(TESTED).is_file(), tested, "{dir}");
        }
        let sealed = sealed_cases(&base);
        assert_eq!(sealed.len(), 1);
        assert_eq!(Format::load(&base, &sealed[0].format), Some(format.clone()));
        assert_eq!(
            test_digests(
                &root,
                &index,
                &format.dirs,
                &[(sealed[0].case.clone(), sealed[0].ran.clone())].into(),
                &none
            )
            .remove(&sealed[0].case),
            Some(Some(sealed[0].tested.clone())),
            "the digest a seal took is the one the same tree gives"
        );
        assert_eq!(
            seal_tested(&base, &root, &none, &format).unwrap(),
            0,
            "taken once"
        );
    }

    /// Fails by: a sweep that carries every record leaving one without a
    /// selection digest (selection never backfilled, so `test:cargo` selects
    /// nothing until a record is re-recorded), a digest other than the one the
    /// live tree gives, or a record's digest read in another format rewritten.
    #[test]
    fn an_all_carry_sweep_leaves_every_record_with_a_selection_digest() {
        use std::fmt::Write as _;
        let (root, format) = selection_tree("schema-carry-tested", SELECTED, "");
        let index = dependency_index(&root, &format).unwrap();
        let base = crate::scratch::scratch("schema-carry-tested-base");
        std::fs::write(base.join(TREE), "t0").unwrap();
        let probes: Vec<String> = ["run", "helper", "checks"]
            .iter()
            .flat_map(|name| index.digests_of(name))
            .collect();
        let mut depends = String::from("Dsame\n");
        for digest in &probes {
            let _ = writeln!(depends, "F{digest}");
        }
        for (dir, tested) in [
            ("bare", None),
            ("stale", Some(format!("{}\tstale", format.key()))),
            ("foreign", Some(String::from("other\tkept"))),
        ] {
            let dir = base.join(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("case"), "tests::checks\tfix").unwrap();
            std::fs::write(dir.join(OVER), "t0").unwrap();
            std::fs::write(dir.join(DONE), "0").unwrap();
            std::fs::write(dir.join(READ), "").unwrap();
            std::fs::write(dir.join(DEPENDS), &depends).unwrap();
            if let Some(tested) = tested {
                std::fs::write(dir.join(TESTED), tested).unwrap();
            }
        }
        let fns = std::collections::BTreeMap::new();
        let classic = BTreeSet::new();
        let identity = Identity {
            probes: &probes,
            sites: &[],
            mutant_fns: &fns,
            classic: &classic,
        };
        let same = |executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
                    _: &std::collections::BTreeMap<Case, BTreeSet<String>>| {
            executed
                .keys()
                .map(|case| (case.clone(), String::from("same")))
                .collect()
        };
        let none = std::collections::BTreeMap::new();
        assert_eq!(
            carry_forward(
                &base,
                "t1",
                &identity,
                (&same, Some((&root, &none, &format)))
            )
            .unwrap(),
            (3, 0),
            "every record carries"
        );
        let live = test_digests(
            &root,
            &index,
            &format.dirs,
            &[(
                (String::from("tests::checks"), String::from("fix")),
                (probes.iter().cloned().collect(), Some(BTreeSet::new())),
            )]
            .into(),
            &none,
        )
        .into_values()
        .next()
        .flatten()
        .expect("the live tree gives the case a digest");
        let want = format!("{}\t{live}", format.key());
        for (dir, held) in [("bare", &want), ("stale", &want)] {
            assert_eq!(
                std::fs::read_to_string(base.join(dir).join(TESTED)).unwrap(),
                *held,
                "{dir}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(base.join("foreign").join(TESTED)).unwrap(),
            "other\tkept",
            "a digest read in another format is that format's"
        );
        assert_eq!(Format::load(&base, &format.key()), Some(format.clone()));
        assert_eq!(sealed_cases(&base).len(), 3, "every record is sealed");
    }

    #[test]
    fn a_journaled_verdict_outranks_the_line_before_it_and_a_torn_line_is_dropped() {
        let loaded = load_verdicts(
            "k\tunviable\tm1\nj\tcaught\tm2\nk\tcaught\tm1\ns\tmissed\tm3\n-\tcaught\tm4\n\
             e\terror\tm5\nu\tuncovered\tm6\nt\tcau",
        );
        assert_eq!(loaded.get("k").map(String::as_str), Some("caught"));
        assert!(!loaded.contains_key("t"), "a torn line is dropped");
        assert!(
            !loaded.contains_key("e"),
            "a run that erred decided nothing"
        );
        assert_eq!(loaded.get("s").map(String::as_str), Some("missed"));
        let found = load_verdicts("h\thanded\tm7\nu\tunprobed\tsrc/a.rs\n");
        assert_eq!(
            (found.get("h"), found.get("u")),
            (Some(&String::from(HANDED)), Some(&String::from(UNPROBED))),
            "a build's findings load, or every sweep rebuilds to find them"
        );
        assert!(
            !reusable(HANDED) && !reusable(UNPROBED),
            "neither stands in for a run"
        );
        assert_eq!(loaded.get("u").map(String::as_str), Some("uncovered"));
        assert_eq!(loaded.len(), 4);
        assert_eq!(journal_line(None, "missed", "m"), "-\tmissed\tm\n");
    }

    /// An identity with no probes, no sites and nothing handed back.
    fn no_identity() -> Identity<'static> {
        static FNS: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
        static CLASSIC: BTreeSet<u32> = BTreeSet::new();
        Identity {
            probes: &[],
            sites: &[],
            mutant_fns: &FNS,
            classic: &CLASSIC,
        }
    }

    /// One case record under `base` at `dir`: its name, exit code and files.
    fn record(
        base: &std::path::Path,
        dir: &str,
        name: &str,
        done: Option<&str>,
        files: &[(&str, &str)],
    ) {
        let at = base.join(dir);
        std::fs::create_dir_all(&at).unwrap();
        std::fs::write(at.join("case"), format!("{name}\tbin")).unwrap();
        if let Some(code) = done {
            std::fs::write(at.join(DONE), code).unwrap();
        }
        for (file, text) in files {
            std::fs::write(at.join(file), text).unwrap();
        }
    }

    /// An unsealed record resumes only over the tree it was recorded on: one
    /// that finished passing is kept and counted, one that failed or never
    /// finished is cleared; over another tree every unsealed record goes.
    ///
    /// Fails by: an unsealed record kept over another tree (its ids are
    /// another rendering's), a failed or torn case kept, or a finished one not.
    #[test]
    fn an_unsealed_reach_record_resumes_only_over_its_own_tree() {
        let base = crate::scratch::scratch("schema-reach-resume");
        record(&base, "a", "a", Some("0"), &[("1", "f0\n")]);
        record(&base, "b", "b", Some("101"), &[]);
        record(&base, "c", "c", None, &[]);
        std::fs::write(base.join(TREE), "tree-1").unwrap();
        let none = |_: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
                    _: &std::collections::BTreeMap<Case, BTreeSet<String>>| {
            std::collections::BTreeMap::new()
        };
        assert_eq!(
            carry_forward(&base, "tree-1", &no_identity(), (&none, None)).unwrap(),
            (0, 1)
        );
        assert!(base.join("a").exists());
        assert!(
            !base.join("b").exists() && !base.join("c").exists(),
            "run again"
        );
        assert_eq!(
            carry_forward(&base, "tree-2", &no_identity(), (&none, None)).unwrap(),
            (0, 0)
        );
        assert!(
            !base.join("a").exists(),
            "another tree's unsealed record is cleared"
        );
        assert_eq!(std::fs::read_to_string(base.join(TREE)).unwrap(), "tree-2");
    }

    /// A sealed record is carried across a change when its functions still
    /// exist, its dependency digest is unchanged and no new mutant sits in a
    /// function it ran; otherwise it is cleared, so only that case runs again.
    ///
    /// Fails by: a record carried over a changed dependency (a stale reach
    /// judges the new code), over a vanished function, or past a new mutant it
    /// could not have reached; or a trustworthy record cleared (the whole
    /// suite re-run on every lap).
    #[test]
    fn a_sealed_reach_record_is_carried_only_when_nothing_it_depends_on_moved() {
        let base = crate::scratch::scratch("schema-reach-carry");
        let sealed =
            |digest: &str, function: &str| format!("D{digest}\nF{function}\nSkey-0\nT2.5\n");
        record(
            &base,
            "kept",
            "kept",
            Some("0"),
            &[(DEPENDS, &sealed("same", "fa"))],
        );
        record(
            &base,
            "moved",
            "moved",
            Some("0"),
            &[(DEPENDS, &sealed("old", "fa"))],
        );
        record(
            &base,
            "gone",
            "gone",
            Some("0"),
            &[(DEPENDS, &sealed("same", "fz"))],
        );
        record(
            &base,
            "fresh",
            "fresh",
            Some("0"),
            &[(DEPENDS, &sealed("same", "fb"))],
        );
        std::fs::write(base.join(LISTED), "key-0\n").unwrap();
        let probes = [String::from("fb"), String::from("fa")];
        let sites = [Some(String::from("key-0")), Some(String::from("key-new"))];
        let fns: std::collections::BTreeMap<u32, String> = [(1, String::from("fb"))].into();
        let classic = BTreeSet::new();
        let identity = Identity {
            probes: &probes,
            sites: &sites,
            mutant_fns: &fns,
            classic: &classic,
        };
        let recompute =
            |executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
             _: &std::collections::BTreeMap<Case, BTreeSet<String>>| {
                executed
                    .iter()
                    .map(|(case, ids)| {
                        assert_eq!(ids, &BTreeSet::from([1]), "carried to the new probe id");
                        (case.clone(), String::from("same"))
                    })
                    .collect()
            };
        assert_eq!(
            carry_forward(&base, "tree-2", &identity, (&recompute, None)).unwrap(),
            (1, 0)
        );
        assert!(base.join("kept").exists());
        assert!(!base.join("moved").exists(), "its dependency digest moved");
        assert!(!base.join("gone").exists(), "a function it ran is gone");
        assert!(
            !base.join("fresh").exists(),
            "a new mutant sits in a function it ran"
        );
        let reach = collect_reach(&base, &identity).unwrap();
        let kept = (String::from("kept"), String::from("bin"));
        assert_eq!(reach.executed.get(&kept), Some(&BTreeSet::from([1])));
        assert_eq!(reach.sites.get(&0), Some(&BTreeSet::from([kept.clone()])));
        assert_eq!(reach.seconds.get(&kept), Some(&2.5));
    }

    /// Sealing writes each case in identities, drops its per-process files and
    /// records the listing; a case reaching a keyless site stays unsealed.
    ///
    /// Fails by: a record sealed in positional ids (carried to the wrong
    /// function next lap), process files left to be read twice, a keyless
    /// site sealed (it could never be carried back), or a failed baseline's
    /// pass sealing the tree (a restart would skip the refusal) or no case.
    #[test]
    fn a_sealed_record_names_functions_and_sites_by_identity() {
        let base = crate::scratch::scratch("schema-reach-seal");
        record(&base, "one", "one", Some("0"), &[("100", "0\nf1\n")]);
        record(&base, "two", "two", Some("0"), &[("200", "1\nf0\n")]);
        let probes = [String::from("fa"), String::from("fb")];
        let sites = [Some(String::from("key-0")), None];
        let fns = std::collections::BTreeMap::new();
        let classic = BTreeSet::new();
        let identity = Identity {
            probes: &probes,
            sites: &sites,
            mutant_fns: &fns,
            classic: &classic,
        };
        let mut reach = collect_reach(&base, &identity).unwrap();
        reach.tree = String::from("tree-1");
        let (one, two) = (
            (String::from("one"), String::from("bin")),
            (String::from("two"), String::from("bin")),
        );
        let digests = [
            (one.clone(), String::from("d1")),
            (two.clone(), String::from("d2")),
        ]
        .into();
        let seconds = [(one, 1.5)].into();
        // A FAILED BASELINE SEALS EACH CASE AND NOT THE TREE: the passing
        // case's `depends` carries to the next run, and no seal over this tree
        // lets a restart skip the suite and so the refusal.
        seal_reach(&base, &reach, &digests, &identity, &seconds, false).unwrap();
        assert!(base.join("one").join(DEPENDS).is_file(), "the case carries");
        assert!(!base.join(SEALED).exists(), "the tree is not sealed");
        seal_reach(&base, &reach, &digests, &identity, &seconds, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(base.join("one").join(DEPENDS)).unwrap(),
            "Dd1\nFfb\nSkey-0\nT1.5\n"
        );
        assert!(
            !base.join("one/100").exists(),
            "process files go once sealed"
        );
        assert!(
            !base.join("two").join(DEPENDS).exists(),
            "a keyless site stays unsealed"
        );
        assert_eq!(
            std::fs::read_to_string(base.join(LISTED)).unwrap(),
            "key-0\n"
        );
        assert_eq!(
            std::fs::read_to_string(base.join(SEALED)).unwrap(),
            "tree-1"
        );
    }

    /// A two-probe, one-site context over an empty root, as a sweep writes it.
    fn seal_context() -> SealContext {
        SealContext {
            root: crate::scratch::scratch("schema-seal-case-root"),
            dirs: std::collections::BTreeMap::new(),
            probes: vec![String::from("fa"), String::from("fb")],
            names: vec![BTreeSet::new(), BTreeSet::new()],
            items: std::collections::BTreeMap::new(),
            mentions: std::collections::BTreeMap::new(),
            resources: std::collections::BTreeMap::new(),
            untraced: String::from("u"),
            sites: vec![Some(String::from("key-0"))],
            mutant_fns: std::collections::BTreeMap::new(),
            classic: BTreeSet::new(),
            format: None,
        }
    }

    /// A stopped run's finished records are sealed by the next sweep exactly
    /// as the stopped run's own end-of-run seal would have, so a sweep killed
    /// partway leaves every finished case carryable across a moving head.
    ///
    /// Fails by: a leftover seal disagreeing with the end-of-run seal (a carry
    /// over the wrong dependencies), process files kept, a leftover not carried
    /// to a new tree, a failed case sealed, a sealed record rewritten, or a
    /// seal written with no context.
    #[test]
    fn a_stopped_runs_records_are_sealed_as_its_own_seal_would_and_carry() {
        let context = seal_context();
        let by_recorder = crate::scratch::scratch("schema-seal-case-recorder");
        let by_sweep = crate::scratch::scratch("schema-seal-case-sweep");
        for base in [&by_recorder, &by_sweep] {
            record(base, "one", "one", Some("0"), &[("100", "0\nf1\n")]);
        }
        let bare = crate::scratch::scratch("schema-seal-case-bare");
        record(&bare, "one", "one", Some("0"), &[("100", "0\nf1\n")]);
        assert_eq!(seal_leftovers(&bare).unwrap(), 0);
        assert!(
            !bare.join("one").join(DEPENDS).exists(),
            "no context, no seal"
        );
        record(
            &by_recorder,
            "bad",
            "bad",
            Some("101"),
            &[("300", "0\nf0\n")],
        );
        record(
            &by_recorder,
            "kept",
            "kept",
            Some("0"),
            &[(DEPENDS, "Dheld\n")],
        );
        std::fs::write(
            by_recorder.join(CONTEXT),
            serde_json::to_string(&context).unwrap(),
        )
        .unwrap();
        assert_eq!(
            seal_leftovers(&by_recorder).unwrap(),
            1,
            "only the leftover"
        );
        assert!(
            !by_recorder.join("bad").join(DEPENDS).exists(),
            "a failed case is not sealed"
        );
        assert_eq!(
            std::fs::read_to_string(by_recorder.join("kept").join(DEPENDS)).unwrap(),
            "Dheld\n",
            "a sealed record is not rewritten"
        );
        assert!(
            !by_recorder.join("one/100").exists(),
            "process files go once sealed"
        );
        let identity = context.identity();
        let mut reach = collect_reach(&by_sweep, &identity).unwrap();
        reach.tree = String::from("tree-1");
        let digests = case_digests(
            &context.root,
            reach.executed.keys(),
            &context.dirs,
            &reach.executed,
            &Depends {
                probes: &context.probes,
                names: &context.names,
                items: &context.items,
                mentions: &context.mentions,
                read: &reach.read,
                resources: &context.resources,
                untraced: &context.untraced,
            },
        );
        seal_reach(
            &by_sweep,
            &reach,
            &digests,
            &identity,
            &std::collections::BTreeMap::new(),
            true,
        )
        .unwrap();
        let untimed = |base: &std::path::Path| {
            std::fs::read_to_string(base.join("one").join(DEPENDS))
                .unwrap()
                .lines()
                .filter(|line| !line.starts_with('T'))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(untimed(&by_recorder), untimed(&by_sweep));
        assert!(untimed(&by_recorder).contains("Ffb\nSkey-0"));
        // THE LISTING AS A KILLED RUN LEFT IT: written when reach started, and
        // no end-of-run seal followed.
        write_listed(&by_recorder, &identity).unwrap();
        assert!(!by_recorder.join(SEALED).exists());
        let recompute =
            |_: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
             _: &std::collections::BTreeMap<Case, BTreeSet<String>>| {
                digests.clone()
            };
        assert_eq!(
            carry_forward(&by_recorder, "tree-2", &identity, (&recompute, None)).unwrap(),
            (1, 0),
            "the recorder's seal carries to a new tree"
        );
    }

    /// A case recorded passing is not run again; one recorded failing is.
    /// The program does not exist, so running it is an error and skipping it
    /// is not: the outcome says which happened.
    ///
    /// Fails by: a finished case run again (the whole suite re-run on every
    /// restart), or a failed one skipped (a baseline failure hidden).
    #[test]
    fn a_finished_case_is_skipped_and_a_failed_one_runs_again() {
        let base = crate::scratch::scratch("schema-reach-skip");
        let test = [
            String::from("/nonexistent/batten-reach-case"),
            String::from("--exact"),
            String::from("case"),
        ];
        let key = blake3::hash(test.join("\u{1f}").as_bytes()).to_hex()[..16].to_owned();
        std::fs::create_dir_all(base.join(&key)).unwrap();
        std::fs::write(base.join(&key).join(DONE), "0").unwrap();
        assert_eq!(record_into(&base, &test).unwrap(), 0, "skipped");
        std::fs::write(base.join(&key).join(DONE), "101").unwrap();
        // Run again either way the host runs it: untraced, the missing
        // program is a spawn error; under a tracer, the tracer's own failing
        // exit. Only the skip answers a clean 0.
        assert!(!matches!(record_into(&base, &test), Ok(0)), "run again");
    }

    /// The exit-code file is the record's own, never a site: `0` would read as
    /// site 0 reached by every case.
    ///
    /// Fails by: the done file read as a record line.
    #[test]
    fn a_finished_cases_exit_code_is_not_a_site() {
        let base = crate::scratch::scratch("schema-reach-done");
        let case = base.join("k");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(case.join("case"), "name\tbinary").unwrap();
        std::fs::write(case.join(DONE), "0").unwrap();
        std::fs::write(case.join("1234"), "7\nf3\n").unwrap();
        let reach = collect_reach(&base, &no_identity()).unwrap();
        assert_eq!(reach.sites.keys().copied().collect::<Vec<_>>(), [7]);
    }

    #[test]
    fn the_reach_seal_moves_with_a_source_and_not_with_build_output() {
        let work = std::env::temp_dir().join(format!("batten-schema-seal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::create_dir_all(work.join("target")).unwrap();
        std::fs::write(work.join("src/lib.rs"), "fn a() {}").unwrap();
        let before = tree_digest(&work);
        std::fs::write(work.join("target/out"), "built").unwrap();
        assert_eq!(tree_digest(&work), before);
        std::fs::write(work.join("src/lib.rs"), "fn b() {}").unwrap();
        assert_ne!(tree_digest(&work), before);
        let _ = std::fs::remove_dir_all(&work);
    }

    fn listed(genre: &str, replacement: &str, from: (usize, usize), to: (usize, usize)) -> Listed {
        Listed {
            name: String::new(),
            file: String::from("src/lib.rs"),
            package: String::from("p"),
            genre: genre.to_owned(),
            replacement: replacement.to_owned(),
            span: Span {
                start: Position {
                    line: from.0,
                    column: from.1,
                },
                end: Position {
                    line: to.0,
                    column: to.1,
                },
            },
            function: Some(Function {
                function_name: String::from("f"),
                return_type: String::from("-> bool"),
                span: None,
            }),
        }
    }

    fn render_all(source: &str, mutants: &[Listed]) -> Rendered {
        let numbered: Vec<(u32, &Listed)> = mutants
            .iter()
            .enumerate()
            .map(|(id, m)| (u32::try_from(id).unwrap(), m))
            .collect();
        render(source, &numbered, &BTreeSet::new(), None)
    }

    /// A case's reach is every site any of its processes recorded, and each
    /// site lists the cases that reached it with their binaries.
    ///
    /// Fails by: a spawned process's record dropped, a case attributed to the
    /// wrong binary, or a non-number read as a site.
    #[test]
    fn reach_is_every_site_any_process_of_a_case_recorded() {
        let base = crate::scratch::scratch("schema-reach");
        let one = base.join("aa");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::write(one.join("case"), "m::first\tbatten::it").unwrap();
        std::fs::write(one.join("100"), "3\n7\n").unwrap();
        std::fs::write(one.join("101"), "7\n9\nnoise\n").unwrap();
        let two = base.join("bb");
        std::fs::create_dir_all(&two).unwrap();
        std::fs::write(two.join("case"), "m::tests::second\tbatten").unwrap();
        std::fs::write(two.join("200"), "9\n").unwrap();
        std::fs::write(one.join("102"), "f4\nf2\n").unwrap();
        let recorded = collect_reach(&base, &no_identity()).unwrap();
        assert_eq!(
            recorded
                .executed
                .get(&(String::from("m::first"), String::from("batten::it"))),
            Some(&[2, 4].into()),
            "a case's executed functions, from every process"
        );
        let reach = recorded.sites;
        let first = (String::from("m::first"), String::from("batten::it"));
        let second = (String::from("m::tests::second"), String::from("batten"));
        assert_eq!(reach.get(&3), Some(&[first.clone()].into_iter().collect()));
        assert_eq!(reach.get(&7), Some(&[first.clone()].into_iter().collect()));
        assert_eq!(reach.get(&9), Some(&[first, second].into_iter().collect()));
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn a_binary_names_its_package() {
        assert_eq!(package_of("batten::it"), "batten");
        assert_eq!(package_of("batten-fsio"), "batten-fsio");
        assert_eq!(package_of("batten::bin/batten"), "batten");
    }

    #[test]
    fn a_position_is_a_byte_offset_by_characters() {
        let text = "ab\nçd\n";
        assert_eq!(offset(text, Position { line: 1, column: 1 }), Some(0));
        assert_eq!(offset(text, Position { line: 2, column: 2 }), Some(5));
        assert_eq!(offset(text, Position { line: 2, column: 3 }), Some(6));
        assert_eq!(offset(text, Position { line: 9, column: 1 }), None);
    }

    /// Each kind of site renders its switch, and an unmutated file is
    /// byte-identical.
    #[test]
    fn every_kind_of_mutant_renders_as_a_switch() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        assert_eq!(render_all(source, &[]).text, source);
        let body = render_all(source, &[listed("FnValue", "true", (2, 5), (2, 11))]);
        assert_eq!(
            body.text,
            "fn f(a: u8, b: u8) -> bool {\n    if crate::__batten_mutant(0) { true } else { a == b }\n}\n"
        );
        let op = render_all(source, &[listed("BinaryOperator", "!=", (2, 7), (2, 9))]);
        assert_eq!(
            op.text,
            "fn f(a: u8, b: u8) -> bool {\n    (if crate::__batten_mutant(0) { a != b } else { a == b })\n}\n"
        );
        let not = render_all(
            "fn f(a: bool) -> bool {\n    !a\n}\n",
            &[listed("UnaryOperator", "", (2, 5), (2, 6))],
        );
        assert_eq!(
            not.text,
            "fn f(a: bool) -> bool {\n    (if crate::__batten_mutant(0) { a } else { !a })\n}\n"
        );
    }

    /// A mutant inside another's site is rendered inside both branches, and
    /// two mutants of one site nest as `else if`.
    #[test]
    fn nested_and_shared_sites_compose() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let both = render_all(
            source,
            &[
                listed("FnValue", "true", (2, 5), (2, 11)),
                listed("FnValue", "false", (2, 5), (2, 11)),
                listed("BinaryOperator", "!=", (2, 7), (2, 9)),
            ],
        );
        assert_eq!(
            both.text,
            "fn f(a: u8, b: u8) -> bool {\n    if crate::__batten_mutant(0) { true } else if \
             crate::__batten_mutant(1) { false } else { (if crate::__batten_mutant(2) { a != b } \
             else { a == b }) }\n}\n"
        );
    }

    /// A deleted arm gains a guard; a replaced guard is switched; both on one
    /// arm compose.
    #[test]
    fn arms_and_guards_switch_off() {
        let source = "fn f(x: u8, g: bool) -> u8 {\n    match x {\n        1 if g => 2,\n        3 => 4,\n        _ => 0,\n    }\n}\n";
        let rendered = render_all(
            source,
            &[
                listed("MatchArm", "", (4, 9), (4, 15)),
                listed("MatchArmGuard", "true", (3, 14), (3, 15)),
                listed("MatchArm", "", (3, 9), (3, 20)),
            ],
        );
        assert!(
            rendered
                .text
                .contains("3 if !(crate::__batten_mutant(0)) => 4,"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains(
                "1 if ((if crate::__batten_mutant(1) { true } else { g })) && !(crate::__batten_mutant(2)) => 2,"
            ),
            "{}",
            rendered.text
        );
    }

    /// A const context, an `impl Trait` body and a struct field are handed
    /// back, and a skipped mutant renders as the original.
    #[test]
    fn what_cannot_switch_is_handed_back() {
        let source = "const C: bool = 1 == 2;\nfn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let rendered = render_all(
            source,
            &[
                listed("BinaryOperator", "!=", (1, 19), (1, 21)),
                listed("StructField", "", (3, 5), (3, 11)),
            ],
        );
        assert_eq!(rendered.classic, vec![0, 1]);
        assert_eq!(rendered.text, source);
        let mut opaque = listed("FnValue", "x", (3, 5), (3, 11));
        opaque.function.as_mut().unwrap().return_type = String::from("-> impl Fn()");
        assert_eq!(render_all(source, &[opaque]).classic, vec![0]);
        let skipped = render(
            source,
            &[(7, &listed("BinaryOperator", "!=", (3, 7), (3, 9)))],
            &[7].into_iter().collect(),
            None,
        );
        assert_eq!(skipped.text, source);
    }

    /// An error inside a mutant's branch belongs to that mutant; one inside a
    /// nested branch belongs to the innermost.
    #[test]
    fn an_error_belongs_to_the_innermost_branch_holding_it() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let rendered = render_all(
            source,
            &[
                listed("FnValue", "true", (2, 5), (2, 11)),
                listed("BinaryOperator", "!=", (2, 7), (2, 9)),
            ],
        );
        let at_true = rendered.text.find("true").unwrap();
        assert_eq!(rendered.owners(at_true), Some(&[0][..]));
        let at_ne = rendered.text.find("!=").unwrap();
        assert_eq!(rendered.owners(at_ne), Some(&[1][..]));
        assert_eq!(rendered.owners(0), None, "outside every switch");
    }

    fn case(name: &str) -> Case {
        (name.to_owned(), String::from("batten::it"))
    }

    #[test]
    fn a_junit_report_times_each_case_by_name_and_binary() {
        let report = "<testsuite name=\"batten::it\"><testcase name=\"a::b&lt;1&gt;\" \
                      classname=\"batten::it\" timestamp=\"x\" time=\"0.250\">\
                      </testcase><testcase name=\"c\" classname=\"batten\" time=\"2\"/></testsuite>";
        let timed = durations(report);
        assert_eq!(timed.get(&case("a::b<1>")), Some(&0.25));
        assert_eq!(
            timed.get(&(String::from("c"), String::from("batten"))),
            Some(&2.0)
        );
        assert_eq!(timed.len(), 2);
    }

    #[test]
    fn the_first_phase_tries_a_siblings_killer_then_the_cheapest_cases() {
        let cases: BTreeSet<Case> = ["slow", "cheap", "killer", "mid"].map(case).into();
        let seconds = [
            ("slow", 30.0),
            ("cheap", 0.5),
            ("killer", 9.0),
            ("mid", 3.0),
        ]
        .map(|(name, time)| (case(name), time))
        .into();
        let hints: BTreeSet<Case> = [case("killer"), case("elsewhere")].into();
        let (first, second) = phases(&cases, &hints, &seconds);
        assert_eq!(
            first,
            [case("killer")].into(),
            "a hint alone spends the budget"
        );
        assert_eq!(second, ["cheap", "mid", "slow"].map(case).into());
        let (first, second) = phases(&cases, &BTreeSet::new(), &seconds);
        assert_eq!(first, ["cheap", "mid", "killer"].map(case).into());
        assert_eq!(
            second,
            [case("slow")].into(),
            "every case runs in one phase or the other"
        );
    }

    #[test]
    fn a_first_phase_is_never_empty_while_a_case_reaches() {
        let cases: BTreeSet<Case> = [case("only")].into();
        let seconds = [(case("only"), 500.0)].into();
        let (first, second) = phases(&cases, &BTreeSet::new(), &seconds);
        assert_eq!(first, cases);
        assert!(second.is_empty());
    }

    /// nextest's `JUnit` markup as it writes it (cargo-nextest 0.9.104,
    /// measured on #1276): a failure's message and the case's own output carry
    /// words that read as a status.
    const JUNIT_FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="2" errors="0">
    <testsuite name="batten::it" tests="4" disabled="0" errors="0" failures="2">
        <testcase name="tests::a" classname="batten" time="0.006">
        </testcase>
        <testcase name="m::b" classname="batten::it" time="0.113">
            <failure message="panicked" type="test failure with exit code 101">TIMEOUT_MULTIPLIER * measured</failure>
            <system-out>TIMEOUT [ 9s] not a status</system-out>
        </testcase>
        <testcase name="m::slow" classname="batten::it" time="2.007">
            <failure type="test timeout"/>
        </testcase>
        <testcase name="tests::c" classname="batten" time="0.003">
        </testcase>
    </testsuite>
</testsuites>"#;

    /// Every case a report names, and how each ended, read from the element and
    /// its `type`, never from the words inside it.
    ///
    /// Fails by: a failure whose text names a timeout read as one, a timeout
    /// read as a failure, a pass dropped, or a case keyed by the wrong binary.
    #[test]
    fn a_junit_report_names_each_case_and_how_it_ended() {
        let pair = |name: &str, binary: &str| (String::from(name), String::from(binary));
        assert_eq!(
            junit_cases(JUNIT_FIXTURE).expect("XML"),
            [
                (pair("tests::a", "batten"), CaseEnd::Passed),
                (pair("m::b", "batten::it"), CaseEnd::Failed),
                (pair("m::slow", "batten::it"), CaseEnd::TimedOut),
                (pair("tests::c", "batten"), CaseEnd::Passed),
            ]
        );
        assert_eq!(junit_cases("FAIL [ 1s] batten::it x"), None);
    }

    /// A region holds its start and not its end, an empty one holds its start,
    /// and the smallest holding region decides.
    ///
    /// Fails by: an error at a region's end attributed to it, an error on an
    /// arm's zero-width switch attributed to its enclosing site, or the
    /// widest region winning.
    #[test]
    fn a_region_holds_its_start_and_not_its_end() {
        let rendered = Rendered {
            text: String::new(),
            regions: vec![(0..10, vec![1]), (2..4, vec![2]), (6..6, vec![3])],
            classic: Vec::new(),
            ..Rendered::default()
        };
        assert_eq!(rendered.owners(3), Some(&[2][..]));
        assert_eq!(rendered.owners(4), Some(&[1][..]), "an end is exclusive");
        assert_eq!(
            rendered.owners(6),
            Some(&[3][..]),
            "an empty region holds its start"
        );
        assert_eq!(rendered.owners(10), None);
    }

    /// A `const fn` body is a const context, so its mutants are handed back,
    /// and a match-arm span that is not the arm is handed back too.
    #[test]
    fn a_const_fn_drops_its_const_and_a_stray_arm_span_is_handed_back() {
        let source = "pub const fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let rendered = render_all(source, &[listed("BinaryOperator", "!=", (2, 7), (2, 9))]);
        assert!(rendered.classic.is_empty());
        assert_eq!(
            rendered.text,
            "pub fn f(a: u8, b: u8) -> bool {\n    (if crate::__batten_mutant(0) { a != b } else { a == b })\n}\n"
        );
        assert_eq!(rendered.deconst, vec![(String::from("f"), vec![0])]);
        assert_eq!(
            rendered.owners(rendered.text.find("fn").unwrap()),
            None,
            "the erased const owns no error"
        );
        let mut nameless = listed("BinaryOperator", "!=", (2, 7), (2, 9));
        nameless.function = None;
        assert_eq!(render_all(source, &[nameless]).classic, vec![0]);
        let item = "const fn f() -> u8 {\n    const N: u8 = 1 + 2;\n    N\n}\n";
        let inner = render_all(item, &[listed("BinaryOperator", "-", (2, 21), (2, 22))]);
        assert_eq!(inner.classic, vec![0], "a const item inside a const fn");
        let source =
            "fn f(x: u8) -> u8 {\n    match x {\n        3 => 4,\n        _ => 0,\n    }\n}\n";
        let stray = render_all(source, &[listed("MatchArm", "", (3, 9), (3, 10))]);
        assert_eq!(stray.classic, vec![0], "the pattern alone is not the arm");
    }

    /// Two mutants of one operator, or two deletions of one arm, share a
    /// switch; an error between their branches belongs to both.
    ///
    /// Fails by: a second operator mutant wrapped around the first instead of
    /// joining it, or a second arm deletion dropped.
    #[test]
    fn mutants_of_one_operator_or_arm_share_its_switch() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let ops = render_all(
            source,
            &[
                listed("BinaryOperator", "!=", (2, 7), (2, 9)),
                listed("BinaryOperator", "<", (2, 7), (2, 9)),
            ],
        );
        assert_eq!(
            ops.text,
            "fn f(a: u8, b: u8) -> bool {\n    (if crate::__batten_mutant(0) { a != b } else if \
             crate::__batten_mutant(1) { a < b } else { a == b })\n}\n"
        );
        let between = ops.text.find(" else if").unwrap();
        assert_eq!(ops.owners(between), Some(&[0, 1][..]));
        let source =
            "fn f(x: u8) -> u8 {\n    match x {\n        3 => 4,\n        _ => 0,\n    }\n}\n";
        let arms = render_all(
            source,
            &[
                listed("MatchArm", "", (3, 9), (3, 15)),
                listed("MatchArm", "", (3, 9), (3, 15)),
            ],
        );
        assert!(
            arms.text
                .contains("3 if !(crate::__batten_mutant(0) || crate::__batten_mutant(1)) => 4,"),
            "{}",
            arms.text
        );
    }

    /// A site inside a wider one renders inside it, and an operator swapped in
    /// a site holding a child is swapped in the gap that holds it only.
    ///
    /// Fails by: a site starting where its parent starts left beside it, or
    /// an operator swap applied to a gap that does not hold the operator.
    #[test]
    fn a_site_inside_another_renders_inside_it() {
        let source = "fn f(a: u8, b: u8, c: bool) -> bool {\n    a == b && c\n}\n";
        let nested = render_all(
            source,
            &[
                listed("FnValue", "true", (2, 5), (2, 16)),
                listed("BinaryOperator", "!=", (2, 7), (2, 9)),
            ],
        );
        assert_eq!(
            nested.text,
            "fn f(a: u8, b: u8, c: bool) -> bool {\n    if crate::__batten_mutant(0) { true } else { \
             (if crate::__batten_mutant(1) { a != b } else { a == b }) && c }\n}\n"
        );
        let source = "fn f(a: u8, b: u8, c: u8) -> u8 {\n    (a + b) * c\n}\n";
        let swapped = render_all(
            source,
            &[
                listed("BinaryOperator", "-", (2, 8), (2, 9)),
                listed("BinaryOperator", "+", (2, 13), (2, 14)),
            ],
        );
        let inner = "(if crate::__batten_mutant(0) { a - b } else { a + b })";
        assert_eq!(
            swapped.text,
            format!(
                "fn f(a: u8, b: u8, c: u8) -> u8 {{\n    (if crate::__batten_mutant(1) {{ ({inner}) + c }} \
                 else {{ ({inner}) * c }})\n}}\n"
            )
        );
    }

    #[test]
    fn a_listing_is_read_past_the_text_around_it() {
        let text = "  Compiling\n[{\"name\":\"m\",\"file\":\"src/lib.rs\",\"package\":\"p\",\
                    \"genre\":\"FnValue\",\"replacement\":\"true\",\"span\":{\"start\":\
                    {\"line\":1,\"column\":2},\"end\":{\"line\":3,\"column\":4}},\
                    \"function\":null}]\n[exited with code 0]\n";
        let got = listing(text).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].name.as_str(), got[0].span.end.column), ("m", 4));
        assert!(listing("nothing listed").is_err());
    }

    /// The tree mirrors the checkout: files, nested directories and links,
    /// a changed file or link rewritten, a removed one removed, the top
    /// `target/` left out on both sides, and a rendered file left to the build.
    ///
    /// Fails by: a stale file kept (a test listing a directory sees a tree no
    /// listing read), the work tree's build output deleted, or a rendered file
    /// overwritten (every sweep rebuilds every crate the schema touches).
    #[test]
    fn a_sync_mirrors_the_checkout_but_its_top_target() {
        let base = crate::scratch::scratch("schema-sync");
        let (root, work) = (base.join("root"), base.join("work"));
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::create_dir_all(root.join("sub/target")).unwrap();
        std::fs::write(root.join("a.txt"), "one").unwrap();
        std::fs::write(root.join("target/x"), "built").unwrap();
        std::fs::write(root.join("sub/target/y"), "kept").unwrap();
        std::fs::write(root.join("sub/b.txt"), "two").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
        sync(&root, &work, &BTreeSet::new()).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("a.txt")).unwrap(), "one");
        assert_eq!(
            std::fs::read_to_string(work.join("sub/b.txt")).unwrap(),
            "two"
        );
        assert!(
            !work.join("target").exists(),
            "the top target is the build's"
        );
        assert!(
            work.join("sub/target/y").is_file(),
            "a nested target is source"
        );
        std::fs::write(root.join("a.txt"), "uno").unwrap();
        sync(&root, &work, &BTreeSet::new()).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("a.txt")).unwrap(), "uno");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(work.join("link")).unwrap(),
                std::path::Path::new("a.txt")
            );
            std::fs::remove_file(root.join("link")).unwrap();
            std::os::unix::fs::symlink("sub/b.txt", root.join("link")).unwrap();
            sync(&root, &work, &BTreeSet::new()).unwrap();
            assert_eq!(
                std::fs::read_link(work.join("link")).unwrap(),
                std::path::Path::new("sub/b.txt")
            );
        }
        let file = base.join("w");
        write_if_changed(&file, "a").unwrap();
        write_if_changed(&file, "b").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "b");
        journal(&base.join("j"), "x\n").unwrap();
        journal(&base.join("j"), "y\n").unwrap();
        assert_eq!(std::fs::read_to_string(base.join("j")).unwrap(), "x\ny\n");
        std::fs::create_dir_all(work.join("target")).unwrap();
        std::fs::write(work.join("target/z"), "built").unwrap();
        std::fs::create_dir_all(work.join("target/tmp/case")).unwrap();
        std::fs::write(work.join("target/tmp/case/f"), "fixture").unwrap();
        std::fs::remove_file(root.join("sub/b.txt")).unwrap();
        std::fs::write(work.join("a.txt"), "rendered").unwrap();
        sync(&root, &work, &[String::from("a.txt")].into()).unwrap();
        assert!(
            !work.join("sub/b.txt").exists(),
            "a file gone from the checkout goes"
        );
        assert!(
            work.join("target/z").is_file(),
            "the work tree's own target stays"
        );
        assert!(
            !work.join("target/tmp").exists(),
            "a run's fixture scratch does not"
        );
        assert_eq!(
            std::fs::read_to_string(work.join("a.txt")).unwrap(),
            "rendered",
            "a rendered file is the build's to write"
        );
    }

    /// The switch goes into every crate root a mutant's package has, and each
    /// mutated file is rendered into the tree.
    #[test]
    fn the_schema_is_written_with_the_switch_in_each_crate_root() {
        let base = crate::scratch::scratch("schema-write");
        let (root, work) = (base.join("root"), base.join("work"));
        for dir in [&root, &work] {
            std::fs::create_dir_all(dir.join("crates/x/src")).unwrap();
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("crates/x/src/lib.rs"), "pub mod m;\n").unwrap();
            std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
            std::fs::write(
                dir.join("crates/x/src/m.rs"),
                "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n",
            )
            .unwrap();
        }
        let mut inner = listed("BinaryOperator", "!=", (2, 7), (2, 9));
        inner.file = String::from("crates/x/src/m.rs");
        let mut top = listed("FnValue", "()", (1, 11), (1, 13));
        top.file = String::from("src/b.rs");
        let mut loose = top.clone();
        loose.file = String::from("build.rs");
        assert_eq!(
            crate_roots(&work, &[inner.clone(), top, loose]),
            ["crates/x/src/lib.rs", "src/main.rs"]
                .map(String::from)
                .into()
        );
        let schema = write_schema(
            &root,
            &work,
            std::slice::from_ref(&inner),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(schema.files.contains_key("crates/x/src/m.rs"));
        let m = std::fs::read_to_string(work.join("crates/x/src/m.rs")).unwrap();
        assert!(m.contains("crate::__batten_mutant(0) { a != b }"), "{m}");
        let lib = std::fs::read_to_string(work.join("crates/x/src/lib.rs")).unwrap();
        assert_eq!(lib, format!("pub mod m;\n{}", prelude(schema.probes.len())));
        assert_eq!(schema.probes.len(), 1, "m.rs's one function");
        // Fails by: a file the build refused probed again because no build
        // script includes it.
        let unprobed = [String::from("crates/x/src/m.rs")].into();
        let again = write_schema(&root, &work, &[inner], &BTreeSet::new(), &unprobed).unwrap();
        assert!(again.probes.is_empty(), "an unprobed file carries no probe");
    }

    /// An error is owned by the mutant whose region holds its primary span;
    /// a warning, a non-compiler line, or an error outside every region is not.
    #[test]
    fn an_error_is_owned_by_its_primary_span() {
        let rendered = Rendered {
            text: String::new(),
            regions: vec![(10..20, vec![4]), (30..40, vec![5])],
            classic: Vec::new(),
            ..Rendered::default()
        };
        let schema = Schema {
            files: [(String::from("src/m.rs"), rendered)].into(),
            ..Schema::default()
        };
        let span = |primary: bool, at: u32| {
            format!("{{\"is_primary\":{primary},\"file_name\":\"src/m.rs\",\"byte_start\":{at}}}")
        };
        let line = |reason: &str, level: &str, message: &str, spans: &str| {
            format!(
                "{{\"reason\":\"{reason}\",\"message\":{{\"level\":\"{level}\",\"message\":\"{message}\",\"spans\":[{spans}]}}}}"
            )
        };
        let messages = [
            line(
                "compiler-message",
                "error",
                "e",
                &format!("{},{}", span(false, 35), span(true, 15)),
            ),
            line("compiler-message", "warning", "w", &span(true, 35)),
            line("build-finished", "error", "b", &span(true, 35)),
            line("compiler-message", "error", "stray", &span(true, 25)),
            String::from("not json"),
        ]
        .join("\n");
        let refused = unviable(&schema, &messages);
        assert_eq!(refused.owned, [4].into());
        let deconsted = Rendered {
            deconst: vec![(String::from("Prior::as_str"), vec![7, 8])],
            ..Rendered::default()
        };
        let schema = Schema {
            files: [
                (
                    String::from("src/m.rs"),
                    schema.files.into_values().next().unwrap(),
                ),
                (String::from("src/p.rs"), deconsted),
            ]
            .into(),
            ..Schema::default()
        };
        let caller = line(
            "compiler-message",
            "error",
            "cannot call non-const method `attribution::Prior::as_str` in constants",
            &span(true, 15),
        );
        let refused = unviable(&schema, &caller);
        assert_eq!(
            refused.reconst,
            [7, 8].into(),
            "inside mutant 4's region too"
        );
        assert!(refused.owned.is_empty());
        assert!(refuses_const_call(
            "cannot call non-const fn `as_str` in constant functions",
            "as_str"
        ));
        assert!(!refuses_const_call(
            "cannot call non-const fn `to_str` in constants",
            "as_str"
        ));
        assert!(!refuses_const_call(
            "mismatched types: `Prior::as_str`",
            "Prior::as_str"
        ));
        let refused = unviable(&schema, &messages);
        assert_eq!(refused.owned, [4].into());
        assert!(refused.reconst.is_empty());
        assert_eq!(refused.stray, vec![String::from("stray")]);
    }

    /// A phase too long for one argument is cut into runs that each fit, and
    /// together hold every case once.
    ///
    /// Fails by: a run past the cap, a case dropped or repeated, or an empty
    /// phase spending a run.
    #[test]
    fn a_phase_is_cut_into_runs_whose_filters_fit_one_argument() {
        // 1,024 bytes a case, so exactly 96 fill a run to the cap.
        let long = "x".repeat(1_011);
        let phase: BTreeSet<Case> = (0..193).map(|n| case(&format!("{long}{n:03}"))).collect();
        let runs = batches(&phase);
        assert_eq!(
            runs.iter().map(BTreeSet::len).collect::<Vec<_>>(),
            [96, 96, 1],
            "a run is filled to the cap and no further"
        );
        assert_eq!(
            runs.into_iter().flatten().collect::<BTreeSet<Case>>(),
            phase
        );
        assert!(batches(&BTreeSet::new()).is_empty());
        assert_eq!(batches(&[case("one")].into()).len(), 1);
    }

    /// Fails by: a mutant in two shards or none, or the order not kept.
    #[test]
    fn the_shards_of_a_listing_partition_it() {
        let named = |names: &[&str]| -> Vec<Listed> {
            names
                .iter()
                .map(|name| Listed {
                    name: (*name).to_owned(),
                    ..listed("FnValue", "true", (1, 1), (1, 2))
                })
                .collect()
        };
        let picked = |shard: Vec<Listed>| shard.into_iter().map(|m| m.name).collect::<Vec<_>>();
        let all = named(&["a", "b", "c", "d", "e"]);
        assert_eq!(picked(shard_of(all.clone(), Some((0, 2)))), ["a", "c", "e"]);
        assert_eq!(picked(shard_of(all.clone(), Some((1, 2)))), ["b", "d"]);
        assert_eq!(picked(shard_of(all, None)).len(), 5);
    }

    #[test]
    fn a_sweep_exit_maps_onto_the_contract_and_the_graver_one_wins() {
        use crate::exit::ExitCode;
        assert_eq!(exit_of(0), ExitCode::Success);
        assert_eq!(exit_of(2), ExitCode::Violation);
        assert_eq!(exit_of(3), ExitCode::Internal);
        assert_eq!(exit_of(1), ExitCode::Internal);
        for (a, b, graver) in [
            (ExitCode::Success, ExitCode::Violation, ExitCode::Violation),
            (ExitCode::Violation, ExitCode::Success, ExitCode::Violation),
            (ExitCode::Violation, ExitCode::Internal, ExitCode::Internal),
            (ExitCode::Usage, ExitCode::Usage, ExitCode::Usage),
        ] {
            assert_eq!(worse(a, b), graver, "{a:?} {b:?}");
        }
    }

    #[test]
    fn a_first_phase_stops_once_its_budget_is_spent_exactly() {
        let cases: BTreeSet<Case> = ["a", "b", "c"].map(case).into();
        let seconds = [("a", 1.0), ("b", 3.0), ("c", 5.0)]
            .map(|(name, time)| (case(name), time))
            .into();
        let (first, second) = phases(&cases, &BTreeSet::new(), &seconds);
        assert_eq!(first, ["a", "b"].map(case).into());
        assert_eq!(second, [case("c")].into());
    }

    #[test]
    fn a_cases_sources_are_its_module_or_its_test_target() {
        let dirs: std::collections::BTreeMap<String, String> = [
            (String::from("batten"), String::from("crates/batten")),
            (String::from("root"), String::new()),
        ]
        .into();
        let sources = |name: &str, binary: &str| case_sources(&dirs, name, binary);
        assert_eq!(sources("top", "root"), vec!["src/lib.rs"]);
        assert_eq!(
            sources("hook::tests::x", "batten"),
            vec!["crates/batten/src/hook.rs", "crates/batten/src/hook/mod.rs"]
        );
        assert_eq!(
            sources("mutate::schema::x", "batten"),
            vec![
                "crates/batten/src/mutate/schema.rs",
                "crates/batten/src/mutate/schema/mod.rs"
            ]
        );
        assert_eq!(
            sources("cli::a_case", "batten::it"),
            vec![
                "crates/batten/tests/it/cli.rs",
                "crates/batten/tests/it/common/mod.rs",
                "crates/batten/tests/it.rs"
            ]
        );
        assert_eq!(
            sources("x", "batten::bin/batten"),
            vec!["crates/batten/src/main.rs"]
        );
        assert!(sources("x", "nobody").is_empty());
    }

    fn in_function(mut mutant: Listed, from: (usize, usize), to: (usize, usize)) -> Listed {
        if let Some(function) = mutant.function.as_mut() {
            function.span = Some(Span {
                start: Position {
                    line: from.0,
                    column: from.1,
                },
                end: Position {
                    line: to.0,
                    column: to.1,
                },
            });
        }
        mutant
    }

    /// A site's key is its function's text and the mutation: two mutations
    /// of one site differ, a function moved whole keeps its key, and a
    /// verdict's key also moves with the reaching cases' files.
    #[test]
    fn a_key_follows_the_function_and_not_its_position() {
        let root = crate::scratch::scratch("schema-keys");
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), source).unwrap();
        let ne = in_function(
            listed("BinaryOperator", "!=", (2, 7), (2, 9)),
            (1, 1),
            (3, 2),
        );
        let lt = in_function(
            listed("BinaryOperator", "<", (2, 7), (2, 9)),
            (1, 1),
            (3, 2),
        );
        let key = site_key(&root, &ne).unwrap();
        assert_eq!(key.len(), 64);
        assert_ne!(Some(key.clone()), site_key(&root, &lt));
        assert_eq!(
            site_key(&root, &listed("BinaryOperator", "!=", (2, 7), (2, 9))),
            None
        );
        let dirs = [(String::from("p"), String::new())].into();
        let cases = [(String::from("x"), String::from("p"))].into();
        let none = std::collections::BTreeMap::new();
        let digests = case_digests(&root, &cases, &dirs, &none, &depends(&[]));
        let verdict = verdict_key(&root, &ne, &cases, &digests).unwrap();
        assert_eq!(verdict.len(), 64);
        assert_ne!(verdict, key);
        std::fs::write(root.join("src/lib.rs"), format!("\n{source}")).unwrap();
        let moved = in_function(
            listed("BinaryOperator", "!=", (3, 7), (3, 9)),
            (2, 1),
            (4, 2),
        );
        assert_eq!(site_key(&root, &moved), Some(key));
        let digests = case_digests(&root, &cases, &dirs, &none, &depends(&[]));
        assert_ne!(verdict_key(&root, &moved, &cases, &digests), Some(verdict));
    }

    /// A case's digest moves with its own test and the helpers beside it,
    /// and with nothing else in its file: an edit to another test or to the
    /// code under test leaves it.
    ///
    /// Fails by: the file read whole (any edit moves every case), a helper
    /// left out (its edit moves nothing), or two tests sharing one digest.
    #[test]
    fn a_case_is_keyed_by_its_own_test_and_helpers() {
        let root = crate::scratch::scratch("schema-case-digests");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let write = |code: &str, helper: &str, b: &str| {
            std::fs::write(
                root.join("src/lib.rs"),
                format!(
                    "pub fn code() -> u8 {{ {code} }}\n\
                     #[cfg(test)]\nmod tests {{\n\
                     fn helper() -> u8 {{ {helper} }}\n\
                     #[test]\nfn a() {{ assert_eq!(helper(), 1); }}\n\
                     #[test]\nfn b() {{ assert_eq!(super::code(), {b}); }}\n}}\n"
                ),
            )
            .unwrap();
        };
        let dirs = [(String::from("p"), String::new())].into();
        let cases: BTreeSet<Case> = ["tests::a", "tests::b"]
            .map(|name| (name.to_owned(), String::from("p")))
            .into();
        let digest = |name: &str| {
            case_digests(
                &root,
                &cases,
                &dirs,
                &std::collections::BTreeMap::new(),
                &depends(&[]),
            )[&(name.to_owned(), String::from("p"))]
                .clone()
        };
        write("1", "1", "1");
        let (a, b) = (digest("tests::a"), digest("tests::b"));
        assert_ne!(a, b);
        write("2", "1", "1");
        assert_eq!(
            (digest("tests::a"), digest("tests::b")),
            (a.clone(), b.clone())
        );
        write("2", "1", "2");
        assert_eq!(digest("tests::a"), a, "another test's edit");
        assert_ne!(digest("tests::b"), b);
        write("2", "3", "2");
        assert_ne!(digest("tests::a"), a, "a helper's edit");
    }

    /// Every function body that runs at run time gains a probe, numbered from
    /// the id given, and a `const fn`, a body-less declaration or a function
    /// in a const item does not; with no id, nothing is probed.
    #[test]
    fn every_runtime_function_body_gains_a_probe() {
        let source = "fn f(a: u8) -> u8 {\n    a\n}\nconst fn g() -> u8 {\n    1\n}\n\
                      trait T {\n    fn h(&self);\n    fn d(&self) {}\n}\n\
                      const C: u8 = { fn inner() -> u8 { 2 } inner() };\n";
        let rendered = render(source, &[], &BTreeSet::new(), Some(5));
        assert!(
            rendered
                .text
                .contains("fn f(a: u8) -> u8 {crate::__batten_fn(5);"),
            "{}",
            rendered.text
        );
        assert!(
            rendered
                .text
                .contains("fn d(&self) {crate::__batten_fn(6);}"),
            "{}",
            rendered.text
        );
        assert_eq!(rendered.probes.len(), 2, "{}", rendered.text);
        assert_eq!(rendered.probe_regions.len(), 2);
        let first = &rendered.probe_regions[0];
        assert_eq!(&rendered.text[first.clone()], "crate::__batten_fn(5);");
        let bare = render(source, &[], &BTreeSet::new(), None);
        assert_eq!(bare.text, source);
        assert!(bare.probes.is_empty());
    }

    /// The skeleton holds what no probe records: it moves with a type or a
    /// `const fn` body, and not with a probed function — body, signature, or
    /// the function being new — nor with a comment or whitespace. A probed
    /// function's own digest moves with its signature instead.
    ///
    /// Fails by: a probed signature left in the skeleton (every added helper
    /// moves every key), trivia hashed, or a signature in neither digest.
    #[test]
    fn the_skeleton_moves_with_what_no_probe_records() {
        let skeleton = |source: &str| render(source, &[], &BTreeSet::new(), Some(0)).skeleton;
        let probes = |source: &str| render(source, &[], &BTreeSet::new(), Some(0)).probes;
        let base = "struct S(u8);\nfn f() -> u8 {\n    1\n}\nconst fn g() -> u8 {\n    1\n}\n";
        let held = skeleton(base);
        assert_eq!(
            skeleton(&base.replace("    1\n}\nconst", "    2\n}\nconst")),
            held
        );
        assert_ne!(
            skeleton(&base.replace("struct S(u8)", "struct S(u16)")),
            held
        );
        let retyped = base.replace("fn f() -> u8", "fn f() -> u16");
        assert_eq!(skeleton(&retyped), held, "a probed signature is its own");
        assert_ne!(probes(&retyped), probes(base), "and moves its probe");
        assert_eq!(
            skeleton(&format!(
                "{base}/// helper\n#[inline]\nfn h(x: u8) -> u8 {{\n    x\n}}\n"
            )),
            held,
            "a new probed function moves no other key"
        );
        assert_eq!(
            skeleton(&base.replace("struct S(u8);", "// note\nstruct  S( u8 ) ;")),
            held,
            "trivia is not hashed"
        );
        assert_ne!(
            skeleton(&format!("{}2\n}}\n", &base[..base.len() - 4])),
            held
        );
        let unprobed = render(base, &[], &BTreeSet::new(), None).skeleton;
        assert_ne!(
            render(
                &base.replace("    1\n}\nconst", "    2\n}\nconst"),
                &[],
                &BTreeSet::new(),
                None
            )
            .skeleton,
            unprobed,
            "an unprobed file is whole"
        );
    }

    /// A case's digest moves with a function it executed and with nothing it
    /// did not, and every untraced case's moves with every non-Rust file.
    ///
    /// Fails by: the executed functions left out (a callee's edit reuses a
    /// stale kill), or another case's functions read into this one.
    #[test]
    fn a_case_moves_with_the_functions_it_executed() {
        let root = crate::scratch::scratch("schema-executed-digests");
        let dirs = std::collections::BTreeMap::new();
        let (one, two) = (case("one"), case("two"));
        let cases: BTreeSet<Case> = [one.clone(), two.clone()].into();
        let executed = [(one.clone(), [0].into()), (two.clone(), [1].into())].into();
        let digests = |probes: &[String], untraced: &str| {
            case_digests(
                &root,
                &cases,
                &dirs,
                &executed,
                &Depends {
                    untraced,
                    ..depends(probes)
                },
            )
        };
        let held = digests(&[String::from("a"), String::from("b")], "g");
        let moved = digests(&[String::from("a2"), String::from("b")], "g");
        assert_ne!(moved[&one], held[&one], "its callee changed");
        assert_eq!(moved[&two], held[&two], "not a function it ran");
        let global = digests(&[String::from("a"), String::from("b")], "h");
        assert!(cases.iter().all(|case| global[case] != held[case]));
    }

    /// No dependencies beyond a case's own text and `probes`: no names, no
    /// items, no case traced, no resources.
    fn depends(probes: &[String]) -> Depends<'_> {
        static ITEMS: std::collections::BTreeMap<String, BTreeSet<String>> =
            std::collections::BTreeMap::new();
        static READ: std::collections::BTreeMap<Case, BTreeSet<String>> =
            std::collections::BTreeMap::new();
        static IDS: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        Depends {
            probes,
            names: &[],
            items: &ITEMS,
            mentions: &ITEMS,
            read: &READ,
            resources: &IDS,
            untraced: "",
        }
    }

    /// An item added moves no case, and an item edited moves exactly the cases
    /// whose executed functions name it, a name a format string captures
    /// included.
    ///
    /// Fails by: a tree-wide skeleton in every key (the added item moves all
    /// three), a const read by no name (its edit moves nothing), or a captured
    /// `"{OTHER}"` missed.
    #[test]
    fn an_added_item_moves_no_case_and_an_edited_one_moves_the_cases_naming_it() {
        let root = crate::scratch::scratch("schema-item-digests");
        let dirs = std::collections::BTreeMap::new();
        let (a, b, c, d) = (case("a"), case("b"), case("c"), case("d"));
        let cases: BTreeSet<Case> = [a.clone(), b.clone(), c.clone(), d.clone()].into();
        let executed = [
            (a.clone(), [0].into()),
            (b.clone(), [1].into()),
            (c.clone(), [2].into()),
            (d.clone(), [3].into()),
        ]
        .into();
        let base = "const LIMIT: u8 = 1;\nconst OTHER: u8 = 2;\n\
                    pub fn uses_limit() -> u8 { LIMIT }\n\
                    pub fn uses_format() -> String { format!(\"{OTHER}\") }\n\
                    pub fn plain() -> u8 { 3 }\n\
                    pub const fn seed() -> u8 { 11 }\nconst CHAIN: u8 = seed();\n\
                    pub fn uses_chain() -> u8 { CHAIN }\n";
        let digests = |source: &str| {
            let rendered = render(source, &[], &BTreeSet::new(), Some(0));
            let mut items: std::collections::BTreeMap<String, BTreeSet<String>> =
                std::collections::BTreeMap::new();
            for (name, digest) in &rendered.items {
                items
                    .entry(name.clone())
                    .or_default()
                    .insert(digest.clone());
            }
            let mut mentions: std::collections::BTreeMap<String, BTreeSet<String>> =
                std::collections::BTreeMap::new();
            for (name, mentioned) in &rendered.mentions {
                mentions
                    .entry(name.clone())
                    .or_default()
                    .extend(mentioned.iter().cloned());
            }
            let depends = Depends {
                names: &rendered.names,
                items: &items,
                mentions: &mentions,
                ..depends(&rendered.probes)
            };
            case_digests(&root, &cases, &dirs, &executed, &depends)
        };
        let held = digests(base);
        let added = digests(&format!(
            "{base}pub fn added() -> u8 {{ 4 }}\nconst NEW: u8 = 5;\n"
        ));
        assert_eq!(added, held, "an added function and const move no case");
        let limit = digests(&base.replace("LIMIT: u8 = 1", "LIMIT: u8 = 9"));
        assert_ne!(limit[&a], held[&a], "a names LIMIT");
        assert_eq!(
            (limit[&b].clone(), limit[&c].clone()),
            (held[&b].clone(), held[&c].clone())
        );
        let other = digests(&base.replace("OTHER: u8 = 2", "OTHER: u8 = 9"));
        assert_ne!(other[&b], held[&b], "b captures OTHER in a format string");
        assert_eq!(
            (other[&a].clone(), other[&c].clone()),
            (held[&a].clone(), held[&c].clone())
        );
        let seeded = digests(&base.replace("{ 11 }", "{ 12 }"));
        assert_ne!(
            seeded[&d], held[&d],
            "d names CHAIN, whose value seed() makes"
        );
        assert_eq!(
            (seeded[&a].clone(), seeded[&b].clone(), seeded[&c].clone()),
            (held[&a].clone(), held[&b].clone(), held[&c].clone())
        );
    }

    /// A traced case keys on the files it touched, an absent one and a
    /// directory's listing included, and on nothing else; an untraced case
    /// keys on every non-Rust file.
    ///
    /// Fails by: a traced case keyed on the untraced digest (an unread config
    /// edit moves it), a read path dropped (its edit reuses a stale verdict), an
    /// absent path keyed on nothing (a file appearing moves nothing), or a
    /// directory keyed on its own entry only (an added sibling moves nothing).
    #[test]
    fn a_traced_case_keys_on_what_it_touched_and_an_untraced_one_on_every_file() {
        let root = crate::scratch::scratch("schema-read-digests");
        let dirs = std::collections::BTreeMap::new();
        let none = std::collections::BTreeMap::new();
        let (traced, untraced) = (case("traced"), case("untraced"));
        let cases: BTreeSet<Case> = [traced.clone(), untraced.clone()].into();
        let read = [(
            traced.clone(),
            [
                String::from("fixture.txt"),
                String::from("missing.toml"),
                String::from("dir"),
            ]
            .into(),
        )]
        .into();
        let digests = |resources: &[(&str, &str)], all: &str| {
            let resources = resources
                .iter()
                .map(|(path, id)| ((*path).to_owned(), (*id).to_owned()))
                .collect();
            let depends = Depends {
                read: &read,
                resources: &resources,
                untraced: all,
                ..depends(&[])
            };
            case_digests(&root, &cases, &dirs, &none, &depends)
        };
        let base = [("fixture.txt", "1"), ("mutants.toml", "1"), ("dir/a", "1")];
        let held = digests(&base, "all-1");
        let config = digests(
            &[("fixture.txt", "1"), ("mutants.toml", "2"), ("dir/a", "1")],
            "all-2",
        );
        assert_eq!(
            config[&traced], held[&traced],
            "it never touched mutants.toml"
        );
        assert_ne!(
            config[&untraced], held[&untraced],
            "untraced keys on every file"
        );
        let fixture = digests(
            &[("fixture.txt", "2"), ("mutants.toml", "1"), ("dir/a", "1")],
            "all-1",
        );
        assert_ne!(fixture[&traced], held[&traced], "a file it read changed");
        let appeared = digests(
            &[("missing.toml", "1"), ("fixture.txt", "1"), ("dir/a", "1")],
            "all-1",
        );
        assert_ne!(
            appeared[&traced], held[&traced],
            "a path it probed for now exists"
        );
        let sibling = digests(
            &[("fixture.txt", "1"), ("dir/a", "1"), ("dir/b", "1")],
            "all-1",
        );
        assert_ne!(
            sibling[&traced], held[&traced],
            "a directory it read gained an entry"
        );
        let edited = digests(&[("fixture.txt", "1"), ("dir/a", "2")], "all-1");
        assert_eq!(
            edited[&traced], held[&traced],
            "a listing is names, not contents"
        );
    }

    /// The trace reader resolves each touched path against the descriptor
    /// strace printed, keeps the tree's own paths relative, and refuses a
    /// trace it cannot read whole.
    ///
    /// Fails by: a relative path kept unresolved, `target/` or a system path
    /// read as an input, a resumed line's result dropped, or a `.git` read, an
    /// unresolvable path or an undecoded escape answered as a partial set.
    #[test]
    fn a_trace_names_the_tree_paths_a_case_touched_or_nothing() {
        let tree = [std::path::PathBuf::from("/w")];
        let whole = |body: &str| {
            format!(
                "100 execve(\"/usr/bin/t\", [\"t\"], 0x7ff /* 1 vars */) = 0\n{body}\
                 101 +++ exited with 0 +++\n100 --- SIGCHLD {{si_signo=SIGCHLD}} ---\n\
                 100 +++ exited with 0 +++\n"
            )
        };
        let lines = "100 openat(AT_FDCWD</w/crates/batten>, \"tests/x.toml\", O_RDONLY) = 3</w/crates/batten/tests/x.toml>\n\
                     100 newfstatat(AT_FDCWD</w>, \"absent.toml\", 0x7ff, 0) = -1 ENOENT (No such file or directory)\n\
                     101 openat(AT_FDCWD</tmp>, \"/etc/ld.so.cache\", O_RDONLY) = 3</etc/ld.so.cache>\n\
                     101 openat(AT_FDCWD</w>, \"target/debug/x\", O_RDONLY) = 4</w/target/debug/x>\n\
                     102 <... openat resumed>) = 5</w/a/../b.txt>\n";
        assert_eq!(
            read_trace(&whole(lines), &tree),
            Some(
                ["crates/batten/tests/x.toml", "absent.toml", "b.txt"]
                    .map(String::from)
                    .into()
            )
        );
        let git = "100 openat(AT_FDCWD</w>, \".git/index\", O_RDONLY) = 3</w/.git/index>\n";
        assert_eq!(
            read_trace(&whole(git), &tree),
            None,
            "a .git read depends on every file"
        );
        let bare = "100 stat(\"relative\", 0x7ff) = 0\n";
        assert_eq!(
            read_trace(&whole(bare), &tree),
            None,
            "no directory to resolve against"
        );
        let escaped = "100 openat(AT_FDCWD</w>, \"a\\x01\", O_RDONLY) = 3</w/a>\n";
        assert_eq!(
            read_trace(&whole(escaped), &tree),
            None,
            "an escape this reader does not decode"
        );
        // A DETACHED TRACER'S PARTIAL TRACE IS NO TRACE: without the case's own
        // exit the tracer may still be writing, or never attached at all.
        let unfinished = whole(lines).replace("100 +++ exited with 0 +++\n", "");
        assert_eq!(
            read_trace(&unfinished, &tree),
            None,
            "the case's exit is missing"
        );
        let child_only = format!(
            "100 execve(\"/usr/bin/t\", [], 0x7ff) = 0\n{lines}101 +++ exited with 0 +++\n"
        );
        assert_eq!(
            read_trace(&child_only, &tree),
            None,
            "only a child's exit is no whole trace"
        );
        assert_eq!(read_trace("", &tree), None, "an empty trace says nothing");
        // strace pads a short pid to five columns.
        let padded = whole(lines)
            .lines()
            .map(|line| line.replacen(' ', "   ", 1) + "\n")
            .collect::<String>();
        assert_eq!(
            read_trace(&padded, &tree),
            read_trace(&whole(lines), &tree),
            "a padded pid column reads as the plain one"
        );
        let killed =
            whole(lines).replace("100 +++ exited with 0 +++", "100 +++ killed by SIGKILL +++");
        assert!(
            read_trace(&killed, &tree).is_some(),
            "a case killed by a signal finished"
        );
    }

    /// A handed-back mutant is judged by each case that ran its enclosing
    /// function or names its function through a chain of items; with neither
    /// to go on, by every case.
    ///
    /// Fails by: a const fn's caller through a const missed (its mutant judged
    /// by no case and read uncovered), an unrelated case selected, or a mutant
    /// with nothing to go on narrowed to nothing.
    #[test]
    fn a_handed_back_mutant_is_judged_by_the_cases_that_can_observe_it() {
        assert_eq!(function_ident("Foo::bar").as_deref(), Some("bar"));
        assert_eq!(
            function_ident("<impl Display for Foo>::fmt").as_deref(),
            Some("fmt")
        );
        assert_eq!(function_ident("two").as_deref(), Some("two"));
        let mentions: std::collections::BTreeMap<String, BTreeSet<String>> = [
            (
                String::from("CHAIN"),
                BTreeSet::from([String::from("seed")]),
            ),
            (String::from("OTHER"), BTreeSet::from([String::from("u8")])),
        ]
        .into();
        assert_eq!(
            mentioners("seed", &mentions),
            BTreeSet::from([String::from("seed"), String::from("CHAIN")])
        );
        let schema = Schema {
            probes: vec![
                String::from("f-uses-chain"),
                String::from("f-plain"),
                String::from("f-body"),
            ],
            names: vec![
                BTreeSet::from([String::from("CHAIN")]),
                BTreeSet::from([String::from("u8")]),
                BTreeSet::new(),
            ],
            mutant_fns: [(2, String::from("f-body"))].into(),
            mentions,
            ..Schema::default()
        };
        let (chain, plain, body) = (case("chain"), case("plain"), case("body"));
        let reach = Reach {
            executed: [
                (chain.clone(), BTreeSet::from([0])),
                (plain.clone(), BTreeSet::from([1])),
                (body.clone(), BTreeSet::from([2])),
            ]
            .into(),
            ..Reach::default()
        };
        let named = |function: Option<&str>| {
            let mut mutant = listed("FnValue", "0", (1, 1), (1, 2));
            mutant.function = function.map(|name| Function {
                function_name: name.to_owned(),
                return_type: String::new(),
                span: Some(mutant.span),
            });
            mutant
        };
        assert_eq!(
            handback_cases(0, &named(Some("seed")), &schema, &reach),
            Some(BTreeSet::from([chain.clone()])),
            "the case naming CHAIN observes seed"
        );
        assert_eq!(
            handback_cases(2, &named(None), &schema, &reach),
            Some(BTreeSet::from([body])),
            "the case that ran its enclosing function"
        );
        assert_eq!(
            handback_cases(1, &named(None), &schema, &reach),
            None,
            "nothing to go on"
        );
    }

    /// A handed-back verdict is a kill only where cargo-mutants' `caught.txt`
    /// names the mutant; unviable wins; a survivor no case observed is
    /// uncovered; anything else is an error, never a kill.
    ///
    /// Fails by: an `--re` that matched nothing read as a kill (exit 0 with no
    /// outcome line), an unviable mutant read as caught, or an unobserved
    /// survivor read as missed.
    #[test]
    fn a_handed_back_verdict_is_read_from_the_outcome_files() {
        let output = crate::scratch::scratch("schema-handback-verdict");
        let outcomes = output.join("mutants.out");
        std::fs::create_dir_all(&outcomes).unwrap();
        std::fs::write(outcomes.join("caught.txt"), "src/lib.rs:2:7: kill\n").unwrap();
        std::fs::write(outcomes.join("unviable.txt"), "src/lib.rs:9:1: dead\n").unwrap();
        let verdict =
            |outcome, name, unobserved| handback_verdict(outcome, &output, name, unobserved);
        assert_eq!(
            verdict(super::super::Outcome::Passed, "src/lib.rs:2:7: kill", false),
            "caught"
        );
        assert_eq!(
            verdict(
                super::super::Outcome::Passed,
                "src/lib.rs:5:1: absent",
                false
            ),
            "error"
        );
        assert_eq!(
            verdict(super::super::Outcome::Passed, "src/lib.rs:9:1: dead", false),
            "unviable"
        );
        assert_eq!(
            verdict(super::super::Outcome::Failed(Some(2)), "m", false),
            "missed"
        );
        assert_eq!(
            verdict(super::super::Outcome::Failed(Some(2)), "m", true),
            "uncovered"
        );
        assert_eq!(
            verdict(super::super::Outcome::Failed(Some(3)), "m", false),
            "timeout"
        );
        assert_eq!(
            verdict(super::super::Outcome::Failed(Some(4)), "m", false),
            "error"
        );
    }

    /// A run selects its cases' own packages; a case whose binary went
    /// unrecorded, or none recorded at all, falls back to the mutant's package.
    ///
    /// Fails by: an unrecorded binary's empty package kept as `-p ""`, or the
    /// fallback taken only when every binary went unrecorded.
    #[test]
    fn a_run_selects_its_cases_packages_or_the_mutants_when_one_is_unrecorded() {
        let mut mutant = listed("BinaryOperator", "!=", (2, 7), (2, 9));
        mutant.package = String::from("other");
        let packages = |cases: &[(&str, &str)]| {
            let cases: BTreeSet<Case> = cases
                .iter()
                .map(|(name, binary)| ((*name).to_owned(), (*binary).to_owned()))
                .collect();
            let args = nextest_args(&mutant, &cases);
            args.windows(2)
                .filter(|pair| pair[0] == "-p")
                .map(|pair| pair[1].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(packages(&[("t", "batten")]), ["batten"]);
        assert_eq!(packages(&[("t", "batten"), ("u", "")]), ["other"]);
        assert_eq!(packages(&[("u", "")]), ["other"]);
    }

    /// An error ending exactly where a probe region ends is outside it.
    ///
    /// Fails by: a region read as closed at its end, which unprobes a file
    /// for an error that is not the probe's.
    #[test]
    fn an_error_at_a_probe_regions_end_does_not_unprobe_its_file() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let rendered = render(
            source,
            &[(0, &listed("BinaryOperator", "!=", (2, 7), (2, 9)))],
            &BTreeSet::new(),
            Some(0),
        );
        let at = rendered.probe_regions[0].end;
        let schema = Schema {
            files: [(String::from("src/m.rs"), rendered)].into(),
            ..Schema::default()
        };
        let message = format!(
            "{{\"reason\":\"compiler-message\",\"message\":{{\"level\":\"error\",\"message\":\"e\",\
             \"spans\":[{{\"is_primary\":true,\"file_name\":\"src/m.rs\",\"byte_start\":{at}}}]}}}}"
        );
        assert!(unviable(&schema, &message).unprobe.is_empty());
    }

    /// A `const fn` inside a `const fn` drops its own `const`, not its
    /// container's.
    ///
    /// Fails by: an enclosing function's `const` taken for the innermost one.
    #[test]
    fn a_nested_const_fn_drops_its_own_const() {
        let source = "const fn g() -> u8 {\n    const fn f(a: u8) -> bool {\n        a == 1\n    }\n    1\n}\n";
        let rendered = render_all(source, &[listed("BinaryOperator", "!=", (3, 11), (3, 13))]);
        assert!(
            rendered.text.starts_with("const fn g()"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("\n    fn f(a: u8)"),
            "{}",
            rendered.text
        );
    }

    /// Only a seal over this very tree skips the reach run.
    ///
    /// Fails by: a seal over another tree honoured.
    #[test]
    fn only_a_seal_over_this_tree_skips_reach() {
        let base = crate::scratch::scratch("schema-reach-sealed");
        assert!(!sealed_over(&base, "t1"), "no seal yet");
        std::fs::write(base.join(SEALED), "t1").unwrap();
        assert!(sealed_over(&base, "t1"));
        assert!(!sealed_over(&base, "t2"), "a seal over another tree");
    }

    /// The resource digest moves with a non-Rust file a run may read, and not
    /// with a Rust source, which the probes already key.
    ///
    /// Fails by: a constant digest, which reuses a verdict over a changed
    /// fixture.
    #[test]
    fn the_resource_digest_moves_with_a_fixture_and_not_a_source() {
        let base = crate::scratch::scratch("schema-resource-digest");
        crate::gitwrite::init_on_main(&base).unwrap();
        std::fs::write(base.join("notes.md"), "one\n").unwrap();
        std::fs::write(base.join("lib.rs"), "fn f() {}\n").unwrap();
        let paths = [String::from("notes.md"), String::from("lib.rs")];
        crate::gitwrite::commit_paths(&base, &paths, "base").unwrap();
        let held = resource_digest(&base).unwrap();
        std::fs::write(base.join("notes.md"), "two\n").unwrap();
        let moved = resource_digest(&base).unwrap();
        assert_ne!(moved, held, "a fixture changed");
        std::fs::write(base.join("lib.rs"), "fn g() {}\n").unwrap();
        assert_eq!(
            resource_digest(&base).unwrap(),
            moved,
            "a source is the probes'"
        );
    }

    /// A run is bounded by five times its cases' measured time, never under
    /// the floor, plus its startup; an unmeasured case counts its default.
    ///
    /// Fails by: the multiplier, the floor or the startup dropped, or an
    /// unmeasured case counted as free.
    #[test]
    fn a_run_is_bounded_by_its_own_cases_time() {
        let (quick, slow) = (case("quick"), case("slow"));
        let seconds = [(quick.clone(), 0.5), (slow.clone(), 10.0)].into();
        let bound = |cases: &[&Case]| {
            case_bound(&cases.iter().map(|c| (*c).clone()).collect(), &seconds).as_secs_f64()
        };
        assert!((bound(&[&quick]) - 50.0).abs() < 1e-9, "the floor");
        assert!((bound(&[&quick, &slow]) - 82.5).abs() < 1e-9, "5x 10.5 s");
        let unmeasured = case("unmeasured");
        let many: Vec<Case> = (0..5).map(|n| case(&format!("u{n}"))).collect();
        let refs: Vec<&Case> = many.iter().chain([&unmeasured]).collect();
        assert!((bound(&refs) - 60.0).abs() < 1e-9, "six at 1 s each");
    }

    /// An error on a probe unprobes its file, even inside a mutant's branch.
    #[test]
    fn an_error_on_a_probe_unprobes_its_file() {
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        let rendered = render(
            source,
            &[(0, &listed("BinaryOperator", "!=", (2, 7), (2, 9)))],
            &BTreeSet::new(),
            Some(0),
        );
        let at = rendered.probe_regions[0].start + 2;
        let schema = Schema {
            files: [(String::from("src/m.rs"), rendered)].into(),
            ..Schema::default()
        };
        let message = format!(
            "{{\"reason\":\"compiler-message\",\"message\":{{\"level\":\"error\",\"message\":\"e\",\
             \"spans\":[{{\"is_primary\":true,\"file_name\":\"src/m.rs\",\"byte_start\":{at}}}]}}}}"
        );
        let refused = unviable(&schema, &message);
        assert_eq!(refused.unprobe, [String::from("src/m.rs")].into());
        assert!(refused.owned.is_empty() && refused.stray.is_empty());
    }

    #[test]
    fn only_a_stored_unviable_verdict_skips_a_build() {
        let keys = [Some("k1"), None, Some("k2"), Some("k3")].map(|k| k.map(String::from));
        let cache = [
            (String::from("k1"), String::from("unviable")),
            (String::from("k2"), String::from("caught")),
        ]
        .into();
        assert_eq!(cached_unviable(&keys, &cache), [0].into());
    }

    /// The report names every verdict but a kill, counts each, and exits 2 on
    /// a survivor and 0 when every mutant was caught.
    #[test]
    fn a_report_names_each_survivor_and_counts_every_verdict() {
        let state = crate::scratch::scratch("schema-report");
        let mutants: Vec<Listed> = ["m0", "m1", "m2"]
            .map(|name| {
                let mut mutant = listed("FnValue", "true", (1, 1), (1, 2));
                mutant.name = String::from(name);
                mutant
            })
            .into();
        let mut out = Vec::new();
        let verdicts = [
            (0, Verdict::Caught),
            (1, Verdict::Missed),
            (2, Verdict::Uncovered),
        ];
        let code = report(&mut out, &mutants, &verdicts, (4, 5), &state, 7).unwrap();
        let said = String::from_utf8(out).unwrap();
        assert_eq!(code, 2);
        assert!(
            said.contains("missed\tm1\n") && said.contains("uncovered\tm2\n"),
            "{said}"
        );
        assert!(!said.contains("\tm0"), "{said}");
        assert!(
            said.contains(
                "{\"caught\": 1, \"missed\": 1, \"uncovered\": 1}, 4 unviable, 5 classic, in 7s"
            ),
            "{said}"
        );
        let mut out = Vec::new();
        let code = report(&mut out, &mutants, &verdicts[..1], (0, 0), &state, 7).unwrap();
        assert_eq!(code, 0);
    }

    /// Each case's own recorded outcome against a mutant decides it or narrows
    /// its run: a recorded kill is a kill with no run, every case recorded
    /// passing is a survivor with no run, and a case recorded passing is left
    /// out of the run the rest still owe.
    ///
    /// Fails by: a recorded kill run again, a mutant whose every case passed
    /// run again, or a recorded pass not narrowing the run.
    #[test]
    fn a_recorded_outcome_per_case_decides_or_narrows_a_mutant() {
        /// An id no other case's run uses, so its kept log is this case's.
        const ERRING: u32 = 90_017;
        let base = crate::scratch::scratch("schema-judge-pairs");
        std::fs::create_dir_all(base.join("src")).unwrap();
        std::fs::write(
            base.join("src/lib.rs"),
            "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n",
        )
        .unwrap();
        let mutant = in_function(
            listed("BinaryOperator", "!=", (2, 7), (2, 9)),
            (1, 1),
            (3, 2),
        );
        let a: Case = (String::from("a"), String::from("batten"));
        let b: Case = (String::from("b"), String::from("batten"));
        let cases: BTreeSet<Case> = [a.clone(), b.clone()].into();
        let digests = std::collections::BTreeMap::new();
        let pair = |case: &Case| pair_key(&base, &mutant, case, &digests).unwrap();
        let mutants = [mutant.clone()];
        let judged = |cache: std::collections::BTreeMap<String, String>| {
            let (reach, seconds) = Default::default();
            let store = base.join("verdicts");
            let judging = Judging {
                work: &base,
                target: &base,
                scratch: &base,
                root: &base,
                mutants: &mutants,
                reach: &reach,
                seconds: &seconds,
                cache: &cache,
                digests: &digests,
                store: &store,
            };
            let hints = std::sync::Mutex::new(std::collections::BTreeMap::new());
            let journal = std::sync::Mutex::new(None);
            judge(&judging, ERRING, &mutant, &cases, &hints, &journal)
        };
        let caught = String::from("caught");
        let passed = String::from(PASSED);
        assert_eq!(
            judged([(pair(&b), caught)].into()),
            (Verdict::Caught, 2),
            "a recorded kill decides it"
        );
        assert_eq!(
            judged([(pair(&a), passed.clone()), (pair(&b), passed.clone())].into()),
            (Verdict::Missed, 2),
            "every case recorded passing"
        );
        let (verdict, skipped) = judged([(pair(&a), passed)].into());
        assert_eq!(skipped, 1, "the recorded pass is left out of the run");
        assert!(
            !matches!(verdict, Verdict::Caught | Verdict::Missed),
            "the open case was run, and here no run can start: {verdict:?}"
        );
        // Fails by: an erring run's words dropped rather than kept.
        let kept = base
            .parent()
            .unwrap()
            .join("errors")
            .join(format!("{ERRING}.log"));
        assert!(kept.is_file(), "{} is kept", kept.display());
        assert_eq!(journaled_kill(Verdict::Caught, Some(&a)), Some(&a));
        assert_eq!(journaled_kill(Verdict::Timeout, Some(&a)), None);
        assert_ne!(pair(&a), pair(&b), "each case is its own pair");
    }

    /// Each way a judging run can end, judged from its process outcome and its
    /// report alone.
    ///
    /// Fails by: a caught mutant filed a timeout or a miss, a timeout filed a
    /// kill, a run with no report or a report missing a case read as a miss, or
    /// a passing run's cases dropped.
    #[test]
    fn a_run_is_judged_from_its_report_and_its_exit() {
        use super::super::Outcome;
        let pair = |name: &str, binary: &str| (String::from(name), String::from(binary));
        let a = pair("tests::a", "batten");
        let b = pair("m::b", "batten::it");
        let cases: BTreeSet<Case> = [a.clone(), b.clone()].into();
        let caught = junit_cases(JUNIT_FIXTURE).expect("XML");
        let (verdict, killer, passed) =
            verdict_of_run(Outcome::Failed(Some(100)), Some(&caught), &cases);
        assert_eq!((verdict, killer), (Verdict::Caught, Some(b.clone())));
        assert!(passed.contains(&a) && !passed.contains(&b), "{passed:?}");
        let timed = [(a.clone(), CaseEnd::Passed), (b.clone(), CaseEnd::TimedOut)];
        assert_eq!(
            verdict_of_run(Outcome::Failed(Some(100)), Some(&timed), &cases).0,
            Verdict::Timeout
        );
        assert_eq!(
            verdict_of_run(Outcome::TimedOut, None, &cases).0,
            Verdict::Timeout
        );
        let clean = [(a.clone(), CaseEnd::Passed), (b.clone(), CaseEnd::Passed)];
        let missed = verdict_of_run(Outcome::Passed, Some(&clean), &cases);
        assert_eq!((missed.0, missed.2.len()), (Verdict::Missed, 2));
        // Could-not-look: no report, an empty one, or one missing a case.
        assert_eq!(
            verdict_of_run(Outcome::Passed, None, &cases).0,
            Verdict::Error
        );
        assert_eq!(
            verdict_of_run(Outcome::Passed, Some(&[]), &cases).0,
            Verdict::Error
        );
        assert_eq!(
            verdict_of_run(Outcome::Passed, Some(&clean[..1]), &cases).0,
            Verdict::Error
        );
        assert_eq!(
            verdict_of_run(Outcome::Failed(Some(101)), Some(&clean), &cases).0,
            Verdict::Error
        );
    }

    /// A stored verdict, a kept survivor's too, is reused without a run and without a second
    /// journal line, a mutant nothing reaches is uncovered and journaled, and
    /// progress is printed every hundred verdicts and at the end.
    ///
    /// Fails by: a reused verdict re-judged (no case reaches it, so it would
    /// read uncovered), or progress printed on the wrong count.
    #[test]
    fn stored_kills_are_reused_and_progress_is_counted_by_hundreds() {
        let base = crate::scratch::scratch("schema-judge-all");
        let source = "fn f(a: u8, b: u8) -> bool {\n    a == b\n}\n";
        std::fs::create_dir_all(base.join("src")).unwrap();
        std::fs::write(base.join("src/lib.rs"), source).unwrap();
        let with = |replacement: &str, name: &str| {
            let mut mutant = in_function(
                listed("BinaryOperator", replacement, (2, 7), (2, 9)),
                (1, 1),
                (3, 2),
            );
            mutant.name = String::from(name);
            mutant
        };
        let mut mutants: Vec<Listed> = (0..101).map(|_| with("!=", "kill")).collect();
        mutants.push(with("<", "hang"));
        mutants.push(with("<=", "none"));
        mutants.push(with(">", "kept-survivor"));
        mutants.push(with(">=", "kept-unreached"));
        let digests = std::collections::BTreeMap::new();
        let nobody = BTreeSet::new();
        let key = |m: &Listed| verdict_key(&base, m, &nobody, &digests).unwrap();
        let cache = [
            (key(&mutants[0]), String::from("caught")),
            (key(&mutants[101]), String::from("timeout")),
            (key(&mutants[103]), String::from("missed")),
            (key(&mutants[104]), String::from("uncovered")),
        ]
        .into();
        let store = base.join("verdicts");
        let reach = std::collections::BTreeMap::new();
        let seconds = std::collections::BTreeMap::new();
        let judging = Judging {
            work: &base,
            target: &base,
            scratch: &base,
            root: &base,
            mutants: &mutants,
            reach: &reach,
            seconds: &seconds,
            cache: &cache,
            digests: &digests,
            store: &store,
        };
        let todo: Vec<u32> = (0..105).collect();
        let mut out = Vec::new();
        let mut verdicts = judge_all(&judging, &todo, 2, &mut out);
        verdicts.sort_by_key(|(id, _)| *id);
        assert!(verdicts[..101].iter().all(|(_, v)| *v == Verdict::Caught));
        assert_eq!(verdicts[101].1, Verdict::Timeout);
        assert_eq!(verdicts[102].1, Verdict::Uncovered);
        assert_eq!(
            verdicts[103].1,
            Verdict::Missed,
            "a kept survivor, not re-judged"
        );
        assert_eq!(verdicts[104].1, Verdict::Uncovered);
        let said = String::from_utf8(out).unwrap();
        let progress: Vec<&str> = said
            .lines()
            .filter(|line| line.starts_with("mutate schema: judged"))
            .map(|line| line.split(" in ").next().unwrap_or_default())
            .collect();
        assert!(
            said.contains("mutate schema: reused 104 of 105 verdict(s)"),
            "{said}"
        );
        assert_eq!(
            progress,
            [
                "mutate schema: judged 100/105",
                "mutate schema: judged 105/105"
            ]
        );
        let journaled = std::fs::read_to_string(&store).unwrap();
        assert_eq!(
            journaled,
            journal_line(Some(&key(&mutants[102])), "uncovered", "none")
        );
    }

    /// Fails by: a mutant credited to an enclosing function rather than the
    /// innermost (a smaller span read as the larger), one on a function's own
    /// bounds dropped, or one past a function's end credited to it.
    #[test]
    fn a_mutant_belongs_to_its_innermost_enclosing_function() {
        let functions = [
            (0..100, String::from("outer")),
            (40..90, String::from("inner")),
        ];
        let placed = [
            (1, 50..60),
            (2, 10..20),
            (3, 95..105),
            (4, 40..90),
            (5, 200..210),
        ];
        assert_eq!(
            innermost(&placed, &functions),
            vec![
                (1, String::from("inner")),
                (2, String::from("outer")),
                (4, String::from("inner")),
            ]
        );
    }

    /// The items of `source`, parsed.
    fn items_of(source: &str) -> Vec<ast::Item> {
        use ast::HasModuleItem as _;
        SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024)
            .tree()
            .items()
            .collect()
    }

    /// The first token of `source` whose text is `text`.
    fn token_of(source: &str, text: &str) -> ra_ap_syntax::SyntaxToken {
        SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024)
            .tree()
            .syntax()
            .descendants_with_tokens()
            .filter_map(ra_ap_syntax::NodeOrToken::into_token)
            .find(|token| token.text() == text)
            .expect("the token is in the source")
    }

    /// Fails by: a named item answering to every word inside it (a struct to
    /// its field types, a module to its functions), which reruns every case
    /// naming any of them.
    #[test]
    fn a_named_item_answers_to_its_own_name_alone() {
        let source = "struct S { f: u8 }\ntrait T { fn m(); }\n\
            macro_rules! mac { () => { other }; }\nmod md { fn inner() {} }\n";
        let names: Vec<Vec<String>> = items_of(source).iter().map(item_names).collect();
        assert_eq!(
            names,
            [["S"], ["T"], ["mac"], ["md"]].map(|n| vec![n[0].to_owned()])
        );
    }

    /// Fails by: an item-position macro skipped as if it were a call in an
    /// expression, which leaves what it binds owned by nothing.
    #[test]
    fn an_item_position_macro_owns_its_own_tokens() {
        let source = "thread_local! { static X: u8 = 1; }\nconst C: u8 = m!(2);\n";
        let item = owning_item(&token_of(source, "X")).expect("owned");
        assert!(matches!(item, ast::Item::MacroCall(_)), "{item:?}");
        let item = owning_item(&token_of(source, "2")).expect("owned");
        assert!(matches!(item, ast::Item::Const(_)), "{item:?}");
    }

    /// Fails by: a gate credited to a function whose span ends where it
    /// starts, or to an enclosing function rather than the innermost.
    #[test]
    fn a_gate_belongs_to_the_innermost_span_holding_its_start() {
        let source = "fn a() { let value = 1; }\n";
        let token = token_of(source, "value");
        let at = usize::from(token.text_range().start());
        assert!(at > 10, "the fixture places the token past a sum's tie");
        let inner = (7, at..at + 50);
        let outer = (8, 0..at + 60);
        assert!(matches!(
            owner_of(&token, &[outer.clone(), inner]),
            Owner::Probe(7)
        ));
        assert!(matches!(owner_of(&token, &[outer]), Owner::Probe(8)));
        assert!(matches!(
            owner_of(&token, &[(9, 0..at)]),
            Owner::Names(names) if names == [String::from("a")]
        ));
    }

    /// Fails by: a gate on anything but a feature read as one.
    #[test]
    fn only_a_feature_gate_names_a_feature() {
        let gated = "#[cfg(feature = \"x\")]\nfn a() {}\n";
        assert!(names_a_feature(&token_of(gated, "cfg")));
        let plain = "#[cfg(test)]\nfn b() {}\n";
        assert!(!names_a_feature(&token_of(plain, "cfg")));
    }

    /// Fails by: an edit to an unprobed file leaving its key standing (the
    /// build asked again never), or two files sharing one.
    #[test]
    fn an_unprobed_files_key_is_its_path_and_bytes() {
        let root = crate::scratch::scratch("schema-unprobe-key");
        std::fs::write(root.join("a.rs"), "one").unwrap();
        std::fs::write(root.join("b.rs"), "one").unwrap();
        let held = unprobe_key(&root, "a.rs");
        assert!(held.starts_with("unprobe-"), "{held}");
        assert_eq!(held, unprobe_key(&root, "a.rs"));
        assert_ne!(held, unprobe_key(&root, "b.rs"));
        std::fs::write(root.join("a.rs"), "two").unwrap();
        assert_ne!(held, unprobe_key(&root, "a.rs"));
    }

    /// Fails by: two formats naming one key, or a key that is not a digest.
    #[test]
    fn a_formats_key_is_a_digest_of_all_of_it() {
        let plain = Format::default().key();
        assert_eq!(plain.len(), 16);
        assert!(plain.chars().all(|c| c.is_ascii_hexdigit()), "{plain}");
        let featured = Format {
            features: vec![String::from("x")],
            ..Format::default()
        };
        assert_ne!(plain, featured.key());
    }

    /// Fails by: a profile override or a compiler flag left out of the build
    /// key, or a variable that runs no other code moving it.
    #[test]
    fn the_build_flags_are_the_code_generation_variables() {
        let vars = [
            ("RUSTFLAGS", "-Cx"),
            ("CARGO_PROFILE_TEST_OPT_LEVEL", "1"),
            ("CARGO_HOME", "/h"),
            ("PATH", "/bin"),
        ]
        .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        let kept: Vec<String> = build_flags_in(vars.into_iter()).into_keys().collect();
        assert_eq!(kept, ["CARGO_PROFILE_TEST_OPT_LEVEL", "RUSTFLAGS"]);
    }

    /// Fails by: a run that left nothing to seal saying it sealed some.
    #[test]
    fn a_run_that_left_nothing_says_nothing() {
        let state = crate::scratch::scratch("schema-leftovers-none");
        let mut out = Vec::new();
        keep_leftovers(&state, &mut out).unwrap();
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    }

    /// Fails by: a package's non-Rust file read as one of its sources.
    #[test]
    fn a_packages_sources_are_its_rust_files() {
        let root = crate::scratch::scratch("schema-package-sources");
        std::fs::create_dir_all(root.join("crates/p/src")).unwrap();
        for file in [
            "crates/p/src/lib.rs",
            "crates/p/src/more.rs",
            "crates/p/src/notes.txt",
        ] {
            std::fs::write(root.join(file), "").unwrap();
        }
        let mut mutant = listed("binary", "x", (1, 1), (1, 2));
        mutant.file = String::from("crates/p/src/lib.rs");
        let sources = package_sources(&root, &[mutant]);
        assert_eq!(
            sources,
            [
                String::from("crates/p/src/lib.rs"),
                String::from("crates/p/src/more.rs")
            ]
            .into()
        );
    }

    /// Fails by: a fixture scratch that cannot be cleared passed over (a run
    /// carrying the last one's fixtures), or a stale top-level entry of the
    /// work tree kept because it sits at the top.
    #[test]
    fn a_sync_clears_what_the_checkout_lacks_and_reports_what_it_cannot() {
        let base = crate::scratch::scratch("schema-sync-clear");
        let (root, work) = (base.join("root"), base.join("work"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "one").unwrap();
        std::fs::create_dir_all(work.join("target")).unwrap();
        std::fs::write(work.join("stale.txt"), "gone").unwrap();
        sync(&root, &work, &BTreeSet::new()).unwrap();
        assert!(
            !work.join("stale.txt").exists(),
            "a stale top-level file goes"
        );
        std::fs::write(work.join("target").join("tmp"), "a file, not a dir").unwrap();
        assert!(
            sync(&root, &work, &BTreeSet::new()).is_err(),
            "a scratch that cannot be cleared is an error"
        );
    }

    /// Fails by: a gate in a file after the first credited to another probe,
    /// because the second file's ids were placed off its own offset.
    #[test]
    fn a_gate_in_a_later_file_is_credited_to_its_own_function() {
        let (root, mut format) = selection_tree(
            "schema-gate-later-file",
            SELECTED,
            "pub fn a() {}\npub fn b() {\n    #[cfg(feature = \"x\")]\n    let _ = 0;\n}\n",
        );
        format.probed.insert(String::from("src/more.rs"));
        let index = dependency_index(&root, &format).unwrap();
        assert_eq!(
            index.gated_probes, index.own_names["b"],
            "the gate is b's, and only b's"
        );
        assert!(index.gated_probes.is_disjoint(&index.own_names["a"]));
    }

    /// Fails by: the handbacks' unviable mutants left out of the reported
    /// count, or subtracted from it.
    #[test]
    fn the_unviable_count_is_both_builds() {
        assert_eq!(unviable_total(3, 2), 5);
    }

    /// Fails by: the reach suite built for no package, under another profile,
    /// or reading its records in a format that names none of the schema's
    /// probed files.
    #[test]
    fn a_sweeps_format_names_its_packages_and_probed_files() {
        let live = crate::scratch::scratch("schema-sweep-format");
        let mut mutant = listed("binary", "x", (1, 1), (1, 2));
        mutant.file = String::from("crates/p/src/lib.rs");
        let schema = Schema {
            probed: [String::from("crates/p/src/lib.rs")].into(),
            ..Schema::default()
        };
        let format = sweep_format(&live, &[mutant], &schema, [String::from("u.rs")].into());
        assert_eq!(
            format.cargo_args,
            ["--cargo-profile", "test", "-p", "p"].map(String::from)
        );
        assert_eq!(
            format.dirs,
            [(String::from("p"), String::from("crates/p"))].into()
        );
        assert_eq!(format.probed, schema.probed);
        assert_eq!(format.unprobed, [String::from("u.rs")].into());
        assert_eq!(format.flags, build_flags());
    }
}

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
let file = std::fs::OpenOptions::new().create(true).append(true)\
.open(std::path::Path::new(&dir).join(std::process::id().to_string())).ok()?;\n        \
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
    let mut sites: Vec<Site> = Vec::new();
    let mut erased: std::collections::BTreeMap<(usize, usize), (String, Vec<u32>)> =
        std::collections::BTreeMap::new();
    for (id, mutant) in mutants {
        if skip.contains(id) {
            continue;
        }
        let Some((range, wrap, erase)) = place(&root, source, *id, mutant) else {
            classic.push(*id);
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
        match sites.iter_mut().find(|site| site.range == range) {
            Some(site) => merge(&mut site.wraps, wrap),
            None => sites.push(Site {
                range,
                wraps: vec![wrap],
                children: Vec::new(),
            }),
        }
    }
    let (probes, skeleton) = probe_sites(&root, probe_from, &mut sites);
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
        probes,
        probe_regions: writer.probe_regions,
        skeleton,
    }
}

/// A probe site in every function body that runs at run time, ids counted
/// from `probe_from` (none when it is `None`), each with its function's
/// source digest; and the skeleton digest (see [`Rendered::skeleton`]).
///
/// THE FUNCTION IS THE UNIT (RTS++, Fu et al. 2019; RustyRTS, Hundsdorfer et
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
fn probe_sites(
    root: &SyntaxNode,
    probe_from: Option<usize>,
    sites: &mut Vec<Site>,
) -> (Vec<String>, String) {
    let mut probes = Vec::new();
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
            probes.push(
                blake3::hash(function.syntax().to_string().as_bytes())
                    .to_hex()
                    .to_string(),
            );
            let item = function.syntax().text_range();
            cuts.push(usize::from(item.start())..usize::from(item.end()));
            next += 1;
        }
    }
    cuts.sort_by_key(|cut| cut.start);
    let mut skeleton = blake3::Hasher::new();
    let mut cut = cuts.iter().peekable();
    for token in root
        .descendants_with_tokens()
        .filter_map(|e| e.into_token())
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
    }
    (probes, skeleton.finalize().to_hex().to_string())
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
///
/// # Errors
///
/// A directory cannot be read or a file cannot be written.
pub fn sync(root: &std::path::Path, work: &std::path::Path) -> anyhow::Result<()> {
    sync_dir(root, work, true)
}

fn sync_dir(from: &std::path::Path, to: &std::path::Path, top: bool) -> anyhow::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if top && name == "target" {
            continue;
        }
        let source = entry.path();
        let dest = to.join(&name);
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_dir(&source, &dest, false)?;
        } else if kind.is_symlink() {
            let link = std::fs::read_link(&source)?;
            if std::fs::read_link(&dest).ok() != Some(link.clone()) {
                let _ = std::fs::remove_file(&dest);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&link, &dest)?;
            }
        } else if crate::fsio::read(&dest).ok() != crate::fsio::read(&source).ok() {
            std::fs::copy(&source, &dest)?;
        }
    }
    Ok(())
}

/// Write `text` to `path` only if it differs, keeping an unchanged file's time.
fn write_if_changed(path: &std::path::Path, text: &str) -> anyhow::Result<()> {
    if crate::fsio::read_to_string(path).ok().as_deref() != Some(text) {
        std::fs::write(path, text)?;
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
        schema.probes.extend(rendered.probes.iter().cloned());
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
    known_unviable: BTreeSet<u32>,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Built> {
    let packages: BTreeSet<&str> = mutants.iter().map(|m| m.package.as_str()).collect();
    let mut args: Vec<String> = [
        "test",
        "--no-run",
        "--profile",
        "mutants",
        "--message-format",
        "json",
    ]
    .map(String::from)
    .to_vec();
    for package in &packages {
        args.extend([String::from("-p"), (*package).to_owned()]);
    }
    let env = [(
        String::from("CARGO_TARGET_DIR"),
        target.to_string_lossy().into_owned(),
    )];
    let mut skip = known_unviable;
    let mut handed = BTreeSet::new();
    let mut unprobed = BTreeSet::new();
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
        unprobed.extend(refused.unprobe);
        skip.extend(refused.owned);
        // HANDED BACK, NOT UNVIABLE: the mutants compile, only not switched,
        // and with every one of them skipped the function keeps its `const`.
        skip.extend(refused.reconst.iter().copied());
        handed.extend(refused.reconst);
    }
    anyhow::bail!("the schema build was not clean within 12 rounds")
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

/// Each case's measured seconds, from a nextest `JUnit` report: the `name`,
/// `classname` (the binary) and `time` of every `<testcase>`.
fn durations(junit: &str) -> std::collections::BTreeMap<Case, f64> {
    let mut timed = std::collections::BTreeMap::new();
    for element in junit.split("<testcase ").skip(1) {
        let head = format!(" {}", element.split('>').next().unwrap_or_default());
        let (Some(name), Some(binary), Some(time)) = (
            attribute(&head, "name"),
            attribute(&head, "classname"),
            attribute(&head, "time"),
        ) else {
            continue;
        };
        if let Ok(time) = time.parse::<f64>() {
            timed.insert((name, binary), time);
        }
    }
    timed
}

/// One XML attribute's unescaped value from an element's head.
fn attribute(head: &str, key: &str) -> Option<String> {
    let needle = format!(" {key}=\"");
    let at = head.find(&needle)? + needle.len();
    let value = &head[at..];
    let value = &value[..value.find('"')?];
    Some(
        value
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
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

/// The case a failed run names first, from nextest's `FAIL [ time] binary
/// name` line (`--color never`).
fn killer(output: &str) -> Option<Case> {
    output.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("FAIL [")?;
        let (_, rest) = rest.split_once("] ")?;
        let (binary, name) = rest.trim().split_once(' ')?;
        Some((name.trim().to_owned(), binary.to_owned()))
    })
}

/// Run `cases` once with mutant `id` switched on, and answer its verdict and
/// the case that killed it. `cases` must not be empty.
///
/// # Errors
///
/// The run could not be started.
fn run_cases(
    judging: &Judging<'_>,
    id: u32,
    mutant: &Listed,
    cases: &BTreeSet<Case>,
) -> anyhow::Result<(Verdict, Option<Case>)> {
    let tests: BTreeSet<&str> = cases.iter().map(|(name, _)| name.as_str()).collect();
    let binaries: BTreeSet<&str> = cases.iter().map(|(_, binary)| binary.as_str()).collect();
    let mut args: Vec<String> = [
        "nextest",
        "run",
        "--cargo-profile",
        "mutants",
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
    let own = judging.scratch.join(id.to_string());
    let _ = std::fs::create_dir_all(own.join("tmp"));
    let _ = std::fs::create_dir_all(own.join("fixtures"));
    let env = [
        (
            String::from("CARGO_TARGET_DIR"),
            judging.target.to_string_lossy().into_owned(),
        ),
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
    ];
    let ran = super::spawn(
        judging.work,
        super::Program::Cargo,
        &args,
        &env,
        super::runner_bound(),
    );
    // THE RUN'S OWN SCRATCH GOES WITH IT: nothing else ever reads it.
    let _ = std::fs::remove_dir_all(&own);
    let ran = ran?;
    Ok(match ran.outcome {
        super::Outcome::Passed => (Verdict::Missed, None),
        super::Outcome::TimedOut => (Verdict::Timeout, None),
        super::Outcome::Failed(_) if ran.output.contains("TIMEOUT") => (Verdict::Timeout, None),
        super::Outcome::Failed(Some(100)) => (Verdict::Caught, killer(&ran.output)),
        super::Outcome::Failed(_) => {
            // THE RUN'S OWN WORDS, KEPT: on #1276 2,213 runs failed before a
            // case started and said nothing anywhere, so an error now leaves
            // its output beside the tree, where the summary points.
            keep_error(judging, id, &ran.output);
            (Verdict::Error, None)
        }
    })
}

/// Keep what an erring run of mutant `id` said under the sweep's `errors/`,
/// where the summary points.
fn keep_error(judging: &Judging<'_>, id: u32, said: &str) {
    if let Some(state) = judging.work.parent() {
        let errors = state.join("errors");
        let _ = std::fs::create_dir_all(&errors);
        let _ = std::fs::write(errors.join(format!("{id}.log")), said);
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
) -> Verdict {
    if cases.is_empty() {
        return Verdict::Uncovered;
    }
    let sibling: Option<Sibling> = mutant.function.as_ref().map(|function| {
        (
            mutant.file.clone(),
            function.function_name.clone(),
            function.span.as_ref().map(|span| span.start.line),
        )
    });
    let hinted = sibling
        .as_ref()
        .and_then(|key| hints.lock().ok()?.get(key).cloned())
        .unwrap_or_default();
    let (first, second) = phases(cases, &hinted, judging.seconds);
    for phase in batches(&first).iter().chain(&batches(&second)) {
        match run_cases(judging, id, mutant, phase) {
            Ok((Verdict::Missed, _)) => {}
            Ok((verdict, killed_by)) => {
                if let (Some(key), Some(case)) = (sibling, killed_by)
                    && let Ok(mut hints) = hints.lock()
                {
                    hints.entry(key).or_default().insert(case);
                }
                return verdict;
            }
            Err(why) => {
                // A RUN THAT COULD NOT START SAYS WHY, beside the runs that
                // failed: on #1276 six such errors left no log at all.
                keep_error(judging, id, &format!("{why:#}\n"));
                return Verdict::Error;
            }
        }
    }
    Verdict::Missed
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
    std::fs::write(dir.join("case"), format!("{name}\t{binary}"))?;
    let cwd = std::env::current_dir()?;
    let ran = super::spawn_as(
        &cwd,
        super::Program::Test(program),
        rest,
        &[(String::from(RECORD), dir.to_string_lossy().into_owned())],
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    let code = match ran.outcome {
        super::Outcome::Passed => 0,
        super::Outcome::Failed(Some(code)) => u8::try_from(code).unwrap_or(101),
        super::Outcome::Failed(None) | super::Outcome::TimedOut => 101,
    };
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

/// Keep `base` when it is being recorded over the tree `inputs` names, else
/// clear it for that tree; how many cases it already holds recorded.
///
/// # Errors
///
/// The directory cannot be cleared or written.
fn resume_reach(base: &std::path::Path, inputs: &str) -> anyhow::Result<usize> {
    if crate::fsio::read_to_string(base.join(TREE)).is_ok_and(|held| held == inputs) {
        return Ok(std::fs::read_dir(base)?
            .filter_map(Result::ok)
            .filter(|entry| finished_passing(&entry.path()))
            .count());
    }
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base)?;
    crate::durable::replace(base.join(TREE), inputs)?;
    Ok(0)
}

/// What the reach run recorded: per mutant site, the cases that reached it;
/// per case, the probed functions it executed.
#[derive(Debug, Default)]
pub struct Reach {
    /// Each site's reaching cases, by mutant id.
    pub sites: std::collections::BTreeMap<u32, BTreeSet<Case>>,
    /// Each case's executed functions, by probe id.
    pub executed: std::collections::BTreeMap<Case, BTreeSet<usize>>,
}

/// Every mutant site each case reached and every function it executed, from
/// every process of each case.
///
/// # Errors
///
/// The reach directory cannot be read.
pub fn collect_reach(base: &std::path::Path) -> anyhow::Result<Reach> {
    let mut reach = Reach::default();
    for case in std::fs::read_dir(base)? {
        let dir = case?.path();
        let Ok(head) = crate::fsio::read_to_string(dir.join("case")) else {
            continue;
        };
        let (name, binary) = head.split_once('\t').unwrap_or((head.as_str(), ""));
        let case: Case = (name.to_owned(), binary.to_owned());
        for file in std::fs::read_dir(&dir)? {
            let path = file?.path();
            if path.file_name().is_some_and(|f| f == "case" || f == DONE) {
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

/// Run the whole suite once on the schema build with no mutant active,
/// recording which sites each case reaches. It is also the baseline: a case
/// that fails unmutated makes every verdict meaningless, so it refuses.
///
/// # Errors
///
/// A case failed unmutated, or the run could not be made.
pub fn record_reach(
    work: &std::path::Path,
    target: &std::path::Path,
    state: &std::path::Path,
    packages: &BTreeSet<&str>,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Reach> {
    let base = state.join("reach");
    // REACH IS A FUNCTION OF THE SCHEMA TREE, so a restart over the same tree
    // resumes from the record a finished run sealed instead of re-running the
    // suite (640 s on #1276).
    let inputs = tree_digest(work);
    let seal = base.join(SEALED);
    if crate::fsio::read_to_string(&seal).is_ok_and(|held| held == inputs) {
        return collect_reach(&base);
    }
    let resumed = resume_reach(&base, &inputs)?;
    if resumed > 0 {
        writeln!(
            out,
            "mutate schema: reach resumed with {resumed} case(s) already recorded"
        )?;
    }
    let config = state.join("nextest.toml");
    // A PRIVATE COPY of this binary is the recorder: the suite runs for minutes,
    // and the checkout's own `target/debug/batten` is relinked by any build in
    // between, so a case could run a half-linked one. Renamed into place, so a
    // running copy is never written.
    let recorder = state.join("recorder");
    let staged = state.join(format!("recorder.{}", std::process::id()));
    std::fs::copy(std::env::current_exe()?, &staged)?;
    std::fs::rename(&staged, &recorder)?;
    std::fs::write(
        &config,
        super::cover::wrapped_config(work, &recorder, RECORD_ARG, &state.join("nextest"))?,
    )?;
    let mut args: Vec<String> = [
        "nextest",
        "run",
        "--cargo-profile",
        "mutants",
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
    let env = [
        (
            String::from("CARGO_TARGET_DIR"),
            target.to_string_lossy().into_owned(),
        ),
        (String::from(REACH), base.to_string_lossy().into_owned()),
    ];
    let ran = super::spawn_as(
        work,
        super::Program::Cargo,
        &args,
        &env,
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    anyhow::ensure!(
        ran.passed(),
        "the unmutated suite failed on the schema build, so no verdict would mean anything"
    );
    // THE FINISHED SUITE'S FIXTURES GO: nothing reads them once it has exited,
    // and on #1276 they held 3.7 GB of the tree's target while the judging ran.
    let _ = std::fs::remove_dir_all(target.join("tmp"));
    let reach = collect_reach(&base)?;
    std::fs::write(&seal, inputs)?;
    Ok(reach)
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
    for path in paths.iter().filter(|path| !path.ends_with(".rs")) {
        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(&crate::fsio::read(live.join(path)).unwrap_or_default());
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
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

/// Each case's own text, digested once per sweep (read once per file): in
/// each of its own module files, the test function it names and the helper
/// functions beside it; the whole file where no such test is found; and the
/// shared fixtures (`common/mod.rs`) whole. KEYED BY THE CASE, NOT ITS FILE:
/// on #1276 a file-wide key moved every mutant a `lib.rs` case reaches on any
/// edit to `lib.rs`, so a lap re-judged nearly all of them.
///
/// THE FUNCTIONS IT EXECUTED, BY THEIR SOURCE (Ekstazi, Gligoric et al., ISSTA
/// 2015; RTS++): each probed function the reach run saw the case run, by its
/// digest, so an edit anywhere on its path moves its key; and `global`, the
/// skeleton and every resource it may read, which no probe sees.
#[must_use]
pub fn case_digests<'c>(
    root: &std::path::Path,
    cases: impl IntoIterator<Item = &'c Case>,
    package_dirs: &std::collections::BTreeMap<String, String>,
    executed: &std::collections::BTreeMap<Case, BTreeSet<usize>>,
    probes: &[String],
    global: &str,
) -> std::collections::BTreeMap<Case, String> {
    type Parsed = Option<(Vec<u8>, std::collections::BTreeMap<String, Vec<String>>)>;
    let mut parsed: std::collections::BTreeMap<String, Parsed> = std::collections::BTreeMap::new();
    let mut digests = std::collections::BTreeMap::new();
    for case in cases {
        let (name, binary) = case;
        let test = name.rsplit("::").next().unwrap_or(name);
        let mut hasher = blake3::Hasher::new();
        hasher.update(global.as_bytes());
        for probe in executed.get(case).into_iter().flatten() {
            hasher.update(b"\x1c");
            hasher.update(probes.get(*probe).map_or("", String::as_str).as_bytes());
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
                Some(texts) => {
                    for text in texts {
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
        .filter(|(key, verdict)| *key != "-" && reusable(verdict))
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
        let mutants = listing(&crate::fsio::read_to_string(path)?)?;
        sweep(&root, &mutants, jobs, &mut out)
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
    let journal = std::sync::Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(judging.store)
            .ok(),
    );
    let next = std::sync::atomic::AtomicUsize::new(0);
    let reused_count = std::sync::atomic::AtomicUsize::new(0);
    let (sent, decided) = std::sync::mpsc::channel::<(u32, Verdict)>();
    let mut verdicts = Vec::with_capacity(todo.len());
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            let sent = sent.clone();
            let (next, hints, journal, nobody, reused_count) =
                (&next, &hints, &journal, &nobody, &reused_count);
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
                        Some("uncovered") => Verdict::Uncovered,
                        _ => judge(judging, id, mutant, cases, hints),
                    };
                    // EVERY VERDICT, SURVIVORS TOO, the moment it is decided:
                    // one write per line, so a crash tears at most the last.
                    // Only a kill is reused (`reusable`); a survivor's line is
                    // the record a stopped sweep keeps.
                    if reused.is_none()
                        && let Ok(mut held) = journal.lock()
                        && let Some(file) = held.as_mut()
                    {
                        let line = journal_line(key.as_deref(), verdict.name(), &mutant.name);
                        let _ = std::io::Write::write_all(file, line.as_bytes());
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
                let _ = writeln!(
                    out,
                    "mutate schema: judged {}/{} in {}s",
                    verdicts.len(),
                    todo.len(),
                    started.elapsed().as_secs()
                );
            }
        }
    });
    let _ = writeln!(
        out,
        "mutate schema: reused {} of {} verdict(s)",
        reused_count.into_inner(),
        todo.len()
    );
    verdicts
}

/// Append `lines` to the verdict journal in one write. APPEND-ONLY, never
/// rewritten: a crash tears at most the last line, which `load_verdicts`
/// skips, and a survivor's line outlives the sweep that decided it.
fn journal(path: &std::path::Path, lines: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(lines.as_bytes())?;
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
fn cached_unviable(
    site_keys: &[Option<String>],
    cache: &std::collections::BTreeMap<String, String>,
) -> BTreeSet<u32> {
    site_keys
        .iter()
        .enumerate()
        .filter(|(_, key)| {
            key.as_ref()
                .is_some_and(|key| cache.get(key).is_some_and(|v| v == "unviable"))
        })
        .filter_map(|(id, _)| u32::try_from(id).ok())
        .collect()
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
        "mutate schema: {counts:?}, {} unviable, {} classic, in {}s",
        unviable, classic, seconds
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
    jobs: usize,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Swept> {
    let state = crate::state::repo_state_dir(root)?
        .join("mutate")
        .join("schema");
    let work = state.join("tree");
    // INSIDE THE TREE, where cargo-mutants' copies keep theirs: a case's
    // fixtures land under the target's `tmp/`, and on #1276 one with no `.git`
    // of its own passed only inside a checkout, so a target beside the tree
    // failed the unmutated baseline.
    let target = work.join("target");
    let started = std::time::Instant::now();
    sync(root, &work)?;
    // THE SOURCES AS THE SWEEP FOUND THEM: every rendering, key and case file
    // is read from this snapshot, never the live checkout, which an edit during
    // an hour-long sweep would move under the listing's spans.
    let snapshot = state.join("pristine");
    super::cover::pristine(root, &snapshot)?;
    let resources = resource_digest(root)?;
    let root = snapshot;
    // AN ERROR LOG IS THIS SWEEP'S OR NOTHING: one left by a killed sweep
    // would read as a run of this one erring.
    let _ = std::fs::remove_dir_all(state.join("errors"));
    let cache_path = state.join("verdicts");
    let mut cache = load_verdicts(&crate::fsio::read_to_string(&cache_path).unwrap_or_default());
    let dirs = package_dirs(mutants);
    let site_keys: Vec<Option<String>> = mutants.iter().map(|m| site_key(&root, m)).collect();
    let known_unviable = cached_unviable(&site_keys, &cache);
    writeln!(
        out,
        "mutate schema: {} unviable known from earlier runs",
        known_unviable.len()
    )?;
    let Built {
        unviable,
        handed,
        schema,
    } = build(&root, &work, &target, mutants, known_unviable, out)?;
    // KEPT BEFORE ANY TEST RUNS: a restart skips the unviable loop's builds.
    journal(
        &cache_path,
        &newly_unviable(&unviable, &site_keys, mutants, &mut cache),
    )?;
    let classic: BTreeSet<u32> = schema
        .files
        .values()
        .flat_map(|r| r.classic.iter().copied())
        .chain(handed)
        .collect();
    writeln!(
        out,
        "mutate schema: {} mutant(s), {} unviable, {} classic, built in {}s",
        mutants.len(),
        unviable.len(),
        classic.len(),
        started.elapsed().as_secs()
    )?;
    let packages: BTreeSet<&str> = mutants.iter().map(|m| m.package.as_str()).collect();
    let reach = record_reach(&work, &target, &state, &packages, out)?;
    let global = blake3::hash(format!("{}\x1f{resources}", schema.skeleton).as_bytes())
        .to_hex()
        .to_string();
    let digests = case_digests(
        &root,
        reach.sites.values().flatten(),
        &dirs,
        &reach.executed,
        &schema.probes,
        &global,
    );
    writeln!(
        out,
        "mutate schema: reach recorded for {} site(s), {} function(s) probed, in {}s",
        reach.sites.len(),
        schema.probes.len(),
        started.elapsed().as_secs()
    )?;
    let seconds = durations(
        &crate::fsio::read_to_string(
            state
                .join("nextest")
                .join("batten-cover")
                .join(super::cover::JUNIT),
        )
        .unwrap_or_default(),
    );
    let scratch = state.join("scratch");
    std::fs::create_dir_all(&scratch)?;
    let todo: Vec<u32> = (0..u32::try_from(mutants.len())?)
        .filter(|id| !unviable.contains(id) && !classic.contains(id))
        .collect();
    let verdicts = judge_all(
        &Judging {
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
        },
        &todo,
        jobs,
        out,
    );
    let names = handed_back(out, mutants, &classic)?;
    let code = report(
        out,
        mutants,
        &verdicts,
        (unviable.len(), classic.len()),
        &state,
        started.elapsed().as_secs(),
    )?;
    Ok(Swept {
        code,
        classic: names,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
        assert_eq!(loaded.get("u").map(String::as_str), Some("uncovered"));
        assert_eq!(loaded.len(), 4);
        assert_eq!(journal_line(None, "missed", "m"), "-\tmissed\tm\n");
    }

    /// A reach record over the same tree resumes: a case that finished
    /// passing is kept and counted, one that failed or never finished is not;
    /// a record over another tree is cleared for this one.
    ///
    /// Fails by: a record over another tree kept (reach from other code), a
    /// failed or torn case counted, or a finished one not.
    #[test]
    fn a_reach_record_resumes_only_over_its_own_tree() {
        let base = crate::scratch::scratch("schema-reach-resume");
        for (case, done) in [("a", Some("0")), ("b", Some("101")), ("c", None)] {
            std::fs::create_dir_all(base.join(case)).unwrap();
            if let Some(code) = done {
                std::fs::write(base.join(case).join(DONE), code).unwrap();
            }
        }
        std::fs::write(base.join(TREE), "tree-1").unwrap();
        assert_eq!(resume_reach(&base, "tree-1").unwrap(), 1);
        assert!(base.join("b").exists(), "kept, to be run again");
        assert_eq!(resume_reach(&base, "tree-2").unwrap(), 0);
        assert!(!base.join("a").exists(), "another tree's record is cleared");
        assert_eq!(std::fs::read_to_string(base.join(TREE)).unwrap(), "tree-2");
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
        assert!(record_into(&base, &test).is_err(), "run again");
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
        let reach = collect_reach(&base).unwrap();
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
        let recorded = collect_reach(&base).unwrap();
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
                      </testcase><testcase name=\"c\" classname=\"batten\" time=\"2\"/>";
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

    #[test]
    fn the_killer_is_the_first_failed_case_a_run_names() {
        let output = "   SETUP FAIL [ 0.1s] clear-scratch: sh\n\
                      \x20       FAIL [   4.551s] batten::it mutate::a_change\n\
                      \x20       FAIL [   1.000s] batten unit::other\n";
        assert_eq!(killer(output), Some(case("mutate::a_change")));
        assert_eq!(killer("PASS [ 1s] batten::it x"), None);
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
    /// a changed file or link rewritten, and only the top `target/` left out.
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
        sync(&root, &work).unwrap();
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
        sync(&root, &work).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("a.txt")).unwrap(), "uno");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(work.join("link")).unwrap(),
                std::path::Path::new("a.txt")
            );
            std::fs::remove_file(root.join("link")).unwrap();
            std::os::unix::fs::symlink("sub/b.txt", root.join("link")).unwrap();
            sync(&root, &work).unwrap();
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
        let schema =
            write_schema(&root, &work, &[inner], &BTreeSet::new(), &BTreeSet::new()).unwrap();
        assert!(schema.files.contains_key("crates/x/src/m.rs"));
        let m = std::fs::read_to_string(work.join("crates/x/src/m.rs")).unwrap();
        assert!(m.contains("crate::__batten_mutant(0) { a != b }"), "{m}");
        let lib = std::fs::read_to_string(work.join("crates/x/src/lib.rs")).unwrap();
        assert_eq!(lib, format!("pub mod m;\n{}", prelude(schema.probes.len())));
        assert_eq!(schema.probes.len(), 1, "m.rs's one function");
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
        let digests = case_digests(&root, &cases, &dirs, &none, &[], "");
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
        let digests = case_digests(&root, &cases, &dirs, &none, &[], "");
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
                &[],
                "",
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
    /// did not, and every case's moves with the global digest.
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
        let digests = |probes: &[String], global: &str| {
            case_digests(&root, &cases, &dirs, &executed, probes, global)
        };
        let held = digests(&[String::from("a"), String::from("b")], "g");
        let moved = digests(&[String::from("a2"), String::from("b")], "g");
        assert_ne!(moved[&one], held[&one], "its callee changed");
        assert_eq!(moved[&two], held[&two], "not a function it ran");
        let global = digests(&[String::from("a"), String::from("b")], "h");
        assert!(cases.iter().all(|case| global[case] != held[case]));
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
}

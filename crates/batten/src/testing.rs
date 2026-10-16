//! Decisions the test harness makes about a spawn, kept in the crate so
//! `batten mutate` can show each one red (CLOUD-2059).
//!
//! Test-support rather than product surface, and `#[doc(hidden)]` says so,
//! exactly as [`crate::scratch`] does. `tests/it/common` applies these on every
//! spawn of the binary under test; the decisions live here, where a declared row
//! is swept like any engine module's, rather than in the harness, where a row is
//! a comment whose kill is shown by hand.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The OS data directory THIS process resolves state under, once a test has
/// contained it ([`contain_state`]).
static CONTAINED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Resolve this process's own state under `data_dir` from now on, as a spawned
/// child pointed there by [`state_pins`] resolves its (CLOUD-2059).
///
/// THE IN-PROCESS HALF OF THE PIN. A case that calls the library — an admission
/// issued, a lap verified, a decision appended — resolves the store from its own
/// environment, which no spawn door touches and `unsafe_code = "forbid"` puts out
/// of reach, so those calls wrote the developer's real store: 22 segments in one
/// full run after every door was pinned. Set once per process (nextest runs each
/// case in its own), first value wins, and nothing outside a test can reach it:
/// it reads no environment variable, and the binary never calls it.
#[doc(hidden)]
pub fn contain_state(data_dir: &Path) {
    let _ = CONTAINED.set(data_dir.to_path_buf());
}

/// The contained data directory, if a test set one.
///
/// ONE SUITE FOR EVERY ROW IN THIS FILE: `mutate` judges a row under the
/// `MUTANT-SUITE` above it (CLOUD-2193), and a Rust suite selects the runner, not
/// a target — each row's case filter runs over the whole `it` binary, wherever
/// the case lives.
//MUTANT-SUITE crates/batten/tests/it/harness_isolation.rs
//MUTANT in-process-uncontained|s@^    CONTAINED.get().map(PathBuf::as_path)$@    None@|in_process_state_resolves_to_the_cases_own_root
pub(crate) fn contained_data_dir() -> Option<&'static Path> {
    CONTAINED.get().map(PathBuf::as_path)
}

/// The variables that place a child's state root at `<dir>/batten` on every
/// platform: the XDG data home `etcetera` reads on unix and macOS, and the
/// `%APPDATA%` its Windows strategy reads. A redirect spelled for one platform
/// writes the real user's store on the other, which is how CLOUD-113's Windows
/// job found the first copy of this.
///
/// `LOCALAPPDATA` is deliberately absent. Batten keeps nothing there, and mise on
/// Windows keeps its whole toolchain there with no `MISE_DATA_DIR` pinned on that
/// leg, so moving it on every spawn would reinstall the toolchain per case —
/// CLOUD-2021's cost, on every case rather than one.
//MUTANT state-pin-posix-only|s@("APPDATA", dir)@("APPDATA_UNREAD", dir)@|the_ambient_state_root_never_reaches_the_binary_under_test
#[doc(hidden)]
#[must_use]
pub fn state_pins(dir: &Path) -> [(&'static str, &Path); 2] {
    [("XDG_DATA_HOME", dir), ("APPDATA", dir)]
}

/// The variables that place a child's home directory at `dir` on every platform:
/// `HOME` on unix and macOS, and the `USERPROFILE` `std::env::home_dir` reads on
/// Windows. A home overridden for one platform reads the real user's profile on
/// the other, which is how CLOUD-113's Windows job found `wiring_reclaim.rs`.
///
/// What a case's home holds is then the case's business: a developer's
/// `~/.claude`, `~/.gitconfig` or global mise config can no longer move a verdict
/// here that a CI runner, which has none of them, would not reproduce.
//MUTANT home-pin-posix-only|s@("USERPROFILE", dir)@("USERPROFILE_UNREAD", dir)@|every_spawn_of_the_binary_pins_the_home
#[doc(hidden)]
#[must_use]
pub fn home_pins(dir: &Path) -> [(&'static str, &Path); 2] {
    [("HOME", dir), ("USERPROFILE", dir)]
}

/// Whether a spawn whose working directory is `cwd` would FALL THROUGH to an
/// enclosing repository: `cwd` lies at or below `scratch_root`, and the working
/// tree discovery resolves it to lies above `scratch_root`.
///
/// RESOLVED, NOT INFERRED FROM A `.git` THAT EXISTS. An empty or malformed `.git`
/// is not a repository, so discovery walks straight past it to the checkout —
/// the one case a presence test calls owned while the binary falls through. This
/// asks [`crate::git::worktree_root`], the resolver the binary itself uses, and a
/// directory no repository encloses is not judged: the binary refuses there, and
/// nothing reaches a checkout.
///
/// # The defect this refuses
///
/// `git::repo_root` deliberately ignores `GIT_CEILING_DIRECTORIES`, so a fixture
/// under the build's scratch root with no repository of its own resolves to the
/// checkout that holds the build — the real one. A verb run there reads the real
/// configuration, writes the real `.git`, and keys the real state segment, while
/// the case believes it judged its fixture.
///
/// # What it leaves alone, deliberately
///
/// A `cwd` OUTSIDE `scratch_root` is not judged: a suite whose subject is the
/// committed configuration runs at the real root on purpose, and a fixture under
/// the system temp directory falls through to nothing. Only the scratch root sits
/// inside the checkout, so only there is a missing `.git` an accident.
//MUTANT spawn-falls-through|s@^    resolved.is_ok_and.*$@    false@|a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused
//MUTANT verbatim-scratch-root|s@^    let scratch = crate::git::canonical(scratch_root);$@    let scratch = scratch_root.canonicalize().unwrap_or_else(\x7c_\x7c scratch_root.to_path_buf());@|no_engine_file_adds_a_bare_canonicalize
#[doc(hidden)]
#[must_use]
pub fn falls_through(cwd: &Path, scratch_root: &Path) -> bool {
    if !cwd.starts_with(scratch_root) {
        return false;
    }
    // Both sides in the RESOLVER'S spelling, because a scratch root reached
    // through a symlink would otherwise own nothing — and `git::canonical`, not a
    // bare `canonicalize`, whose verbatim Windows answer shares no prefix with the
    // plain root `worktree_root` returns: that read every owned fixture as
    // falling through and refused 2,614 cases on the Windows leg (CLOUD-2059).
    let scratch = crate::git::canonical(scratch_root);
    let resolved = crate::git::worktree_root(cwd);
    resolved.is_ok_and(|owner| !owner.starts_with(&scratch))
}

/// What one source file's assertions do with the clock.
///
/// TIME IS AN INPUT TO A CASE, NEVER WHAT IT ASSERTS (CLOUD-2059). A bound the
/// case imposes and a deadline its poll gives up at are inputs; a ceiling or a
/// floor on elapsed time is an assertion about the scheduler, and every one this
/// tree carried was replaced by the outcome it stood in for — the kill line, the
/// recorded escalation, the drain's notice, the fetch's own `timed out`.
#[doc(hidden)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClockCensus {
    /// Assertion macros whose arguments parsed and were judged.
    pub judged: usize,
    /// Locals bound from a clock read. The anti-vacuity count: a census that
    /// stopped recognising a read finds none.
    pub clocked: usize,
    /// The functions holding an assertion whose CONDITION reads the clock.
    pub refused: Vec<String>,
    /// The functions holding an assertion whose arguments do not parse as
    /// expressions — unjudged, so reported rather than passed.
    pub unparsed: Vec<String>,
}

/// Every assertion in `file` that reads the clock in what it asserts.
///
/// A message argument is never judged: printing the elapsed time beside a count
/// is a report, and the count is what is asserted. A clock read reaches an
/// assertion directly or through a `let` in the same function; a field, a
/// helper's return value, a reassignment or a call to a local bound to a
/// closure carries one unseen.
#[doc(hidden)]
#[must_use]
pub fn clock_census(file: &syn::File) -> ClockCensus {
    let mut walk = ClockWalk::default();
    walk.visit_file(file);
    walk.census
}

/// How many variants `source` declares for the enum `name`, split by whether
/// each carries a payload, counted off the declaration rather than off a list
/// somebody re-typed (CLOUD-2379).
///
/// **IT ASKS THE PARSER, because a text scan kept being wrong in a way that
/// read as right.** Three line-shape heuristics stood here in turn and review
/// found a hole in each: a `starts_with("///")` clause its neighbour already
/// subsumed, a `contains('(')` split that read a struct variant as a unit, and
/// — the one that settles it — a per-LINE scan, under which a declaration
/// `rustfmt` wraps counts as neither. Every one of those failures is silent:
/// the totals still match, so a caller's assertions stay green while the
/// vocabulary goes unchained. The grammar has no such holes, and
/// [`crate::source::rust`] is the crate's one parse (CLOUD-1008).
///
/// **The predicate had three copies before this one, and they had already
/// diverged by a clause.** `WeakeningKind`, `DriftId` and `SmellId` each hold
/// their `ALL`/`UNITS` whole by counting the enum body, and a fourth such enum
/// would have copied whichever copy it found first. One authority decides what
/// a variant line is.
///
/// **BOTH COUNTS ARE RETURNED, and dropping the second was a hole in exactly
/// the mechanism this helper serves.** A unit variant is enumerated by a
/// hand-written list; a TUPLE variant delegates to another vocabulary and is
/// enumerated by a `chain` into that vocabulary's own `ALL`. An exhaustive
/// `definition()` forces an arm for either, but nothing forces the `chain` — so
/// a delegated variant added without one compiles, leaves the unit count
/// matching, and yields ids `all()` never reports. That is the
/// emitted-but-unexplainable id the type exists to make impossible, returning
/// through the type's own extension point. A caller asserts the tuple count it
/// has wired, so adding a variant is what fails.
///
/// The caller passes the source, because `include_str!` resolves against the
/// file it is written in and the point is to read the CALLER's declaration.
#[doc(hidden)]
#[must_use]
pub fn declared_variants(source: &str, name: &str) -> Option<DeclaredVariants> {
    let file = crate::source::rust(source).ok()?;
    let declared = file.items.iter().find_map(|item| match item {
        syn::Item::Enum(declared) if declared.ident == name => Some(declared),
        _ => None,
    })?;
    let mut counts = DeclaredVariants {
        unit: 0,
        delegated: 0,
    };
    for variant in &declared.variants {
        if matches!(variant.fields, syn::Fields::Unit) {
            counts.unit += 1;
        } else {
            counts.delegated += 1;
        }
    }
    Some(counts)
}

/// The cases holding [`declared_variants`] itself (CLOUD-2379).
///
/// **It is the one authority on what a declared variant is, and it had none.**
/// `mutate` showed every clause of the text scan that stood here surviving,
/// because its three callers only ever hand it source that already agrees with
/// their own lists — so a filter that decided nothing still produced the right
/// totals. A census nothing discriminates is the vacuous pass this repository
/// prices (non-negotiable rule 2), one level under the vocabularies it holds.
///
/// **And a surviving mutant was not the only way that scan could be wrong.**
/// Review found two more holes no mutation could reach: a clause its neighbour
/// already subsumed, and a per-line reading under which a wrapped declaration
/// counted as neither kind. Each failed silently. Asking the grammar retires
/// the whole class, so these cases are about VARIANTS now rather than about
/// line shapes — the distinctions the scan needed (a doc line, a lowercase
/// name, a missing comma) were artefacts of reading text and are gone with it.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod declared_variants_tests {
    use super::{DeclaredVariants, declared_variants};

    /// Both payload shapes, a wrapped declaration, and a doc comment.
    const SOURCE: &str = "\
pub enum Sample {
    /// A doc comment, which declares no variant.
    First,
    Second,
    Delegated(Other),
    Shaped { kind: Other },
    Wrapped(
        Other,
    ),
}
";

    fn counted() -> DeclaredVariants {
        declared_variants(SOURCE, "Sample").expect("the sample enum parses")
    }

    #[test]
    fn a_variant_carrying_a_payload_counts_apart_from_a_unit_variant() {
        // Pins both arms: `Delegated`, `Shaped` and `Wrapped` each carry a
        // vocabulary, and the doc comment declares nothing.
        assert_eq!(
            counted(),
            DeclaredVariants {
                unit: 2,
                delegated: 3
            }
        );
    }

    /// A struct variant delegates exactly as a tuple variant does.
    ///
    /// Its own case because the retired scan split the two on `(` alone, so a
    /// struct-shaped delegate read as a unit — the delegate count a caller
    /// asserts stayed right while the vocabulary it names went unchained.
    #[test]
    fn a_struct_variant_is_a_delegate_rather_than_a_unit() {
        let without_struct = SOURCE.replace("    Shaped { kind: Other },\n", "");
        assert_eq!(
            declared_variants(&without_struct, "Sample").expect("it still parses"),
            DeclaredVariants {
                unit: 2,
                delegated: 2
            },
            "removing the struct variant removes a DELEGATE, never a unit"
        );
    }

    /// A declaration spread over several lines is still one variant.
    ///
    /// The case the retired per-line scan could not pass: `Wrapped` matched no
    /// line shape, so it incremented neither count and every caller's totals
    /// stayed green over a delegate nothing had chained. `rustfmt` wraps a
    /// declaration whenever its payload pushes past the width, so this is the
    /// ordinary shape rather than a contrived one.
    #[test]
    fn a_declaration_wrapped_over_lines_is_counted_once_as_a_delegate() {
        let flat = SOURCE.replace("    Wrapped(\n        Other,\n    ),\n", "");
        assert_eq!(
            declared_variants(&flat, "Sample").expect("it still parses"),
            DeclaredVariants {
                unit: 2,
                delegated: 2
            },
            "the wrapped declaration was worth exactly one delegate"
        );
    }

    #[test]
    fn an_enum_the_source_does_not_declare_is_could_not_look() {
        assert!(declared_variants(SOURCE, "Absent").is_none());
    }

    #[test]
    fn source_the_grammar_refuses_is_could_not_look() {
        assert!(declared_variants("pub enum Open {\n    First,\n", "Sample").is_none());
    }

    #[test]
    fn the_count_is_of_the_named_enum_rather_than_its_neighbours() {
        let two = format!("{SOURCE}\npub enum Later {{\n    Third,\n    Fourth,\n}}\n");
        assert_eq!(
            declared_variants(&two, "Sample").expect("both enums parse"),
            counted()
        );
        assert_eq!(
            declared_variants(&two, "Later").expect("both enums parse"),
            DeclaredVariants {
                unit: 2,
                delegated: 0
            }
        );
    }
}

/// What [`declared_variants`] counted: variants enumerated by a list, and
/// variants enumerated by delegating to another vocabulary.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredVariants {
    /// Unit variants, each owing a row in the enum's own list.
    pub unit: usize,
    /// Tuple variants, each owing a `chain` into the vocabulary it wraps.
    pub delegated: usize,
}

/// How many leading arguments of an assertion macro are its condition, or
/// `None` for a macro that asserts nothing.
fn conditions_of(path: &syn::Path) -> Option<usize> {
    let name = path.segments.last()?.ident.to_string();
    match name.as_str() {
        "assert" | "debug_assert" => Some(1),
        "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne" => Some(2),
        _ => None,
    }
}

/// Whether `expr` reads the clock: `Instant::now` or `SystemTime::now`, any
/// `.elapsed()`, or a local in `clocked`. A `Duration` alone is a constant, not
/// a reading.
//MUTANT elapsed-unread|s@^        self.found \x7c= call.method == "elapsed";$@        self.found \x7c= call.method == "elapsed_unread";@|an_upper_bound_on_elapsed_is_refused
//MUTANT now-unread|s@^            \[.., clock, now\] => now == "now"@            [.., clock, now] => now == "now_unread"@|a_deadline_asserted_against_now_is_refused
//MUTANT clock-taint-unread|s@^            \[local\] => self.clocked.contains(local),$@            [_] => false,@|a_clock_read_through_a_local_is_refused
#[doc(hidden)]
#[must_use]
pub fn reads_clock(expr: &syn::Expr, clocked: &BTreeSet<String>) -> bool {
    let mut reads = Reads {
        clocked,
        found: false,
    };
    reads.visit_expr(expr);
    reads.found
}

struct Reads<'a> {
    clocked: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for Reads<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.found |= call.method == "elapsed";
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.found |= match segments.as_slice() {
            [.., clock, now] => now == "now" && (clock == "Instant" || clock == "SystemTime"),
            [local] => self.clocked.contains(local),
            [] => false,
        };
        syn::visit::visit_expr_path(self, path);
    }
}

/// The names a pattern binds.
#[derive(Default)]
struct Bindings(Vec<String>);

impl<'ast> Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, ident: &'ast syn::PatIdent) {
        self.0.push(ident.ident.to_string());
        syn::visit::visit_pat_ident(self, ident);
    }
}

#[derive(Default)]
struct ClockWalk {
    /// The enclosing function and the locals it bound from a clock read,
    /// innermost last.
    within: Vec<(String, BTreeSet<String>)>,
    census: ClockCensus,
}

//MUTANT clock-message-judged|s@^                        .take(conditions)$@                        .take(usize::MAX)@|the_clock_in_a_message_is_not_asserted
impl<'ast> Visit<'ast> for ClockWalk {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within
            .push((item.sig.ident.to_string(), BTreeSet::new()));
        syn::visit::visit_item_fn(self, item);
        self.within.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.within
            .push((item.sig.ident.to_string(), BTreeSet::new()));
        syn::visit::visit_impl_item_fn(self, item);
        self.within.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        // A LOCAL BOUND TO A CLOSURE IS A FUNCTION VALUE, NOT A READING: what a
        // call to it returns is whatever the closure computes. Only the binding
        // is exempt; a clock read inside a closure in a condition, or in one
        // called on the spot, is still read by `reads_clock`.
        if let (Some(init), Some((_, clocked))) = (&local.init, self.within.last_mut())
            && !matches!(*init.expr, syn::Expr::Closure(_))
            && reads_clock(&init.expr, clocked)
        {
            let mut bound = Bindings::default();
            bound.visit_pat(&local.pat);
            self.census.clocked += bound.0.len();
            clocked.extend(bound.0);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let (Some(conditions), Some((function, clocked))) =
            (conditions_of(&mac.path), self.within.last())
        {
            let parsed = mac.parse_body_with(
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
            );
            match parsed {
                Ok(args) => {
                    self.census.judged += 1;
                    if args
                        .iter()
                        .take(conditions)
                        .any(|condition| reads_clock(condition, clocked))
                    {
                        self.census.refused.push(function.clone());
                    }
                }
                Err(_) => self.census.unparsed.push(function.clone()),
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Whether `attrs` mark a function nextest runs as a case: `#[test]` or
/// `#[rstest]`, by last segment, so a qualified spelling counts too.
#[doc(hidden)]
#[must_use]
pub fn is_case(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test" || segment.ident == "rstest")
    })
}

/// What one source file's cases do when their subject is missing.
///
/// A MISSING TOOL IS A FAILURE; A MISSING SUBJECT IS A `cfg!` ARM (CLOUD-2059).
/// A case that returns before it asserts PASSES, and nextest cannot tell "looked
/// and found it right" from "never looked". A probe that finds no `hk`, no `pkl`
/// or no `flock` and returns is a leg reporting coverage it does not have. The
/// one admitted early exit is under `if cfg!(…)` or `if !cfg!(…)`: the
/// off-platform contract, stated where a reader sees it and decided at compile
/// time rather than by what a runner happens to have installed.
#[doc(hidden)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SkipCensus {
    /// Cases walked.
    pub cases: usize,
    /// Early exits under a platform guard, admitted. The anti-vacuity count: a
    /// census that stopped recognising the guard would refuse these instead.
    pub guarded: usize,
    /// The cases holding an early exit no platform guard covers.
    pub refused: Vec<String>,
}

/// Every case in `file` that can return before it asserts.
///
/// Every function is walked, a `mod tests` inside the library included. A
/// `return` inside a closure, an async block or a nested item leaves that and
/// not the case, so it is not counted. An exit a HELPER takes is the helper's:
/// a case that calls one which returns early is not seen here.
#[doc(hidden)]
#[must_use]
pub fn skip_census(file: &syn::File) -> SkipCensus {
    let mut walk = SkipWalk::default();
    walk.visit_file(file);
    walk.census
}

#[derive(Default)]
struct SkipWalk {
    census: SkipCensus,
}

impl<'ast> Visit<'ast> for SkipWalk {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if is_case(&item.attrs) {
            let mut exits = Exits::default();
            exits.visit_block(&item.block);
            self.census.cases += 1;
            self.census.guarded += exits.guarded;
            if exits.silent > 0 {
                self.census.refused.push(item.sig.ident.to_string());
            }
        }
        syn::visit::visit_item_fn(self, item);
    }
}

/// Whether `condition` is a platform guard: `cfg!(…)` under any number of `!`.
//MUTANT platform-guard-unread|s@^    matches!(condition, syn::Expr::Macro(guard) if guard.mac.path.is_ident("cfg"))$@    false@|a_return_under_a_cfg_guard_is_admitted
fn platform_guard(condition: &syn::Expr) -> bool {
    let mut condition = condition;
    while let syn::Expr::Unary(syn::ExprUnary {
        op: syn::UnOp::Not(_),
        expr,
        ..
    }) = condition
    {
        condition = expr;
    }
    matches!(condition, syn::Expr::Macro(guard) if guard.mac.path.is_ident("cfg"))
}

/// The early exits in one case body, split by whether a platform guard holds
/// them.
#[derive(Default)]
struct Exits {
    /// How many enclosing `if`s are platform guards, at the current node.
    within_guard: usize,
    silent: usize,
    guarded: usize,
}

//MUTANT silent-skip-admitted|s@^        if self.within_guard == 0 {$@        if self.within_guard == usize::MAX {@|a_bare_return_in_a_case_is_refused
impl<'ast> Visit<'ast> for Exits {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        let guard = usize::from(platform_guard(&branch.cond));
        self.within_guard += guard;
        syn::visit::visit_expr_if(self, branch);
        self.within_guard -= guard;
    }

    fn visit_expr_return(&mut self, exit: &'ast syn::ExprReturn) {
        if self.within_guard == 0 {
            self.silent += 1;
        } else {
            self.guarded += 1;
        }
        syn::visit::visit_expr_return(self, exit);
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}

    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

/// Every shell command a `run:` text runs, each as its words and the text its
/// stdin is fed, through the hooks' own parse (CLOUD-2388); `None` when that
/// parse could not read it.
#[doc(hidden)]
#[must_use]
pub fn shell_commands(text: &str) -> Option<Vec<(Vec<String>, Vec<String>)>> {
    crate::hook::shell_commands(text)
}

/// What a source's `require_tool`/`require_bin` calls declare (CLOUD-2388).
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct RequireCensus {
    /// Each call's first argument, when it is a string literal.
    pub tools: Vec<String>,
    /// Calls whose first argument is not a string literal, and the resolver
    /// named as a value (`.map(require_tool)`): requirements no reader can name.
    pub unnamed: usize,
    /// String literals spelling `which`: a `mise which` the resolver does not make.
    pub which_literals: usize,
    /// Each `Command::new("<literal>")` program: a pinned tool among them is
    /// reached around the resolver, so no reader sees it required.
    pub spawned: Vec<String>,
}

/// Whether `path` names the resolver: its last segment is `require_tool` or
/// `require_bin`, whatever path reaches it.
fn names_resolver(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|last| last.ident == "require_tool" || last.ident == "require_bin")
}

/// The `require_tool`/`require_bin` calls in `file`, by any path that ends in
/// one, inside a macro whose body is comma-separated expressions (`assert!`,
/// `vec!`, `format!`) as well as outside.
#[doc(hidden)]
#[must_use]
pub fn require_census(file: &syn::File) -> RequireCensus {
    /// The census, and whether the walk is inside the resolver's own body,
    /// where `require_bin(name, name)` and its `mise which` are the mechanism.
    struct Walk(RequireCensus, bool);
    impl<'a> Visit<'a> for Walk {
        fn visit_item_fn(&mut self, item: &'a syn::ItemFn) {
            let resolver = item.sig.ident == "require_tool" || item.sig.ident == "require_bin";
            let outer = std::mem::replace(&mut self.1, resolver);
            syn::visit::visit_item_fn(self, item);
            self.1 = outer;
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func
                && names_resolver(&path.path)
            {
                match call.args.first() {
                    Some(syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(tool),
                        ..
                    })) => self.0.tools.push(tool.value()),
                    _ if self.1 => {}
                    _ => self.0.unnamed += 1,
                }
                // The callee is this call's, not a bare path's: walk the
                // arguments only, or the path would count again below.
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                return;
            }
            if let syn::Expr::Path(path) = &*call.func
                && let [.., ty, new] = path.path.segments.iter().collect::<Vec<_>>()[..]
                && ty.ident == "Command"
                && new.ident == "new"
                && let Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(program),
                    ..
                })) = call.args.first()
            {
                self.0.spawned.push(program.value());
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_path(&mut self, path: &'a syn::ExprPath) {
            if names_resolver(&path.path) && !self.1 {
                self.0.unnamed += 1;
            }
        }
        fn visit_macro(&mut self, mac: &'a syn::Macro) {
            if let Ok(args) = mac.parse_body_with(
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
            ) {
                for arg in &args {
                    self.visit_expr(arg);
                }
            }
        }
        fn visit_lit_str(&mut self, lit: &'a syn::LitStr) {
            // Split, so the census does not count its own needle.
            if lit.value() == concat!("whi", "ch") && !self.1 {
                self.0.which_literals += 1;
            }
        }
    }
    let mut walk = Walk(RequireCensus::default(), false);
    walk.visit_file(file);
    walk.0
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// A checkout at `<scratch>/checkout` whose own scratch root is `tmp` inside
    /// it — this build's shape, one level down — with an empty fixture beneath.
    fn checkout(name: &str) -> std::path::PathBuf {
        let dir = crate::scratch::scratch(&format!("testing-{name}")).join("checkout");
        std::fs::create_dir_all(dir.join("tmp/fixture/sub")).expect("create the tree");
        crate::gitwrite::init_on_main(&dir).expect("the enclosing checkout");
        dir
    }

    /// A fixture with no repository of its own resolves to the enclosing checkout.
    #[test]
    fn a_fixture_with_no_repository_under_the_scratch_root_falls_through() {
        let dir = checkout("bare");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// A repository between the fixture and the scratch root owns it.
    #[test]
    fn a_repository_anywhere_up_to_the_scratch_root_owns_the_fixture() {
        let dir = checkout("owned");
        crate::gitwrite::init_on_main(&dir.join("tmp/fixture"))
            .expect("the fixture's own repository");
        assert!(!falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// An empty `.git` is no repository, so ownership is resolved, never inferred
    /// from the entry existing (review of #1089).
    #[test]
    fn a_dot_git_that_is_not_a_repository_owns_nothing() {
        let dir = checkout("hollow");
        std::fs::create_dir_all(dir.join("tmp/fixture/.git")).expect("an empty .git");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// Only a directory under the scratch root is judged; the real root is not a
    /// fixture.
    #[test]
    fn a_directory_outside_the_scratch_root_is_not_judged() {
        let dir = checkout("outside");
        assert!(!falls_through(&dir, &dir.join("tmp")));
    }

    /// Fails by: the closure exemption reaching past a binding, so a clock read
    /// inside a closure in a condition, or in one called on the spot, goes unseen.
    #[test]
    fn a_closure_in_a_condition_still_reads_the_clock() {
        let none = BTreeSet::new();
        for condition in [
            "samples.iter().all(|s| s.elapsed() < LIMIT)",
            "(|| Instant::now() < deadline)()",
        ] {
            let expr: syn::Expr = syn::parse_str(condition).expect("parse");
            assert!(reads_clock(&expr, &none), "{condition}");
        }
    }

    /// Fails by: a census that stops recognising a clock spelling, a taint
    /// through a `let`, an assertion macro's condition count, an `impl` method,
    /// or an unparsed body, or that taints a local bound to a closure that reads
    /// the clock — every count and name is asserted exactly.
    #[test]
    fn the_clock_census_counts_and_names_each_assertion_exactly() {
        let file: syn::File = syn::parse_str(
            r#"
            fn tainted() {
                let start = Instant::now();
                let (from, to) = (std::time::SystemTime::now(), Instant::now());
                assert!(start < limit);
                assert_eq!(count, 3, "took {:?}", start.elapsed());
            }
            fn elapsed() { assert!(timer().elapsed() < bound); }
            struct S;
            impl S {
                fn deadline() { assert!(deadline > Instant::now()); }
            }
            fn second() { debug_assert_ne!(stamp, SystemTime::now()); }
            fn clean() {
                let n = count();
                assert!(n == Clock::now());
                assert!(t < Instant::MAX);
                debug_assert!(n.checked_add(1).is_some());
                assert_ne!(n, 2);
                other!(Instant::now());
                let run = || outcome(Instant::now());
                assert_eq!(run(), 3);
            }
            fn unparsed() { assert!(a b); }
            "#,
        )
        .expect("the fixture parses");
        assert_eq!(
            clock_census(&file),
            ClockCensus {
                judged: 10,
                clocked: 3,
                refused: ["tainted", "elapsed", "deadline", "second"]
                    .map(String::from)
                    .to_vec(),
                unparsed: vec!["unparsed".to_owned()],
            }
        );
    }

    /// Fails by: a census that miscounts cases, admits a bare early exit, refuses
    /// one under `cfg!`/`!cfg!`, lets a guard outlive its `if`, or misses an
    /// `rstest`, a qualified `test` or a case inside a nested module.
    #[test]
    fn the_skip_census_splits_guarded_from_silent_exits_exactly() {
        let file: syn::File = syn::parse_str(
            r"
            #[test]
            fn bare() { if probe() { return; } assert!(x); }
            #[test]
            fn guarded() { if !cfg!(unix) { return; } if cfg!(windows) { if other { return; } } }
            #[rstest]
            fn after_guard() { if cfg!(unix) {} return; }
            #[tokio::test]
            fn enclosed() { let f = || { return 1; }; fn inner() { return; } }
            fn helper() { return; }
            #[test]
            fn nothing() {}
            mod tests {
                #[test]
                fn nested() { return; }
            }
            ",
        )
        .expect("the fixture parses");
        assert_eq!(
            skip_census(&file),
            SkipCensus {
                cases: 6,
                guarded: 2,
                refused: ["bare", "after_guard", "nested"].map(String::from).to_vec(),
            }
        );
    }
}

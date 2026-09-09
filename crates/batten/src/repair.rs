//! Running a row's declared repair at the mediated boundary (CLOUD-1639).
//!
//! [`crate::rules::Rule::fix`] has existed since CLOUD-81 as "the mutating half
//! of §9's duality" and was executed by nothing. This is the half that executes
//! it — for the rows whose raised class declares
//! [`crate::verdict::Applicability::Retry`] or `Silent`, and no other.
//!
//! # NO NEW SPAWN SITE, AND THAT IS A GATE RATHER THAN A PREFERENCE
//!
//! `policy/spawn-widening.rego` refuses an ADDED `#[expect(clippy::disallowed_types)]`
//! escape, and CLOUD-1338 already collapsed two spawns in [`crate::exec`] into
//! one shared [`crate::exec::piped_through`] for exactly this reason: an
//! annotation records a spawn somebody decided on, and it is not the cheap way
//! past the lint. So a repair goes through [`crate::exec::piped_argv`], which
//! resolves the first word by name and hands back `(exit, output)`. This module
//! carries no `Command::new` and therefore no annotation of its own.
//!
//! It also inherits what that path already decided: the process group, the
//! forwarded signals, the pipe drain, and the diagnostics disposition.
//!
//! # WHAT A REPAIR MAY BE, AND WHY THE ANSWER IS THIS NARROW
//!
//! The string is the CONSUMER's, and the call being repaired is the AGENT's.
//! Keeping those apart is the whole safety argument:
//!
//! * **one substitution, `{key}`**, and it is a value the row itself resolved
//!   through `key_from`/`key_base` — for a receipt row, the tracker key the call
//!   named. Nothing from the command line reaches the repair, because a repair
//!   that could splice the refused command back in is the echo SRC-056 measures;
//! * **the key is shape-checked before it is spliced**. A row's `key_shape`
//!   already narrows it at the boundary, and [`resolve`] refuses anything
//!   carrying whitespace, a quote or a shell metacharacter on top of that. A
//!   `{key}` is a NAME, and a name that could be an argument break is not one;
//!   the substitution is into an already-split argv, so this is belt and braces
//!   rather than the only thing standing between here and an injection;
//! * **`shape` and `pipeline` rows take no substitution at all**, having no key
//!   to resolve — a `{key}` on one of those is refused at load rather than
//!   silently interpolating an empty string.
//!
//! # THE ORDER OF THE ARMS IS THE CONTRACT
//!
//! Run the fix. A non-zero exit, a program that will not resolve, or a bounded
//! wait that expires all fall back to the ORIGINAL class's ordinary refusal — a
//! repair that did not happen must never be reported as one, which is the single
//! most important property in this file. Only a zero exit reaches the postures,
//! and which posture is the CLASS's declaration rather than this module's guess.

use std::path::Path;

use crate::verdict::Applicability;

/// What running a repair produced.
///
/// Three outcomes and no fourth: the two the class can declare, and the failure
/// that collapses to the original refusal. [`Outcome::Failed`] carries nothing —
/// deliberately. The caller's fallback is the refusal it already composed, and a
/// reason string here would be a second explanation competing with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The repair ran and the class says re-issue the identical call.
    Retry,
    /// The repair ran and the class says proceed, owing a record.
    Silent,
    /// The repair did not happen. Fall back to the ordinary refusal.
    Failed,
}

/// The metacharacters a `{key}` may not carry.
///
/// Not a shell-quoting layer — the substitution goes into an already-split argv,
/// so there is no shell to quote for. This refuses a key that would be a
/// SURPRISE: whitespace splits a word in any reader's head even where it does
/// not here, and a quote or a redirect in a tracker key means the key is not a
/// tracker key and the row's `key_shape` is wrong about its own subject.
const REFUSED_IN_KEY: &[char] = &[
    ' ', '\t', '\n', '\r', '"', '\'', '`', '$', '\\', ';', '|', '&', '<', '>', '(', ')', '{', '}',
    '*', '?', '[', ']', '!', '#', '~',
];

/// The one substitution a `fix` string admits.
///
/// `None` when the string names `{key}` and no key resolved, or when the key
/// would carry something [`REFUSED_IN_KEY`] names — both are "this repair cannot
/// be composed", which the caller reads as [`Outcome::Failed`] and answers with
/// the ordinary refusal. Refusing to COMPOSE is the safe direction: the
/// alternative is running a command with an empty or surprising operand, and a
/// repair that repairs the wrong subject is worse than one that does not run.
///
/// A string naming no `{key}` is returned unchanged, which is every `shape` and
/// `pipeline` row.
#[must_use]
pub fn resolve(fix: &str, key: Option<&str>) -> Option<String> {
    const TOKEN: &str = "{key}";
    if !fix.contains(TOKEN) {
        return Some(fix.to_owned());
    }
    let key = key?;
    if key.is_empty() || key.contains(REFUSED_IN_KEY) {
        return None;
    }
    // TRAVERSAL IS A SEPARATE CONCERN FROM METACHARACTERS, and the adversarial
    // case above is what said so: `../../etc/passwd` carries none of the
    // characters that list names, so the list alone composed it. `/` cannot join
    // that list — a key legitimately naming a path (`rules/scanning.md`) is the
    // very thing a `document`-shaped repair operates on — so the discriminator is
    // `..`, which is what turns a path INSIDE the tree into one outside it.
    //
    // Refused rather than normalised: this module does not know whether the
    // repair will treat the key as a path at all, and a caller that resolved a
    // key containing `..` has a `key_shape` that is wrong about its subject.
    if key.split(['/', '\\']).any(|part| part == "..") {
        return None;
    }
    Some(fix.replace(TOKEN, key))
}

/// Split a resolved fix into argv, the way a caller would type it.
///
/// Whitespace splitting and nothing cleverer: a repair is a declared program and
/// its operands, not a shell line. A row needing a pipe, a redirect or a
/// variable is declaring a script, and the honest way to run a script is to name
/// one — which `key_shape`'s own refusal of whitespace in the key keeps
/// unambiguous.
#[must_use]
fn argv(resolved: &str) -> Vec<String> {
    resolved.split_whitespace().map(str::to_owned).collect()
}

/// Run a row's repair and say which arm the boundary takes.
///
/// `applicability` is the CLASS's declaration, read by the caller and passed in
/// rather than re-derived here: this module runs a command and reports, and
/// deciding which class a row raises is the boundary's job.
///
/// # The bounds, and where each is enforced
///
/// * **cwd is the repository root** — passed as `root`, which is
///   [`crate::exec::piped_argv`]'s resolve root as well, so a relative program
///   name cannot reach outside the tree;
/// * **no stdin** — a repair that wanted the payload would be reading the call
///   it is repairing, which is the coupling this module exists to refuse;
/// * **diagnostics dropped** — the child's output is not the caller's business
///   and is not echoed anywhere (rule 4). What the caller gets is the exit code;
/// * **the wall clock is the hook's**, inherited from the boundary that called
///   this. `perf-assert` prices the hook at 100 ms and a repair does not get its
///   own budget on top; a row whose fix cannot finish inside the boundary's
///   budget is a row that should not declare one.
#[must_use]
pub fn run(root: &Path, fix: &str, key: Option<&str>, applicability: Applicability) -> Outcome {
    // ADVICE NEVER REACHES THE SPAWN. Asked here as well as at the call site,
    // because this is the function that runs a command and a caller that got the
    // guard wrong would otherwise execute one for a class that declared nothing.
    if !applicability.repairs() {
        return Outcome::Failed;
    }
    let Some(resolved) = resolve(fix, key) else {
        return Outcome::Failed;
    };
    let words = argv(&resolved);
    if words.is_empty() {
        return Outcome::Failed;
    }
    // `Diagnostics::Drop`: the repair's own chatter is not a finding, and a
    // consumer's command could print anything at all.
    let Some((code, _output)) =
        crate::exec::piped_argv(root, &words, "", crate::exec::Diagnostics::Drop)
    else {
        // The program would not resolve. A declared repair naming something this
        // host does not have is a config defect, and the ordinary refusal is the
        // honest answer to the caller in front of it.
        return Outcome::Failed;
    };
    if code != 0 {
        return Outcome::Failed;
    }
    // THE ARMS, AND THEIR ORDER IS THE MUTATION SLUG'S SUBJECT. Swapping these
    // two reports a repaired-and-refused call as a repaired-and-allowed one,
    // which is the silent-rewrite posture arriving without anybody declaring it.
    //MUTANT-SUITE crates/batten/tests/it/cli.rs
    //MUTANT retry-reports-silent|s@        Applicability::Retry => Outcome::Retry,@        Applicability::Retry => Outcome::Silent,@|a_retry_repair_refuses_and_never_allows
    match applicability {
        Applicability::Retry => Outcome::Retry,
        Applicability::Silent => Outcome::Silent,
        // Unreachable past the guard above, and spelled rather than wildcarded so
        // a fourth posture is a compile error here.
        Applicability::Advice => Outcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fix_naming_no_key_is_returned_unchanged() {
        assert_eq!(
            resolve("mise run config-lint", None).as_deref(),
            Some("mise run config-lint")
        );
    }

    #[test]
    fn a_fix_naming_a_key_takes_the_rows_own_value() {
        assert_eq!(
            resolve("batten mcp call Linear get_issue {key}", Some("CLOUD-1639")).as_deref(),
            Some("batten mcp call Linear get_issue CLOUD-1639")
        );
    }

    #[test]
    fn a_key_the_row_could_not_resolve_refuses_to_compose() {
        // The safe direction: no repair rather than a repair over an empty
        // operand, which would repair the wrong subject or none.
        assert_eq!(resolve("get_issue {key}", None), None);
        assert_eq!(resolve("get_issue {key}", Some("")), None);
    }

    /// A key carrying a metacharacter is refused rather than spliced.
    ///
    /// The substitution goes into an already-split argv, so none of these is an
    /// injection today. They are refused because a tracker key containing one is
    /// not a tracker key, and the row's `key_shape` is then wrong about its own
    /// subject — which is worth a refusal rather than a surprising operand.
    #[test]
    fn a_key_that_could_surprise_a_reader_is_refused() {
        for hostile in [
            "CLOUD-1 CLOUD-2",
            "CLOUD-1;rm -rf /",
            "CLOUD-1|tee",
            "$(id)",
            "`id`",
            "CLOUD-1&&id",
        ] {
            assert_eq!(
                resolve("get_issue {key}", Some(hostile)),
                None,
                "a key carrying a metacharacter is refused: {hostile}"
            );
        }
    }

    /// A traversing key is refused, and it is NOT the metacharacter list that
    /// does it.
    ///
    /// Written as its own case because the first draft folded it into the
    /// metacharacter corpus and the corpus passed it: `../../etc/passwd` carries
    /// none of those characters. The two bounds are separate and both are
    /// needed, which one shared case would keep hiding.
    #[test]
    fn a_key_that_traverses_out_of_the_tree_is_refused() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "rules/../../../etc/passwd",
            "..\\..\\windows",
        ] {
            assert_eq!(
                resolve("read {key}", Some(hostile)),
                None,
                "a key that climbs out of the tree is refused: {hostile}"
            );
        }
    }

    #[test]
    fn a_path_shaped_key_without_metacharacters_still_composes() {
        // The bound is metacharacters, not "looks like a path" — narrowing it to
        // a judgement about shape would be this module deciding what a consumer's
        // key means, which `key_shape` is the authority on.
        assert_eq!(
            resolve("read {key}", Some("rules/scanning.md")).as_deref(),
            Some("read rules/scanning.md")
        );
    }

    #[test]
    fn an_advice_class_never_runs_a_repair() {
        // The guard, asserted at this function rather than only at the caller:
        // `run` is what spawns, so `run` is what must refuse.
        assert_eq!(
            run(
                Path::new("."),
                "definitely-not-a-program",
                None,
                Applicability::Advice
            ),
            Outcome::Failed
        );
    }

    #[test]
    fn a_program_that_will_not_resolve_is_a_failed_repair() {
        // And NOT a panic, and not a success: the ordinary refusal is what the
        // caller falls back to.
        assert_eq!(
            run(
                Path::new("."),
                "batten-no-such-program-1639",
                None,
                Applicability::Retry
            ),
            Outcome::Failed
        );
    }

    #[test]
    fn argv_is_a_program_and_operands_not_a_shell_line() {
        assert_eq!(argv("  batten   mcp call  "), vec!["batten", "mcp", "call"]);
        assert!(argv("   ").is_empty());
    }
}

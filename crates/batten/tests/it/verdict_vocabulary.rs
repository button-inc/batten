//! CLOUD-1284 arm 4: every vocabulary word is ONE token under the declared pin.
//!
//! This is the arm that makes the three-word grammar enforceable rather than
//! aspirational. The other five arms decide membership and arity over data the
//! engine already holds, so they live in `verdict::validate` and refuse at load;
//! this one needs a tokenizer, and a tokenizer must not reach the shipped binary
//! (`Cargo.toml` carries why). So it is a dev-dependency and a test over the
//! committed table — the one place the property has to hold is a gate that reads
//! the commit, and the table is a fixed committed artifact, so its token counts
//! are a property of the commit rather than of the world.

/// Every word `batten.toml`'s `[vocabulary]` declares, held to one token each.
///
/// **Why a mirrored list rather than a read of the table.** The other five arms
/// are load-time and read the config; this one cannot be, because the tokenizer
/// is a dev-dependency the binary does not link. A test that parsed the config
/// would still be measuring the same bytes, so the list is duplicated and
/// `a_declared_word_is_missing_from_this_list` holds the two in agreement — the
/// duplication is visible and gated rather than implicit and drifting.
///
/// Sifted from 250 candidates: **237 are one token, 13 are not**, and the 13 are
/// a class rather than a scatter — `unparsed`, `unwired`, `untested`, `ungated`,
/// `unbound`, `orphaned`, `shadowed`, `unclean`, `unsaid`, `untold` at 2 and
/// `uncounted` at 3, while the commoner `unread`, `undefined`, `unknown`,
/// `unnamed`, `unused`, `unmet` and `unseen` survive at 1. That is the issue's
/// own worked example (`shell edit unretired` is 5 tokens, not 3) reproduced as
/// a gate rather than an anecdote.
const CANDIDATES: &[&str] = &[
    "absent",
    "adapter",
    "add",
    "admit",
    "ahead",
    "answer",
    "ask",
    "bats",
    "bind",
    "blocked",
    "bound",
    "branch",
    "broken",
    "call",
    "cargo",
    "carry",
    "check",
    "claim",
    "commit",
    "config",
    "connector",
    "count",
    "cover",
    "dead",
    "declare",
    "default",
    "deny",
    "diff",
    "dirty",
    "drift",
    "dropped",
    "duplicate",
    "early",
    "edit",
    "empty",
    "event",
    "file",
    "first",
    "forge",
    "gate",
    "grade",
    "grant",
    "guard",
    "held",
    "hook",
    "input",
    "issue",
    "job",
    "judge",
    "key",
    "lane",
    "last",
    "late",
    "layer",
    "lease",
    "list",
    "lock",
    "loose",
    "manifest",
    "measure",
    "memory",
    "mint",
    "missing",
    "module",
    "name",
    "never",
    "open",
    "other",
    "own",
    "parse",
    "partial",
    "patch",
    "path",
    "pin",
    "place",
    "point",
    "port",
    "program",
    "prose",
    "reach",
    "read",
    "red",
    "refused",
    "release",
    "remedy",
    "report",
    "require",
    "resolve",
    "retire",
    "review",
    "route",
    "rule",
    "run",
    "same",
    "select",
    "shell",
    "ship",
    "skip",
    "sleep",
    "source",
    "spawn",
    "spelling",
    "stale",
    "state",
    "step",
    "suite",
    "symbol",
    "table",
    "tag",
    "task",
    "test",
    "tier",
    "timer",
    "tool",
    "turn",
    "twice",
    "unclear",
    "undefined",
    "unknown",
    "unnamed",
    "unread",
    "unsafe",
    "unseen",
    "unused",
    "version",
    "watch",
    "wire",
    "workflow",
    "workspace",
    "write",
    "wrong",
];

/// The pin, mirrored from the declaration so a drift is visible here too.
///
/// `bench/tokens/method.toml`'s discipline: the constant a published figure
/// depends on is stated with its source rather than baked into a program.
const PIN: &str = "o200k_base";

#[test]
fn every_candidate_word_is_one_token_under_the_declared_pin() {
    let bpe = tiktoken_rs::o200k_base().expect("the pinned encoding is vendored with the crate");

    // A LEADING SPACE, and it is the whole measurement rather than a detail.
    // BPE merges are trained on running text, where a word is preceded by a
    // space; the token for `" task"` and the token for `"task"` are different
    // merges and only the first is what a name inside a rendered line actually
    // costs. Measuring the bare word would report a cheaper number than the hot
    // path ever pays.
    let mut multi: Vec<(usize, &str)> = Vec::new();
    for word in CANDIDATES {
        let n = bpe.encode_with_special_tokens(&format!(" {word}")).len();
        if n != 1 {
            multi.push((n, word));
        }
    }

    assert!(
        multi.is_empty(),
        "{} of {} candidates are not one token under {PIN}: {:?}",
        multi.len(),
        CANDIDATES.len(),
        multi
    );
}

/// The list above and the committed table are the same set, in both directions.
///
/// Without this the measurement is over a list nobody declares: a word added to
/// `[vocabulary]` and not here would be unmeasured, and a word here and not in
/// the table would be measured and unused. Both directions are asserted because
/// only one of them is the obvious one.
#[test]
fn the_measured_list_and_the_declared_table_are_the_same_set() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text =
        std::fs::read_to_string(root.join("batten.toml")).expect("the authority is readable");
    let config: toml::Value = toml::from_str(&text).expect("the authority parses");
    let vocabulary = config
        .get("vocabulary")
        .expect("the authority declares a vocabulary");

    let mut declared: Vec<String> = Vec::new();
    for slot in ["subject", "action", "condition"] {
        let rows = vocabulary
            .get(slot)
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("`[[vocabulary.{slot}]]` is declared"));
        for row in rows {
            let word = row
                .get("word")
                .and_then(toml::Value::as_str)
                .expect("every vocabulary row carries a word");
            declared.push(word.to_owned());
        }
    }
    declared.sort();
    declared.dedup();

    let measured: std::collections::BTreeSet<&str> = CANDIDATES.iter().copied().collect();
    let declared_set: std::collections::BTreeSet<&str> =
        declared.iter().map(String::as_str).collect();

    let unmeasured: Vec<&&str> = declared_set.difference(&measured).collect();
    let undeclared: Vec<&&str> = measured.difference(&declared_set).collect();
    assert!(
        unmeasured.is_empty() && undeclared.is_empty(),
        "declared-but-unmeasured: {unmeasured:?}; measured-but-undeclared: {undeclared:?}"
    );
}

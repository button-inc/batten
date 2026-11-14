//! No instruction surface and no path-valued setting names a shell script or a
//! bats suite that is not in the tree (CLOUD-2740).
//!
//! The authored shell retired file by file, and the prose that routed by it did
//! not: an always-loaded index sent an editor to a suite glob matching nothing,
//! a live refusal routed its reader to a deleted script, and the lease guarded
//! two paths that no longer exist. A reader follows a named path, so a name
//! that resolves to nothing is an instruction that cannot be followed.
//!
//! TWO READINGS, ONE PREDICATE. On an instruction surface a token is a code
//! span, a whitespace-separated word of a fenced block, or a `paths:` entry of
//! a rule file's front matter. In the committed authority it is a refusal's
//! route target or a lease landing path. A token carrying one of the two
//! suffixes must name a tracked file, and one holding a wildcard must match one.
//!
//! WHAT IT CANNOT SEE: plain prose. Whether a sentence is history or a claim is
//! a judgement, and a gate may not rest on one, so a name outside a code span is
//! never read.
//!
//! THE NEEDLES ARE ASSEMBLED, NEVER SPELLED (`rules/scanning.md`): this file is
//! scanned by the censuses that scan the tree, and its last case holds it to
//! carrying neither suffix whole.

/*
#MUTANT-SUITE crates/batten/tests/it/missing_shell_named.rs
#MUTANT untracked-shell-name-passes|s@^        return tracked.contains(name);$@        return true;@|a_code_spanned_script_must_be_tracked_and_plain_prose_is_not_read
#MUTANT glob-with-no-match-passes|s@^    tracked.iter().any(|path| glob.is_match(path))$@    true@|a_glob_needs_a_match
#MUTANT front-matter-paths-unread|s@^    found.extend(front_matter_paths(text));$@@|a_front_matter_path_is_judged
#MUTANT verdict-route-target-unread|s@^        values.extend(strings(route.get("target")));$@@|a_route_target_and_a_landing_path_are_judged
#MUTANT landing-path-unread|s@^    values.extend(strings(landing));$@@|a_route_target_and_a_landing_path_are_judged
#MUTANT stale-tolerated-pair-passes|s@^    let stale = tolerated.difference(found).cloned().collect();$@    let stale = Vec::new();@|the_list_only_shrinks
#MUTANT line-suffix-breaks-match|s@^    let name = without_line(&name);$@@|a_line_suffix_is_ignored
#MUTANT plain-prose-reported|s@^    let spanned = prose.split('`').skip(1).step_by(2);$@    let spanned = prose.split_whitespace();@|a_code_spanned_script_must_be_tracked_and_plain_prose_is_not_read
*/
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use crate::common;

/// A surface or setting file, and the name in it that resolves to nothing.
type Pair = (String, String);

/// The two suffixes, assembled so this file never spells one.
fn script() -> String {
    [".", "sh"].concat()
}

fn suite() -> String {
    [".", "bats"].concat()
}

/// The instruction surfaces, as globs over the tracked set.
const SURFACES: [&str; 8] = [
    "AGENTS.md",
    "rules/*.md",
    ".claude/rules/*.md",
    ".claude/commands/*.md",
    "CONTRIBUTING.md",
    "README.md",
    "skills/**/SKILL.md",
    ".serena/memories/**/*.md",
];

/// The names other rows remove, as `(file, stem, suffix)`: the retirement
/// doctrine CLOUD-2337 deletes still speaks of the two globs. Held exactly, so
/// the list can only shrink.
fn tolerated() -> BTreeSet<Pair> {
    let scripts = format!("mise-tasks/*{}", script());
    let suites = format!("tests/**/*{}", suite());
    [
        ("rules/toolchain.md", &scripts),
        ("rules/toolchain.md", &suites),
        (".serena/memories/toolchain-and-hooks.md", &scripts),
        (".serena/memories/toolchain-and-hooks.md", &suites),
        (".serena/memories/core.md", &scripts),
        (".serena/memories/core.md", &suites),
    ]
    .into_iter()
    .map(|(file, name)| (file.to_owned(), name.clone()))
    .collect()
}

/// One trailing `:line`, removed.
fn without_line(name: &str) -> String {
    match name.rsplit_once(':') {
        Some((path, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => {
            path.to_owned()
        }
        _ => name.to_owned(),
    }
}

/// The name a token carries, when it is one this file judges.
///
/// Backslashes go first, then one trailing `:line`, then one trailing wildcard.
/// What remains is in scope when it ends in a suffix with something before it.
/// A template — a token holding an angle bracket or a dollar — is not a path,
/// and neither is an address with a scheme. A leading `./` names the root.
fn named(token: &str) -> Option<String> {
    let name = token.replace('\\', "");
    let name = without_line(&name);
    let name = name.strip_suffix('*').unwrap_or(&name);
    let name = name.strip_prefix("./").unwrap_or(name);
    let in_scope = [script(), suite()]
        .iter()
        .any(|suffix| name.len() > suffix.len() && name.ends_with(suffix.as_str()));
    let template = name.contains(['<', '>', '$']);
    let address = name.contains("://");
    (in_scope && !template && !address).then(|| name.to_owned())
}

/// Whether `name` is a tracked file, or a wildcard matching one.
fn resolves(tracked: &BTreeSet<String>, name: &str) -> bool {
    if !name.contains('*') {
        return tracked.contains(name);
    }
    let Ok(glob) = globset::Glob::new(name) else {
        return false;
    };
    let glob = glob.compile_matcher();
    tracked.iter().any(|path| glob.is_match(path))
}

/// The code spans of one paragraph of prose.
fn spans(prose: &str, found: &mut Vec<String>) {
    let spanned = prose.split('`').skip(1).step_by(2);
    found.extend(spanned.map(|span| span.trim().to_owned()));
}

/// The `paths:` entries of a rule file's front matter.
fn front_matter_paths(text: &str) -> Vec<String> {
    let Some(rest) = text.strip_prefix("---\n") else {
        return Vec::new();
    };
    let Some((head, _)) = rest.split_once("\n---") else {
        return Vec::new();
    };
    head.lines()
        .skip_while(|line| line.trim() != "paths:")
        .skip(1)
        .map_while(|line| line.trim().strip_prefix("- "))
        .map(|entry| entry.trim_matches(['"', '\'']).to_owned())
        .collect()
}

/// Every token of one instruction surface.
fn tokens(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    found.extend(front_matter_paths(text));
    let mut prose = String::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            spans(&prose, &mut found);
            prose.clear();
        } else if fenced {
            found.extend(line.split_whitespace().map(str::to_owned));
        } else if line.trim().is_empty() {
            spans(&prose, &mut found);
            prose.clear();
        } else {
            prose.push_str(line.trim());
            prose.push(' ');
        }
    }
    spans(&prose, &mut found);
    found
}

/// The names on one surface that resolve to nothing.
fn unresolved(tracked: &BTreeSet<String>, file: &str, text: &str) -> BTreeSet<Pair> {
    tokens(text)
        .iter()
        .filter_map(|token| named(token))
        .filter(|name| !resolves(tracked, name))
        .map(|name| (file.to_owned(), name))
        .collect()
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::String(one)) => vec![one.clone()],
        Some(toml::Value::Array(many)) => many
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The path-valued settings of one authority that resolve to nothing.
fn unresolved_settings(tracked: &BTreeSet<String>, file: &str, config: &str) -> BTreeSet<Pair> {
    let authority: toml::Value = toml::from_str(config).expect("the authority is TOML");
    let mut values = Vec::new();
    let verdicts = authority.get("verdict").and_then(toml::Value::as_array);
    let routes = verdicts
        .into_iter()
        .flatten()
        .filter_map(|verdict| verdict.get("route").and_then(toml::Value::as_array))
        .flatten();
    for route in routes {
        values.extend(strings(route.get("target")));
    }
    let landing = authority
        .get("lease")
        .and_then(|lease| lease.get("landing_paths"));
    values.extend(strings(landing));
    values
        .iter()
        .filter_map(|value| named(value))
        .filter(|name| !resolves(tracked, name))
        .map(|name| (file.to_owned(), name))
        .collect()
}

/// What the tolerated list does not cover, and what it covers that is gone.
fn judged(found: &BTreeSet<Pair>, tolerated: &BTreeSet<Pair>) -> (Vec<Pair>, Vec<Pair>) {
    let fresh = found.difference(tolerated).cloned().collect();
    let stale = tolerated.difference(found).cloned().collect();
    (fresh, stale)
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|path| (*path).to_owned()).collect()
}

fn pair(file: &str, name: &str) -> BTreeSet<Pair> {
    BTreeSet::from([(file.to_owned(), name.to_owned())])
}

/// The tracked set, from git: the real root when the staged tree a mutation
/// sweep reads through carries no repository.
fn tracked() -> BTreeSet<String> {
    let listed = common::git_in(&common::at_root("."), &["ls-files"]);
    listed.lines().map(str::to_owned).collect()
}

#[test]
fn the_committed_tree_names_no_missing_shell() {
    let tracked = tracked();
    assert!(
        tracked.contains("AGENTS.md"),
        "the premise: git lists the tree"
    );
    let surfaces = globset::GlobSetBuilder::new();
    let surfaces = SURFACES
        .iter()
        .fold(surfaces, |mut set, glob| {
            set.add(
                globset::GlobBuilder::new(glob)
                    .literal_separator(true)
                    .build()
                    .unwrap(),
            );
            set
        })
        .build()
        .unwrap();
    let mut found = BTreeSet::new();
    for file in tracked.iter().filter(|file| surfaces.is_match(file)) {
        let text = std::fs::read_to_string(common::at_root(file)).unwrap();
        found.extend(unresolved(&tracked, file, &text));
    }
    let config = std::fs::read_to_string(common::at_root("batten.toml")).unwrap();
    found.extend(unresolved_settings(&tracked, "batten.toml", &config));
    let (fresh, stale) = judged(&found, &tolerated());
    assert!(
        fresh.is_empty(),
        "these name a script or suite that is not tracked; name what does the job today: {fresh:#?}"
    );
    assert!(
        stale.is_empty(),
        "these tolerated pairs no longer occur; drop them from the list: {stale:#?}"
    );
}

#[test]
fn a_code_spanned_script_must_be_tracked_and_plain_prose_is_not_read() {
    let gone = format!("tools/gone{}", script());
    let kept = format!("tools/kept{}", script());
    let tracked = set(&[&kept]);
    let spanned = format!("Run `{gone}` first, then `{kept}`.\n");
    assert_eq!(
        unresolved(&tracked, "rules/x.md", &spanned),
        pair("rules/x.md", &gone)
    );
    let plain = format!("The retired {gone} did this once.\n");
    assert!(unresolved(&tracked, "rules/x.md", &plain).is_empty());
}

#[test]
fn a_line_suffix_is_ignored() {
    let gone = format!("tools/gone{}", script());
    let kept = format!("tools/kept{}", script());
    let tracked = set(&[&kept]);
    let text = format!("See `{kept}:845` and `{gone}:12`.\n");
    assert_eq!(
        unresolved(&tracked, "rules/x.md", &text),
        pair("rules/x.md", &gone)
    );
}

#[test]
fn a_glob_needs_a_match() {
    let glob = format!("tests/**/*{}", suite());
    let text = format!("Editing `{glob}`? Read this.\n");
    assert_eq!(
        unresolved(&set(&["README.md"]), "AGENTS.md", &text),
        pair("AGENTS.md", &glob)
    );
    let one = format!("tests/it/land{}", suite());
    assert!(unresolved(&set(&[&one]), "AGENTS.md", &text).is_empty());
}

#[test]
fn a_front_matter_path_is_judged() {
    let glob = format!("tests/*{}", suite());
    let text = format!("---\npaths:\n  - \"mise.toml\"\n  - \"{glob}\"\n---\n\n# Moved\n");
    assert_eq!(
        unresolved(&set(&["mise.toml"]), ".claude/rules/x.md", &text),
        pair(".claude/rules/x.md", &glob)
    );
}

#[test]
fn a_route_target_and_a_landing_path_are_judged() {
    let target = format!("mise-tasks/landed-check{}", script());
    let landing = format!("mise-tasks/land{}", script());
    let tracked = set(&["crates/batten/src/land.rs"]);
    let routed = format!(
        "[[verdict]]\nid = \"a b c\"\n[[verdict.route]]\nid = \"task run first\"\n\
         kind = \"document\"\ntarget = \"{target}\"\n"
    );
    assert_eq!(
        unresolved_settings(&tracked, "batten.toml", &routed),
        pair("batten.toml", &target)
    );
    let leased =
        format!("[lease]\nlanding_paths = [\"crates/batten/src/land.rs\", \"{landing}\"]\n");
    assert_eq!(
        unresolved_settings(&tracked, "batten.toml", &leased),
        pair("batten.toml", &landing)
    );
}

#[test]
fn what_is_not_a_path_is_skipped_and_what_is_one_is_not() {
    let gone = format!("tools/gone{}", script());
    let tracked = set(&["README.md"]);
    let skipped = format!(
        "An extension `{bare}`, a template `mise-tasks/<gate>{sh}`, and a variable `$HOME/x{sh}`.\n",
        bare = script(),
        sh = script(),
    );
    assert!(unresolved(&tracked, "rules/x.md", &skipped).is_empty());

    let fetched = format!(
        "```sh\ncurl -fsSL https://example.invalid/main/install{sh} | sh\n./kept{sh}\n```\n",
        sh = script(),
    );
    let kept = format!("kept{}", script());
    assert!(
        unresolved(&set(&[&kept]), "README.md", &fetched).is_empty(),
        "an address is not a tree path, and a leading `./` names the root"
    );

    let escaped = format!("A glob written `tools/\\*{}` in a table.\n", script());
    assert_eq!(
        unresolved(&tracked, "rules/x.md", &escaped),
        pair("rules/x.md", &format!("tools/*{}", script())),
        "a backslash before the wildcard is read as if it were absent"
    );

    let prefixed = format!("Every `{gone}*` file.\n");
    assert_eq!(
        unresolved(&tracked, "rules/x.md", &prefixed),
        pair("rules/x.md", &gone)
    );

    let fenced = format!("```sh\nbash {gone} --flag\n```\n");
    assert_eq!(
        unresolved(&tracked, "rules/x.md", &fenced),
        pair("rules/x.md", &gone)
    );
}

#[test]
fn the_list_only_shrinks() {
    let gone = format!("tools/gone{}", script());
    let found = pair("rules/x.md", &gone);
    let (fresh, stale) = judged(&found, &found);
    assert!(fresh.is_empty() && stale.is_empty());

    let (fresh, stale) = judged(&BTreeSet::new(), &found);
    assert!(fresh.is_empty());
    assert_eq!(
        stale,
        vec![("rules/x.md".to_owned(), gone.clone())],
        "a tolerated pair that occurs nowhere is named"
    );

    let (fresh, _) = judged(&found, &BTreeSet::new());
    assert_eq!(fresh, vec![("rules/x.md".to_owned(), gone)]);
}

#[test]
fn the_scanner_does_not_match_itself() {
    let own = std::fs::read_to_string(common::at_root(
        "crates/batten/tests/it/missing_shell_named.rs",
    ))
    .unwrap();
    for suffix in [script(), suite()] {
        assert!(
            !own.contains(&suffix),
            "this file spells a suffix whole, so a census over the tree reads it as a name"
        );
    }
}

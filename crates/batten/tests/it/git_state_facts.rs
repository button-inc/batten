//! The repository-STATE git facts, over the compiled binary (CLOUD-843, package
//! a-git): `input.tree["git-tags"]`, `["git-config"]`, `["git-index"]`, and the
//! widened `["commit-meta"]`.
//!
//! # Why these four, and why here
//!
//! Forty-five `mise.toml` bodies spawn `git` to READ a fact and then decide over
//! it in shell. The reads fall into four shapes — which tags exist and when each
//! was cut, what a range's commits carry, how the checkout's config resolves a
//! signing key, and what the index holds under a set of paths — and each is now a
//! declared projection a module decides over. This tier is what shows the engine
//! FILLS the key a module reads; a `with input as` case fabricates exactly the
//! shape the engine may be unable to produce (CLOUD-845, CLOUD-857).
//!
//! # The reference implementation is the oracle
//!
//! Every positive here is asserted twice over the same repository: once through
//! the projection, by a probe module that fires only on the exact shape, and once
//! through the `git` command the retiring bodies ran (`tag --list`, `cat-file`,
//! `config --type=bool`, `ls-files -s`, `diff --name-only`, `ls-files
//! --others`). Where the two could disagree, the case pins that they do not — the
//! replay the retirement owes, taken at the fact rather than at each body.
//!
//! # Could-not-look is not an empty answer
//!
//! The family's standing rule, one level down each time: a glob matching no tag
//! is an EMPTY list, a key no scope sets has a NULL `effective`, and an
//! undeclared family is `null`. Each is asserted on its own arm, because a
//! module that confuses them decides over a repository nobody looked at.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, batten, git_command, git_in, run, scratch, stderr, stdout, write};

/// A tree-scoped `policy` row declaring `declares`, with a warn-severity probe.
///
/// The module is the assertion: it raises a finding when its predicate HOLDS, so
/// a case reads its verdict off whether the rule id appears in stdout.
fn config(declares: &str) -> String {
    format!(
        "version = 1\n\
         \n\
         [[rule]]\n\
         id = \"state-probe\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         module = \"policy/probe.rego\"\n\
         severity = \"warn\"\n\
         no_fix_reason = \"this row exists to report what the engine emitted\"\n\
         {declares}\
         \n\
         [[verdict]]\n\
         id = \"the predicate held\"\n\
         gloss = \"the probe predicate held\"\n\
         class = \"What this fixture's probe asserts, at the length explain answers with.\"\n\
         \n\
         [[verdict.route]]\n\
         id = \"read the probe\"\n\
         kind = \"document\"\n\
         target = \"policy/probe.rego\"\n"
    )
}

/// The Rego module, wrapping `body` as the violation condition.
fn module(body: &str) -> String {
    format!(
        "package batten\n\
         \n\
         rules contains \"state-probe\"\n\
         \n\
         violation contains {{\n\
         \t\"rule\": \"state-probe\",\n\
         \t\"verdict\": \"the predicate held\",\n\
         }} if {{\n\
         {body}\n\
         }}\n"
    )
}

/// A committed fixture whose one rule declares `declares` and asserts `body`.
fn repo(name: &str, declares: &str, body: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config(declares))
        .file("policy/probe.rego", &module(body))
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build()
}

/// Whether the probe fired, with the run asserted to have DECIDED first.
///
/// The exit status before the verdict, because the absence of a rule id in stdout
/// is evidence only if the run reached policy evaluation: a run that died at
/// config load prints nothing and would satisfy every negative for the wrong
/// reason.
fn fired(dir: &Path) -> bool {
    decided(dir, &run(dir, &["check"]))
}

fn decided(dir: &Path, output: &std::process::Output) -> bool {
    assert_eq!(
        output.status.code(),
        Some(0),
        "a warn-severity row in {}: the run has to decide for its verdict to mean anything\n{}{}",
        dir.display(),
        stdout(output),
        stderr(output)
    );
    stdout(output).contains("state-probe")
}

/// `git` with extra environment — pinned dates, a controlled global config.
fn git_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut command = git_command(dir, args);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout is UTF-8")
        .trim_end()
        .to_owned()
}

/// 2020-01-02T03:04:05Z, as git reads an instant.
const AUTHORED: &str = "@1577934245 +0000";
/// 2021-06-01T12:00:00Z.
const LATER: &str = "@1622548800 +0000";

// --- git-tags ---------------------------------------------------------------

#[test]
fn a_tag_glob_lists_the_tags_it_matches_and_no_others() {
    // `v[0-9]*` is the release glob the retiring bodies list, and `git tag
    // --list` is the oracle: two of the four tags match, one lightweight and one
    // annotated, and neither `other` nor `vnext` does. A projection that listed
    // every tag, or matched through a selector whose `[0-9]` meant something
    // else, would count four or three.
    let dir = repo(
        "git-tags-glob",
        "tags = [\"v[0-9]*\"]\n",
        "\tlisted := input.tree[\"git-tags\"][\"v[0-9]*\"]\n\
         \tcount(listed) == 2\n\
         \tlisted[0].tag == \"v0.1.0\"\n\
         \tnot listed[0].annotated\n\
         \tlisted[1].tag == \"v0.2.0\"\n\
         \tlisted[1].annotated",
    );
    git_in(&dir, &["tag", "v0.1.0"]);
    git_in(&dir, &["tag", "-a", "v0.2.0", "-m", "release"]);
    git_in(&dir, &["tag", "other"]);
    git_in(&dir, &["tag", "vnext"]);
    assert_eq!(
        git_in(&dir, &["tag", "--list", "v[0-9]*"]),
        "v0.1.0\nv0.2.0",
        "the oracle's own listing"
    );
    assert!(
        fired(&dir),
        "the glob selects exactly what `git tag --list` selects, sorted by name"
    );
}

#[test]
fn a_tag_is_dated_by_its_tagger_when_annotated_and_by_its_commit_when_not() {
    // git's `creatordate`: the TAGGER's time for an annotated tag, the commit's
    // committer time for a lightweight one. Both tags sit on one commit dated a
    // year before the annotated tag was cut, so the two readings disagree and a
    // projection that took either date for both answers one tag wrongly.
    let dir = Fixture::new("git-tags-dates")
        .config(&config("tags = [\"v*\"]\n"))
        .file(
            "policy/probe.rego",
            &module(
                "\tsome light in input.tree[\"git-tags\"][\"v*\"]\n\
                 \tlight.tag == \"v1\"\n\
                 \tlight.created == \"2020-01-02T03:04:05Z\"\n\
                 \tlight.committed == \"2020-01-02T03:04:05Z\"\n\
                 \tsome heavy in input.tree[\"git-tags\"][\"v*\"]\n\
                 \theavy.tag == \"v2\"\n\
                 \theavy.created == \"2021-06-01T12:00:00Z\"\n\
                 \theavy.committed == \"2020-01-02T03:04:05Z\"",
            ),
        )
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    let dated = [
        ("GIT_AUTHOR_DATE", AUTHORED),
        ("GIT_COMMITTER_DATE", AUTHORED),
    ];
    git_env(&dir, &["commit", "-q", "-m", "dated"], &dated);
    git_in(&dir, &["tag", "v1"]);
    git_env(
        &dir,
        &["tag", "-a", "v2", "-m", "release"],
        &[("GIT_COMMITTER_DATE", LATER)],
    );
    // The oracle's reading of the same two tags, so the fixture's premise is
    // asserted rather than assumed.
    assert_eq!(
        git_in(
            &dir,
            &[
                "for-each-ref",
                "--sort=refname",
                "--format=%(refname:short) %(creatordate:unix)",
                "refs/tags"
            ]
        ),
        "v1 1577934245\nv2 1622548800"
    );
    assert!(
        fired(&dir),
        "each tag carries git's creatordate and its commit's date"
    );
}

#[test]
fn a_glob_matching_no_tag_is_an_empty_list_and_an_undeclared_one_is_null() {
    // THE FAMILY'S RULE ONE LEVEL DOWN. `no release tags exist` is an ANSWER a
    // release gate decides on; `nobody asked` is not. Collapsing the two would
    // report a tagless clone as an unreadable one, or the reverse.
    let empty = repo(
        "git-tags-empty",
        "tags = [\"v*\"]\n",
        "\tinput.tree[\"git-tags\"][\"v*\"] == []",
    );
    assert!(fired(&empty), "a declared glob matching nothing is []");

    let not_null = repo(
        "git-tags-empty-not-null",
        "tags = [\"v*\"]\n",
        "\tinput.tree[\"git-tags\"] == null",
    );
    assert!(!fired(&not_null), "a declared glob is never read as null");

    let undeclared = repo(
        "git-tags-undeclared",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-tags\"] == null",
    );
    assert!(
        fired(&undeclared),
        "an undeclared family acquires nothing and projects null"
    );
}

#[test]
fn a_tag_listing_answers_on_a_shallow_clone() {
    // THE DIFFERENCE FROM `git-history`, and the reason this is its own fact.
    // That family nulls on a shallow repository because a path query walks
    // history it cannot see; a tag listing walks none, and CI checks out
    // shallow.
    let source = repo(
        "git-tags-shallow-source",
        "tags = [\"v*\"]\n",
        "\tcount(input.tree[\"git-tags\"][\"v*\"]) == 1",
    );
    git_in(&source, &["tag", "-a", "v1.0.0", "-m", "release"]);
    let parent = scratch("git-tags-shallow");
    let url = format!("file://{}", source.display());
    git_in(&parent, &["clone", "-q", "--depth", "1", &url, "clone"]);
    let clone = parent.join("clone");
    // Both premises, asserted: the clone IS shallow and DOES carry the tag.
    assert_eq!(
        git_in(&clone, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );
    assert_eq!(git_in(&clone, &["tag", "--list", "v*"]), "v1.0.0");
    assert!(
        fired(&clone),
        "a shallow clone still lists the tags it carries"
    );
}

// --- commit-meta, widened ---------------------------------------------------

#[test]
fn commit_meta_carries_the_subject_the_dates_and_the_paths_a_commit_touched() {
    // `show --name-only` against the FIRST parent, `%s`, `%aI` and `%cI` — the
    // fields `commit-lint` reads per commit. Authored and committed are pinned a
    // year apart so a projection that took one for the other answers wrongly, and
    // the base carries a file the commit does NOT touch so a diff against the
    // empty tree would name it.
    let dir = repo(
        "commit-meta-widened",
        "commits = [\"HEAD~1..HEAD\"]\n",
        "\tsome entry in input.tree[\"commit-meta\"][\"HEAD~1..HEAD\"]\n\
         \tentry.subject == \"feat: second\"\n\
         \tentry.authored == \"2020-01-02T03:04:05Z\"\n\
         \tentry.committed == \"2021-06-01T12:00:00Z\"\n\
         \tentry.paths == [\"src/added.rs\", \"src/lib.rs\"]\n\
         \tentry.signed == false\n\
         \tentry.trailers == [\"Refs: X-1\"]",
    );
    write(&dir, "src/added.rs", "fn added() {}\n");
    write(&dir, "src/lib.rs", "fn main() { /* edited */ }\n");
    git_in(&dir, &["add", "-A"]);
    git_env(
        &dir,
        &[
            "commit",
            "-q",
            "-m",
            "feat: second\n\nA body that must not reach the input.\n\nRefs: X-1",
        ],
        &[("GIT_AUTHOR_DATE", AUTHORED), ("GIT_COMMITTER_DATE", LATER)],
    );
    // The oracle's reading of the same commit.
    assert_eq!(
        git_in(&dir, &["show", "--name-only", "--format=", "HEAD"]),
        "src/added.rs\nsrc/lib.rs"
    );
    let output = run(&dir, &["check"]);
    assert!(
        decided(&dir, &output),
        "the widened fields reach the module\n{}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("must not reach"),
        "a message body reached the output"
    );
}

/// Write one raw commit object and return its id.
///
/// The reference implementation writes it, from a file, because a signature
/// HEADER cannot be produced without a signing program — and the property under
/// test is where the word appears, not whether a key verifies.
fn raw_commit(dir: &Path, name: &str, body: &str) -> String {
    write(dir, name, body);
    let id = git_in(dir, &["hash-object", "-t", "commit", "-w", name]);
    std::fs::remove_file(dir.join(name)).expect("remove the raw object file");
    id
}

#[test]
fn a_signature_header_reads_signed_and_the_same_word_in_a_body_does_not() {
    // THE RETIRING SIGNING SCAN, REPLAYED. `signing-posture-record` read
    // `cat-file commit | sed '/^$/q'` and matched `gpgsig ` at a line start —
    // the HEADER, never the message, because a `gpgsig` line a body carries is
    // prose somebody typed. Two commits: one with the header, one whose BODY
    // spells the header. The old reading and the projection must agree on both.
    let dir = repo(
        "commit-meta-signed",
        "commits = [\"HEAD~2..HEAD\"]\n",
        "\tsome signed in input.tree[\"commit-meta\"][\"HEAD~2..HEAD\"]\n\
         \tsigned.subject == \"signed one\"\n\
         \tsigned.signed\n\
         \tsome prose in input.tree[\"commit-meta\"][\"HEAD~2..HEAD\"]\n\
         \tprose.subject == \"body mentions it\"\n\
         \tnot prose.signed",
    );
    let tree = git_in(&dir, &["rev-parse", "HEAD^{tree}"]);
    let base = git_in(&dir, &["rev-parse", "HEAD"]);
    let identity = "t <t@example.com> 1577934245 +0000";
    let signed = raw_commit(
        &dir,
        "signed.raw",
        &format!(
            "tree {tree}\nparent {base}\nauthor {identity}\ncommitter {identity}\n\
             gpgsig -----BEGIN PGP SIGNATURE-----\n \n not a real signature\n \
             -----END PGP SIGNATURE-----\n\nsigned one\n"
        ),
    );
    let prose = raw_commit(
        &dir,
        "prose.raw",
        &format!(
            "tree {tree}\nparent {signed}\nauthor {identity}\ncommitter {identity}\n\n\
             body mentions it\n\ngpgsig this line is prose in a message\n"
        ),
    );
    git_in(&dir, &["update-ref", "refs/heads/main", &prose]);

    // The old body's reading, over the same two commits.
    let old: Vec<String> = git_in(&dir, &["rev-list", "--no-merges", &format!("{base}..HEAD")])
        .lines()
        .filter(|sha| {
            let object = git_in(&dir, &["cat-file", "commit", sha]);
            let header = object.split("\n\n").next().unwrap_or_default();
            format!("\n{header}").contains("\ngpgsig ")
        })
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(
        old,
        [signed],
        "the retiring scan flags the header and only it"
    );
    assert!(
        fired(&dir),
        "the projection agrees: the header reads signed and the body does not"
    );
}

// --- git-config -------------------------------------------------------------

/// A global config file for the fixture, and the environment that points git —
/// and the binary — at it and at nothing wider.
fn global_config(dir: &Path, contents: &str) -> Vec<(String, String)> {
    let path = dir.join("global.gitconfig");
    std::fs::write(&path, contents).expect("write the global config");
    vec![
        (
            "GIT_CONFIG_GLOBAL".to_owned(),
            path.to_string_lossy().into_owned(),
        ),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
    ]
}

/// `batten check` under `env`, answering whether the probe fired.
fn fired_with(dir: &Path, env: &[(String, String)]) -> bool {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    for (name, value) in env {
        command.env(name, value);
    }
    decided(dir, &command.output().expect("run batten check"))
}

/// The oracle's `git config` reading under the same environment.
fn git_config(dir: &Path, env: &[(String, String)], args: &[&str]) -> String {
    let pairs: Vec<(&str, &str)> = env
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut command = git_command(dir, args);
    for (name, value) in pairs {
        command.env(name, value);
    }
    let output = command.output().expect("run git config");
    String::from_utf8(output.stdout)
        .expect("git stdout is UTF-8")
        .trim_end()
        .to_owned()
}

#[test]
fn git_config_reports_the_value_in_force_and_what_each_scope_set() {
    // THE SIGNING POSTURE'S CONFLICT, which is the whole reason this fact is per
    // scope. A GLOBAL `commit.gpgsign = 1` (a boolean the literal `true` does not
    // match) against a LOCAL `off` (one `false` does not match): the retiring
    // body needed `--type=bool` on both reads to get either right, and the value
    // in force is the local one. `tag.gpgSign` is IMPLICIT — no `=` — which git
    // reads as true and has no text for.
    let dir = repo(
        "git-config-scopes",
        "git_config = [\"commit.gpgsign\", \"user.signingkey\", \"tag.gpgsign\", \"gpg.format\"]\n",
        "\tsign := input.tree[\"git-config\"][\"commit.gpgsign\"]\n\
         \tsign.scopes[\"global\"] == {\"value\": \"1\", \"boolean\": true}\n\
         \tsign.scopes[\"local\"] == {\"value\": \"off\", \"boolean\": false}\n\
         \tsign.effective == {\"value\": \"off\", \"boolean\": false}\n\
         \tinput.tree[\"git-config\"][\"user.signingkey\"].effective.value == \"/nonexistent/key\"\n\
         \tinput.tree[\"git-config\"][\"tag.gpgsign\"].effective == {\"value\": null, \"boolean\": true}\n\
         \tinput.tree[\"git-config\"][\"gpg.format\"].effective == null\n\
         \tinput.tree[\"git-config\"][\"gpg.format\"].scopes == {}",
    );
    let env = global_config(
        &dir,
        "[commit]\n\tgpgsign = 1\n[user]\n\tsigningkey = /nonexistent/key\n[tag]\n\tgpgSign\n",
    );
    git_in(&dir, &["config", "commit.gpgsign", "off"]);
    // The oracle, over the same scopes the retiring body read.
    let bool_get = |scope: &str| {
        git_config(
            &dir,
            &env,
            &["config", "--type=bool", scope, "--get", "commit.gpgsign"],
        )
    };
    assert_eq!(bool_get("--global"), "true");
    assert_eq!(bool_get("--local"), "false");
    assert_eq!(
        git_config(
            &dir,
            &env,
            &["config", "--type=bool", "--get", "commit.gpgsign"]
        ),
        "false",
        "the value in force is the local one"
    );
    assert_eq!(
        git_config(
            &dir,
            &env,
            &["config", "--type=bool", "--get", "tag.gpgsign"]
        ),
        "true",
        "an implicit key reads true"
    );
    assert!(
        fired_with(&dir, &env),
        "each scope's value, git's boolean reading of it, and the value in force"
    );
}

#[test]
fn a_config_key_git_cannot_address_is_refused_at_load() {
    // A key with an empty section would resolve to a permanent `unset`, and a
    // gate over it would decide over a key nothing can set. Refused where it is
    // written, naming the column.
    let dir = repo(
        "git-config-unaddressable",
        "git_config = [\".gpgsign\"]\n",
        "\tinput.tree[\"git-config\"]",
    );
    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault is exit 1\n{}{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("git_config"),
        "{}",
        stderr(&output)
    );
}

// --- git-index --------------------------------------------------------------

/// The oracle's `git ls-files -s -- <spec>` as the Rego array literal the
/// projection must equal, entry for entry.
fn ls_files_stage(dir: &Path, spec: &str) -> String {
    let rows: Vec<String> = git_in(dir, &["ls-files", "-s", "--", spec])
        .lines()
        .map(|line| {
            let (meta, path) = line.split_once('\t').expect("a tab before the path");
            let mut fields = meta.split(' ');
            let (mode, oid, stage) = (
                fields.next().expect("mode"),
                fields.next().expect("oid"),
                fields.next().expect("stage"),
            );
            format!(
                "{{\"path\": \"{path}\", \"mode\": \"{mode}\", \"oid\": \"{oid}\", \"stage\": {stage}}}"
            )
        })
        .collect();
    format!("[{}]", rows.join(", "))
}

#[test]
fn the_index_under_a_pathspec_is_ls_files_stage_entry_for_entry() {
    // THE REPLAY of the step cache's `ls-files -s -- <specs>`. An executable
    // entry is staged so a mode other than 100644 has to be reported, and a file
    // OUTSIDE the spec is tracked so a spec read as "everything" would list it.
    let dir = Fixture::new("git-index-entries")
        .config(&config("index = [\"src\"]\n"))
        .file("policy/probe.rego", "package batten\n")
        .file("src/lib.rs", "fn main() {}\n")
        .file("src/run.sh", "echo hi\n")
        .file("docs/a.md", "# a\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["update-index", "--chmod=+x", "src/run.sh"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    let expected = ls_files_stage(&dir, "src");
    assert!(expected.contains("100755"), "the premise: {expected}");
    assert!(!expected.contains("docs/a.md"), "the premise: {expected}");
    // The probe is written and NOT staged: `add -A` would re-stage `src/run.sh`
    // from disk, where it is not executable, and silently undo the premise.
    write(
        &dir,
        "policy/probe.rego",
        &module(&format!(
            "\tinput.tree[\"git-index\"][\"src\"].entries == {expected}"
        )),
    );
    assert_eq!(ls_files_stage(&dir, "src"), expected, "the premise held");
    assert!(
        fired(&dir),
        "the projection is `git ls-files -s -- src`, entry for entry"
    );
}

#[test]
fn divergence_and_untracked_paths_are_reported_beneath_the_pathspec_only() {
    // THE REPLAY of the step cache's `diff --quiet -- <specs>` and `ls-files
    // --others --exclude-standard -- <specs>`: an edited tracked file and a new
    // one beneath the spec, their twins OUTSIDE it, and an ignored file beneath
    // it that neither half may name.
    let dir = repo(
        "git-index-divergence",
        "index = [\"src\"]\n",
        "\tfact := input.tree[\"git-index\"][\"src\"]\n\
         \tfact.diverged == [\"src/lib.rs\"]\n\
         \tfact.untracked == [\"src/new.rs\"]",
    );
    write(&dir, ".gitignore", "*.log\n");
    write(&dir, "docs/a.md", "# a\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "ignore logs"]);
    write(&dir, "src/lib.rs", "fn main() { /* edited */ }\n");
    write(&dir, "src/new.rs", "fn new() {}\n");
    write(&dir, "src/noise.log", "ignored\n");
    write(&dir, "docs/a.md", "# edited\n");
    write(&dir, "docs/new.md", "# new\n");
    // The oracle, over the same tree.
    assert_eq!(
        git_in(&dir, &["diff", "--name-only", "--", "src"]),
        "src/lib.rs"
    );
    assert_eq!(
        git_in(
            &dir,
            &["ls-files", "--others", "--exclude-standard", "--", "src"]
        ),
        "src/new.rs"
    );
    assert!(
        fired(&dir),
        "the diverged and untracked paths are git's, beneath the spec only"
    );
}

#[test]
fn a_clean_pathspec_is_three_empty_answers_and_not_null() {
    // Clean is an ANSWER. A spec selecting a committed, unedited path reports its
    // entries and nothing else — which is what a cache HIT is keyed on, so a
    // projection that invented a divergence would never hit and one that
    // returned null would never be asked.
    let dir = repo(
        "git-index-clean",
        "index = [\"src\"]\n",
        "\tfact := input.tree[\"git-index\"][\"src\"]\n\
         \tcount(fact.entries) == 1\n\
         \tfact.diverged == []\n\
         \tfact.untracked == []",
    );
    assert!(fired(&dir), "a clean spec: one entry, nothing diverged");
}

#[test]
fn a_flipped_executable_bit_diverges_only_where_file_mode_counts() {
    // `git diff` reports a mode change where `core.fileMode` is on and ignores
    // it where it is off, and a cache key that disagreed would trust a tree git
    // calls dirty. The INDEX side is flipped, so the case needs no platform
    // permission call: the file on disk stays non-executable either way.
    let dir = repo(
        "git-index-filemode",
        "index = [\"src\"]\n",
        "\tinput.tree[\"git-index\"][\"src\"].diverged == [\"src/lib.rs\"]",
    );
    git_in(&dir, &["update-index", "--chmod=+x", "src/lib.rs"]);
    let counts = git_in(&dir, &["config", "--get", "core.filemode"]) == "true";
    assert_eq!(
        git_in(&dir, &["diff", "--name-only", "--", "src"]).is_empty(),
        !counts,
        "the oracle reports the flip exactly where core.fileMode counts it"
    );
    assert_eq!(
        fired(&dir),
        counts,
        "the projection agrees with the oracle on this platform's default"
    );
    git_in(&dir, &["config", "core.filemode", "false"]);
    assert!(
        git_in(&dir, &["diff", "--name-only", "--", "src"]).is_empty(),
        "the oracle, with core.fileMode off"
    );
    assert!(
        !fired(&dir),
        "with core.fileMode off a mode flip is not a divergence"
    );
}

#[test]
fn a_magic_pathspec_is_refused_at_load_rather_than_read_as_a_literal() {
    // `:(exclude)src` read as a literal selects nothing and reports a clean,
    // empty answer over paths the spec meant. Refused where it is written.
    let dir = repo(
        "git-index-magic",
        "index = [\":(exclude)src\"]\n",
        "\tinput.tree[\"git-index\"]",
    );
    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault is exit 1\n{}{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(stderr(&output).contains("pathspec"), "{}", stderr(&output));
}

#[test]
fn an_undeclared_config_or_index_family_is_null() {
    // THE BOUND. Nothing is read that no row declared: the config family opens no
    // configuration beyond the repository's own, and the index family hashes no
    // file.
    let config_null = repo(
        "git-config-undeclared",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-config\"] == null",
    );
    assert!(fired(&config_null), "no key declared: null");
    let index_null = repo(
        "git-index-undeclared",
        "git = [\"head\"]\n",
        "\tinput.tree[\"git-index\"] == null",
    );
    assert!(fired(&index_null), "no pathspec declared: null");
}

// --- the one write primitive -------------------------------------------------

/// `git::set_config_local` from a LINKED worktree (CLOUD-843 p10 review).
///
/// A linked worktree's `git_dir` is its private `.git/worktrees/<name>`, and git
/// never reads a `config` file there: `git config --local` writes the COMMON
/// config. A write keyed on the private directory reported success while git
/// kept the old value. `attribution signing` is the verb that reaches the
/// primitive with nothing else in the way, and git itself is the oracle.
#[test]
fn a_repo_local_config_write_from_a_linked_worktree_lands_where_git_reads_it() {
    let dir = Fixture::new("git-config-write-linked")
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let global = dir.join(".git").join("case-global.gitconfig");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");
    let global = global.to_str().expect("utf8 path");
    let scopes = [("GIT_CONFIG_GLOBAL", global), ("GIT_CONFIG_NOSYSTEM", "1")];
    // An EMPTY key file is a broken signer, so the verb writes the override.
    let key = dir.join(".git").join("case-key.pub");
    std::fs::write(&key, "").expect("write the key");
    git_in(
        &dir,
        &[
            "config",
            "user.signingkey",
            key.to_str().expect("utf8 path"),
        ],
    );

    // `scratch` wipes and creates; `git worktree add` wants to create the
    // directory itself, so it is removed again straight away.
    let linked = scratch("git-config-write-linked-worktree");
    let _ = std::fs::remove_dir_all(&linked);
    let target = linked.to_str().expect("utf8 path");
    git_in(&dir, &["worktree", "add", "--quiet", "--detach", target]);

    let repaired = batten()
        .args(["attribution", "signing"])
        .current_dir(&linked)
        .envs(scopes)
        .output()
        .expect("run batten");
    assert_eq!(
        repaired.status.code(),
        Some(0),
        "{}{}",
        stdout(&repaired),
        stderr(&repaired)
    );
    assert_eq!(
        git_env(&linked, &["config", "--get", "commit.gpgsign"], &scopes),
        "false",
        "git, asked from the worktree, reads the value the write claims to have made"
    );
    assert_eq!(
        git_env(
            &dir,
            &["config", "--local", "--get", "commit.gpgsign"],
            &scopes
        ),
        "false",
        "the write is the repository's local config, shared by every worktree"
    );
}

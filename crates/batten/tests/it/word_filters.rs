//! `word` and `unless_word` read a line's argv one whole word at a time
//! (CLOUD-2669).
//!
//! `contains` is a substring test over the line's raw text, so a row meant to
//! catch a flag also caught the same bytes inside a commit message. These
//! columns match an anchored expression against each word the program was
//! handed: quotes already stripped by the segmenter, so a quoted argument is
//! one word, and redirections left out (CLOUD-2670), so a redirect target is no
//! word at all. Every case here failed at its parent, where a row carrying
//! either column did not load.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stderr};

/// A repository whose one mediated row is keyed on `pattern` and narrowed by
/// `filter`, a TOML line carrying `word` or `unless_word`.
fn fixture(name: &str, pattern: &str, filter: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"word-row\"\n\
             kind = \"shape\"\n\
             scope = \"mediated_call\"\n\
             severity = \"deny\"\n\
             pattern = \"{pattern}\"\n\
             {filter}\n\
             reason = \"the row under test\"\n"
        ))
        .git()
        .base_commit()
        .build()
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"s1\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// The exit status `command` earns in `dir`: `0` allowed, `2` refused.
fn verdict(dir: &Path, command: &str) -> (Option<i32>, String) {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload(command),
    );
    (out.status.code(), stderr(&out))
}

fn refuses(dir: &Path, command: &str) {
    let (code, cause) = verdict(dir, command);
    assert_eq!(code, Some(2), "`{command}` should be refused: {cause}");
}

fn allows(dir: &Path, command: &str) {
    let (code, cause) = verdict(dir, command);
    assert_eq!(code, Some(0), "`{command}` should be allowed: {cause}");
}

/// A flag is a word; the same bytes inside a quoted message are not, and a word
/// on line one does not qualify line two's program.
#[test]
fn a_word_row_reads_flags_not_message_text() {
    let dir = fixture("word-literal", "git", "word = \"--no-verify\"");
    refuses(&dir, "git commit --no-verify -m x");
    refuses(&dir, "git push --no-verify");
    allows(&dir, "git commit -m \"docs: never use --no-verify\"");
    allows(&dir, "echo --no-verify\ngit commit -m x");

    // A bundled short flag is an honest spelling, which is why the value is an
    // expression: `-n` alone or inside `-anm`, but not `-uno`'s `n` (a value of
    // `-u`), nor `-mnote`'s (a value of `-m`), nor a quoted message.
    let dir = fixture(
        "word-bundled",
        "git commit",
        "word = '-[abd-ln-sv-zABDEG-RT-Z]*n[A-Za-z]*'",
    );
    refuses(&dir, "git commit -n -m x");
    refuses(&dir, "git commit -anm x");
    allows(&dir, "git commit -uno -m x");
    allows(&dir, "git commit -mnote");
    allows(&dir, "git commit -m \"-n flag removed\"");
}

/// The exemption reads THIS line's words, so an `--onto` echoed on line one
/// does not switch the deny off for line two.
#[test]
fn an_unless_word_row_exempts_only_its_own_line() {
    let dir = fixture("unless-word", "git rebase", "unless_word = \"--onto\"");
    refuses(&dir, "git rebase origin/main");
    refuses(&dir, "echo --onto\ngit rebase origin/main");
    allows(&dir, "git rebase --onto origin/main a b");
}

/// A redirect target is where output goes, not something the program was
/// handed.
#[test]
fn a_redirection_target_is_not_a_word() {
    let dir = fixture("word-redirect", "git", "word = \"--no-verify\"");
    allows(&dir, "git commit -m x > --no-verify");
    refuses(&dir, "git commit --no-verify -m x > out");
}

/// On a row keyed by anything but a command there is no argv for either column
/// to read, so it is refused at load rather than ignored on every call; a
/// receipt row refuses it through its own permits.
#[test]
fn a_word_column_on_a_content_row_fails_to_load() {
    let content = Fixture::new("word-on-content")
        .config(
            "version = 1\n\n[[rule]]\nid = \"content-row\"\nkind = \"shape\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\ncontent = \"^never$\"\n\
             word = \"--no-verify\"\nreason = \"the row under test\"\n",
        )
        .git()
        .base_commit()
        .build();
    let out = run(&content, &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("`word`"), "{}", stderr(&out));

    let receipt = Fixture::new("word-on-receipt")
        .config(
            "version = 1\n\n[[rule]]\nid = \"ready-receipt\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr ready\"\n\
             checks = [\"verify\"]\nkey = \"head\"\nword = \"--draft\"\nreason = \"run verify\"\n",
        )
        .git()
        .base_commit()
        .build();
    let out = run(&receipt, &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("word"), "{}", stderr(&out));

    // A bad expression is refused at load too, never skipped at adjudication.
    let bad = fixture("word-bad-regex", "git", "word = \"(\"");
    let out = run(&bad, &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("`word`"), "{}", stderr(&out));
}

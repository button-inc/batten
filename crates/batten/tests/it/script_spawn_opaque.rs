//! `shell reach unread` over the compiled binary (#1276, CLOUD-2775): a spawn
//! the reach could not read is refused from a script nobody reviewed and runs
//! from one the repository tracks unchanged.
//!
//! Through `adjudicate`, because the fact the module decides on (`opaque`,
//! `trusted`) is the reach's, and only the binary computes it: a Rego case can
//! fabricate the entry, never show that the boundary builds it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

const VERDICT: &str = "shell reach unread";

/// A Python program whose spawn's argv is computed: opaque to the reach.
const OPAQUE: &str = "import subprocess, sys\nsubprocess.run(sys.argv[1:])\n";

fn config() -> String {
    String::from(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"shell reach unread\"\n\
         no_fix_reason = \"a fixture row\"\n\
         kind = \"policy\"\n\
         scope = \"mediated_call\"\n\
         module = \"policy/script-spawn-opaque.rego\"\n\
         severity = \"deny\"\n\n\
         [[verdict]]\n\
         id = \"shell reach unread\"\n\
         gloss = \"a call runs program text nothing could read\"\n\
         class = \"\"\"\nopaque reach from an unreviewed file\n\"\"\"\n\n\
         [[verdict.route]]\n\
         id = \"module read first\"\n\
         kind = \"document\"\n\
         target = \"policy/script-spawn-opaque.rego\"\n",
    )
}

fn decision(dir: &std::path::Path, command: &str) -> String {
    let escaped = serde_json::to_string(command).unwrap();
    let said = common::stdout(&common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
             \"tool_input\":{{\"command\":{escaped}}}}}"
        ),
    ));
    // A deny from a config that did not load names the verdict in its reason
    // too; only the module's own refusal counts.
    assert!(!said.contains("engine-cannot-adjudicate"), "{said}");
    said
}

/// Fails by: an opaque spawn from an untracked script admitted (the reach's
/// `trusted` read as true, or the module inverted), or one from a tracked,
/// unchanged script refused (review not trusted), or an edit to that tracked
/// script left trusted.
#[test]
fn opaque_reach_from_an_untracked_script_is_refused_and_a_tracked_one_runs() {
    let module =
        std::fs::read_to_string(common::at_root("policy/script-spawn-opaque.rego")).unwrap();
    let dir = common::Fixture::new("script-spawn-opaque")
        .config(&config())
        .file("policy/script-spawn-opaque.rego", &module)
        .file("tools/reviewed.py", OPAQUE)
        .base_commit()
        .build();
    std::fs::write(dir.join("tools/fresh.py"), OPAQUE).unwrap();

    let fresh = decision(&dir, "python3 tools/fresh.py git push");
    assert!(
        fresh.contains("\"deny\"") && fresh.contains(VERDICT),
        "an untracked script's opaque spawn is refused: {fresh}"
    );
    let reviewed = decision(&dir, "python3 tools/reviewed.py git push");
    assert!(
        !reviewed.contains(VERDICT),
        "a tracked, unchanged script runs: {reviewed}"
    );

    std::fs::write(dir.join("tools/reviewed.py"), format!("{OPAQUE}# edited\n")).unwrap();
    let edited = decision(&dir, "python3 tools/reviewed.py git push");
    assert!(
        edited.contains("\"deny\"") && edited.contains(VERDICT),
        "a tracked script edited in place is no longer reviewed: {edited}"
    );
}

/// A repository registering the module, with `tools/reviewed.sh` (plain shell)
/// and `tools/reviewed.py` (an opaque spawn) tracked and unchanged.
fn staged(name: &str) -> std::path::PathBuf {
    let module =
        std::fs::read_to_string(common::at_root("policy/script-spawn-opaque.rego")).unwrap();
    common::Fixture::new(name)
        .config(&config())
        .file("policy/script-spawn-opaque.rego", &module)
        .file("tools/reviewed.sh", "echo reviewed\n")
        .file("tools/reviewed.py", OPAQUE)
        .file("root.sh", "echo root\n")
        .base_commit()
        .build()
}

fn refused(said: &str) -> bool {
    said.contains("\"deny\"") && said.contains(VERDICT)
}

/// THE REACH READS A SCRIPT WHERE ITS STAGE RUNS (CLOUD-2775): after `cd
/// tools`, `sh reviewed.sh` runs `tools/reviewed.sh`, which is tracked and
/// unchanged, so it is not opaque; and `python3 fresh.py` runs
/// `tools/fresh.py`, whose computed spawn is read and refused. Fails by: the
/// `cd` unfollowed, so the operand is looked for beside the call, where it is
/// absent (refusing the reviewed script, or never reading the fresh one).
#[test]
fn a_script_after_a_cd_is_read_in_that_directory() {
    let dir = staged("script-spawn-cd");
    std::fs::write(dir.join("tools/fresh.py"), OPAQUE).unwrap();
    let reviewed = decision(&dir, "cd tools && sh reviewed.sh");
    assert!(
        !reviewed.contains(VERDICT),
        "a tracked, unchanged script in the cd's directory runs: {reviewed}"
    );
    let fresh = decision(&dir, "cd tools && python3 fresh.py git push");
    assert!(
        refused(&fresh),
        "the untracked script in the cd's directory is read: {fresh}"
    );
}

/// A script absent where its stage runs is program text nothing read, so it is
/// opaque. Fails by: an absent file read as a script that runs nothing.
#[test]
fn a_script_absent_at_its_resolved_path_is_opaque() {
    let dir = staged("script-spawn-absent");
    let absent = decision(&dir, "sh missing.sh");
    assert!(refused(&absent), "an absent script is refused: {absent}");
    let moved = decision(&dir, "cd tools && sh root.sh");
    assert!(
        refused(&moved),
        "a script present beside the call but absent in the cd's directory: {moved}"
    );
}

/// A script an earlier stage writes is absent when the call is judged, so
/// what it runs is unread. Fails by: the write-then-run shape admitted
/// unjudged, which it was before CLOUD-2775.
#[test]
fn a_script_written_by_an_earlier_stage_is_opaque() {
    let dir = staged("script-spawn-written");
    let written = decision(
        &dir,
        "cat > ship.sh <<'EOF' && sh ship.sh\ngit push --force origin main\nEOF",
    );
    assert!(refused(&written), "{written}");
}

/// A file `source` or `.` runs that is absent where its stage runs is program
/// text nothing read, as a script operand's is. Fails by: the sourced file
/// skipped when absent, as only a shell's or an interpreter's operand was
/// made opaque.
#[test]
fn a_sourced_file_absent_at_its_resolved_path_is_opaque() {
    let dir = staged("script-spawn-source");
    for command in ["source missing.sh", ". missing.sh", "cd tools && . root.sh"] {
        let said = decision(&dir, command);
        assert!(refused(&said), "{command}: {said}");
    }
    let present = decision(&dir, "source root.sh");
    assert!(
        !present.contains(VERDICT),
        "a tracked, unchanged sourced file runs: {present}"
    );
}

/// A script an EARLIER stage of the same call writes is opaque even where an
/// older copy sits at that path: the bytes judged are not the bytes run. Each
/// write a stage makes counts: an output redirection, `tee`, and a `cp` or
/// `mv` destination, placed through the `cd`s before it. Fails by: the
/// tracked, unchanged copy read and trusted in place of what the call writes.
#[test]
fn a_script_an_earlier_stage_writes_is_opaque_over_an_older_copy() {
    let dir = staged("script-spawn-overwritten");
    for command in [
        "echo 'git push --force origin main' > root.sh && sh root.sh",
        "echo 'git push' >> root.sh; sh root.sh",
        "echo 'git push' | tee root.sh && sh root.sh",
        "cp tools/reviewed.sh root.sh && sh root.sh",
        "mv tools/reviewed.sh root.sh && bash root.sh",
        "cp tools/reviewed.sh . && sh reviewed.sh",
        "echo 'git push' > tools/reviewed.sh && cd tools && sh reviewed.sh",
        "cd tools && echo 'git push' > ../root.sh && cd .. && sh root.sh",
        "echo 'git push' > root.sh && source root.sh",
        "cp OPAQUE.py tools/reviewed.py && python3 tools/reviewed.py",
    ] {
        let said = decision(&dir, command);
        assert!(refused(&said), "{command}: {said}");
    }
    let elsewhere = decision(&dir, "echo hi > other.sh && sh root.sh");
    assert!(
        !elsewhere.contains(VERDICT),
        "a write to another path leaves the tracked script trusted: {elsewhere}"
    );
}

/// A `cd` the reach cannot place (an expansion) leaves the next stage's
/// directory unknown, so a relative script there is opaque even where a file
/// of that name sits beside the call. Fails by: the operand read beside the
/// call, as if the `cd` were not there.
#[test]
fn a_script_after_an_unplaceable_cd_is_opaque() {
    let dir = staged("script-spawn-cd-expansion");
    let unplaced = decision(&dir, "cd \"$D\" && sh root.sh");
    assert!(refused(&unplaced), "{unplaced}");
    let beside = decision(&dir, "sh root.sh");
    assert!(
        !beside.contains(VERDICT),
        "the same tracked script with no cd runs: {beside}"
    );
}

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

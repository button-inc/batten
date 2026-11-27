//! `tool install loose` (`policy/tool-install-locked.rego`, CLOUD-2881) over the
//! compiled binary: every mise install reads `mise.lock`, and nothing turns that
//! off.
//!
//! THE COMMITTED ROWS, NOT A RESTATEMENT. Each fixture's config is built from the
//! committed `batten.toml`'s own `tool install loose` row, its two verdicts and
//! the patterns the module reads, so a case judges the regex and the
//! `line_sources` this repository ships rather than a copy that could drift from
//! them. The module is copied from the tree for the same reason.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{git_in, run, scratch, stdout, write};

const RULE: &str = "tool install loose";

/// The `[[pattern]]` rows `policy/tool-install-locked.rego` reads.
const PATTERNS: &[&str] = &[
    "mise-config-file",
    "mise-rc-file",
    "mise-task-file",
    "lock-env-file",
    "toml-table-header",
    "toml-key-segment",
    "comment-hash",
    "comment-slash",
    "mise-task-directive",
    "mise-lock-truthy",
    "mise-lock-env",
    "mise-lock-expansion",
    "mise-locked-scopes-expansion",
    "mise-locked-scopes-env",
    "mise-locked-scopes-project",
    "mise-lock-indirect",
    "mise-settings-lock",
    "mise-settings-unset",
    "mise-config-env",
    "mise-action-config",
    "mise-config-write",
    "mise-lock-writer",
    "mise-name-escaped",
];

/// The verdicts the module raises.
const VERDICTS: &[&str] = &["lock read loose", "tool install unsafe"];

/// The committed rows this rule needs, as a config of their own.
fn committed_config() -> String {
    let authority: toml::Table = std::fs::read_to_string(common::at_root("batten.toml"))
        .expect("read batten.toml")
        .parse()
        .expect("batten.toml parses");
    let rows = |table: &str, keep: &dyn Fn(&str) -> bool| -> toml::Value {
        toml::Value::Array(
            authority[table]
                .as_array()
                .expect("an array of tables")
                .iter()
                .filter(|row| row["id"].as_str().is_some_and(keep))
                .cloned()
                .collect(),
        )
    };
    let mut config = toml::Table::new();
    config.insert("version".to_owned(), toml::Value::Integer(1));
    config.insert(
        "pattern".to_owned(),
        rows("pattern", &|id| PATTERNS.contains(&id)),
    );
    config.insert("rule".to_owned(), rows("rule", &|id| id == RULE));
    config.insert(
        "verdict".to_owned(),
        rows("verdict", &|id| VERDICTS.contains(&id)),
    );
    for (table, want) in [
        ("pattern", PATTERNS.len()),
        ("rule", 1),
        ("verdict", VERDICTS.len()),
    ] {
        assert_eq!(
            config[table].as_array().map(Vec::len),
            Some(want),
            "batten.toml declares every {table} row this rule needs"
        );
    }
    toml::to_string(&config).expect("the config serializes")
}

/// A repository carrying the committed module, the committed rows and `files`.
fn fixture(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = scratch(name);
    let module = std::fs::read_to_string(common::at_root("policy/tool-install-locked.rego"))
        .expect("the committed module");
    write(&dir, "policy/tool-install-locked.rego", &module);
    write(&dir, "batten.toml", &committed_config());
    for (path, body) in files {
        write(&dir, path, body);
    }
    git_in(&dir, &["init", "--initial-branch=main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-m", "fixture"]);
    dir
}

/// Judge `dir` on this one rule.
fn judge(dir: &Path) -> (Option<i32>, String) {
    let out = run(dir, &["check", "--rule", RULE]);
    // stderr too: a check that ERRORED (exit 1) says why only there.
    (
        out.status.code(),
        format!("{}{}", stdout(&out), common::stderr(&out)),
    )
}

/// A root manifest with `settings` and one tool, then `tail`.
fn manifest(settings: &str, tail: &str) -> String {
    format!("[settings]\n{settings}\n\n[tools]\n\"t\" = \"1.0.0\"\n{tail}")
}

const LOCKED: &str = "lockfile = true\nlocked = true";

#[test]
fn the_locked_settings_are_clean() {
    let (code, said) = judge(&fixture(
        "install-locked-clean",
        &[("mise.toml", &manifest(LOCKED, ""))],
    ));
    assert_eq!(code, Some(0), "both settings on is clean\n{said}");
}

#[test]
fn an_unread_lockfile_is_reported() {
    // The setting this repository held until CLOUD-2881: with the lockfile off,
    // every install path that did not opt in by env resolved through the API.
    let (code, said) = judge(&fixture(
        "install-locked-lockfile-off",
        &[(
            "mise.toml",
            &manifest("lockfile = false\nlocked = true", ""),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("lock read loose") && said.contains("mise.toml:1"),
        "{said}"
    );
}

#[test]
fn a_lockfile_without_locked_mode_is_reported() {
    // Read but not enforced: an install still resolves through the API and
    // writes the lock.
    let (code, said) = judge(&fixture(
        "install-locked-unlocked",
        &[("mise.toml", &manifest("lockfile = true", ""))],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("lock read loose"), "{said}");
}

#[test]
fn an_overlay_turning_the_lock_off_is_reported() {
    // An overlay's `[settings]` outranks the root's for whoever loads it. A
    // literally named overlay is staged and PARSED, so any TOML spelling of the
    // key — a commented header, a quoted key, an inline table — is read.
    let (code, said) = judge(&fixture(
        "install-locked-overlay",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                "mise.local.toml",
                "[ settings ] # local\n\"locked\" = false\n",
            ),
            (".config/mise/config.toml", "tool_config = { locked = 0 }\n"),
            (".miserc.toml", "lockfile = false\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        "mise.local.toml",
        ".config/mise/config.toml",
        ".miserc.toml",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

#[test]
fn a_globbed_overlay_turning_the_lock_off_is_reported() {
    // A name only a glob reaches (`mise.<env>.toml`, `conf.d/*.toml`) is a
    // document the row's `sources` selects, PARSED as a literal name is: an
    // indented header, a quoted dotted key and an inline table each read as
    // TOML reads them, and a `[tasks]` key named `locked` is not a setting.
    let (code, said) = judge(&fixture(
        "install-locked-globbed-overlay",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            ("mise.agent.toml", "\"settings\".locked = false\n"),
            ("mise.ci.toml", "  [settings]\n  locked = false\n"),
            (
                ".config/mise/conf.d/a.toml",
                "tool_config = { lockfile = 0 }\n",
            ),
            ("mise.dev.toml", "[tasks.x]\nlocked = false\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        "mise.agent.toml",
        "mise.ci.toml",
        ".config/mise/conf.d/a.toml",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
    assert!(
        !said.contains("mise.dev.toml"),
        "a task key is not a setting\n{said}"
    );
}

/// B: a colon-named or indented table header is a header, so a switch under it
/// belongs to it and not to the `[tasks.lock-check]` above.
#[test]
fn a_colon_or_indented_table_is_its_own_table() {
    let (code, said) = judge(&fixture(
        "install-locked-colon-table",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.lock-check]\nrun = \"mise lock\"\n[tasks.\"lock:refresh\"]\nenv = { MISE_LOCKED = \"false\" }\n[tasks.lock-check.env]\n  [tasks.build]\nenv = { MISE_LOCKED = \"false\" }\n",
            ),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in ["mise.toml:11", "mise.toml:14"] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

/// D: a shebang's `env -S` runs its arguments, and a shell `name=x` before a
/// command is an assignment, not a prose key.
#[test]
fn a_shell_assignment_named_like_prose_is_read() {
    let (code, said) = judge(&fixture(
        "install-locked-shell-prose",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                "mise-tasks/a",
                "#!/usr/bin/env -S MISE_LOCKED=false mise exec -- bash\n",
            ),
            (
                "mise-tasks/b",
                "#!/bin/sh\nname=x MISE_LOCKED=false mise install\n",
            ),
            // A `//` line is no comment in a shell task, nor `#` in pkl; a
            // suffixed name and a `$NAME=` are refused too (round 6).
            (
                "mise-tasks/c",
                "// MISE_LOCKED=false\nFOO_MISE_LOCKED=false mise install\n$MISE_LOCKED=false\n",
            ),
            ("hk.pkl", "# MISE_LOCKED = \"false\"\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        "mise-tasks/a:1",
        "mise-tasks/b:2",
        "mise-tasks/c:1",
        "mise-tasks/c:2",
        "mise-tasks/c:3",
        "hk.pkl:1",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

#[test]
fn a_switch_inside_a_script_block_is_reported() {
    // E01, E25: a `run = """`/`'''` script is not prose. E26: a stray `'''` in a
    // workflow exempts nothing — the triple-quote exemption is TOML's, and only
    // for a block a prose key opens.
    let (code, said) = judge(&fixture(
        "install-locked-script-block",
        &[
            (
                "mise.toml",
                &manifest(
                    LOCKED,
                    "\n[tasks.a]\nrun = \"\"\"\nMISE_LOCKED=false mise install\n\"\"\"\n\n[tasks.b]\nrun = '''\nMISE_LOCKFILE=false mise install\n'''\n",
                ),
            ),
            (
                ".github/workflows/w.yml",
                "# '''\nenv:\n  MISE_LOCKED: false\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in ["mise.toml:10", "mise.toml:15", ".github/workflows/w.yml:3"] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

/// THE ROW AND THE MODULE NAME THE SAME PATHS: one file under each committed
/// `line_sources` glob, each carrying an off-switch, and every one reported.
/// Fails by: a glob the module does not admit (it reads nothing there), or a
/// path the module names that the row never feeds it.
#[test]
fn every_line_source_is_read() {
    let authority: toml::Table = std::fs::read_to_string(common::at_root("batten.toml"))
        .expect("read batten.toml")
        .parse()
        .expect("batten.toml parses");
    let row = authority["rule"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|row| row["id"].as_str() == Some(RULE))
        .expect("the committed row");
    let staged: Vec<&str> = row["staged"]
        .as_array()
        .expect("staged")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    let mut files: Vec<(String, String)> = vec![("mise.toml".to_owned(), manifest(LOCKED, ""))];
    for glob in row["line_sources"].as_array().expect("line_sources") {
        let glob = glob.as_str().expect("a glob");
        // The root manifest and the staged names are parsed, not line-read, and
        // `batten.toml` is the fixture's own config (`every_route…` covers argv).
        if glob == "mise.toml" || glob == "batten.toml" || staged.contains(&glob) {
            continue;
        }
        let path = glob.replace("**", "t/run").replace('*', "x");
        files.push((path, "MISE_LOCKED=false\n".to_owned()));
    }
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, body)| (path.as_str(), body.as_str()))
        .collect();
    let (code, said) = judge(&fixture("install-locked-every-source", &borrowed));
    assert_eq!(code, Some(2), "{said}");
    for (path, _) in files.iter().skip(1) {
        assert!(
            said.contains(&format!("{path}:1")),
            "{path} is fed by the row and read by the module\n{said}"
        );
    }
}

#[test]
fn a_task_env_turning_the_lock_off_is_reported() {
    // An env assignment outranks `[settings]` for the command it wraps.
    let (code, said) = judge(&fixture(
        "install-locked-task-env",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.build]\nenv = { MISE_LOCKED = \"false\" }\nrun = \"true\"\n",
            ),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("tool install unsafe") && said.contains("mise.toml:9"),
        "{said}"
    );
}

#[test]
fn every_route_an_env_reaches_is_read() {
    // The committed `line_sources`: a workflow in either extension, an action, a
    // task script's directive, and an hk step — each with a value that cannot be
    // read as on.
    let (code, said) = judge(&fixture(
        "install-locked-routes",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                ".github/workflows/w.yaml",
                "env:\n  MISE_LOCKED: ${{ inputs.locked }}\n",
            ),
            (
                ".github/actions/a/action.yml",
                "env:\n  MISE_LOCKFILE: \" false\"\n",
            ),
            (
                "mise-tasks/t/run.sh",
                "#!/bin/sh\n#MISE env={MISE_LOCKED=\"no\"}\n",
            ),
            (
                ".mise/tasks/u",
                "#!/bin/sh\n# [MISE] env={MISE_LOCKED=\"0\"}\n",
            ),
            (
                ".config/mise/tasks/v",
                "#!/bin/sh\n// MISE env={MISE_LOCKFILE=\"off\"}\n",
            ),
            ("hk.pkl", "env { [\"MISE_LOCKED\"] = \"\" }\n"),
            (
                "hk-fix-selection.pkl",
                "env { [\"MISE_LOCKFILE\"] = \"false\" }\n",
            ),
            ("action.yaml", "env:\n  MISE_LOCKED: false\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        ".github/workflows/w.yaml:2",
        ".github/actions/a/action.yml:2",
        "mise-tasks/t/run.sh:2",
        ".mise/tasks/u:2",
        ".config/mise/tasks/v:2",
        "hk.pkl:1",
        "hk-fix-selection.pkl:1",
        "action.yaml:2",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

#[test]
fn a_widened_lock_scope_is_reported() {
    // A task's `MISE_LOCKED_SCOPES = "project"` keeps the user's global tools out
    // of locked mode; any other value moves the line, so it is a switch.
    let (code, said) = judge(&fixture(
        "install-locked-scopes",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.check]\nenv = { MISE_LOCKED_SCOPES = \"project\" }\n\n[tasks.wide]\nenv = { MISE_LOCKED_SCOPES = \"global,project\" }\n",
            ),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("tool install unsafe") && said.contains("mise.toml:12"),
        "{said}"
    );
    assert!(
        !said.contains("mise.toml:9"),
        "the project scope is not a switch\n{said}"
    );
}

#[test]
fn the_declared_writer_may_turn_it_off() {
    let (code, said) = judge(&fixture(
        "install-locked-writer",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.\"lock-check\"]\nenv = { MISE_LOCKFILE = \"true\", MISE_LOCKED = \"false\" }\nrun = \"mise lock\"\n",
            ),
        )],
    ));
    assert_eq!(code, Some(0), "the declared writer is clean\n{said}");
}

/// ONLY A COMMENT OR A PURE READ IS NOT A SWITCH: a `#` comment where `#` is
/// one, a `//` comment in pkl and JSON5, and a read that assigns nothing.
#[test]
fn a_comment_or_pure_read_is_untouched() {
    let (code, said) = judge(&fixture(
        "install-locked-comment-read",
        &[
            (
                "mise.toml",
                &manifest(LOCKED, "# MISE_LOCKED = \"false\" in a comment\n"),
            ),
            (
                "mise-tasks/guard.sh",
                "#!/bin/sh\nif [ \"$MISE_LOCKED\" = \"false\" ]; then echo \"${MISE_LOCKED}\" $MISE_LOCKFILE; fi\n",
            ),
            (
                ".github/workflows/w.yml",
                "jobs:\n  a:\n    steps:\n      # MISE_LOCKED: false is refused\n      - run: echo\n",
            ),
            (
                "renovate.json5",
                "{\n  // MISE_LOCKFILE: false would be refused\n}\n",
            ),
            ("hk.pkl", "// MISE_LOCKED = \"false\" in a pkl comment\n"),
        ],
    ));
    assert_eq!(code, Some(0), "no switch is set\n{said}");
}

/// ROUND 6, SHAPES 1, 2, 4, 5: PROSE IS NOT EXEMPT. A prose-looking value that
/// runs a command, a `'''` value holding `"""`, a JSON5 prose key beside an
/// `env`, a `description = """` inside a `run = '''` script, and plain prose
/// naming a switch are each read.
#[test]
fn prose_naming_a_switch_is_read() {
    let (code, said) = judge(&fixture(
        "install-locked-prose-read",
        &[
            (
                "mise.toml",
                &manifest(
                    LOCKED,
                    "\n[tasks.a]\nrun = \"\"\"\nsummary=\"$(MISE_LOCKFILE=0 mise install)\"\n\"\"\"\n\n[tasks.b]\ndescription = '''a \"\"\" inside'''\nrun = \"MISE_LOCKED=false mise install\"\n\n[tasks.c]\nrun = '''\ndescription = \"\"\"\n'''\nenv = { MISE_LOCKFILE = \"off\" }\n",
                ),
            ),
            (
                ".github/workflows/w.yml",
                "jobs:\n  a:\n    steps:\n      - run: |\n          title=\"$(MISE_LOCKED=false mise install)\"\n          title=\"`MISE_LOCKED=false mise install`\"\n      - name: MISE_LOCKED=false\n",
            ),
            (
                "renovate.json5",
                "{\n  description: \"probe\", env: { MISE_LOCKED: \"false\" },\n}\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        "mise.toml:10",
        "mise.toml:15",
        "mise.toml:21",
        ".github/workflows/w.yml:5",
        ".github/workflows/w.yml:6",
        ".github/workflows/w.yml:7",
        "renovate.json5:2",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

/// ROUND 6, SHAPE 3: an expansion that assigns or defaults is a switch; only a
/// bare `${NAME}` is a read.
#[test]
fn a_defaulting_expansion_is_a_switch() {
    let (code, said) = judge(&fixture(
        "install-locked-expansion",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                "mise-tasks/t",
                "#!/bin/sh\n: \"${MISE_LOCKED=false}\"\n: \"${MISE_LOCKFILE:=0}\"\necho \"${MISE_LOCKED-false}\"\n: \"${MISE_LOCKED_SCOPES:=global}\"\necho \"${MISE_LOCKED}\"\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    for pointer in [
        "mise-tasks/t:2",
        "mise-tasks/t:3",
        "mise-tasks/t:4",
        "mise-tasks/t:5",
    ] {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
    assert!(
        !said.contains("mise-tasks/t:6"),
        "a bare read is not a switch\n{said}"
    );
}

/// THE COMMITTED PROSE THIS RULE REWORDED (round 6), both ways: each old
/// spelling names a switch in its `NAME=value` form and is refused; each new
/// one names it without that form and is read as nothing.
#[test]
fn the_reworded_prose_decides_as_written() {
    let old = judge(&fixture(
        "install-locked-old-prose",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.a]\ndescription = \"sets no MISE_LOCKFILE, so it installs UNLOCKED\"\nhelp = \"Add `MISE_LOCKFILE: \\\"true\\\"` to the workflow's env.\"\n",
            ),
        )],
    ));
    assert_eq!(old.0, Some(2), "{}", old.1);
    for pointer in ["mise.toml:9", "mise.toml:10"] {
        assert!(old.1.contains(pointer), "{pointer} is reported\n{}", old.1);
    }
    let new = judge(&fixture(
        "install-locked-new-prose",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.a]\ndescription = \"sets no `MISE_LOCKFILE` env, so it installs UNLOCKED\"\nhelp = \"Set the workflow's `MISE_LOCKFILE` env to `true`.\"\n",
            ),
        )],
    ));
    assert_eq!(new.0, Some(0), "{}", new.1);
}

/// ROUND 7: a header key holding `\"` is still a header, so a switch under
/// `[tasks."probe\"x"]` belongs to it and not to the `[tasks.lock-check]` above.
#[test]
fn an_escaped_quote_header_is_its_own_table() {
    let (code, said) = judge(&fixture(
        "install-locked-escaped-header",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.lock-check]\nrun = \"mise lock\"\n[tasks.\"probe\\\"x\"]\nenv = { MISE_LOCKED = \"false\" }\n",
            ),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("mise.toml:11"), "{said}");
}

/// ROUND 7: TOML is judged by its parse. A line-ending backslash joins
/// `MISE_LOCKED\` and `=false` into one string no line shows, and a string that
/// spells `[tasks.lock-check]` still sits in its own table.
#[test]
fn the_parse_reads_what_a_line_cannot() {
    let (code, said) = judge(&fixture(
        "install-locked-parsed",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.x]\nrun = \"\"\"MISE_LOCKED\\\n=false mise install\"\"\"\n",
            ),
        )],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("tool install unsafe at mise.toml"), "{said}");

    let (code, said) = judge(&fixture(
        "install-locked-header-in-string",
        &[(
            "mise.toml",
            &manifest(
                LOCKED,
                "\n[tasks.x]\nrun = \"\"\"\n[tasks.lock-check]\nMISE_LOCKED=false mise install\n\"\"\"\n",
            ),
        )],
    ));
    assert_eq!(
        code,
        Some(2),
        "a writer header inside a string hides nothing\n{said}"
    );
    assert!(said.contains("tool install unsafe at mise.toml"), "{said}");
}

/// ROUND 7: an env file a config loads is a route. One the row reads is judged
/// by line; one it cannot read is refused unread.
#[test]
fn an_env_file_is_read_or_refused() {
    let loads = manifest(LOCKED, "\n[env]\n_.file = \".env\"\n");
    let (code, said) = judge(&fixture(
        "install-locked-env-unread",
        &[("mise.toml", &loads)],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("tool install unsafe at mise.toml"), "{said}");

    let (code, said) = judge(&fixture(
        "install-locked-env-read",
        &[("mise.toml", &loads), (".env", "MISE_LOCKED=false\n")],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains(".env:1"), "{said}");

    let (code, said) = judge(&fixture(
        "install-locked-env-clean",
        &[("mise.toml", &loads), (".env", "A=1\n")],
    ));
    assert_eq!(code, Some(0), "a read, clean env file is clean\n{said}");
}

#[test]
fn a_truthy_assignment_is_untouched() {
    let (code, said) = judge(&fixture(
        "install-locked-truthy",
        &[
            (
                "mise.toml",
                &manifest(
                    LOCKED,
                    "\n[tasks.install]\nenv = { MISE_LOCKFILE = \"true\", MISE_LOCKED = \"1\" }\n",
                ),
            ),
            (
                ".github/workflows/w.yml",
                "env:\n  MISE_LOCKFILE: \"true\"\n  MISE_LOCKED: yes\n",
            ),
            ("hk.pkl", "env { [\"MISE_LOCKED\"] = \"true\" }\n"),
        ],
    ));
    assert_eq!(code, Some(0), "every value is on\n{said}");
}

/// Assert `said` names every pointer in `want`.
fn reports_each(said: &str, want: &[&str]) {
    for pointer in want {
        assert!(said.contains(pointer), "{pointer} is reported\n{said}");
    }
}

/// R8 M1: mise loads its config names in EVERY ancestor of its cwd, and a task
/// with `dir = "{{cwd}}"` runs from a subdirectory, so an overlay or a task dir
/// below the root is read as one at the root is.
#[test]
fn an_overlay_in_a_subdirectory_is_read() {
    let off = "[settings]\nlocked = false\n";
    let (code, said) = judge(&fixture(
        "install-locked-deep-overlay",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            ("crates/a/mise.local.toml", off),
            ("crates/a/.mise.local.toml", off),
            ("crates/a/mise.ci.toml", off),
            (
                "crates/a/mise.agent.toml",
                "tool_config = { lockfile = 0 }\n",
            ),
            ("crates/b/.config/mise/config.toml", off),
            ("crates/b/mise/config.toml", off),
            ("crates/c/.mise/config.toml", off),
            ("crates/c/.rtx.toml", off),
            ("crates/c/mise/conf.d/x.toml", off),
            (
                "crates/a/mise-tasks/t",
                "#!/bin/sh\nMISE_LOCKED=false mise install\n",
            ),
            (
                "crates/b/.mise/tasks/u",
                "#!/bin/sh\n#MISE env={MISE_LOCKED=\"0\"}\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(
        &said,
        &[
            "crates/a/mise.local.toml",
            "crates/a/.mise.local.toml",
            "crates/a/mise.ci.toml",
            "crates/a/mise.agent.toml",
            "crates/b/.config/mise/config.toml",
            "crates/b/mise/config.toml",
            "crates/c/.mise/config.toml",
            "crates/c/.rtx.toml",
            "crates/c/mise/conf.d/x.toml",
            "crates/a/mise-tasks/t:2",
            "crates/b/.mise/tasks/u:2",
        ],
    );
}

/// R8 M2: every file that can hand a process its env is read — the harness's
/// settings, an MCP server's env, a bats suite, the installer, an action
/// outside `.github/actions`, a direnv file, cargo's `[env]`, a crate's script.
#[test]
fn every_env_carrier_is_read() {
    let (code, said) = judge(&fixture(
        "install-locked-carriers",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                ".claude/settings.json",
                "{\n  \"env\": {\"MISE_LOCKED\": \"false\"}\n}\n",
            ),
            (
                ".mcp.json",
                "{\"mcpServers\": {\"x\": {\n  \"env\": {\"MISE_LOCKFILE\": \"0\"}}}}\n",
            ),
            (
                "tests/a.bats",
                "@test x {\n  MISE_LOCKED=false run mise install\n}\n",
            ),
            ("install.sh", "#!/bin/sh\nexport MISE_LOCKED=0\n"),
            (
                "actions/a/action.yml",
                "runs:\n  env:\n    MISE_LOCKED: false\n",
            ),
            (".envrc", "export MISE_LOCKED=false\n"),
            ("crates/a/.envrc", "export MISE_LOCKFILE=no\n"),
            (".cargo/config.toml", "[env]\nMISE_LOCKED = \"false\"\n"),
            (
                "crates/a/scripts/run.sh",
                "#!/bin/sh\nMISE_LOCKED=off mise x\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(
        &said,
        &[
            ".claude/settings.json:2",
            ".mcp.json:2",
            "tests/a.bats:2",
            "install.sh:2",
            "actions/a/action.yml:3",
            ".envrc:1",
            "crates/a/.envrc:1",
            ".cargo/config.toml:2",
            "crates/a/scripts/run.sh:2",
        ],
    );
}

/// R8 M3: the lock turned off with no env-var name — a settings write, a config
/// the process is pointed at, mise-action's inline config, and a config file
/// written at run time. A settings READ, and a write of `true`, are not.
#[test]
fn the_lock_turned_off_without_its_name_is_reported() {
    let (code, said) = judge(&fixture(
        "install-locked-unnamed",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                "mise-tasks/a",
                "#!/bin/sh\nmise settings set locked false\n",
            ),
            ("mise-tasks/b", "#!/bin/sh\nmise settings unset lockfile\n"),
            ("mise-tasks/c", "#!/bin/sh\nmise settings locked=0\n"),
            (
                "mise-tasks/d",
                "#!/bin/sh\nMISE_GLOBAL_CONFIG_FILE=/tmp/g.toml mise install\n",
            ),
            (
                ".github/workflows/w.yml",
                "env:\n  MISE_CONFIG_FILE: other.toml\n",
            ),
            (
                ".github/workflows/v.yml",
                "steps:\n  - uses: jdx/mise-action@v2\n    with:\n      mise_toml: |\n        [tools]\n",
            ),
            (
                "mise-tasks/e",
                "#!/bin/sh\ncat > mise.local.toml <<EOF\n[settings]\nEOF\n",
            ),
            (
                "mise-tasks/f",
                "#!/bin/sh\necho x | tee -a crates/a/.mise.toml\n",
            ),
            (
                "mise-tasks/g",
                "#!/bin/sh\nmise settings get locked\nmise settings set locked true\n",
            ),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(
        &said,
        &[
            "mise-tasks/a:2",
            "mise-tasks/b:2",
            "mise-tasks/c:2",
            "mise-tasks/d:2",
            ".github/workflows/w.yml:2",
            ".github/workflows/v.yml:4",
            "mise-tasks/e:2",
            "mise-tasks/f:2",
        ],
    );
    assert!(
        !said.contains("mise-tasks/g"),
        "a settings read or a write of true is not a switch\n{said}"
    );
}

/// R8 M4: the shell's other assignment spellings — append, `printf -v`, `read`,
/// a name and value written to `$GITHUB_ENV` apart, a backslash-newline
/// continuation on a line and inside a parsed `'''` script.
#[test]
fn every_shell_assignment_spelling_is_read() {
    let (code, said) = judge(&fixture(
        "install-locked-assign-forms",
        &[
            (
                "mise.toml",
                &manifest(
                    LOCKED,
                    "\n[tasks.x]\nrun = '''\ncat <<'EOF'\n[tasks.lock-check]\nEOF\nexport MISE_LOCK\\\nED=false\n'''\n",
                ),
            ),
            ("mise-tasks/a", "#!/bin/sh\nMISE_LOCKED+=x\n"),
            (
                "mise-tasks/b",
                "#!/bin/sh\nprintf -v MISE_LOCKED %s false\n",
            ),
            (
                ".github/workflows/w.yml",
                "steps:\n  - run: printf '%s=%s\\n' MISE_LOCKED false >> \"$GITHUB_ENV\"\n",
            ),
            (
                "mise-tasks/c",
                "#!/bin/bash\nread -r MISE_LOCKED <<< false\n",
            ),
            ("mise-tasks/d", "#!/bin/sh\nexport MISE_LOCK\\\nED=false\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(
        &said,
        &[
            "tool install unsafe at mise.toml",
            "mise-tasks/a:2",
            "mise-tasks/b:2",
            ".github/workflows/w.yml:2",
            "mise-tasks/c:2",
            "mise-tasks/d:2",
        ],
    );
}

/// R8 minor: a YAML key spelled with an escape and a pkl backtick identifier
/// name the switch as surely as a bare one.
#[test]
fn every_key_spelling_is_read() {
    let (code, said) = judge(&fixture(
        "install-locked-key-spellings",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                ".github/workflows/w.yml",
                "env:\n  \"MISE_LOCK\\x45D\": false\n",
            ),
            ("hk.pkl", "env {\n  `MISE_LOCKED` = \"false\"\n}\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(&said, &[".github/workflows/w.yml:2", "hk.pkl:2"]);
}

/// R8 minor, OVER-REFUSAL: the value ends where the shell word ends, so a true
/// prefix assignment before a command is not a switch, and a `==` comparison
/// is a read.
#[test]
fn a_true_prefix_or_comparison_is_untouched() {
    let (code, said) = judge(&fixture(
        "install-locked-prefix-read",
        &[
            ("mise.toml", &manifest(LOCKED, "")),
            (
                "mise-tasks/a",
                "#!/bin/sh\nMISE_LOCKFILE=true MISE_LOCKED=1 mise install\n",
            ),
            (
                ".github/workflows/w.yml",
                "jobs:\n  a:\n    if: env.MISE_LOCKED == 'false'\n",
            ),
        ],
    ));
    assert_eq!(code, Some(0), "nothing assigns a non-true value\n{said}");
}

/// R8 minor: `mise lock` writes the lock, and only `[tasks.lock-check]` may run
/// it; prose that names the command in backticks runs nothing.
#[test]
fn a_second_lock_writer_is_reported() {
    let (code, said) = judge(&fixture(
        "install-locked-second-writer",
        &[
            (
                "mise.toml",
                &manifest(
                    LOCKED,
                    "\n[tasks.\"lock-check\"]\nrun = \"mise lock\"\n\n[tasks.other]\ndescription = \"not `mise lock` itself\"\nrun = \"mise lock --platform x\"\n",
                ),
            ),
            ("mise-tasks/relock", "#!/bin/sh\nset -e\nmise lock\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(&said, &["mise.toml:13", "mise-tasks/relock:3"]);
    for clean in ["mise.toml:9", "mise.toml:12"] {
        assert!(
            !said.contains(clean),
            "{clean} is not a second writer\n{said}"
        );
    }
}

/// R8 minor: an `[[env]]` array's `_.file` is a route, and a `_.file` resolves
/// against the CONFIG ROOT — the directory above `.config/mise/`, `mise/` or
/// `.mise/` — not the file's own directory.
#[test]
fn an_env_file_resolves_against_the_config_root() {
    let (code, said) = judge(&fixture(
        "install-locked-env-root",
        &[
            (
                "mise.toml",
                &manifest(LOCKED, "\n[[env]]\n_.file = \".env.unread\"\n"),
            ),
            (".config/mise/config.toml", "[env]\n_.file = \".env\"\n"),
            (".env", "MISE_LOCKED=false\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    reports_each(&said, &["tool install unsafe at mise.toml", ".env:1"]);
    assert!(
        !said.contains("at .config/mise/config.toml"),
        "the root's `.env` is the file that config loads, and it is read\n{said}"
    );
}

/// R8 minor: tools declared only below the root install under the root's
/// settings, so a root with no `[tools]` still needs the lock on.
#[test]
fn a_root_without_tools_still_needs_the_lock() {
    let (code, said) = judge(&fixture(
        "install-locked-rootless-tools",
        &[
            ("mise.toml", "[settings]\nlockfile = true\n"),
            ("crates/a/mise.toml", "[tools]\n\"t\" = \"1.0.0\"\n"),
        ],
    ));
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("lock read loose"), "{said}");
}

/// THE COMMITTED TREE INSTALLS LOCKED EVERYWHERE: the committed rule, run over
/// this repository itself — its `mise.toml`, every overlay, `batten.toml`'s
/// handler and startup argv, every workflow, action, hk step and task script.
/// `[tasks.lock-complete]`'s `#MUTANT` rows flip `[settings]` and
/// `session:install`'s env and redden this case.
#[test]
fn the_committed_tree_installs_locked_everywhere() {
    let out = run(
        &common::committed_repo().to_path_buf(),
        &["check", "--rule", RULE],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the committed tree installs locked\n{}{}",
        stdout(&out),
        common::stderr(&out)
    );
}

/// Mark `path` executable where the platform has the bit.
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("make the tool executable");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The `mise` the suite runs under.
fn host_mise() -> PathBuf {
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join("mise"))
        .find(|candidate| candidate.is_file())
        .expect("the suite runs under mise, so `mise` is on PATH")
}

/// `mise <args>` in `project`, against the cold `home`, with every ambient
/// `MISE_*` dropped: exit status and stdout.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is how the real `mise` resolves a toolchain, so nothing in process can stand in for it"
)]
fn cold_mise(project: &Path, home: &Path, args: &[&str]) -> (bool, String) {
    use batten::capture::Streamed as _;
    let mut command = std::process::Command::new(host_mise());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("MISE_") {
            command.env_remove(name);
        }
    }
    let output = command
        .args(args)
        .current_dir(project)
        .env("MISE_DATA_DIR", home.join("data"))
        .env("MISE_CACHE_DIR", home.join("cache"))
        .env("MISE_STATE_DIR", home.join("state"))
        .env("MISE_CONFIG_DIR", home.join("config"))
        .env("MISE_CEILING_PATHS", home)
        .env("MISE_TRUSTED_CONFIG_PATHS", project)
        .streamed_output()
        .expect("run mise");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// THE TOOLCHAIN CHECKS DECIDE AS THE JOB RESOLVES (CLOUD-2881). A `github:`
/// install dir placed by hand, with no `.mise.backend.toml`, is the state a
/// by-hand repair leaves. Under `lockfile = false` the verdicts split on it,
/// measured on mise 2026.9.1: `toolchain-check`'s `mise install
/// --dry-run-code` said 1, `toolchain-is-provisioned`'s `mise ls --current
/// --missing` said nothing (pass), and `mise run` failed 127 on the API's 403.
/// Under this repository's committed `[settings]`, read here rather than
/// restated, the two checks must agree with the job for the bare dir and the
/// registered one alike. `[tasks.lock-complete]`'s `settings-split-verdicts`
/// row reopens the split, and this case reddens.
#[test]
fn the_toolchain_checks_decide_as_the_job_resolves() {
    // THE FIXTURE TOOL IS AN `sh` SCRIPT: off unix there is no tool for the job
    // to run, and the case compiles everywhere so the other target type-checks
    // it.
    if !cfg!(unix) {
        return;
    }
    let committed: toml::Table = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("read mise.toml")
        .parse()
        .expect("mise.toml parses");
    let setting = |key: &str| {
        committed["settings"]
            .get(key)
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    };
    let (lockfile, locked) = (setting("lockfile"), setting("locked"));
    let tool = "github:example-org/example-tool";
    let mut lock = format!("[[tools.\"{tool}\"]]\nversion = \"1.0.0\"\nbackend = \"{tool}\"\n\n");
    for platform in ["linux-x64", "linux-arm64", "macos-x64", "macos-arm64"] {
        let block = format!(
            "[tools.\"{tool}\".\"platforms.{platform}\"]\nchecksum = \"sha256:{}\"\nurl = \"https://example.invalid/{platform}.tar.gz\"\n\n",
            "0".repeat(64)
        );
        lock.push_str(&block);
    }
    for registered in [false, true] {
        let home = scratch(if registered {
            "install-checks-agree-registered"
        } else {
            "install-checks-agree-bare"
        });
        let project = home.join("project");
        write(
            &project,
            "mise.toml",
            &format!(
                "[settings]\nlockfile = {lockfile}\nlocked = {locked}\n\n[tools]\n\"{tool}\" = \"1.0.0\"\n\n[tasks.t]\nrun = \"example-tool\"\n"
            ),
        );
        write(&project, "mise.lock", &lock);
        let installs = home.join("data/installs/github-example-org-example-tool");
        write(&installs, "1.0.0/example-tool", "#!/bin/sh\nexit 0\n");
        make_executable(&installs.join("1.0.0/example-tool"));
        if registered {
            write(
                &installs,
                ".mise.backend.toml",
                &format!("short = \"{tool}\"\nfull = \"{tool}\"\nexplicit_backend = true\n"),
            );
        }
        let (check, _) = cold_mise(&project, &home, &["install", "--dry-run-code"]);
        let (listed, missing) = cold_mise(&project, &home, &["ls", "--current", "--missing"]);
        let startup = listed && missing.trim().is_empty();
        let (job, _) = cold_mise(&project, &home, &["run", "t"]);
        assert_eq!(
            (check, startup),
            (job, job),
            "registered={registered}: toolchain-check {check}, startup check {startup}, \
             the job {job}, under lockfile={lockfile} locked={locked}"
        );
    }
}

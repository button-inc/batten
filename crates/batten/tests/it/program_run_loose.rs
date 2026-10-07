//! `program run loose` over the compiled binary (CLOUD-2123): no `mise` task
//! calls the installer.
//!
//! THE COMMITTED ROW, NOT A COPY. The fixture under `tests/fixtures/repos` holds
//! the regex as text, so it would stay green over an edit to `batten.toml`; this
//! lifts the row out of the authority itself, so the `#MUTANT` row beside it has
//! something to redden.

use crate::common;

use common::{Fixture, run, stdout};

/// The `[[rule]]` block whose id is `program run loose`, as `batten.toml` spells it.
fn committed_row() -> String {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("the authority");
    let id = text
        .find("id = \"program run loose\"")
        .expect("batten.toml declares the row");
    let start = text[..id].rfind("[[rule]]").expect("the row's header");
    let end = text[id..]
        .find("\n\n")
        .map_or(text.len(), |offset| id + offset);
    text[start..end].to_owned()
}

/// `check` the row over a fixture `mise.toml`; return the exit code and stdout.
fn check(name: &str, tasks: &str) -> (Option<i32>, String) {
    let config = format!("version = 1\n\n{}\n", committed_row());
    let dir = Fixture::new(name)
        .config(&config)
        .files(&[("mise.toml", tasks)])
        .base_commit()
        .build();
    let out = run(&dir, &["check"]);
    (out.status.code(), stdout(&out))
}

#[test]
fn a_task_calling_the_installer_is_refused_and_prose_is_not() {
    let (code, out) = check(
        "program-run-loose-committed",
        "# Prose naming `./install.sh` in backticks is not a call.\n\
         [tasks.a]\n\
         run = [\"./install.sh\", \"batten engine update\"]\n\
         [tasks.b]\n\
         run = \"./install.sh\"\n\
         [tasks.c]\n\
         run = [\"batten engine update\", \"batten wiring reclaim -y\"]\n",
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("mise.toml:3 rule 'program run loose'"),
        "an argv entry: {out}"
    );
    assert!(
        out.contains("mise.toml:5 rule 'program run loose'"),
        "a whole run string: {out}"
    );
    assert!(
        !out.contains("mise.toml:1 "),
        "prose in backticks is not a call: {out}"
    );
    assert!(
        !out.contains("mise.toml:7 "),
        "the binary installing itself is the route: {out}"
    );
}

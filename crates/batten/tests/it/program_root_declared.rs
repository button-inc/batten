//! The consumer's program root is declared once, and every reader reads it
//! (CLOUD-2366).
//!
//! `land` reaps an abandoned landing's process groups only through
//! `BATTEN_TASK_PROGRAM_ROOT` (`run_land_singleton`), and nothing set it: the
//! reap was dead code, so a killed landing's verify groups — reparented to init,
//! which a background stop's tree walk never reaches — ran on into the next
//! landing. `alive` spelled the same fact as a literal beside it, which is the
//! second authority this pins away.
//!
//! READ THROUGH `common::task_block`, the sweep's own boundary, so under
//! `mutate sweep` the staged manifest is the one judged.

use crate::common;

#[test]
fn the_program_root_is_declared_once_and_alive_reads_it() {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("the task manifest is readable");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml is TOML");
    let declared = parsed
        .get("env")
        .and_then(|env| env.get("BATTEN_TASK_PROGRAM_ROOT"))
        .and_then(toml::Value::as_str);
    assert_eq!(
        declared,
        Some("mise-tasks"),
        "`[env]` declares the program root `land`'s reap reads"
    );
    let spellings = manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("BATTEN_TASK_PROGRAM_ROOT ="))
        .count();
    assert_eq!(spellings, 1, "the program root is declared exactly once");

    let block = common::task_block("alive").expect("alive is a declared task");
    let run = common::task_value(&block, "run");
    assert!(
        run.contains("{{env.BATTEN_TASK_PROGRAM_ROOT}}"),
        "alive reads the declared root: {run}"
    );
    assert!(
        !run.contains("mise-tasks"),
        "alive repeats no literal root beside the declared one: {run}"
    );
}

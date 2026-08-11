---
paths:
  - "crates/**/*.rs"
  - "crates/**/Cargo.toml"
---

# Rust conventions

These load when you touch Rust; they do not need to be in context otherwise.

- Keep `main` thin: logic in the library (`lib.rs` + modules) so it's testable.
  The binary only parses args, calls `run`, and maps the result to an exit status.
- Library code obeys the workspace lints: no `unwrap`/`expect`/`panic` on
  reachable paths, no stray `print*!` (the binary boundary is the one sanctioned
  place to write stderr), `unsafe` forbidden.
- Every behavioral change ships with a test, and a test must be **shown able to
  fail**: where the environment cannot produce the failing condition — this
  sandbox runs as root, so permission bits never bite — extract the decision and
  test it directly (`markers::scannable`) rather than asserting a conclusion over
  a precondition that was never created. A test that still depends on such a
  condition asserts its own premise before its conclusion; `tests/primitives.rs`'s
  `every_permission_drop_asserts_its_own_premise` is the gate (CLOUD-249).
  Prefer end-to-end tests over the
  compiled binary (`crates/batten/tests/cli.rs`) for anything a consumer depends
  on — exit codes, output shape, flag handling.
- Branch on the named `ExitCode` variants in `crates/batten/src/exit.rs`, never
  integer literals. One table, no per-verb exception: `2` is the policy verdict
  everywhere — a `check` violation and a `hook` deny alike — and `1`/`3` are the
  only codes a Batten failure produces, so no failure path can block a call.

## Layout

The per-module map — every `src/*.rs` file, what it owns, and where its
rationale doc comment lives — is `mem:core`, kept current instead of a tree
restated here.

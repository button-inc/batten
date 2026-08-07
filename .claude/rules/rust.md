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
- Every behavioral change ships with a test. Prefer end-to-end tests over the
  compiled binary (`crates/batten/tests/cli.rs`) for anything a consumer depends
  on — exit codes, output shape, flag handling.
- Branch on the named `ExitCode` variants in `crates/batten/src/exit.rs`, never
  integer literals. The `hook` layer inverts part of the contract so exit `2`
  denies a mediated call; that inversion lives with the hook layer only.

## Layout

```
crates/batten/
  src/main.rs   thin binary: parse → run → exit status
  src/lib.rs    library entry (`run`), module tree
  src/cli.rs    clap command surface (empty tree at scaffold stage)
  src/exit.rs   the exit-code contract
  tests/cli.rs  end-to-end tests over the compiled binary
```

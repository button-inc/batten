# Delegation brief — refresh the acceptance corpus

A brief that carries every fact the receiving session cannot infer. Checked in
rather than reconstructed, for the reason `tests/fixtures/hooks/` states: a
fixture written from memory pins what the author believed, not what the format is.

## Identifiers

CLOUD-84. Branch `wenzowski/cloud-84-lint-delegation-briefs-against-a-handoff-schema`.
The corpus lives under `crates/batten/tests/fixtures/acceptance-corpus/`.

## Scope

Only the corpus fixtures and the loader that reads them. The engine's rule
vocabulary is out of scope; so is anything under `crates/batten/src/hook.rs`.

## Per-scope instructions

`.claude/rules/rust.md` binds here: prefer an end-to-end test over the compiled
binary, and branch on the named `ExitCode` variants rather than integer literals.
Findings go on the issue, not into chat.

## Already read

- `crates/batten/src/rules.rs` — the four rule kinds and the `scope` router.
- `crates/batten/tests/acceptance_corpus.rs` — the existing loader.
- `mem:core` — the module map, for where a new module's row belongs.

## Check

Re-runnable, deterministic, and the thing to report back:

```
mise run test:cargo
```

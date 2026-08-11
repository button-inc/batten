# Delegation brief — refresh the acceptance corpus

The failure CLOUD-84 exists to catch, in its commonest shape: everything a human
reader would call complete, and no deterministic check for the receiver to run.
The handoff ends with "report back", which is a request for prose.

## Identifiers

CLOUD-84. Branch `wenzowski/cloud-84-lint-delegation-briefs-against-a-handoff-schema`.
The corpus lives under `crates/batten/tests/fixtures/acceptance-corpus/`.

## Scope

Only the corpus fixtures and the loader that reads them. The engine's rule
vocabulary is out of scope; so is anything under `crates/batten/src/hook.rs`.

## Per-scope instructions

`.claude/rules/rust.md` binds here: prefer an end-to-end test over the compiled
binary, and branch on the named `ExitCode` variants rather than integer literals.

## Already read

- `crates/batten/src/rules.rs` — the four rule kinds and the `scope` router.
- `crates/batten/tests/acceptance_corpus.rs` — the existing loader.

Report back when the corpus loads.

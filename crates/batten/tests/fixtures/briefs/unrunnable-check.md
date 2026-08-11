# Delegation brief — refresh the acceptance corpus

Every section present, and the check section describes the check in prose instead
of handing over a command. This is the shape a separate reply scanner used to be
proposed for: without a runnable pointer in the brief, the only way to learn what
the receiver actually ran is to read what it says it ran.

## Identifiers

CLOUD-84. Branch `wenzowski/cloud-84-lint-delegation-briefs-against-a-handoff-schema`.

## Scope

Only the corpus fixtures and the loader that reads them.

## Per-scope instructions

`.claude/rules/rust.md` binds here.

## Already read

- `crates/batten/src/rules.rs`
- `crates/batten/tests/acceptance_corpus.rs`

## Check

Run the Rust suite and make sure it is green before reporting back.

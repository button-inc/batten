# Batten

Batten is a repo-agnostic **policy engine** that keeps *"done"* aligned with
landed-and-verified work. It gates what gets written, proves what was verified,
and refuses to let unlanded work appear finished — enforcing one repository's
policy consistently at the pre-commit layer, in CI, and at an agent's tool call.

> **Status:** early scaffold. The command surface is being filled in against the
> project plan; see [Roadmap](#roadmap).

## Why

Repo-config-driven permission hooks that can gate an agent's tool call *before*
execution are new, and earlier tooling was built for humans at commit time
rather than agents operating mid-trajectory. Batten's scarce property is
**agent-neutrality**: different harnesses expose different hook contracts and
decision vocabularies, and Batten provides a neutral translation layer — a
normalized stdin JSON envelope, a block decision returned via exit code, and any
richer per-agent behavior handled in thin shims.

## Design principles

- **Agent-neutral** operation rather than a bespoke interposition layer.
- **Deterministic** verification with byte-stable machine-readable output — the
  same input produces identical bytes, keeping agent caches warm.
- **Rules ship with their mechanism.** A prose rule without a gate is
  feedforward-only; a defect log without a gate is sensor-only. Both are half a
  harness.
- **The CLI is data.** A single usage spec is the source of truth for
  completions, man pages, and markdown, and effects are annotated once and
  reused (the agent read-only allowlist is *derived* from those annotations).
- **Narrow configuration.** A two-layer TOML model — a repo file plus env and
  flag overrides — with no upward walk and no `conf.d` merge surface.
- **Zero-config by default.** `check` works on built-in defaults; `init` is
  opt-in; `doctor` provides `--json` and a documented exit-code table.
- **Gates are computable predicates, not model judgements.**
- **Consumer #1 is Batten itself** — its own checked-in `batten.toml` runs
  against its own repository.

## Scope and limits

Batten is a policy engine, **not** a general-purpose hook runner, file-shape
linter, secret scanner, AST linter, or reference monitor. Its threat model is
honest agent or human error: acting on the wrong entity, at the wrong time, or
with the wrong completion signal. It cannot reliably catch attacker- or
error-chosen parameters of otherwise-permitted calls, harmful composition of
individually legal steps, cross-session poisoning, or errors in its own spec.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
```

## Exit-code contract

| Code | Meaning |
| ---- | ------- |
| `0`  | Success — check passed or nothing to report |
| `1`  | Policy violation (the invocation itself was well-formed) |
| `2`  | Usage error (bad flags, unreadable config) |
| `70` | Internal error — Batten could not complete the check |

The `hook` subcommand deliberately inverts part of this contract so that exit
`2` **denies** a mediated tool call.

## Roadmap

Work is tracked on the project board across phases:

0. Pre-implementation blockers and decisions
1. Foundation — scaffold, config, core extraction, fixtures
2. Contracts and checks — CLI contract and rule/check engine
3. Enforcement and capabilities — hook layer, advisory subsystem
4. Packaging and distribution
5. Consumer #1 migration

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work,
as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.

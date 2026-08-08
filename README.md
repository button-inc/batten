# Batten

Batten is a repo-agnostic **policy engine** that keeps _"done"_ aligned with
landed-and-verified work. It gates what gets written, proves what was verified,
and refuses to let unlanded work appear finished — enforcing one repository's
policy consistently at the pre-commit layer, in CI, and at an agent's tool call.

> **Status:** early scaffold. The command surface is being filled in against the
> project plan; see [Roadmap](#roadmap). The crate is not yet published and the
> repository is private, so there is no public install path yet — distribution
> is a recorded, deferred decision on the project board.

## Why

Repo-config-driven permission hooks that can gate an agent's tool call _before_
execution are new, and earlier tooling was built for humans at commit time
rather than agents operating mid-trajectory. The hook layer itself is
deliberately boring: the major harnesses have converged on one wire shape — a
JSON payload on stdin, a block returned as exit code `2`, a JSON verdict on
stdout — so Batten's normalized envelope and thin per-host shims are cheap
insurance against divergence, not the product. What no existing tool occupies
is the layer behind the hook: one policy engine rendering the same verdict from
the same committed config at the pre-commit layer, in CI, and at an agent's
tool call, with completion predicates — landed, verified, CI-green — as
first-class rules.

## Design principles

- **Agent-neutral** operation rather than a bespoke interposition layer.
- **Deterministic** verification with byte-stable machine-readable output — the
  same input produces identical bytes, keeping agent caches warm.
- **Rules ship with their mechanism.** A prose rule without a gate is
  feedforward-only; a defect log without a gate is sensor-only. Both are half a
  harness.
- **The CLI is data.** A single usage spec is the source of truth for
  completions, man pages, and markdown, and effects are annotated once and
  reused (the agent read-only allowlist is _derived_ from those annotations).
- **Narrow configuration.** A two-layer TOML model — a repo file plus env and
  flag overrides — with no upward walk and no `conf.d` merge surface.
- **Zero-config by default** _(planned — CLOUD-70, CLOUD-66)_: `check` on
  built-in defaults, opt-in `init`, and a `doctor` with `--json`. Today `check`
  requires a `batten.toml` in the working directory.
- **Gates are computable predicates, not model judgements.**
- **Consumer #1 is Batten itself** — its own checked-in `batten.toml` runs
  against its own repository.

## Scope and limits

Batten is a policy engine: it **evaluates** narrow content predicates and
**wraps** linters, scanners, and hook runners as evidence sources — a rule kind
exists to gate on a tool's verdict, never to replace the tool, so the boundary
holds even as rule kinds grow. Its threat model is honest agent or human error:
acting on the wrong entity, at the wrong time, or with the wrong completion
signal — where "wrong entity" means a call's argument values, judged against
committed, out-of-band config. It cannot reliably catch attacker- or
error-chosen parameters of otherwise-permitted calls, harmful composition of
individually legal steps, cross-session poisoning, or errors in its own spec.
And a green check certifies exactly its predicates, nothing more: over-trusting
it is the misuse cost of any gate that works, which is why review still gates
release.

## Build and test

```bash
mise install     # the pinned toolchain — see CONTRIBUTING.md for one-time setup
mise run ci      # the same gate CI runs
```

Everything goes through [mise](mise.toml) tasks so local runs, git hooks, and
CI execute byte-identical commands; [CONTRIBUTING.md](CONTRIBUTING.md) has the
per-clone setup and the task tour.

## Exit-code contract

One table, total, with no per-verb exception.

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Success — check passed, nothing to report, mediated call allowed            |
| `1`  | Usage or config error (bad flags, unreadable config)                        |
| `2`  | Policy verdict — a violation found, or a mediated call **denied**           |
| `3`  | Internal error — Batten could not complete the check                        |

The numbering is chosen so the mediation channel needs no translation: hosts
with a pre-tool hook read `0` as allow, `2` as deny with stderr as the reason,
and anything else as "the hook itself failed, let the call through". A deny and
a violation share a code because they are the same kind of answer, and
**failing open is structural** — the only codes a Batten failure can produce
are ones every harness already treats as non-blocking.

The channel varies by harness even though the number does not: a host whose
only decision channel is process status is denied by exit `2`, while a host
that reads an in-band decision document is denied by that document with exit
`0`.

## Roadmap

Work is tracked on the project board across phases:

0. Pre-implementation blockers and decisions
1. Foundation — scaffold, config, core extraction, fixtures
2. Contracts and checks — CLI contract and rule/check engine
3. Enforcement and capabilities — hook layer, advisory subsystem
4. Packaging and distribution
5. Consumer #1 migration

## License

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE). Unless you
explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work, as defined in the Apache-2.0 license, shall be licensed
as above, without any additional terms or conditions.

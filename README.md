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
  reused (the agent read-only allowlist is _derived_ from those annotations and
  emitted by `batten spec` as `read_only_allowlist`, so a consumer reads it
  rather than re-deriving it).
- **Narrow configuration.** A two-layer TOML model — a repo file plus env and
  flag overrides — with no upward walk and no `conf.d` merge surface.
- **Zero-config by default** _(planned — CLOUD-70, CLOUD-66)_: `check` on
  built-in defaults, opt-in `init`, and a `doctor` with `--json`. Today `check`
  requires a `batten.toml` in the working directory.
- **Gates decide, they do not estimate.** A predicate that only approximates its
  own question — a model judgement, or a match over open-ended content — may
  advise; it never blocks.
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

## Performance

Batten runs as a `PreToolUse` hook, so its cost is paid on **every** mediated
tool call rather than once per commit. These are measured numbers, not targets —
`mise run bench` reproduces them, and `mise run bench-assert` fails when a
measured p95 leaves its budget.

| path    | what it does                                   | p50    | p95    | budget   |
| ------- | ---------------------------------------------- | ------ | ------ | -------- |
| `noop`  | process start, command tree, render             | 2.4 ms | 2.9 ms | ≤ 100 ms |
| `check` | + config load, trust resolution, one-rule tree   | 2.5 ms | 2.7 ms | —        |
| `hook`  | + envelope decode, adjudication, decision write | 2.6 ms | 3.1 ms | ≤ 100 ms |

100 ms is the [Command Line Interface Guidelines'][clig] floor for a response
that reads as instant. It is an absolute ceiling rather than a tight band around
the measured value: a shared runner's p95 moves by more than a percentage band
between two runs of identical bytes, so a tighter gate would fire on noise
instead of on regressions. `check` is measured and deliberately not budgeted —
its cost is bounded by the repository it is pointed at, not by Batten, and no
ceiling here could tell a large tree apart from a regression.

<!-- prettier-ignore -->
> Measured at `140ec24`, 2026-08-11, on a 4-core x86_64 Linux container:
> release build, 10 warmup runs discarded, 100 timed runs per path, p95 from
> the sorted run times. Your machine will differ; the budget is what the gate
> holds, and the schedule in
> [`.github/workflows/bench.yml`](.github/workflows/bench.yml) is what keeps
> holding it.

[clig]: https://clig.dev/#responsiveness

## Exit-code contract

One table, total, with no per-verb exception. `batten --help` prints the same
table, and each meaning below is asserted against the binary's own rendering, so
this section cannot drift from the codes the binary returns.

| Code | Meaning                                                 |
| ---- | ------------------------------------------------------- |
| `0`  | clean — nothing to report; a mediated call is allowed   |
| `1`  | config or usage error — fail loud, do not block         |
| `2`  | policy verdict — a violation, or a mediated call denied |
| `3`  | internal error — fail loud, do not block                |

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

`batten doctor` is the post-install self-check: it reports whether Batten can
run in this repository, with `--json` for a byte-stable machine reading. It is a
_diagnostic_, so it never returns `2` — every failure it can report is the
config-or-usage class, and a harness must never read "this checkout is
misconfigured" as a policy denial.

## Extending Batten: three surfaces, and which to reach for

Any predicate you can express as a command plus an exit code is expressible in
Batten. There are three ways to do it, and the failure mode is picking the wrong
one — so the boundary matters more than the mechanics.

| What you are gating on                                  | Reach for                | Where it is configured           |
| ------------------------------------------------------- | ------------------------ | -------------------------------- |
| A **file's contents**                                   | a `command` rule kind    | `[[rule]]` with `kind="command"` |
| A **command's output**, when the tool lies about exit 0 | `exec` output predicates | `[[exec_pattern]]`               |
| An **existing warn finding**, to make it block          | `fail_on_warning`        | a top-level key                  |

Everything a consumer adds is **raise-only** (§8): a git-ignored
`batten.local.toml` may add a rule or a pattern, never redefine or remove one the
committed authority declares. A weakening is refused with exit `1`, not applied.

### Gating on a file's contents — a `command` rule

`glob` selects the files, `run` names the command, and `{{files}}` is substituted
with the matched paths. Exit `0` passes; any non-zero exit is a violation.

```toml
[[rule]]
id = "single-entrypoint"
kind = "command"
glob = "src/**/*.rs"
run = "./scripts/one-entrypoint {{files}}"
severity = "deny"
```

A `command` rule runs under `batten enforce` only. `batten check` **refuses** it
with a usage error rather than running it, which is what keeps `check`'s
read-only effect honest — the read-only surface never reaches user-supplied code.

**Don't reach for this** when you want to gate a command's _output_: the child's
streams are discarded here, deliberately. The exit code is the whole predicate.

### Gating on a command's output — an `exec` output predicate

For a tool that exits `0` while its own output says the work is not really done,
and has no severity knob of its own to make it fail.

```toml
[[exec_pattern]]
id = "no-unfailed-duplicate"
pattern = "warning[duplicate]"
stream = "both"
reason = "set the tool's own severity to deny; do not let a warning ride an exit 0"
```

```console
$ batten exec -- cargo deny check
stdout:14 no-unfailed-duplicate
exec: 1 output match(es)
no-unfailed-duplicate: set the tool's own severity to deny; …
```

A match **always fails**. There is no severity field on a pattern and no
dependence on `fail_on_warning`, because the only surface an agent acts on is the
exit code: a warn-but-pass match would be invisible to it, which is the exact
false green the predicate exists to kill.

Batten only ever _adds_ failure — a child that already exited non-zero passes its
code through untouched.

**Don't reach for this** when the tool has its own severity model. Configure that
instead; re-implementing a tool's severity as output-scraping is the thing this
surface should not become.

### Making an existing warn finding block — `fail_on_warning`

A `warn`-severity rule reports and does not fail the run. `fail_on_warning`
promotes it, and it is the _only_ promotion knob: no verb carries its own.

```toml
fail_on_warning = true
```

`batten exec` is deliberately **not** a consumer — an exec output match already
fails unconditionally, so there is nothing for a promotion to promote.

### The two promotion paths do not share a code, and that is worth knowing

|                                         | Not promoted | Promoted |
| --------------------------------------- | ------------ | -------- |
| a `warn` finding from `check`/`enforce` | exit `0`     | exit `2` |
| an `exec` output match                  | —            | exit `1` |

A rule finding is a policy verdict about the repository, which is exit `2` on
every surface that renders one. An `exec` match reports that the _invocation's own
report_ was untrustworthy, and `exec` is a transparent passthrough whose codes are
otherwise the wrapped command's — so it uses exit `1`.

That asymmetry is a known rough edge rather than a settled design: a transparent
verb cannot also render a policy verdict on the same channel without some
ambiguity against the child's own codes, whichever number it picks. Tracked as
CLOUD-292 rather than papered over here.

### Every example above is executed, not just written

`crates/batten/tests/extension_surfaces.rs` runs each command in this section
against the compiled binary and asserts the exit code it claims. A drifted example
fails CI, so this documentation cannot rot into fiction.

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

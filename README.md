# Batten

Batten is an **agent-era completion gate**: repo-state conformance checks — is
this ref on `main`? did the required checks conclude green for this exact SHA? —
enforced at the agent's tool call, and re-checked in CI and at pre-commit so the
verdict cannot be bypassed.

Your agent says "done." The repository knows otherwise: the branch never landed,
the checks never ran on that SHA, the tests were edited until they passed. Batten
is the deterministic check at the moment of the claim — the throughput stays, the
false _"done"_ dies.

_"Done"_ here is the **minimum falsifiable completion predicate**: landed on
`main` by fast-forward, with the required checks green for that exact SHA. It
kills false success. It does not certify correctness, and review still gates
release.

> **Status:** early scaffold. The command surface is being filled in against the
> project plan; see [Roadmap](#roadmap). The crate is not yet published and the
> repository is private, so there is no public install path yet — distribution
> is a recorded, deferred decision on the project board.

## Install

Binary first: a release archive holds a single static executable, and every
package manager below is a convenience over the same asset. **While the
repository is private a GitHub token is required** — the script reads
`BATTEN_GITHUB_TOKEN`, `GH_TOKEN` or `GITHUB_TOKEN`, and needs none of them once
the repository is public.

```sh
curl -fsSL https://raw.githubusercontent.com/button-inc/batten/main/install.sh | sh
```

It detects your platform, downloads that target's archive, **verifies it against
the SHA-256 digest the release reports and refuses to install on a mismatch**,
and puts `batten` in `${XDG_BIN_HOME:-$HOME/.local/bin}`. `BATTEN_VERSION`
selects a tag other than the latest, `BATTEN_INSTALL_DIR` a different
destination, and `BATTEN_TARGET` overrides platform detection — Linux resolves to
the statically linked `musl` build, which runs whatever the host's glibc version.

`cargo binstall` reads the same assets through `[package.metadata.binstall]`:

```sh
cargo binstall --git https://github.com/button-inc/batten batten
```

The plain `cargo binstall batten` form needs the crate on a registry, which the
distribution decision defers along with the public repository.

Binaries are never committed to this repository; they come from a release, and
`mise run install-check` is the gate that keeps every reader of an asset name
agreeing with the one that writes it.

## Why

Repo-config-driven **conformance gates** that can judge an agent's tool call
_before_ execution are new, and earlier tooling was built for humans at commit
time rather than agents operating mid-trajectory. The hook layer itself is
deliberately boring: the major harnesses have converged on one wire shape — a
JSON payload on stdin, a block returned as exit code `2`, a JSON verdict on
stdout — so Batten's normalized envelope and thin per-host shims are cheap
insurance against divergence, not the product. What no existing tool occupies is
the layer behind the hook: one engine rendering the same verdict from the same
committed config at the agent's tool call — and again in CI and at pre-commit, so
the verdict cannot be bypassed — with completion predicates (landed, verified,
CI-green) as first-class rules.

The hook is the binding surface because it fires on events the agent cannot
decline, and because it reads committed, out-of-band config that the model's
context cannot influence. Any surface the model must _choose_ to consult loses to
the primitive it already trusts.

### Cheap to consult, so it gets consulted

A gate an agent routes around is a gate that does not run, and what agents route
around is expense. Three pains compound in an agent's context, and a tool that
answers with a dump makes every one of them worse:

- **Tail-calling.** The output did not fit, so the agent runs the command again to
  see a different slice — paying twice for one answer, often for the wrong slice.
- **Lost-in-the-middle.** A two-thousand-line dump buries the one line that
  mattered exactly where retrieval is weakest.
- **Context rot.** Every avoidable byte crowds out the working state the agent
  needs to finish the task it was actually doing.

Batten's output contract answers all three at once. A finding is a **pointer, not
a payload** — a count and a `path:line`, never the matched content — so a wrapped
tool's two thousand lines become one. Output is **byte-stable**, so an unchanged
repository renders identical bytes and the agent's prefix cache stays warm instead
of being invalidated by a reordered map or a timestamp. And a refusal **points at
the fix**: a deny names the rule, the reason, and the command to run instead,
which is one hop to right rather than a round of guessing.

Magnitude belongs to the benchmark, not to this page. The
[token-economics benchmark][token-economics] is the proof, and it is measured
per capability against a named workload with a stated baseline and run count. No
figure is published here until it has been measured that way; a capability with no
defensible number reports "not measured" rather than borrowing one.

[token-economics]: https://linear.app/buttoninc/document/batten-adoption-proof-token-economics-benchmark-headline-story-685716ec5b7a

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

Batten **evaluates** narrow content predicates and
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

`wired` is the number an agent actually waits on: the entry point
`.claude/settings.json` invokes, launcher included, **derived from that file at
measure time** rather than hardcoded — so the published figure describes what is
installed rather than a binary nothing calls. `hook` stays measured beside it so
the launcher's own share is attributable.

| path    | what it does                                    | p50    | p95    | budget   |
| ------- | ----------------------------------------------- | ------ | ------ | -------- |
| `noop`  | process start, command tree, render             | 2.1 ms | 2.4 ms | ≤ 100 ms |
| `check` | + config load, trust resolution, one-rule tree  | 2.3 ms | 2.7 ms | —        |
| `hook`  | + envelope decode, adjudication, decision write | 2.8 ms | 3.0 ms | ≤ 100 ms |
| `wired` | the hook as `.claude/settings.json` invokes it  | 8.0 ms | 8.4 ms | ≤ 100 ms |

100 ms is the [Command Line Interface Guidelines'][clig] floor for a response
that reads as instant. It is an absolute ceiling rather than a tight band around
the measured value: a shared runner's p95 moves by more than a percentage band
between two runs of identical bytes, so a tighter gate would fire on noise
instead of on regressions. `check` is measured and deliberately not budgeted —
its cost is bounded by the repository it is pointed at, not by Batten, and no
ceiling here could tell a large tree apart from a regression.

<!-- prettier-ignore -->
> Measured 2026-08-12 on a 4-core x86_64 Linux container: release build, 10
> warmup runs discarded, 100 timed runs per path, p95 from the sorted run times.
> Your machine will differ; the budget is what the gate holds, and the schedule
> in [`.github/workflows/bench.yml`](.github/workflows/bench.yml) is what keeps
> holding it.

<!-- prettier-ignore -->
> **A correction, kept because the mistake is the instructive part.** The
> previous revision of this table published `hook` at 16.6 ms and blamed a
> concurrently-loaded container. That explanation was wrong. The cost was a
> real regression — one `receipt` row made *every* mediated call resolve
> receipts, four git subprocesses' worth, including calls no receipt rule could
> ever match (CLOUD-460). Measured on the command that exposed it, the fix is
> **3.44× ± 0.30 faster**: 9.4 ms → 2.7 ms. It sat inside the ≤ 100 ms budget
> the whole time, so no gate went red — which is exactly why a wrong
> explanation in a performance note is worse than none: it tells the next
> reader the number is environmental and not to look.

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

`glob` selects the files, `check` names the command, and `{{files}}` is
substituted with the matched paths. Exit `0` passes; any non-zero exit is a
violation.

```toml
[[rule]]
id = "single-entrypoint"
kind = "command"
glob = "src/**/*.rs"
check = "./scripts/one-entrypoint {{files}}"
severity = "deny"
```

The key is `check` rather than `run` because the kind carries a **`check`/`fix`
duality** (§9): `check` is the inspection-only gate, and an optional `fix` names
the mutating command that repairs what it condemned. Enforcement is always the
check side. `fix` is **reserved, not yet executed** — serialised fix execution is
not a capability this engine has, so `batten enforce` refuses a rule declaring
one with a usage error rather than accepting a repair that would silently never
run.

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

## Running Batten in GitHub Actions

The shipped Action works with an **empty `with:` block** — that is the bar it is
held to, not a convenience it happens to offer:

```yaml
- uses: actions/checkout@v5
- uses: button-inc/batten@v0.0.61
```

That runs `batten check` in the workspace against the `batten.toml` committed
there, and fails the step on a policy verdict. Every input has a default, and the
defaults are the useful configuration.

The version is not a fourth thing to keep in sync: with `version` unset the Action
reads its **own** crate version from the `Cargo.toml` beside it, so the ref you
pin selects the binary. `@v0.0.61` runs Batten `0.0.61`. There is no `latest`
resolution to let the two disagree, and a tag whose release published no asset
fails loudly rather than substituting another version.

### Inputs

| input               | default               | meaning                                                           |
| ------------------- | --------------------- | ----------------------------------------------------------------- |
| `command`           | `check`               | the verb to run                                                   |
| `args`              | `""`                  | extra arguments, split on whitespace                              |
| `working-directory` | `.`                   | where the verb runs, and therefore which `batten.toml` governs    |
| `version`           | `""`                  | empty means this action ref's own version                         |
| `github-token`      | `${{ github.token }}` | reads the release asset                                           |
| `cache`             | `true`                | restore and save the downloaded binary                            |
| `fail`              | `true`                | fail the step on a non-zero code; `false` reports it as an output |

### Outputs

| output      | meaning                                                  |
| ----------- | -------------------------------------------------------- |
| `exit-code` | Batten's code, under the one contract in the table above |
| `version`   | the version that ran                                     |
| `binary`    | absolute path to the binary, for a later step to invoke  |

`fail: false` is how a caller asserts an **exact** code rather than merely "the
step went red" — the run continues and the code arrives on `exit-code`:

```yaml
- uses: button-inc/batten@v0.0.61
  id: batten
  with:
    fail: false
- run: test "${{ steps.batten.outputs.exit-code }}" = "2"
```

The Action does **not** prepend its install directory to `PATH`. A `$GITHUB_PATH`
write changes how every later step in the job resolves a command, which is a
hazard disproportionate to the convenience; use the `binary` output instead.

### The cache key

The downloaded binary is cached under

```text
key:  batten-<version>-<target>
path: ~/.cache/batten/<version>/<target>
```

where `<target>` is the Rust target triple the runner maps to — `x86_64`/`aarch64`
`-unknown-linux-musl` on Linux (the statically linked build, so it runs on any
image regardless of glibc), `-apple-darwin` on macOS, `x86_64-pc-windows-gnu` on
Windows.

Both the version and the target are in the key and there are **no restore keys**:
a near-miss would restore a different version's binary under this one's name,
which is precisely the confusion a policy engine must not create. An entry is
therefore valid for exactly as long as its version is. Set `cache: false` to skip
restore and save entirely; the download is a little over a megabyte.

### The plain CLI alternative

Nothing above requires the Action. The same thing by hand, with no third-party
action in the path:

```yaml
- name: Install Batten
  env:
    GH_TOKEN: ${{ github.token }}
    VERSION: 0.0.61
    TARGET: x86_64-unknown-linux-musl
  run: |
    set -euo pipefail
    asset="batten-v$VERSION-$TARGET.tar.gz"
    id=$(gh api "repos/button-inc/batten/releases/tags/v$VERSION" \
      --jq ".assets[] | select(.name == \"$asset\") | .id")
    gh api "repos/button-inc/batten/releases/assets/$id" \
      -H "Accept: application/octet-stream" > "$asset"
    tar -xzf "$asset" -C /usr/local/bin batten
- run: batten check
```

The asset name is a contract, not a convenience — `mise-tasks/dist` builds it and
the release workflow uploads it under exactly that name — so this stays correct
independently of the Action.

### Tokens, and what a `GITHUB_TOKEN` will not do

`github-token` defaults to `${{ github.token }}`, which needs `contents: read`.
Inside this repository that is enough to read a release asset. **From another
repository it is not**: the job token is scoped to the repository running the
workflow, so a consumer must pass a token that can read releases on
`button-inc/batten` — which today is private, a recorded decision on the project
board rather than an oversight.

The note worth carrying past the install step: **events created with
`GITHUB_TOKEN` do not trigger further workflow runs.** GitHub suppresses them
deliberately, to stop a workflow recursing into itself. So if you wire Batten's
result into something that pushes a commit, opens a pull request, or files an
issue, that downstream event will start no workflow of its own while the default
token is in play. Reaching for a PAT is the documented way around it, and it is a
deliberate choice with the recursion the suppression exists to prevent — not a
configuration detail.

### The Action self-tests, and the test is allowed to fail

`.github/workflows/test.yml` checks this repository out into a subdirectory,
materializes a fixture repository from `crates/batten/tests/fixtures/repos/` at
the workspace root, and invokes the Action with **no `with:` key at all** — so the
empty-`with:` claim above is executed on a real runner rather than asserted here.

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

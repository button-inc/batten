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

## The spawn census: on a deny, resolve names — never grep

`clippy::disallowed_types` refuses `std::process::Command`, and each site carries
its verdict in the `#[expect(..., reason = "...")]` on the line it describes.
There is no census table and no count to maintain: `#[expect]` rather than
`#[allow]` means a **deleted** spawn with a stale annotation is red too, so the
inventory self-cleans in both directions (CLOUD-743, the mechanism CLOUD-320
shipped without). A new spawn is not forbidden — it is an inventory row, and the
annotation is where you write down whether it stays and why.

**On a deny, find the related sites with Serena's `find_referencing_symbols` over
`std::process::Command` — not `grep`.** rust-analyzer is live here and does true
name resolution; a string scan does not. That is not a preference: `surface.rs`
imports `clap::Command` bare, so the token names two different types in this
crate. Counting the sites with `grep` gave 14; a syntax-only matcher gives 11,
because a call expression looks the same whichever type it names. The answer is
neither, and reaching for a scanner is what produced both of the wrong turns
CLOUD-743 records. The same applies to reading a deny message that
points at somebody else's remedy (CLOUD-437).

## Concurrency posture — one authority, a verdict per row

CLOUD-747. This stance was re-derived independently in five places, each with its
own local reason and none pointing at the others; two of them argued partly on
**dependency cost**, a premise that dies the moment CLOUD-745 vendors an HTTP
client. This section is the one authority — the five sites cite it now instead of
each re-deriving it, and that consolidation is the deliverable.

Concurrency here is **OS threads**. There is no async runtime in the crate today:
`tokio` appears nowhere in `Cargo.lock`, and there is no `async fn` and no
`.await`. `tests/ambient_authority.rs` is the gate on that rather than this
paragraph.

| Row                                    | Today                          | Verdict                                                     |
| -------------------------------------- | ------------------------------ | ----------------------------------------------------------- |
| `exec.rs` drain threads (one per pipe) | OS threads                     | **stays, because nothing measured asks otherwise**          |
| `exec.rs --jobs` bundle                | `std::thread::scope`, in waves | **stays, because nothing measured asks otherwise**          |
| the `ignore` tree walk                 | serial                         | **stays, because nothing measured asks otherwise**          |
| `capture`/`journal` lock               | `fs4` advisory                 | **stays**, on a reason that outlives the dependency premise |
| `batten hook` runtime                  | none                           | **at most one, and never multi-thread**                     |
| mediated-call fact resolution          | lazy and narrow                | **stays serial until the document is wide**                 |

**"Because nothing measured asks otherwise" is the literal wording, and it is the
point.** CLOUD-320's discipline is a verdict backed by a measurement rather than
an argument, and the failure it names is the next reader re-running an experiment
somebody already ran. To move one of those rows, bring a number.

### The measurements (this container, 2026-08-21)

`mise run perf`, 100 runs per path. The README publishes a series from a quieter
machine and those are the numbers to quote; these are ~2.5x slower across the
board, so read the **ratios and the headroom**, which hold in either reading.

| path                                            | p50      | p95      |
| ----------------------------------------------- | -------- | -------- |
| `noop` (process start, no config, no git)       | 5.08 ms  | 11.65 ms |
| `passthrough` (a call no rule selects)          | 4.41 ms  | 7.65 ms  |
| `check` (one-rule fixture repo)                 | 6.33 ms  | 16.55 ms |
| `hook`                                          | 8.93 ms  | 16.54 ms |
| `wired` (as `.claude/settings.json` invokes it) | 21.31 ms | 32.58 ms |

Plus one this repository's own tree, which is the reading the `ignore` row needs
and which `perf`'s fixture is too small to give: `batten check` over **654
tracked files** is **p50 8.67 ms, p95 12.6 ms** (hyperfine, 60 runs). Against the
5.08 ms floor, the whole of config load, trust resolution, the serial walk and
every static rule is **~3.6 ms** — on a 100 ms budget. The parallel walker would
have to buy back §6 byte-stability with a deterministic merge, and there is
nothing here for it to buy that back **with**.

`passthrough` sitting **below** `noop` is the other load-bearing reading: a call
no row selects for does less work than `--help`. That is not an accident, it is
the design — `required_checks_for` narrows to declared rows, `key_base_for` to
`requires_key` rows, an empty waiver table skips the clock, and `stop_facts` runs
only on the Stop event. **There is no serial fan-out on the mediated path to
parallelise**, which is why that row's verdict is "stays" rather than a refusal
of concurrency.

### `batten hook` builds at most one runtime, and never a multi-thread one

The blanket "builds no runtime" is retired, because it **collapsed two very
different answers** and the cheaper one is the one the fact model needs. Measured
out of tree (a scratch crate whose only dependency is tokio, so measuring this
did not vendor the thing being decided; hyperfine, 200 runs, against a floor arm
that constructs nothing):

| arm                  | p50     | p95     | over the floor (p50) |
| -------------------- | ------- | ------- | -------------------- |
| no runtime           | 2.01 ms | 3.24 ms | —                    |
| `new_current_thread` | 2.15 ms | 3.96 ms | **+0.14 ms**         |
| `new_multi_thread`   | 3.69 ms | 7.80 ms | **+1.68 ms**         |

A current-thread runtime is **noise** against the 100 ms ceiling. The
multi-thread arm's overhead is **twelve times** that — worse again at the tail,
and it grows a worker per core, for a workload that is one call's IO where there
is nothing to steal. So the bound is the shape, not the abstinence: **at most one
runtime per invocation, current-thread**. That is what CLOUD-757's `Surface` axis
should cite as the where-resolved boundary; it is a statement about the runtime's
shape, never about what a fact costs.

Both halves ship with a mechanism rather than as a sentence here (non-negotiable
rule 2): `clippy.toml` bans `tokio::signal::*` — signals stay `signal-hook`'s one
registry, so both ends of the pgroup protocol share semantics — and
`tokio::runtime::Builder::new_multi_thread`. Both are **inert today**, because
tokio resolves to nothing, and both go live the day an HTTP client arrives, which
is the day somebody would otherwise have had to remember them.

### Concurrency must not cost byte-stability

If the mediated fact set ever does resolve concurrently — the open row, which
CLOUD-834 is the consumer for — findings stay byte-stable under `-J`. That means
a deterministic merge over concurrently-resolved facts, which is the same
obligation the parallel walker carries and the same one that keeps it unbought.
Assert it with a counter and a repeat-run comparison, never with wall clock: a
timing assertion discriminates nothing here.

### The lock stays `fs4`, on the reason that survives

An OS advisory lock is **released by the kernel when its holder dies**. No
in-process primitive offers that, so a supervisor `SIGKILL`ed mid-write leaves a
reader a defined prefix instead of a lock nobody can release. That argument never
depended on the dependency count, which is why the conclusion is unchanged while
two of the comments stating it were not.

## Layout

The per-module map — every `src/*.rs` file, what it owns, and where its
rationale doc comment lives — is `mem:core`, kept current instead of a tree
restated here.

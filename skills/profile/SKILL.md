---
name: profile
description: Making a batten invocation path fast the way the agent-profiling literature says works — a curated hotspot report queried in a few one-line rows (never a flame graph or a stack dump), call counts from callgrind, a patch, a re-profile, keep the best, stop at the target rather than the first gain — with every trap that has cost a rerun (stripped binary, wrong rustc, the deny exit 2, stdin consumed by repeat iterations, perf_event_paranoid). Use before running samply, valgrind, strace or hyperfine on a batten binary, when a path is over the 10 ms target or the 100 ms `perf-assert` ceiling, or when a change "should have" helped and the number did not move.
---

# Profiling one invocation path

`perf-gate` (paired ratio) and `perf-assert` (100 ms p95 per path) say THAT a
path is slow. This loop finds WHERE and fixes it. Each step is something an
agent has been measured getting wrong.

## The loop

1. **Set the target before measuring.** The target is 10 ms, with a 100 ms p95
   ceiling. Agents satisfice: they stop at the first improvement
   (SWE-fficiency). Stop at the target, or when the remaining hotspot is not
   yours.
2. **Classify: on-CPU or off-CPU** (Gregg). Run `mise exec -- hyperfine -N -i`.
   When `User` is close to the wall time, I/O work will not move it.
3. **Read a curated report, not a dump.** Use `batten-profile hot`. The whole
   PerfAgent loop, curated report plus patch-and-re-profile, beat profiler
   instructions alone 44.1 to 17.6 Opt@1 (the paper does not isolate the
   report's share), and raw profiler output "floods the agent's context
   window". Never read
   a flame graph or folded stacks: they are for eyes, and cost thousands of
   tokens for what ten rows say.
4. **Localize before patching.** Where to act, not how big a patch, is what
   separates agents from experts (SWE-fficiency). Run `batten-profile callers
NAME` to see every path into the hotspot. Run `callgrind_annotate
--tree=caller` for exact call counts. When one callee is called on the same
   input from several sites, that is redundant work, the class RedSpy, LoadSpy
   and Toddler exist to find.
5. **Ask how the cost scales.** Cost that grows with the input, such as
   history, refs or files, is an algorithmic bug, not a constant. A memo
   shrinks it and a structural change removes it (algorithmic and
   input-sensitive profiling, PLDI 2012).
6. **Patch, then re-profile and diff.** Run `batten-profile diff before.json
after.json`, which also reports the frames that vanished. Keep the best
   patch, not the last: PerfAgent iterates up to 5 times and keeps the best.
7. **Validate with two numbers and their commands.**
   - Instructions: cachegrind `Ir`, which is deterministic.
   - Wall time: hyperfine on `release`.

   Both go in the commit. One study found agent performance PRs carry
   validation less often than human ones (45.7% vs 63.6%, arXiv 2512.21757);
   a larger one found comparable rates but fewer benchmarks (arXiv
   2610.03969). Either way, the numbers are the claim.

8. **Write the summary to the tracker row between iterations.** Restarting from
   an externalized summary recovered headroom after a session stopped, in
   PERFOPT-Bench's exploratory pilot. In this repository the summary belongs on the row, never in
   chat.
9. **Turn the fix into an efficiency rule.** Rules taken from 25 patches found
   332 new performance bugs (Jin et al.), and Uber PerfInsights and Google ECO
   both run on an antipattern catalog. A fixed hotspot class is a rule plus a
   gate, so it cannot regrow.

## Setup the steps share

- **Toolchain:** always `mise exec -- cargo …`. Bare `cargo` picks the system
  rustc, not the pinned one.
- **Symbols:**
  - `[profile.release]` strips symbols, so a profiler names only addresses, and
    `program measure unread` refuses that run.
  - Build `--profile profiling` instead: `release`'s code generation plus line
    tables. Run it backgrounded; it takes minutes. The binary is
    `target/profiling/batten`.
  - std frames resolve to a function, never a line.
  - LTO folds callers together. The tool reads inline frames from the symbol
    sidecar; to split one out for good, add `#[inline(never)]` temporarily.
- **Fixture:** of the paths `batten perf measure` times, `check` and `stop` run
  in `target/perf/check-repo` (a one-rule repo); `hook`, `passthrough`,
  `posttool` and `wired` run at the repo root against its full config. Profile a
  path where it is measured, or you cut a cheaper path than the number. Payloads
  are in `crates/batten/tests/fixtures/hooks/`. If the fixture is missing, run
  `mise run perf` once; it deletes `target/perf` first, so keep recordings in
  your scratch directory.
- **Exit 2 is the deny channel.** `stop` exits 2 at the repo root, so hyperfine
  there needs `-i`; in `check-repo` it exits 0.
- **Background every recorder.** valgrind runs 20 to 100 times slower than
  native.
- **The query tool:**
  `mise exec -- cargo build --release -q --manifest-path tools/batten-profile/Cargo.toml --target-dir target/profile-tool`,
  then run `target/profile-tool/release/batten-profile`.

## Recording

**Sampler (the default):** samply, pinned in `mise.toml`. It needs
`kernel.perf_event_paranoid` at 1 or lower: read
`/proc/sys/kernel/perf_event_paranoid` first. Lowering it needs root; if you
cannot, use callgrind below instead. Restore it to 2 afterwards. Each
`--iteration-count` run gets its own stdin only through `sh -c '… < payload'`;
a bare `< payload` is consumed by the first run.

```sh
sysctl -w kernel.perf_event_paranoid=1
cd target/perf/check-repo && mise exec -- samply record --save-only --unstable-presymbolicate \
  --rate 10000 --iteration-count 10 -o <scratch>/stop.json -- \
  sh -c 'exec <repo>/target/profiling/batten adjudicate --harness claude-code < <repo>/crates/batten/tests/fixtures/hooks/claude-code-stop.json'
sysctl -w kernel.perf_event_paranoid=2
<repo>/target/profile-tool/release/batten-profile hot <scratch>/stop.json --top 12
<repo>/target/profile-tool/release/batten-profile callers <scratch>/stop.json root_commits
```

`hot` prints inclusive share, then self share with pprof's `sum%`, a running
total that tells you when to stop reading. It hides std, libc, the allocator
and the runtime unless `--all`, and strips generic arguments from names.

**Call counts and deterministic instruction counts: valgrind 3.22.**

```sh
valgrind --tool=callgrind --toggle-collect='*root_commits*' --callgrind-out-file=<scratch>/c.out <bin> … < payload
callgrind_annotate --tree=caller <scratch>/c.out | grep -B3 '\* .*root_commits'   # callers above, each with (Nx)
valgrind --tool=cachegrind --cachegrind-out-file=<scratch>/before.cg <bin> … < payload
cg_annotate --diff <scratch>/before.cg <scratch>/after.cg | head -30
```

**Off-CPU:** `strace -f -c`, or `-e trace=openat,statx` with repeats per path
counted. Delete raw traces once reduced.

**Allocation:** `valgrind --tool=dhat`.

## Instrument choice, and what it cannot tell you

| question                         | instrument                             |
| -------------------------------- | -------------------------------------- |
| where the wall time goes         | samply + `batten-profile hot`          |
| who calls the hotspot            | `batten-profile callers`               |
| exactly how many calls           | callgrind `calls=`                     |
| did the patch remove work        | cachegrind `Ir` + `cg_annotate --diff` |
| did the patch move the wall time | hyperfine on `release`                 |

- On a shared container, wall clock is the wrong instrument for a
  before/after. Layout and environment flip conclusions (Mytkowicz et al.,
  ASPLOS 2009), and a sound comparison needs repetition and confidence
  intervals (Kalibera & Jones, ISMM 2013). That is why `Ir` comes first.
- A profile ranks cost; it does not predict what a speedup would gain (Coz,
  SOSP 2015). batten is one short-lived thread, so the profile is close to the
  critical path, but every fix is still re-measured.

## Sources

- PerfAgent, arXiv 2607.19653. SWE-fficiency, arXiv 2511.06090. PERFOPT-Bench,
  arXiv 2607.07744. Agent performance PRs: arXiv 2512.21757 and 2610.03969.
- Narrow profiler tools: v8-cpu-profile-decoder-mcp; JProfiler MCP's
  robustness work; bottleneck-aware filtering, arXiv 2603.07169.
- Antipattern catalogs: Jin et al., PLDI 2012; Uber PerfInsights; Google ECO,
  arXiv 2503.15669.
- Redundancy: RedSpy (Wen, Chabbi, Liu, ASPLOS 2017); LoadSpy (Su, Wen, Yang,
  Chabbi, Liu, ICSE 2019); RVN; Toddler (Nistor et al., ICSE 2013).
- Scaling: Zaparanuks & Hauswirth, _Algorithmic profiling_; Coppa et al.,
  _Input-sensitive profiling_; both PLDI 2012.
- Method: Gregg (USE, off-CPU, differential flame graphs); pprof's
  flat/sum/cum report; HPCToolkit's derived metrics and blame shifting;
  Mytkowicz et al.; Kalibera & Jones; Coz.
- Tools: _The Rust Performance Book_; the valgrind manuals; samply; gungraun.
- The full notes, with numbers, are on CLOUD-2813.

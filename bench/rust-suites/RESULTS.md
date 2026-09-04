# The Rust suite's run phase, by term

CLOUD-1419's measurement. Generated from one traced, instrumented run; the
reduction scripts are named beside each term so a reader can reproduce a row
rather than trust it.

**This corrects CLOUD-1419's own §2.** That section reasons from call-site
counts to a share — _"2,728 cases at that shape is the 295.8s; the arithmetic
lands within a few percent of the measurement"_ — and the arithmetic is wrong by
an order of magnitude. Every git process the suite spawns, all 9,476 of them,
is **4.8% of the serial total**. Three cases in one module are **21.8%**.

## The run

|                                           |                                                                                                                  |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| machine                                   | this container, 4 cores, git 2.43.0                                                                              |
| command                                   | `GIT_TRACE2_EVENT=… NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1 mise run test:filter --message-format libtest-json-plus` |
| cases                                     | 4,461 (2,770 in `it`, 19 in `policy_modules`, 1,672 lib unit tests)                                              |
| wall                                      | 133.755s                                                                                                         |
| serial total (Σ per-case `exec_time`)     | 523.3s                                                                                                           |
| observed parallelism (Σ exec_time ÷ wall) | **3.91**                                                                                                         |

Parallelism is measured, not assumed to be `nproc` — they agree here at 3.91
against 4, which is the reading that makes the shares below convertible to wall
time by division.

The CI figure this row opened with — `test` at 295.8s — is a **2-vCPU** runner.
Read the shares, not the seconds: this box is faster and wider, so the wall
clocks are not comparable and only the per-term proportions carry across.

## The four terms

| term                           | serial        | share       | how it was measured                                                                    |
| ------------------------------ | ------------- | ----------- | -------------------------------------------------------------------------------------- |
| **git forks (all of them)**    | **25.17s**    | **4.8%**    | `GIT_TRACE2_EVENT`, one trace file per git process, summing each process's own `t_abs` |
| **nextest per-process floor**  | ~23.9s        | ~4.6%       | 5.36 ms (cheapest-decile median) × 4,461 — an **estimate**, see below                  |
| **`batten` child forks**       | 28.6s – 39.8s | 5.5% – 7.6% | `strace -f -e trace=execve` for the count, `hyperfine` at 200 runs for the cost        |
| **filesystem (wipe + create)** | not separable |             | dominated by the terms above; see "what the fixture actually costs"                    |

Those four are **~15–17% of serial between them**. The rest is the suite doing
its work, and the largest single item in it is not a fork at all.

### The `batten` child forks, counted

`strace -f -e trace=execve` over the whole run, counting only calls that did not
return `ENOENT`/`EACCES` — the raw execve total is 390,745, and all but 60,480 of
those are PATH probes that found nothing, so an uncorrected count overstates the
term by 6.5×.

| binary                                             | successful execs |
| -------------------------------------------------- | ---------------- |
| `/usr/bin/git`                                     | 7,526            |
| `target/debug/batten`                              | **4,854**        |
| `target/debug/deps/it-*` (the grouped test target) | 2,772            |
| `target/debug/deps/batten-*` (lib unit tests)      | 1,674            |
| `/usr/lib/git-core/git` (git's own helpers)        | 1,930            |

The test-binary spawns — 2,772 + 1,674 + 19 — reconcile with the 4,461 cases,
which is the independent check on the floor term above.

At 5.9 ms (`--version`) to 8.2 ms (`check`) per fork, 4,854 forks is
**28.6s–39.8s**, or **5.5%–7.6%** of serial.

### git, exactly

9,476 processes, 25.17s, no process missing an `atexit` record. Per subcommand,
the ones that matter:

| subcommand                       | count | seconds | mean    |
| -------------------------------- | ----- | ------- | ------- |
| `commit`                         | 1,741 | 12.23   | 7.02 ms |
| `add`                            | 1,744 | 4.84    | 2.78 ms |
| `init`                           | 1,819 | 4.49    | 2.47 ms |
| `maintenance`                    | 1,745 | 0.95    | 0.55 ms |
| `update-ref`                     | 1,018 | 0.85    | 0.84 ms |
| `config`                         | 436   | 0.26    | 0.60 ms |
| everything else (44 subcommands) | 973   | 1.55    |         |

**`maintenance` at 1,745 is a finding the plan did not predict**, and its count
tracks `commit`'s to within four: git runs `maintenance run --auto` after each
commit. Removing all 1,745 takes `-c maintenance.auto=false`, **not** the
`gc.auto=0` this paragraph first credited — see step 1 below, where that flag was
landed on its own and measured removing nothing.

**Call sites and executions differ by an order of magnitude, as the plan
warned.** The tree has 79 hand-rolled `git init` call sites; the run spends
**1,819** `init` processes. A census of call sites could not have produced any
row in this table.

### The nextest floor is an estimate and is labelled one

The cheapest decile's median case takes 5.36 ms. Those cases do almost nothing,
so that figure is close to the cost of spawning the ~116 MB test binary — but it
is an upper bound on _doing nothing_, not a measurement of the spawn itself.
`5.36 ms × 4,461 = 23.9s`, **4.6%** of serial, and it is irreducible while
`tests-not-deleted` stands.

### One `batten` fork

`hyperfine`, 200 runs, debug binary, one-rule fixture:

| arm                | mean   | σ      |
| ------------------ | ------ | ------ |
| `batten --version` | 5.9 ms | 0.5 ms |
| `batten check`     | 8.2 ms | 1.3 ms |

The gap is **2.3 ms**, and that is the whole of config load, trust resolution and
a one-rule tree walk. **The vendored preset corpus is not a per-fork cost** —
the speculation that each child pays to compile it is not supported, and the
follow-up row the plan reserved for it is withdrawn rather than filed.

## What the suite actually spends its time on

The slowest modules, by serial seconds:

| module                  | serial      | cases | share     |
| ----------------------- | ----------- | ----- | --------- |
| `symbols`               | **114.20s** | **6** | **21.8%** |
| `shell_retirement`      | 48.85s      | 54    | 9.3%      |
| `cli`                   | 30.90s      | 317   | 5.9%      |
| `board_receipts`        | 22.38s      | 45    | 4.3%      |
| `process_group`         | 21.79s      | 12    | 4.2%      |
| lib unit tests (all)    | 16.84s      | 1,658 | 3.2%      |
| `mediated_verbs`        | 15.97s      | 44    | 3.1%      |
| `shell_retirement_cost` | 11.53s      | 1     | 2.2%      |

Three cases in `symbols` cost 38.3s, 38.3s and 37.6s. They drive a delegated
analyser — the `Cost::Effect` fact — and are not fixture cost in any sense: no
change to `common/mod.rs` moves them. Together with `shell_retirement`'s 54
cases they are **31.3% of the suite**, against **4.8%** for every git fork in it.

`process_group`'s 21.79s over 12 cases is deliberate: those cases wait on real
signals and real process groups, and the waiting is the assertion.

The 138 modules that reach a heavy fixture helper account for 327.3s (62.5%) of
serial — but that is a statement about which modules use the helper, not about
what the helper costs. The helper's own cost is the 25.17s in the git table
above, and the fraction of it this work can remove is the next section.

## What the fixture change can actually remove

Of the 25.17s of git:

**This table was a PREDICTION and two of its rows were wrong.** It is kept with
the errors named rather than quietly rewritten, because both are the same class
this file exists to record — reasoning to a number instead of reading one. The
measured outcome is in "Step 1" and "Step 3" below.

| predicted removal                                         | predicted | measured                                                |
| --------------------------------------------------------- | --------- | ------------------------------------------------------- |
| auto-maintenance (all 1,745 `maintenance` processes)      | 0.95      | 0.95 — but by `maintenance.auto=false`, NOT `gc.auto=0` |
| the `git init` template (1,819 processes)                 | 4.49      | 3.03 (1,819 → 813; the 79 hand-rolled sites remain)     |
| `pin_origin_main` (1,018 `update-ref` processes)          | 0.85      | 0.85 (1,018 → 0)                                        |
| identity baked into the template (436 `config` processes) | 0.26      | **0.00 — not removed at all** (436 → 443)               |

The last row is the instructive one. Baking the identity into the template
removes the two `config` forks a fixture built through `Fixture::git` would have
spent — but the 79 hand-rolled sites set their own identity after their own
`init`, so the count did not fall. A prediction that a change removes a cost is
not a reading that it did.
| **total** | **6.55s** |

**6.55s of 523.3s is 1.25% of serial.** `commit` (12.23s) and `add` (4.84s) stay,
because `commit -a` does not stage untracked files and writing objects by hand
would be a third git implementation.

The one term not bounded by that table was `-c core.fsync=none` against
`commit`'s 12.23s. It landed first, on its own, and it is measured below.

## Step 1, measured on its own: three flags on one line

`-c core.fsync=none -c gc.auto=0 -c maintenance.auto=false`, added to
`git_command`, changing no fixture shape:

|               | baseline           | step 1              | delta              |
| ------------- | ------------------ | ------------------- | ------------------ |
| git processes | 9,476              | **7,829**           | **−1,647**         |
| git seconds   | 25.17              | **18.18**           | **−6.99 (−27.8%)** |
| `commit`      | 12.23s @ 7.02 ms   | **7.67s @ 4.40 ms** | −4.56s             |
| `init`        | 4.49s @ 2.47 ms    | 3.35s @ 1.84 ms     | −1.14s             |
| `maintenance` | 0.95s, 1,745 procs | **gone**            | −1,745 procs       |

**One line removed more git time than the whole rest of the fixture plan is
worth** (§"What the fixture change can actually remove" costs the template,
`pin_origin_main` and the identity move at ~5.6s between them). That is the
ordering the plan predicted and it held.

### `gc.auto=0` alone does nothing, and the first attempt shipped exactly that

Landed first with `core.fsync=none` and `gc.auto=0` only, and measured:
`maintenance` went **1,745 → 1,747 processes**, 0.95s → 0.89s. The flag is the
documented way to switch auto-gc off and it is the wrong key: git 2.43 gates the
post-commit `maintenance run --auto` on `maintenance.auto`, and `gc.auto` reaches
only the legacy `gc --auto` path underneath it. Adding `maintenance.auto=false`
took the count to zero.

**A flag that looks right and removes no process is worse than no flag**, because
the next reader checks the flag rather than the count. It was caught by
re-running the trace after the edit rather than by reading, which is the only
thing that tells a working flag from an inert one — the same reason
`.claude/rules/policy-modules.md` gives for confirming a channel with an
unconditional arm.

### What is not claimed

Wall clock. The baseline run measured 133.755s and the step-1 run 104.348s on
this box, and **that difference is not the flags**: 6.99s of serial git time is
~1.8s of wall at the observed parallelism, and the rest is page cache and
contention from other work on a shared 4-core container. Process counts and
per-process `t_abs` are deterministic and reproducible; wall at this effect size
on this machine is not, so the counts are what this file reports.

## What this settles about the in-process conversion

CLOUD-1419 §3.3 asks for `lib::run` in-process instead of forking `batten`. The
plan gated that on this measurement projecting better than ~5% of the suite, and
it does not:

- the whole `batten`-fork term is **4,854 forks, 5.5%–7.6% of serial**;
- of ~610 fork CALL SITES, roughly 160–190 are convertible at all — the rest are
  excluded by construction (198 pipe stdin and `lib::run` has no stdin
  parameter; ~103 redirect the state root, which resolves through `etcetera`
  inside `state.rs` with no injection point, so an in-process case would write
  the developer's real store; `fs4` locks are released by the kernel when their
  holder dies, so contention cases need two processes; `hook_authority_root()`
  is a per-process `OnceLock`);
- even at 30% of the forks converted, the ceiling is **~10s, ~1.9% of serial**;
- and reaching it costs a `src` change — `report` moved out of `main.rs` into a
  new `boundary.rs` — plus a public-surface delta `batten semver check` grades.

**So the conversion is not done, and that is a measured decision rather than a
deferral.** It is filed with the five preconditions above rather than attempted.

The speculative second row the plan reserved — "each `batten` child compiles the
vendored preset corpus" — is **withdrawn rather than filed**: `check` minus
`--version` is 2.3 ms, which is config load, trust resolution and a one-rule tree
walk together. There is no preset-compile cost per fork to remove.

## Step 3, measured: the template and the loose-ref write

`Fixture::git` copies a repository published once per filesystem;
`base_commit`'s `update-ref` becomes a loose-ref write.

|               | baseline | step 1 | step 3    |
| ------------- | -------- | ------ | --------- |
| git processes | 9,476    | 7,829  | **6,035** |
| git seconds   | 25.17    | 18.18  | **15.42** |
| `init`        | 1,819    | 1,821  | **813**   |
| `update-ref`  | 1,018    | 1,020  | **0**     |
| `maintenance` | 1,745    | 0      | 0         |

Cumulative: **−3,441 git processes (−36%) and −9.75s (−39%)**, which is 1.86% of
the 523.3s serial total.

The 813 `init` processes that remain are the 79 hand-rolled call sites, at
roughly ten executions each. Converting them is worth **1.46s, 0.28% of
serial**, against a diff across 59 modules — so they are left alone, and
`policy/fixture-forks.rego` is what stops a new one being written.

## The ratchet this branch wrote and withdrew

A `kind = "ratchet"` row over `git_in(` was landed here and removed here, and
the reason is the table above.

The row counted CALL SITES. The measurement is that call sites do not track the
cost — 79 `git init` sites produce 1,819 processes — so the template removed
1,008 processes while ADDING 17 call sites, and the row refused its own enabling
change at `580->597`, naming `common/mod.rs`, `fixture_forks.rs` and
`primitives.rs`: the three files that had to grow for the reshaping to exist.

**Its first firing was on the change that improves the thing it guards.** That
is the shape `batten.toml`'s preamble for the volume ratchet it declined to
write already refuses: _"a gate whose first firing is a false positive gets an
exception written for it, and the exception is what rots."_ Spending
`// needs-real-fixture:` on those three files would have bought that exception
immediately — to silence a premise rather than to own an increase.

`policy/fixture-forks.rego` is the gate instead, and in the same run it fired
correctly on `primitives.rs:48`, the one case whose subject genuinely IS a real
`git init`: the arm that compares the copy against the fork. That is the
admission being used for what it is for.

Nothing is left uncovered. The aggregate can only grow through a new fork, and a
new fork is what the module reads — at a `path:line` a reader opens, rather than
as a total they have to reconstruct.

## The honest headline

The fixture is not what the suite spends its time on. Measured end to end, the
change removes **3,441 of 9,476 git processes (−36%) and 9.75s of 25.17s
(−39%)** — which is **1.86% of the 523.3s serial total**.

It is still worth landing: the diff is small, the flags reach every fork, and
`policy/fixture-forks.rego` stops the shape regrowing. But it must not be
reported as having made the suite materially faster, and CLOUD-1419's §2 is
corrected to say so.

**An earlier revision of this paragraph said 5,018 processes**, which was the
predicted table's `init` + `update-ref` + `config` + `maintenance` summed as if
each went to zero. Three of the four did not: 813 `init` processes remain and
`config` did not move. 3,441 is the difference between two readings; 5,018 was
arithmetic over four predictions — the same substitution this whole file is
about, made inside it.

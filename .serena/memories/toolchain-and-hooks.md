# Toolchain (mise) and git hooks (hk) — deep reference

Read when: adding/pinning a tool, adding a `[tasks]` command, touching `hk.pkl`
or the pre-commit/CI gate, or bumping the pinned `hk` version. AGENTS.md carries
the "use mise for everything" rule and the task list; this is the detail.

## mise is the single source

Install/pin every dev tool via `[tools]` (never a one-off brew/cargo install or
system binary); read/set env via `[env]` (never ad-hoc exports); run every
repeatable command as a `[tasks]` task via `mise run` (never bare `cargo …` or a
duplicated snippet in CI/hook). Define it in `mise.toml` first, then call through
mise — CI, hk, and your shell then run byte-identical commands.

Common tasks: `mise run test | lint | fmt | fix | ci | cross-check`; `mise tasks`
lists all. `mise run fmt` is `hk fix --all` and `mise run ci` = `hooks` (`hk
check --all`) + `deny`, so the gate's step list lives in `hk.pkl` alone — there
is no second list in `mise.toml` to keep in sync. `mise run test` aggregates
`test:cargo` + `test:bats`.

`lint` and `fix` are a symmetric pair, and both aggregate (CLOUD-104):

- `lint` → `lint:clippy`, `lint:fmt`, `lint:toml`, `lint:actions`, via
  `depends`. It was clippy alone, which made the name a claim the repo could not
  keep — the tree is TOML-heavy and carries twelve workflows, and hk gated both
  while the task layer offered no way to run either.
- `fix` → `clippy --fix`, then `completions` + `schema`, then `hk fix --all`.
  **Sequential body, not `depends`**: mise runs a `depends` list in parallel and
  those stages contend on the cargo target-dir lock _and_ rewrite each other's
  bytes. `fmt` stays the formatters-only subset.

Two hk steps override the builtin COMMAND with a task — `cargo-fmt` →
`mise run lint:fmt`, `cargo-clippy` → `mise run lint:clippy` — so the hook and
the task cannot disagree about what passes. Their SELECTORS still come from
upstream: `actionlint` globs `.github/workflows/*.y{,a}ml`, `taplo` and
`taplo_format` glob `**/*.toml`, all three `check_first`. Re-declaring those
locally would be a second authority for a selector upstream already tests.

`lint:toml` feeds taplo `git ls-files '*.toml'` instead of letting it walk the
tree: `target/` carries deliberately corrupt TOML the suite writes on purpose
(`target/tmp/trust-corrupt-config/batten.toml` is `this is not = = toml`), so a
bare `taplo lint` fails on its own test data.

## Keep the hooks fast — hk.pkl is living config

The pre-commit hook runs on every commit, so its latency is a constant tax.
Whenever you touch the hooks, add a task the hook runs, or bump `hk` in
`mise.toml`, re-check the hook is still optimal.

Mechanism (not prose-only): the `hk-version` gate (`mise run hk-version`, wired
into the shared hk `gate`, runs on both pre-commit and CI) **fails** if hk's
pinned version drifts between `mise.toml` and `hk.pkl`'s `amends` URL. The two
must move together on every bump — that failure lands you back in this config
when there may be new features to adopt.

Three hk features are the baseline — keep them:

- **`stash = "patch-file"`** — hooks check exactly what's staged; fixers never
  clobber unstaged work (faster than `git stash`, no index-lock races).
- **`check_first`** on fixer steps (e.g. `fmt`) — skip the write pass when clean.
- **`depends`** to chain compile-heavy cargo steps (`cargo-fmt → cargo-clippy →
test`) into one
  serial cargo build — parallel steps only serialize on the target-dir lock while
  oversubscribing the CPU.

The gate lives **once** in `hk.pkl` (the `gate` step mapping), run by two hooks:
`pre-commit` (fix mode) locally and `check` (check-only) on CI via `mise run
hooks` → `hk check --all`, which `mise run ci` depends on. So a misconfigured
step fails CI, not just a commit. Any new gate step belongs in `hk.pkl`, not
bolted onto CI separately. Before adding a step: check `Builtins` for one first — upstream
already carries the file selectors, batching, shebang detection and fix/check
split, and each builtin ships with its own tests. Take the builtin and override
only the command when this repo needs a stricter posture, so the selector logic
stays upstream. Hand-write a step only where no builtin exists; scope its `glob`
so it only fires on relevant files, and put repo-specific logic in a `mise` task
the step calls rather than inline. Adopt new `hk` release
features (batching, caching, scheduling) when they'd tighten this.

**A builtin's selector is a claim about coverage — measure it, never infer it.**
Leaving the selector upstream is right, and it silently decides _which files the
gate reads_. `Builtins.shellcheck` selects `(glob **/*.sh, **/*.bash) OR (types:
sh, bash)`, and `#!/usr/bin/env bats` is neither — so `tests/*.bats` was never
linted at all. Measured with `hk check --all --step shellcheck -v`: 45 files
batched (every `mise-tasks/*`, `session-start.sh`, two fixture `.in` files), none
of the 42 bats files. The step had looked like it covered the suite for its whole
life, and `.shellcheckrc` carried an SC2030/SC2031 suppression reasoning about
bats `run` subshells — **a suppression reads as evidence a file is being read, and
it is not.** Same shape as the `-v` regex and the `pipefail | grep` entries below:
green on a claim nobody checked. `--step <name> -v` prints the batched argv per
step, and that is the only way to see a selector's real reach.

What it cost: SC2314 is bats-only (an `!`-led assertion does not fail a bats
test), so it had never fired over ten `error`-severity dead assertions in six
suites. ShellCheck 0.11.0 derives the `bats` dialect from that shebang unaided —
so the fix is a selector, never a `--shell` flag and never per-file directives.

## The always-loaded context budget

`mise run policy-budget` runs `batten policy budget` and fails when the
always-loaded set exceeds its budget. Since CLOUD-50 this is the engine, not a
shell task: the counted set and both thresholds are `[budget.instructions]` in
`batten.toml` (`paths`, `max_tokens`, optional `max_lines`), so a reviewer reads
the gate as config rather than as arithmetic in bash. `mise-tasks/context-budget`
and its `BATTEN_CONTEXT_BUDGET`/`BATTEN_CONTEXT_LINE_TARGET` overrides are gone —
a budget you can lower with an env var is not a budget.

Tokens, not lines, are the primary predicate: the cost is what every agent pays
on every turn, and an exact count would need a tokenizer, a model-specific
vocabulary and a network fetch — a budget gate that fails because a download
failed is worse than one that is 10% out. So the estimate is bytes/4 over the
content that actually loads, with YAML frontmatter and block-level HTML comments
stripped first: both are dropped before the file reaches a context window, and
charging for them would fail the gate for a construct nobody pays for.
`max_lines` is the second, optional predicate, carried over so the shell gate's
deletion orphaned nothing; absent means unenforced. Both boundaries are `<=`.

Today `paths` is `AGENTS.md` alone. It used to also glob
`.serena/memories/always/*.md`, a directory that has never existed — a dead entry
contributing nothing while the rest counted (CLOUD-298). The engine now refuses
that outright: **an entry matching no file is exit 1, per entry**, so one dead
glob cannot hide behind the siblings that still match. Declaring a memory
always-load therefore means creating that directory AND adding the glob in the
same change; it then costs exactly what an AGENTS.md section costs, which is the
point — moving a section into a memory only reduces the tax if the memory is
genuinely read at a trigger. Ordinary memories are not counted, because a session
that never hits their trigger never pays for them.

Over budget: cut, or move a section to a triggered memory (sorting rule in
`mem:prior-art-and-issue-hygiene`). Raising the number is a decision, not a fix —
and a visible one: `crates/batten/tests/cli.rs` pins both committed thresholds,
so raising either is a diff in two files.

## Memories go through the Serena tools, never a file write

`.serena/memories/*.md` are ordinary files on disk, which makes editing them with
Write/Edit easy and wrong: `write_memory` enforces a size ceiling and
`rename_memory` rewrites `mem:` cross-references in the other memories, and a
direct file write silently skips both. `mise run memory-guard` is a `PreToolUse`
hook (wired in `.claude/settings.json`) that denies such a write and names the
memory to pass to the Serena tool instead. It fails open on anything unparseable
and honours `BATTEN_MEMORY_GUARD_BYPASS=1` — needed when the Serena MCP server is
down, since otherwise a disconnected server would make memories unwritable by any
means.

## MCP allow rules: gate only what the repo can verify

`permissions.allow` is matched against the tool name as exposed to the session,
and a connector's exposed name is **chosen per registration episode by the
host** — `mcp__Linear__*` at session start, `mcp__<uuid>__*` after a mid-session
re-register, `mcp__claude_ai_Linear__*` in the local CLI. A rule naming one of
those matches none of the others, and the failure is silent to the agent: the
only symptom is an approval prompt on every call, which reads as harness
behaviour. Measurements and the standing fix: CLOUD-178.

The account-specific names belong in **user-level** `~/.claude/settings.json`,
never in the repo — rule 1 keeps consumer identifiers out of committed config,
and a UUID is meaningless to any other clone.

So `mise run mcp-allow-check` (in the shared hk `gate`, globbed on
`.claude/settings.json`) asserts only what is repo-verifiable: no allow rule
globs the server segment, since the CLI accepts a tool-name glob only after a
literal `mcp__<server>__` prefix and skips anything broader with a warning — a
rule that reads as a grant and is not one. It deliberately does **not** demand a
`claude_ai_` companion; an earlier version did, which encoded one host's naming
as universal. A gate may only assert what it can verify from the repo.

## A Bash call is a supervised process, not a terminal

Its exit status and its lifetime are what the harness reads. Two habits destroy
one each, and both then fail **green** — exit 0, plausible output — which is why
they survive being noticed:

- **`mise run <task> 2>&1 | tail -6`** exits with the pager's status, always 0.
  This produced two confident "green" reports over failed runs in one session:
  a formatting failure, and `linear-check` refusing a stale branch.
- **`nohup mise run <task> >log 2>&1 &`** returns immediately. The harness records
  the task complete, the work runs unsupervised, and the session loses the
  wake-up it gets when the work actually exits — leaving only polling or an idle
  turn, both forbidden, and an idle turn gets the VM reclaimed mid-run.

One substitution underlies both: making the call return **small** (`| tail`) or
**fast** (`nohup &`), at the cost of the two things that are actually the
interface.

The correct form is **the command alone in the call**:

```
mise run <task> >/tmp/<task>.log 2>&1
```

with `run_in_background` on the tool call itself for anything over ~2 minutes.
`run_in_background` must wrap the long command, not a launcher that returns
immediately — a wrapped launcher looks identical in the tool result and silently
drops the re-invocation. **Read the log in a separate call.** A pager over a
**file** is fine; over a **live task** it is not.

**Nothing may follow it in the same `;` or `||` list.** This note used to
prescribe `…; echo "EXIT=$?"; tail -20 …`, and that form is now denied
(CLOUD-199) — the chain ends in the last element, so the _shell line_ exits 0
whatever the task did, and the tool result says "exit code 0" for the call.
Backgrounded it is worse than a misread: the task-completion notification carries
the compound's status, so a failed task arrives as `completed (exit code 0)` — an
authoritative-looking statement from the harness rather than a reading of yours.
Measured twice in one session: `mise run fmt` notified exit 0 with `EXIT=1` in
the file and shellcheck genuinely failing; a later `verify` did the same.

`&&` is fine and stays: it short-circuits, so a failure still propagates as the
list's status. `;` and `||` do not.

The principle the guard now states, rather than a rule about one command: **a
verdict-bearing command's exit status is read from the harness, never inferred
from its output.** A pager, a filter, a `wc -l`, an eyeballed tail and a trailing
list element are all the same substitution. `run-shape-guard` covers the whole
verdict-bearing family — `mise run`, `git push`/`fetch`/`rebase`, mutating
`gh pr`, and `cargo` — not just `mise run`.

### Ask a running task; never poll for it

A third habit destroys the same interface from the other end. Once a task is
backgrounded, **its exit already re-invokes the session with its status** — so a
wait built to detect that exit is a duplicate of a guaranteed event. It cannot
fire earlier and cannot carry more information:

```
until ! pgrep -f "mise run land" >/dev/null; do sleep 15; done   # never this
```

Measured 2026-08-12: one session had **nine** of these live at once — four
shadowing `verify`, two `land`, one a merge, one `bats` — a hand-rolled
re-implementation of the notification the harness was already going to deliver.
`run-shape-guard` permits it today (CLOUD-482 carved out backgrounded `until`
loops for genuine external-state waits; CLOUD-489 narrows that to exclude polling
one's own child).

For "is it still going, and where is it", the answer is **`mise run alive`**
(CLOUD-425) — one call, one line per task, no log reading:

```
land ci-wait(lap 0) 9170 1066s
```

Task, phase, pid, seconds. It beats `pgrep -f` on correctness, not just on
manners: `pgrep -f` matches a command-line substring, so in a container with
sibling sessions it answers "some process matches this string", which is not the
question. A registered task whose process is gone reports `crashed`, which is the
state worth knowing and the one no `pgrep` can express.

The shape to internalise: **for a task this session started, waiting is free and
automatic; asking is one call; inferring from the outside is always the wrong
third option.**

### Do not hand-roll a waiter for work the harness already supervises

A third habit, same root, no green failure — it just hangs. Backgrounding a
`until ! pgrep -f "hk fix --all"; do sleep; done` waiter to "wait for the real
task" **never exits**: the waiter's own command line contains the pattern, so
`pgrep -f` matches the waiter itself and the loop is true forever. Measured
2026-08-10: five such waiters accumulated, all reporting `STILL RUNNING` for
~15 minutes after `hk` had actually finished and failed, which also masked the
real failure (`lock-complete` rejecting the un-staged old lockfile) until the
log was read directly. `pgrep -fa` shows the self-match immediately, and
`pgrep -f "[h]k fix"` avoids it — but the waiter should not exist at all.

There is nothing to wait _for_: a command already launched with
`run_in_background` re-invokes the session on its exit. A second background call
that watches the first is pure overhead, and each poll of it burns a turn.
Launch the long thing, end the turn, act on the notification. When something
genuinely external must be watched (a condition no tracked task will announce),
use `Monitor` or a single `until` loop over a **file or an API**, never over a
process table the loop is itself a row in.

Two mechanisms, at different layers. `mise run run-shape-guard`, a `PreToolUse`
hook, denies both shapes and names the correct one — a fast path with a good
error message, and inherently incomplete, since it recognises _shapes_ and
`| grep -c`, `| wc -l`, `; true` or a wrapper script all escape it.

`mise run verified` is the invariant underneath: it answers "is HEAD verified?"
from the **receipt** `verify` already wrote, never from a remembered exit status,
so no idiom present or future can fool it. `verify` writes that receipt only
after its guarded steps pass, so a run that failed — or whose status a pipe
swallowed — leaves none. `land` depends on it, closing the gap where
`ready-guard` covered `gh pr ready` but nothing covered landing. Receipts are
keyed to the exact commit and live under `--git-dir`, so an amend, a rebase, or a
`main` that moved all invalidate them, and one worktree cannot vouch for another.

The receipt existed long before anything read it, which is the shape of the
lesson: an artifact recording the truth is sensor without a gate (rule 2). Redirections (`2>&1`, `&>`) are stripped before the
`&` test, since the recommended form contains one. Bypass:
`BATTEN_RUN_SHAPE_BYPASS=1`.

This rule existed as prose before it bound anything, and its placement is the
lesson: it sat in `.claude/rules/toolchain.md` — a vendor-specific file that
`mem:prior-art-and-issue-hygiene` says must not hold instructions, since agents
that cannot read it will violate it — scoped to "these tasks", so it never
generalised to `verify` or `ci`. Prose, in a file only one agent reads, about one
task. Three reasons it failed, and rule 2 predicted all three.

### A backtick in `git commit -m "…"` is a subshell, and it fails green

Same family, different verb. `git commit -m "… \`bench\` uses …"`is a
double-quoted string, so bash runs`bench`as command substitution and splices
its output — usually empty, plus a`command not found` line that scrolls past in
the hook's output. The commit succeeds. The message lands with the word deleted.

Measured 2026-08-13 on CLOUD-509: two of five messages lost a backticked term
(`` `bench` ``, `` `hk run` ``), leaving "Deliberately not hyperfine, which
uses:" and "It reads the line now." The tell is a **double space** where the
span was; nothing else marks it, and the `command not found` line looks like it
came from the gate rather than from the message. House style backticks every
identifier, so the exposure is every commit message this repo wants written.

**Write the message to a file and use `git commit -F <file>`.** Backticks are
literal there. `-m` with single quotes also works but forfeits apostrophes,
which the prose uses constantly. Escaping (`` \` ``) works and is the shape that
rots: it survives exactly as long as whoever edits the message next remembers.

Repairing an unpushed range is `git filter-branch --msg-filter 'sed -f <script>'

<base>..HEAD` with the substitutions in a **file** — a `sed` expression written
inline on the command line re-opens the same hole.

## The shell tasks' exit convention is the inverse of batten's

Read before porting a `mise-tasks/*-check` program into the engine, or before
copying one of their bats cases.

The `*-check` decision halves — `graph-check`, `landed-check`, `ready-lint`,
`verified` — use **exit 1 = violation, exit 2 = could not read the input**.
Batten's contract (house-style §7, CLOUD-226) is the exact opposite: **1 =
usage or unreadable, 2 = the policy verdict**. Both are internally consistent
and neither is wrong; they simply disagree, because batten's numbering is
pinned by what a mediating harness reads as a deny and the shell tasks predate
that constraint.

Two consequences:

- **A ported acceptance case inverts its own verdict.** CLOUD-202 names these
  programs as the behavioural spec and their bats suites as the port's
  acceptance corpus. Carry `assert_equal $status 1` across unchanged and the
  ported test asserts "unreadable input" while the case means "violation" — and
  it **passes**, which is the same failure shape as the `-v` regex and the
  `pipefail | grep` entries below: a gate green on the wrong claim. Translate
  the number, never copy it.
- **The five `PreToolUse` guards are already aligned** (`gh-guard`,
  `ready-guard`, `issue-guard`, `run-shape-guard`, `memory-guard` exit 2 to
  deny), because they always spoke the harness convention. Only the `-check`
  halves are inverted.

The tasks were deliberately not renumbered with CLOUD-226: they are independent
programs the engine will replace, and churning their contract now would rewrite
suites that are about to be deleted. The hazard is recorded rather than fixed
because the fix is the port itself.

## Never hand awk a regex through `-v`

The value is escape-processed by the assignment before awk sees it as a pattern,
and what that does to a backslash is **undefined across implementations**: gawk
strips `\(` to `(` with a warning, mawk keeps it. The same pattern is a literal
paren on one machine and a capturing group on the other.

`ready-lint` matched its §8 label that way. Green on mawk here, matching
**nothing** on the gawk CI runner — so the clause that catches a blocker claimed
without a relation went back to passing silently, and three tests that predated
the change went red with it. **A gate that cannot match its own label does not
fail; it passes.**

Two consequences worth keeping:

- **Local green is not evidence** when the two environments run different
  implementations of the same tool. This machine has mawk; the runner has gawk,
  and neither is wrong — the case is undefined.
- The fix is a split, not a workaround: let `grep` find what the pattern matches,
  and let awk work in **literal** patterns; or inline the regex in the awk
  program, where no assignment processing happens.

Mechanism: `mise run awk-regex-check` (in the shared hk `gate`) reports a `-v`
name the program then uses in regex position — `~ name` or `match(…, name)`.
The predicate is the **use**, not the value: a literal without a backslash is
safe today and unsafe the moment someone adds one, and a variable's runtime
content is invisible to any static check. `-v` for a plain value — compared with
`==`, printed, counted — stays fine and is most of its use.

## Never pipe a producer into an early-exiting `grep` under `pipefail`

`producer | grep -q P` can report **failure on a match**. grep exits at the
first hit; a producer still writing dies of SIGPIPE, and `pipefail` promotes 141
to the pipeline's status. Same for `-l` (stops at the first matching file) and
`-m N`.

It is a **race**, and that is what makes it survive review: whether the producer
is still writing when grep exits depends on output size and scheduling. Measured
here on a two-commit `git log` range — 2 failures in 300 runs. A large producer
loses nearly always; a small one loses rarely, passes every test written for it,
and misfires months later.

Two instances landed before the class was named, both failing toward the verdict
nobody checks:

- `landed-check` read `git log … | grep -q "$id"` and reported a **clean board**
  over three issues whose refs were on `main`.
- `issue-guard` asked the same way whether any commit names an issue, and
  **denied `gh pr ready`** on a branch whose every commit carried
  `Refs: CLOUD-186` — with a reason asserting the opposite of what it had found.
  The guard blocked its own PR, and the deny was not reproducible afterwards.

The fix needs no new tool: read the producer into a variable and match from a
here-string — `x=$(producer); grep -q P <<<"$x"`. A here-string has no upstream
process, so there is no status to promote.

Mechanism: `mise run pipefail-grep-check` (in the shared hk `gate`), scoped to
files that actually enable `pipefail` and to the early-exiting flags only — a
`| grep` that consumes its whole input is honest. Flag clusters are judged by
their letters (`-qxF` is `-q`), because an enumeration of spellings is what rots.

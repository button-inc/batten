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

Common tasks: `mise run test | lint | fmt | ci | cross-check`; `mise tasks` lists
all. `mise run fmt` is `hk fix --all` and `mise run ci` = `hooks` (`hk check
--all`) + `deny`, so the gate's step list lives in `hk.pkl` alone — there is no
second list in `mise.toml` to keep in sync. `mise run test` aggregates
`test:cargo` + `test:bats`.

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

## The always-loaded context budget

`mise run context-budget` fails when AGENTS.md plus anything declared
always-load exceeds `BATTEN_CONTEXT_BUDGET` (default 3500) estimated tokens, at
4 chars/token. Tokens, not lines: the cost is what every agent pays on every
turn, and an exact count would need a tokenizer, a model-specific vocabulary and
a network fetch — a budget gate that fails because a download failed is worse
than one that is 10% out.

The always-loaded set is AGENTS.md plus `.serena/memories/always/*.md`. That
directory does not exist yet; creating one is a declaration that every session
reads that memory, and it then costs exactly what an AGENTS.md section costs.
Counting it here is the whole point — moving a section into a memory only
reduces the tax if the memory is genuinely read at a trigger. Ordinary memories
are not counted, because a session that never hits their trigger never pays for
them.

Over budget: cut, or move a section to a triggered memory (sorting rule in
`mem:prior-art-and-issue-hygiene`). Raising the number is a decision, not a fix.

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

The correct form keeps the status and lets the harness supervise:

```
mise run <task> >/tmp/<task>.log 2>&1; echo "EXIT=$?"; tail -20 /tmp/<task>.log
```

with `run_in_background` on the tool call itself for anything over ~2 minutes.
`run_in_background` must wrap the long command, not a launcher that returns
immediately — a wrapped launcher looks identical in the tool result and silently
drops the re-invocation. A pager over a **file** is fine; over a **live task** it
is not.

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

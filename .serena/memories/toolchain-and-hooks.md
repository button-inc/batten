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
always-load exceeds `BATTEN_CONTEXT_BUDGET` (default 6000) estimated tokens, at
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

## MCP allow rules must name the tool prefix Claude Code actually sees

`.claude/settings.json` `permissions.allow` is matched against the **tool name
as exposed to the session**, and Linear reaches us under two different names:

- Configured locally in Claude Code → `mcp__Linear__<tool>`.
- Pulled in as a **claude.ai connector** → `mcp__claude_ai_Linear__<tool>`.

So a lone `mcp__Linear` rule silently fails to cover the connector path and the
CLI prompts for approval on every Linear call. Both prefixes are allowlisted.
The connector segment is `claude_ai_` plus the connector's **display name with
its casing preserved** — the CLI's own built-in allowlist carries
`mcp__claude_ai_Slack__slack_send_message`, and its scope resolver classes any
server whose name starts with `claude_ai_` as connector-scoped. Don't infer the
name from a Claude Code on the web session: cloud sessions receive connectors as
explicit `--mcp-config` entries and name them differently (plain `mcp__Linear__*`,
or a bare connector UUID), so that naming says nothing about the local CLI.

Mechanism, not prose: `mise run mcp-allow-check` (wired into the shared hk
`gate`, globbed on `.claude/settings.json`) **fails** when an allowed server has
no companion `mcp__claude_ai_<server>__*` rule, or when an allow rule globs the
server segment. A permission rule that matches no tool name grants nothing and
reports nothing — the only symptom is a prompt on every call, which reads as
harness behaviour rather than as a settings bug. That silence is what earns the
gate.

The **"Always" toggle on claude.ai does not fix this.** It governs claude.ai
chats only. The one thing that crosses over from claude.ai is an organization's
per-tool `ask`/`blocked` control, and it only _tightens_: a tool set to `ask`
prompts on every call and a local allow rule cannot skip it, in any permission
mode. Local auto-approval is only ever bought with a local allow rule.

Allow rules also cannot glob the server segment — `mcp__*` and `mcp__claude_ai_*`
are skipped with a warning. The wildcard is legal only after a literal
`mcp__<server>__` prefix.

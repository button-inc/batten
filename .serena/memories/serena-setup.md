# Serena setup and worktree mechanics

Read when: a Serena worktree/index misbehaves (stale/cross-linked symbols), or
you're changing `.serena/` config. AGENTS.md notes only that Serena is wired up
and that memories are checked in; this is the setup detail.

## What it is

Project-scoped Serena MCP server (LSP-backed semantic navigation/edits). Wired in
`.mcp.json`. It does **not** "just start" on a cold container — see "Two gates"
below. Pinned like every tool: `"pipx:serena-agent"`
in `mise.toml [tools]` (pipx backend installs with pinned `uv`), version in
`mise.lock`. `.mcp.json` launches it through `mise-tasks/serena-mcp`, a shim
that records the spawn and then `exec`s the scoped, pinned launch line the file
still carries verbatim: `mise exec pipx:serena-agent@<v> -- serena
start-mcp-server --context claude-code --project .`. The argv stayed in
`.mcp.json` on purpose — `mise-pin-agreement` reads the pin out of it.

`--project .` matters: Serena keys projects by **path** and activates the cwd, so
the main checkout and every `.claude/worktrees/` worktree are independent projects
with their own symbol cache.

## Two gates stand between a cold container and Serena (CLOUD-196)

Both must be closed. Each alone looks sufficient on a **warm** container, which is
why the first fix was validated green and Serena stayed absent anyway.

1. **Install timing.** `mise exec` installs on demand; on a cold container that
   24s `pipx:serena-agent` install lands inside the MCP startup window and the
   handshake never completes. Closed by the synchronous `SessionStart` hook
   (`.claude/hooks/session-start.sh`) running `mise install` **before** the
   session starts.

   **Closed for INSTALLATION, not for everything that happens before Serena
   answers** (CLOUD-714). `mise install` guarantees the files exist; it never
   reads them, and Serena still spends ~1.2 s importing 2,664 `.py` files before
   it opens its own log. That gap is why an absent serena log is _not_ proof the
   process never ran, and why `mise-tasks/serena-mcp` records the spawn.

   **And MCP connections ARE retried** — this memory said they are not, on
   CLOUD-196's evidence. Measured 2026-08-19: after failures at 07:05:17 and
   07:41:58, a third attempt fired unprompted at 14:30:15. The client also
   aborts ~1.5 s _before_ its declared 30,000 ms, so a gate asserting the
   effective budget must expect ~28.3 s and not 30.

2. **Approval.** A `.mcp.json` server is project-scoped and needs per-project
   approval, closed by committing `"enabledMcpjsonServers": ["serena"]` in
   `.claude/settings.json`. Keep that line.

   **But `~/.claude.json` is NOT how you check it, and reading `[]` there means
   nothing** (CLOUD-316). This harness does not record enablement in that file:
   measured 2026-08-11, `projects["/home/user/batten"].enabledMcpjsonServers`
   read `[]` while the CLI launched serena anyway. That `[]` is the CLOUD-196
   signature and it is now a **false** one — it has sent two sessions down the
   approval path for a launch failure. Evidence that approval worked is a
   `Starting connection` record in the log, nothing else.

3. **A scoped launch (CLOUD-316).** The one that actually cost a whole session.
   `.mcp.json` ran a bare `mise exec`, which provisions **every** tool in the
   active config before it execs anything — so Serena waited on twenty tools and
   died when one unrelated one failed to install, having itself installed
   successfully inside the window. `.mcp.json` now names the tool
   (`mise exec "pipx:serena-agent@<pinned>" -- serena …`), and `mise run
mise-pin-agreement` gates both that the version agrees with `mise.toml` and
   that the launch stays scoped — a revert to a bare exec fails the gate.

**Diagnosing "Serena is missing" — do this in order, it is easy to get wrong.**
**Read the logs FIRST.** Every wrong answer below was reached by reasoning about
config instead of opening the file that records what happened:

- `~/.cache/claude-cli-nodejs/<cwd with / as ->/mcp-logs-<server>/*.jsonl`, newest
  file. `Successfully connected` = attached. `Connection failed (…)` = the launch
  lost, and the parenthesised code says how. `mise run mcp-attach-check` is this
  read with an exit code, and it fires on `UserPromptSubmit` so a lost server is
  reported in the session's first turn.
- Two record shapes mislead, both measured: an `error` **key** usually carries
  routine `Server stderr: INFO …` chatter on a healthy launch, and the failure
  code is **not** fixed at `-32000` — the next real occurrence was
  `CONNECT_TIMEOUT`. Judge the last `Connection failed` / `Successfully
connected` record, not the presence of an error key or a literal code.
- `/tmp/claude-code.log` for the harness side: the `Starting connection with
timeout of 30000ms` line and its timestamp.
- **A server absent from the tool list at the top of a turn may simply still be
  connecting.** Measured 2026-08-11: a healthy attach took 12.5s and the tools
  appeared mid-session. Do not conclude "absent" from an early snapshot — check
  the log, or just try a tool.

Only after the logs say the launch failed:

- Do **not** reach for `mem:connector-allowlist-recovery`. That covers claude.ai
  connectors (Linear/Gmail/Xero) flipping to UUID tool names. Serena is neither:
  the host's injected `/tmp/mcp-config-cse_*.json` lists the connectors and **no
  serena**; Serena comes from the repo's own `.mcp.json`. Wrong mechanism entirely.
- **Prove liveness before concluding anything is broken.** `mise exec -- serena
--version`, then `timeout 45 mise exec -- serena start-mcp-server --context
claude-code --project . </dev/null`. A server that starts in ~1s and advertises
  21 tools while absent in-session means the **handshake** lost — not that Serena
  is down. That exact misdiagnosis has been made.
- Do **not** check `~/.claude.json` → `projects["<repo path>"]`. Demoted to
  non-evidence above: this harness does not record enablement there, so `[]` is
  the normal reading on a session whose server attached fine.
- Timestamps that establish cold vs warm: `ps -o lstart= -p 1` (container start)
  vs `stat -c '%y' /root/.local/share/mise/installs/pipx-serena-agent/*`. An
  install _after_ container start = cold. **A warm container cannot test any of
  this** — it exercises only the case that was never broken.

Known wart: the hook's `mise install` writes a `linux-x64-cargo-zigbuild`
checksum into `mise.lock` that the `lock-complete` gate rejects as install-time
residue, so a cold session starts with a dirty tree that fails `mise run verify`.
Revert `mise.lock` before committing; don't commit the tree wholesale.

## Worktree collisions are configured away

- `.serena/project.yml` — checked in (shared: Rust LS, gitignore-aware indexing).
  Its `ignored_paths` excludes `.claude/worktrees/**` — without that the main
  checkout (which physically contains every worktree) would index N+1 copies of
  the tree and cross-link their symbols. _The_ worktree failure mode; handled.
- `.serena/cache/` (per-machine symbol index) and `.serena/project.local.yml`
  (local overrides) are git-ignored via `.serena/.gitignore`.
- `.claude/worktrees/` is git-ignored.

Stale index in a worktree → delete its `.serena/cache/` and let Serena rebuild.
Never commit `.serena/cache/`; never point two worktrees at one cache.

## Cold-start race: fixed and verified (CLOUD-196)

`mise exec` installs on demand. Before the fix, on a cold container the
`pipx:serena-agent` install (~24s) ran _inside_ the MCP startup window and the
handshake never completed — Serena was absent for the whole session while being
perfectly runnable. (This paragraph used to add "and MCP servers are not retried
mid-session"; that is false, see gate 1 above.)

Fix (`9f78869`): a **synchronous** `SessionStart` hook,
`.claude/hooks/session-start.sh`, runs `mise install` + submodule init before
the session starts, so the install is out of the startup window.

Verified on a genuinely cold container 2026-08-07: PID 1 started 22:00:00,
`pipx-serena-agent` installed 22:00:18–22:00:28 (i.e. after container start,
during this session), hook logs present at `/tmp/session-start-mise-install.log`
and `/tmp/session-start-submodules.log`. Serena's ~21 tools were attached to the
session and `list_memories`/`edit_memory` on `.serena/memories` worked. Cold
start is no longer a race.

### When Serena does not attach, read the spawn ledger first (CLOUD-714)

`$GIT_DIR/batten-mcp-spawns`, one tab-separated line per launch:
`<epoch> <server> <pid> <loadavg-1min> <sibling-count>`. `mise run
mcp-attach-check` compares its newest entry against the connection attempt and
reports one of three things, and the third is the one that keeps the other two
honest:

- **spawned-and-unresponsive** — the client ran the command and the child did
  not answer. The fault is downstream of the spawn.
- **never-spawned** — the ledger has seen this server before and recorded
  nothing for this attempt. The fault is in the client's spawn path.
- **unrecorded** — no ledger, or none for this server. _Not_ a verdict: the shim
  is not wired here, so its silence means nothing.

Do not re-derive this from `/root/.serena/logs/` mtimes. A day went into that on
2026-08-19 and it cannot answer the question: Serena opens its log ~1.2 s of
Python import into the process, so a launch killed during import looks exactly
like one that never happened. Eleven hypotheses were eliminated by measurement
that day — `mise` resolution, the spawn env, cwd, PATH, LSP indexing, the news
fetch, the grant spelling, stdio shape, cold page cache (1,349 ms vs 1,103 ms
warm — the leading theory for hours, and false), proxy vars, and the full launch
shape (3,114 ms). Five isolated replications attach in 3.1–7.3 s. The only
surviving correlate is that every failure happened during a multi-server startup
burst and every success was a lone launch, which is why the ledger records load
and sibling count.

## Which mechanism is at fault when a server is missing

Serena is **repo-scoped**, from this repo's `.mcp.json`. It is _not_ a claude.ai
connector, so `mem:connector-allowlist-recovery` (Linear/Gmail/Xero flipping
between readable and UUID tool names) is the wrong diagnosis — as are
CLOUD-178/191. The distinguishing check:

1. Compare the host's injected config `/tmp/mcp-config-cse_*.json` (connectors:
   Xero, Gmail, Linear, github, Claude_Code_Remote — **no serena**) against
   `.mcp.json` (repo-scoped servers). Whichever file names the server tells you
   which mechanism owns it.
2. Before concluding a server is broken, run its `.mcp.json` command by hand:
   `mise exec -- serena --version`, and
   `timeout 45 mise exec -- serena start-mcp-server --context claude-code --project . </dev/null`
   (expect ~21 tools). A server that starts fine but has no tools in-session
   means the **handshake** lost, not that the server is broken.

## Memories are checked in

`.serena/memories/` is **not** gitignored (unlike `cache/`) — a shared,
version-controlled knowledge surface, read on demand. It holds retrieve-on-demand
**reference and orientation**, never binding behavioral rules: memories aren't
guaranteed in an agent's context, so anything that must _bind_ stays in AGENTS.md
with its gate. AGENTS.md's "Serena memories" index names each memory's trigger.

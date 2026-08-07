# Serena setup and worktree mechanics

Read when: a Serena worktree/index misbehaves (stale/cross-linked symbols), or
you're changing `.serena/` config. AGENTS.md notes only that Serena is wired up
and that memories are checked in; this is the setup detail.

## What it is

Project-scoped Serena MCP server (LSP-backed semantic navigation/edits). Wired in
`.mcp.json`, starts automatically. Pinned like every tool: `"pipx:serena-agent"`
in `mise.toml [tools]` (pipx backend installs with pinned `uv`), version in
`mise.lock`. `.mcp.json` launches it via mise: `mise exec -- serena
start-mcp-server --context claude-code --project .`.

`--project .` matters: Serena keys projects by **path** and activates the cwd, so
the main checkout and every `.claude/worktrees/` worktree are independent projects
with their own symbol cache.

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
`pipx:serena-agent` install (~24s) ran _inside_ the MCP startup window, the
handshake never completed, and MCP servers are not retried mid-session —
Serena was absent for the whole session while being perfectly runnable.

Fix (`9f78869`): a **synchronous** `SessionStart` hook,
`.claude/hooks/session-start.sh`, runs `mise install` + submodule init before
the session starts, so the install is out of the startup window.

Verified on a genuinely cold container 2026-08-07: PID 1 started 22:00:00,
`pipx-serena-agent` installed 22:00:18–22:00:28 (i.e. after container start,
during this session), hook logs present at `/tmp/session-start-mise-install.log`
and `/tmp/session-start-submodules.log`. Serena's ~21 tools were attached to the
session and `list_memories`/`edit_memory` on `.serena/memories` worked. Cold
start is no longer a race.

### Which mechanism is at fault when a server is missing

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

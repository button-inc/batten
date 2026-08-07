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

## Memories are checked in

`.serena/memories/` is **not** gitignored (unlike `cache/`) — a shared,
version-controlled knowledge surface, read on demand. It holds retrieve-on-demand
**reference and orientation**, never binding behavioral rules: memories aren't
guaranteed in an agent's context, so anything that must _bind_ stays in AGENTS.md
with its gate. AGENTS.md's "Serena memories" index names each memory's trigger.

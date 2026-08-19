# Session and transcript access from a worker container

Measured 2026-08-19 (CLOUD-682). A prior session spent most of its budget
re-deriving this and reported two wrong diagnoses on the way. The answer is no —
say it in one line and go to the durable record instead.

## What is readable locally

- `~/.claude/projects/<project>/<uuid>.jsonl` — **this session only**. Every
  container starts at N=1 and ends at N=0; `mise run transcript-corpus-check` is
  the reading.
- `.claude.json` `projects.<path>.history` is empty in a fresh container, and
  `backups/` carries no transcripts.
- The transcript this session is writing IS readable, and is the path
  CLOUD-651's collector takes. It is the only local read that works.

## Route map, probed rather than inferred

| request                                                        | result                                 |
| -------------------------------------------------------------- | -------------------------------------- |
| `GET /v2/ccr-sessions/<id>`                                    | 200 — metadata                         |
| `GET /v2/ccr-sessions/<id>/events`                             | **401** — route exists, worker refused |
| `GET /v1/code/sessions/<id>/events`                            | **401** — same                         |
| `/messages` `/transcript` `/history` `/turns` `/events/stream` | 404                                    |

**401 against 404 is the discriminator**: 404 means no such route, 401 means the
route is real and this principal is refused. Read the status, not the absence.
`no_proxy` covers `*.anthropic.com`, so the agent proxy is never implicated and
is not worth investigating.

## Credentials

- `$CLAUDE_SESSION_INGRESS_TOKEN_FILE` decodes to `iss: session-ingress`,
  `role: worker`, one `session_id`. It DOES authenticate
  `POST /v2/ccr-sessions/<id>/mcp` (JSON-RPC `tools/list` → 200) — which
  contradicts CLOUD-673's "a task cannot authenticate": that 401 was a missing
  `Authorization` header, not a missing credential.
- `/home/claude/.claude/remote/.oauth_token` is a device token, refused on these
  routes (`403 auth method not allowed`).

Never print, log or commit either. JWT claims decode without the signature and
are safe to cite; the token is not.

## The MCP surface

`Claude_Code_Remote` is a **remote** server. `create_session` is a cross-session
write that succeeds because the _service_ performs it — the container holds no
write credential. The endpoint serves 20 tools and **none reads conversation
content**; anything missing locally is this repo's own `deny` list in
`.claude/settings.json`, not a transcript restriction.

## Session ids

`cse_<x>` (service) and `session_<x>` (client) name one session; the client shims
between them. `CLAUDE_CODE_REMOTE_SESSION_ID` is the `cse_` form. Both 404 on
`/v1/sessions/...`, which is Managed Agents — a different object space.

## Where the history actually is

Linear. A past session's finding is on its issue; that is what filing is for.
`list_sessions` gives titles, branches, `task_summary` and per-session token
spend — enough to identify _which_ session, never its content. Sessions missing
from it (measured: 2026-08-11/12) are unreachable here.

The read exists for a **user-scope** principal: the claude.ai session list, or
the CLI on a personal machine where `/v1/code/sessions/<id>/events` is the
working call. Point the user there rather than hunting a wider credential.

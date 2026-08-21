# GitHub access — go around the proxy, never through it

Read when: any GitHub operation, OR before claiming the toolchain/tests/CI can't
run because "the proxy/network blocks GitHub" (that claim is almost always
false here — prove it locally first). AGENTS.md carries the one-line directive;
this is the full mechanics and fallback order.

## The core fact

Routing a GitHub call _through_ the security proxy fails: it answers with a
scoped app credential and 403s almost everything (`not accessible by
integration`; GraphQL pinned to a tiny allowlist). GitHub itself is reachable —
a direct PAT-authenticated request to `api.github.com` returns 200 with the full
5000/hr limit. Go _around_ the proxy.

## Fixed preference order (fall through only on an observed failure)

1. **`gh` through mise — default for everything.** `mise exec -- gh <…>`.
   `mise.toml [env]` sets `GH_TOKEN` to our PAT and `NO_PROXY=api.github.com`, so
   `gh` authenticates as us and reaches GitHub directly. PR create/ready/view,
   comments, landing (`gh pr comment <n> --body /fast-forward`), issues, `gh api`.
2. **GitHub API direct with our PAT**, routed around the proxy — `gh api …`, or
   `env -u HTTPS_PROXY curl -H "Authorization: Bearer
$GITHUB_PERSONAL_ACCESS_TOKEN" …`. `rate_limit`, repo, `pulls/<n>`,
   `commits/<sha>/status` all return 200.
3. **`mcp__github__*` tools — LAST RESORT**, only after (1) and (2) both actually
   failed for that operation.

## Why the toolchain runs here (ignore /root/.ccr/README.md on this point)

`mise.toml [env]` sends `api.github.com` + asset hosts around the proxy via
`NO_PROXY` and authenticates mise via `MISE_GITHUB_TOKEN` =
`GITHUB_PERSONAL_ACCESS_TOKEN`; `github.com` stays proxied so `git` keeps its
proxy auth for this private repo. So with the PAT set (sandbox default),
`mise install` / `mise run ci|cross-check|verify` all run green with no ceremony.
The `403 — GitHub access not enabled for this session` you may see is the proxy
answering for _third-party tool repos_ (uv, hk, cargo-deny, release-plz) — not an
egress block. Only if `GITHUB_PERSONAL_ACCESS_TOKEN` is genuinely absent may a
tool install fail; say exactly that, not "policy blocks GitHub."

If a 403 persists _with_ the PAT present, that's a real env-wiring bug — diagnose
(`env -u HTTPS_PROXY curl -H "Authorization: Bearer $GITHUB_PERSONAL_ACCESS_TOKEN"
https://api.github.com/rate_limit` should be 200), don't surrender.

## CI-checks scope gap (don't misdiagnose as a proxy problem)

Reading CI checks needs **Checks: read**. A fine-grained PAT cannot carry it —
`…/commits/<sha>/check-runs` and `gh pr checks --watch` 403 with
`x-accepted-github-permissions: checks=read`, off-proxy included. That's a token
capability, not a network block. Use a **classic PAT scoped `repo`** (bundles
checks-read, so `--watch` works) or the MCP `get_check_runs` tool (carries the
permission via App auth).

**"Everything else works" is not quite true, and the second gap is `gh pr edit`.**
Measured 2026-08-19 with a classic PAT scoped `repo,workflow`: `gh pr edit <n>
--body-file …` fails outright with `GraphQL: Your token has not been granted the
required scopes … The 'login' field requires one of the following scopes:
['read:org']`. The edit itself needs nothing but `repo`; `gh` incidentally
queries `login`/`name`/`slug` on assignees and teams while building the mutation,
and those fields are what demand `read:org`. So the failure names a scope the
operation does not need, which is exactly the shape that sends a reader off to
widen a token unnecessarily.

Do not widen the PAT for this. Use the MCP `update_pull_request` tool, which
carries the permission via App auth and edits the body directly — the same
resolution as `get_check_runs` above, for the same reason. `gh pr create` and
`gh pr ready` are unaffected; only the edit path queries those fields.

## `add_repo` is blocked, so the repo scope cannot be widened at all

Measured 2026-08-21. `add_repo` is served by the Claude Code Remote toolbox
server, whose every tool carries a mandatory-approval flag and returns
`MCP tool call requires approval` (`mem:connector-allowlist-recovery`'s STOP
section has the mechanism and the upstream issues). So:

- **A session cannot attach a second repository**, for any purpose — not to read
  one, not to clone one, not to comment on its issues.
- **The scope you start with is the scope you have.** The system prompt's "call
  `add_repo` to bring in a repository" is unreachable here; do not offer it to
  the user as a next step, and do not spend a turn on it.
- **The consequence that bites hardest:** a session that reproduces an upstream
  bug cannot reach `anthropics/claude-code` to file or update the report. That is
  why `#87548` — our own reproduction — sat un-updated from 2026-08-18. Hand the
  user the comment text to paste; it is the only channel.

## Provider outages — status page first, then poll for recovery

When a hosted dependency misbehaves (jobs that never start, calls that hang/5xx,
webhooks that don't arrive), read the provider's **public status page first**,
before theorizing about tokens, scopes, proxies, or drafts. A platform incident is
invisible from inside the repo but obvious on the status page. For GitHub, fetch
`https://www.githubstatus.com/api/v2/summary.json` (per-component status + active
incidents) — an Actions "major outage" explains zero workflow runs repo-wide far
faster than auditing PR state. (During the Aug-2026 Actions outage, webhook
triggers were throttled, so `ready`/`synchronize` events were _dropped, not
queued_ — they never replay, and CI only ran once a fresh push was made after
recovery.)

During a confirmed outage, **poll for recovery — do not wait on an event**: an
outage has no "recovered" webhook, so waiting is a hang. This is the one deliberate
exception to the event-driven CI rule. Poll **two** signals, since they fail
independently: (1) the status-page component, and (2) the real endpoints
(`actions/runs?branch=…`, `commits/<sha>/check-runs`) for your head SHA. The
recovery team often leaves the advisory up for hours after service is actually
restored, so an appearing run/check for your SHA is _stronger_ proof than the
advisory clearing — treat either as recovery. Run the poll as a **bounded
background loop** (background `sleep` allowed, foreground killed) so it survives and
re-invokes you; then re-trigger CI with a fresh push (the original events were
dropped), confirm green, and land.

## Hygiene

- `git` over `github.com` (clone/fetch/push/ls-remote) uses proxied git auth —
  leave it alone.
- Confirming CI: **one continuous background `gh` poll, no timeout, never
  event-driven.** Do not wait on the webhook / PR activity subscription — in this
  ephemeral cloud env a webhook can only wake a session that still exists, and an
  idle wait gets the VM reclaimed within minutes (before CI finishes), so the event
  has nothing to wake and the landing stalls forever; webhooks also drop _successes_
  outright (proven during the Aug-2026 outage). Instead, right after readying/push,
  launch a **single unbounded background process** that loops
  `gh api …/commits/<sha>/check-runs` on an interval and exits _only_ when every
  check reaches a terminal state — **no `MAX`/iteration cap, no wall-clock
  timeout** (a timeout just reintroduces the reap gap; the loop is already bounded
  by CI completing). Poll the **`final`** aggregate, not just
  `ci`/`cross`/`commit-lint` — it's the authoritative all-green signal. On the
  process's exit it re-invokes you; read conclusions once, then land. Only the
  _foreground_ busy-poll/`sleep` is banned; a backgrounded poll is the durability
  mechanism. Script gotchas that bit us: feed the JSON to `python3` via a pipe, not
  a `<<'PY'` heredoc (the heredoc _is_ stdin, so `sys.stdin` reads empty); and avoid
  backslashes inside f-strings. (A superseded run shows `ci`/`cross` `cancelled` and
  `final` `failure` from CI's concurrency `cancel-in-progress` — not a real failure,
  just the old SHA dropped when you pushed a new head.)
- Never echo a credential. Check presence with `${VAR:+SET}` — never a bare
  `$VAR` or a `${VAR:-…}` that expands the value into the transcript.

## Transparent TLS interception — tools that carry their own CA roots

Egress TLS is intercepted at the network layer, **not** by the `HTTPS_PROXY` env
var. Every connection presents a certificate issued by `O = Anthropic, CN =
Egress Gateway ... CA`, and unsetting `HTTPS_PROXY` or adding a host to `NO_PROXY`
changes nothing — those only steer tools that _read_ the vars, and the
interception is below that layer. Verify in one line:

```
openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null | grep ' i:'
```

Most tools work anyway because the system trust store already carries that CA.
The ones that break are those shipping **their own** root bundle and ignoring the
system store. The fix is never a proxy variable — it is handing that tool the
gateway bundle at `/root/.ccr/ca-bundle.crt`, usually via a `--ca-certificates`
style flag (which typically _replaces_ the tool's roots rather than adding to
them, so pass it only when the file exists).

Known instance: `pkl`. Measured cold — **delete `~/.pkl/cache` before every
attempt**, or a cached package turns the next command into a no-op that reads as
a pass (this is what made an earlier diagnosis wrong):

| attempt (cold cache)                  | result                |
| ------------------------------------- | --------------------- |
| `pkl eval`                            | SSL handshake failure |
| `SSL_CERT_FILE=<bundle> pkl eval`     | same — pkl ignores it |
| `pkl eval --http-no-proxy github.com` | same                  |
| `env -u HTTPS_PROXY pkl eval`         | same                  |
| `pkl eval --ca-certificates <bundle>` | OK                    |

Two things generalise. **Symptom misreads as a content error:** the tool reports
a broken config/package, not a network problem, so the first instinct is to debug
the file. **It only bites cold:** anything cached, and any environment without
interception (CI), never sees it — so "works on CI" is not evidence the sandbox
path is fine.

This is a Claude-sandbox fact and belongs here. It does not belong in the
codebase: repo files carry the guardrail itself, not the story behind it.

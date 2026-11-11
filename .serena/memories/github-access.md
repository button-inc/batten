# GitHub access — the proxy is the route; there is no PAT

Read when: any GitHub operation, OR before claiming the toolchain/tests/CI can't
run because "the proxy/network blocks GitHub" (that claim is almost always
false here — prove it locally first). AGENTS.md carries the one-line directive;
this is the full mechanics and fallback order.

## The core fact (measured 2026-11-11)

**This environment carries NO personal access token.** `GH_TOKEN` and
`GITHUB_TOKEN` hold only the proxy's `proxy-` placeholders, which the agent proxy
replaces with its own credential — the GitHub App installation on this org — on
every request it carries. `BATTEN_GITHUB_TOKEN` and
`GITHUB_PERSONAL_ACCESS_TOKEN` are unset. Check with
`${BATTEN_GITHUB_TOKEN:+SET}` before reasoning about a token.

So **through the proxy is the route** for everything about this repository:
`gh`, the REST API, git push/fetch, and the `mcp__github__*` tools. What the proxy
refuses is API access to a repository NOT attached to the session — it answers
403 `GitHub access to this repository is not enabled for this session` — and no
token you could send changes that, because the proxy discards whatever you send.
Going around it (`--noproxy '*'`) leaves you unauthenticated: 60/hr, and 403 for
anything private.

**Third-party release ASSETS are served; their API is not.** That is why the
toolchain installs LOCKED (`session:install`, `setup.sh` step 2): a locked
`mise install` downloads from the URL and checksum `mise.lock` pins and never
resolves through `api.github.com` — measured, all 38 tools into an empty data
directory, through the proxy, lock unchanged. An UNLOCKED resolve
(`mise ls-remote`, `mise use` of an unpinned tool) is refused 403 here, and the
remedy is a lock entry, never a token. The fence-and-PAT design this memory
used to describe is retired (CLOUD-2688).

## Fixed preference order (fall through only on an observed failure)

1. **`gh` through mise — default for everything.** `mise exec -- gh <…>`. PR
   create/ready/view, comments, landing (`gh pr comment <n> --body
/fast-forward`), issues, `gh api` — all over the proxy's credential.
2. **`mcp__github__*` tools** — when `gh` is not installed or the operation is
   one the connector exposes better.
3. **A repository you need and the session lacks:** `add_repo`, never a token.

## A degraded session start repairs itself, and says batten is broken

**A `batten startup` row you did not cause means the SessionStart chain did not
run — `batten startup --repair` FIRST, before other work, and SAY the repair was
needed.** The `[[hook.handler]]` rows already reap autonomously (`session-wiring`
removes the launcher's hook registrations at the same cadence the launcher writes
them), so needing to repair BY HAND is never the finding: it is evidence the
chain was skipped, and the skip is the defect. A gate that detects what it is
wired to fix and waits to be asked is sensor only — non-negotiable rule 2.

The measured cause, 2026-09-06 (CLOUD-1326, CLOUD-1506): the container provisions
the RELEASED binary, `main` had already landed `[[outcome]]`, and 0.0.144 exits
`1` on `unknown field`. `session-batten` died, every handler after it silently did
not run, and nothing reaped. Worse, exit `1` is a Batten FAILURE, and
`crate::exit` makes only `2` a denial — so no failure path blocks a call. Every
mediated gate permitted for half a session: `no-tool-substitution`,
`protected-mutation`, and `commit-attribution`, which let six commits carrying a
`trailer_deny` trailer reach the remote. **At the hook boundary, refuse and permit
are the same byte.** `mise run install:local` is the unblock.

**Measured again 2026-09-10, with the version numbers, because this class recurs.**
Installed binary **0.0.156**, tree at **0.0.159**. `batten.toml` declares
`command_matcher` (commit `4bc4f57`'s key, whose own footer reads
"`handler::Handler` gains a `command_matcher` field") and 0.0.156 cannot parse
it, so `batten startup` refused the **whole config** — every mediated gate
permitting, `egress-is-unproxied` never reachable, `hook-surfaces-are-battens`
never reaped. `mise run install:local` fixed it; the gates went live immediately
and began correctly denying `no-tool-substitution` and `background-redirect` on
calls that had gone unjudged minutes earlier. `contract-drift` then self-reported:
_"this session's SessionStart registration did not run … every mediated call until
it appeared failed open and said nothing."_

This is CLOUD-1775's shape and it is **self-referential**: the skew detector is
declared with `command_matcher`, the very key a stale binary cannot parse, so it
is unreachable in exactly the case it exists for.

**`batten startup --repair` was ALSO needed by hand** in the same session, and
`hook-surfaces-are-battens failed not-provisioned` went to `ok` only after it —
which is what leaves the launcher's own stop hooks firing when batten is supposed
to have zeroed them in place. Needing the repair by hand is the finding, not the
fix.

A repair the host refuses is the ONE ask to put to a human (CLOUD-680's shape).
Name the refusal you actually got; never assert which settings key would have
granted it unless you measured that key doing something.

## Third-party repositories: git yes, the API no (measured 2026-11-11)

- **git over HTTPS reaches any public repository through the proxy.**
  `git ls-remote https://github.com/EmbarkStudios/cargo-deny HEAD` answered, and
  `git clone --depth 1 <url>` takes the same route. No fence, no credential
  helper, no approval: the clone needs nothing the environment does not already
  give.
- **The REST API refuses a repository not attached to the session**: `gh api
repos/EmbarkStudios/cargo-deny` and a bare `curl` both answer 403, with or
  without the placeholder. That is the proxy's scope, not a token's, so no token
  changes it. **Attach the repository with `add_repo`** when its API is needed —
  issues, comments, metadata — and read code with a clone.
- **`gh` needs a non-empty `GH_TOKEN` to send anything.** `mise.toml` keeps the
  `proxy-` placeholder when no PAT exists (CLOUD-2688); before that it blanked
  it, and `mise exec -- gh` refused even this repository with "populate the
  GH_TOKEN environment variable".

**A shallow checkout can report a normal `main` advance as a force-push.** Measured
2026-09-27:

- `git fetch` printed `+ 4979166...4595ce3 main -> origin/main (forced update)`.
- `merge-base --is-ancestor 4979166 4595ce3` failed.
- GitHub's `compare/4595ce3...4979166` answered `behind 151, ahead 0`: an ordinary
  fast-forward.

The shallow history simply didn't contain the path between them. **Ask the forge
before calling it a rewrite:**

```
mise exec -- gh api repos/{o}/{r}/compare/A...B --jq .status
```

**Forked skills don't inherit the mise route.** A forked `/code-review --comment`
reported "gh isn't installed" and fell back to MCP, while `mise exec -- gh` worked
in the parent (CLOUD-1930). Treat a forked skill's claim that `gh` is absent as a
probe error, not a fact.

## Permission gaps are the App's, never a token to widen

What the proxy's credential may do is a live fact: session start's `batten doctor
forge` reports each permission as `ok` or not. A 403 carrying
`x-accepted-github-permissions` names a permission the App installation lacks,
not a network block — and there is no token here to widen, so the route is the
`mcp__github__*` tool that carries it (`get_check_runs`, `update_pull_request`)
or a change to the App installation, which only an org owner makes.

`gh pr edit --body-file` once failed on a missing `read:org` it does not need
(`gh` queries assignee/team fields while building the mutation; measured
2026-08-19 under the retired PAT). If it fails the same way, use the MCP
`update_pull_request` tool; `gh pr create` and `gh pr ready` never query those
fields.

## A refusal on one surface bounds that surface

Before reporting a capability as absent, try the other routes the environment
already grants — `gh`, git, `curl` through the proxy, `add_repo`, the repo's own
tasks. `anthropics/claude-code#87548`, our own reproduction, sat un-updated for
three days because three sessions concluded "no route" without testing one. **Do
not tell the user something is unreachable, and do not hand them text to paste.**

## Provider outages — status page first, then check on demand

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

An outage has no "recovered" webhook, so do not wait on one, and do not poll
either (AGENTS.md, "Background the slow path"). Check the two signals on demand
whenever the session wakes for another reason: (1) the status-page component,
and (2) the real endpoints (`actions/runs?branch=…`, `commits/<sha>/check-runs`)
for your head SHA. A run or check appearing for your SHA is stronger proof than
the advisory clearing. On recovery, re-trigger CI with a fresh push (the
original events were dropped) and run `mise run land` again.

## Hygiene

- **`git` over `github.com` goes through the proxy, unfenced.** The proxy's App
  credential carries this repository's pushes, the landing lease's CAS included
  (measured 2026-11-11: `git push` of this branch through the proxy). The fenced,
  PAT-carrying route this bullet once required is retired with the PAT
  (CLOUD-2688).
- Confirming CI is **`mise run land`'s job** (AGENTS.md, "Workflow contract").
  On demand, `SHA=<pushed head> mise run checks-green`, backgrounded, judges
  that head over the required roster (`CI_REQUIRED_CHECKS`), so one green job
  is not a green head. Unset, `SHA` falls back to the local HEAD
  (`mise.toml` `[tasks."checks-green"]`), which may not be the head `land`
  waits on. Exit 3 covers both "no answer yet" and a dead end, so read stdout:
  `checks green: dead-end` means no answer is coming. A superseded head is one,
  because its cancelled siblings under a failed `final` are not a verdict
  (`checks_green.rs`, `a_fanin_failure_over_cancelled_siblings_is_no_verdict`).
  For a red run, `mise exec -- gh run list --commit <sha>` names that head's
  workflow runs, and `mise exec -- gh run view <id> --log-failed` reads one; a
  check-run id from the check-runs API is not a workflow-run id.
- Never echo a credential. Check presence with `${VAR:+SET}` — never a bare
  `$VAR` or a `${VAR:-…}` that expands the value into the transcript.
- **`${VAR:+SET}${VAR:-UNSET}` LEAKS THE VALUE, and it reads as safe.** Measured
  2026-09-10: it printed a live `ghp_` PAT into a session transcript. `:-`
  substitutes only when the variable is UNSET or empty, so when it is set the
  second half expands the credential. The concatenated "report either way" form
  is the trap; `${VAR:+SET}` alone is the whole check.

## Transparent TLS interception — tools that carry their own CA roots

Egress TLS is intercepted at the network layer, **not** by the `HTTPS_PROXY` env
var. Every connection presents a certificate issued by `O = Anthropic, CN =
Egress Gateway ... CA`, and unsetting `HTTPS_PROXY` or adding a host to `NO_PROXY`
changes nothing **for the certificate** — those only steer tools that _read_ the
vars, and the interception is below that layer.

**THAT IS ABOUT THE CERTIFICATE ONLY.** TLS is intercepted on every route and the
CA is the same on every route, but who answers is not: proxied, the proxy
answers GitHub with its own credential and its own scope (§"The core fact").
Interception is not authorization. Verify the issuer in one line:

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

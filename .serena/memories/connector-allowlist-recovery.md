# Recovering when a claude.ai connector's tools stop being auto-approved

Read when: a connector's tool calls (Linear, Gmail, Xero) start being denied or
prompting, a connector's tools vanish from the listing and reappear under a
different name, or the tool prefix looks unfamiliar (`mcp__<uuid>__*` rather
than `mcp__Linear__*`).

**This is not currently broken.** It is armed for the next time it is, because
the diagnosis took a full session to reach and none of that survives a container.
Do not "fix" a healthy session against this memory.

## What happens

A connector is exposed under **more than one name over its lifetime**, and an
allow rule can only name one at a time:

- `mcp__Linear__*` — the readable alias, what a fresh session usually gets.
- `mcp__4db58e41-…__*` — the connector's UUID, after a mid-session re-register.
- `mcp__claude_ai_Linear__*` — the local-CLI form (its own built-in allowlist
  carries `mcp__claude_ai_Slack__slack_send_message`).

Measured: **the flip is bidirectional.** One session went readable → UUID →
readable. So there is no monotone boundary to reason about — an allowlist
naming only one form is correct during whichever episodes land on it and denies
everything during the others. **Intermittent success is expected, and "it works
now" is never evidence that it is fixed.** A fresh session that has not
reconnected exercises only the case that was never broken.

The failure is silent to the agent: an agent cannot observe its own approval
prompts. What it observes is a denial on the call, or nothing at all.

**There is a third state, and it reads as an unauthorized connector.** The tools
can be absent _entirely_ — no prefix of any form in the listing — while the host
separately reports the server as needing authentication. Measured 2026-08-10 in
one container: absent-with-auth-notice → readable `mcp__Linear__*` with all 58
tools working → UUID-form with all 58 still working, the auth notice reappearing
_alongside_ the working tools. Three episodes, ~40 minutes, no reconnect the
session initiated and no user action it could observe.

Two consequences, both learned the expensive way in that session:

- **Absent tools are not evidence of a missing grant.** The agent concluded
  Linear needed authorizing and told the user so; the connector had been
  authorized throughout. From inside, "not authorized" and "mid-re-registration"
  produce identical observations, so **do not report an auth gap from absent
  tools alone** — say the tools are not currently exposed, and re-check.
- **Step 1 below does not discriminate.** The injected config listed the server
  identically in every episode — same UUID key, same url, same headers — so
  reading it proves the connector is _registered_, never that its tools are
  _reachable_. It answers "what must an allow rule name", which is a different
  question from "why can I not call this".

And because the flip can happen mid-session, **anything that resolves a tool
name once and caches it for the session is wrong for part of that session by
construction** — including an allow rule written at startup, which is what
CLOUD-191 proposes. Re-search for the tool rather than remembering its name.

## Recovering, in order

1. **Find the live names.** The host writes its injected MCP config to
   `/tmp/mcp-config-cse_<session>.json`, keyed by connector **UUID** — the
   readable name is a display alias over it. Read the `mcpServers` keys; that is
   the ground truth for what an allow rule must name. Print key names only, never
   values (rule 4).
2. **Allow the live name at user level**, `~/.claude/settings.json` — e.g.
   `"mcp__<uuid>"`. Verified to work: calls denied before the entry succeeded
   after it, in one session, nothing else changed.
3. **Never commit the UUID.** It is account-specific and rule 1 keeps it out of
   tracked files. The repo's `.claude/settings.json` carries the portable names
   only.
4. **Record the observation** on CLOUD-178 (live connector keys, which form the
   tool names took, whether the call succeeded or was denied). That series is
   the only way the trigger gets identified, and no container keeps it.

Step 2 does not persist — the container is reclaimed. That is the whole problem,
and CLOUD-191 is the durable answer: derive the live keys from the injected
config in a `SessionStart` hook, so nothing account-specific is stored anywhere.

## When the absent-tools episode hits a LANDING session (2026-08-20)

The third state above, met again and costed. What is new is the coupling, the
dead ends, and the fact that **this memory existed and was not read** — the
session rediscovered its content by experiment, which is the failure `mem:core`'s
routing exists to prevent. Route here from the trigger, do not re-derive.

**It stalls the whole lifecycle, not just the board.** `claim-check` is a pure
function of a `get_issue` payload, so with no callable connector there is no
receipt; `verify` then refuses (`claim <branch> missing`) before it runs a single
gate, and `land` cannot start. A connector blip becomes an unlandable branch.
Commit and push and open the draft PR anyway — that work survives, and a session
whose tools bind can mint the receipt and land it unchanged.

**Forms that are NOT candidates**, so nobody spends turns on them again. The
injected config's server entry carries three ids; only the key is a tool prefix.

- key / `toolbox_mcp_server_id` — `4db58e41-…`, the documented UUID form
- `mcp_server_id` — `8e7891d1-…`, in the url query. Never a tool prefix.
- `directoryUuid` from `ListConnectors` — `fa50c30c-…`. Never a tool prefix.

Also not candidates: lowercase `mcp__linear__*`.

**Two dead ends, both tried:**

- `claude mcp add --transport http linear https://mcp.linear.app/mcp` registers
  fine and then reports `! Needs authentication` forever: the OAuth flow needs a
  browser redirect to a localhost callback, which a remote container has no way
  to complete. It is not a workaround, it is a second broken server.
- Replaying the injected config's `headers` against its endpoint by hand is
  **blocked by the auto-mode classifier**, correctly — it is credential replay.
  Do not route around it.

**What NOT to say to the user.** They are usually running several sessions and
the others are fine, so "the connector is not attached" is both wrong and reads
as blaming their setup. The true statement is narrower: _the config injected it
with all its tools; this session did not bind them._ `ListMcpResourcesTool`
(resources, not tools) and `claude mcp list` (CLI config, not connectors) prove
NOTHING here — the only evidence is a call returning "No such tool available".

**Sensor gap, unfiled because the tracker is the unreachable thing.** Both
`mcp-attach-check` and `mcp-allow-check` pass green through this. Neither
compares the injected config's `tools[].name` against the tools the session can
actually call, which is the one comparison that catches it — and
`connector-allow-resolve` already reads that file, so only the predicate is
missing. Recorded in PR #575's body; wants a row of its own.

## What is NOT known

- **What causes the flip.** No hypothesis is supported by evidence yet.
- **Whether a `SessionStart` hook's settings write affects the session that is
  starting**, or only the next one. Permissions are read at startup and the hook
  runs at startup; the ordering is unmeasured. Measure it, do not assume it.
- **Whether the UUID survives an OAuth re-grant.** Stable across two containers
  is not stable across a re-grant.

## Traps this cost a session

- An org-level `ask` control on a connector overrides allow rules in every
  permission mode. That was a _separate_, already-cleared defect. Do not send
  someone to check it again — it masked this one and is not this one.
- The claude.ai per-connector "Always" toggle governs claude.ai chats. It grants
  nothing locally.
- **A gate can be green while the connector is unreachable.** `mcp-allow-check`
  passed throughout the session where writes were denied, because it was
  checking a name nothing was using. A gate over settings cannot see which name
  is live; only the injected config can.

Board: CLOUD-178 (the defect and its measurements), CLOUD-191 (the self-healing
hook), CLOUD-186 (the board automation's one-PR-per-issue assumption).

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

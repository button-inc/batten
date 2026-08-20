# Host hook payloads (CLOUD-44)

One `PreToolUse`-equivalent payload per supported host, each denying the same
mediated call: `gh pr merge 1`.

These are **fixtures, not documentation**. Their field names and event spellings
come from the M1 harness capability matrix (CLOUD-209), which fetched them from
each host's primary docs on 2026-08-07/08 and then re-verified every claim in an
adversarial pass. The survey's own instruction is why they are checked in rather
than reconstructed: _"model memory of this space is badly stale … anything
re-derived without a fetch should be assumed wrong."_ A fixture pins what was
measured, so a later edit has to argue with a recorded observation instead of a
recollection.

Every one of these normalizes to the **same** envelope — that is what
`tests/cli.rs`'s host matrix asserts. The differences below are exactly the
translation surface the shims exist for:

| Host        | Event spelling         | Tool key    | Args key      | Session key       |
| ----------- | ---------------------- | ----------- | ------------- | ----------------- |
| claude-code | `PreToolUse`           | `tool_name` | `tool_input`  | `session_id`      |
| codex-cli   | `PreToolUse`           | `tool_name` | `tool_input`  | `session_id`      |
| copilot-cli | `PreToolUse`           | `tool_name` | `tool_input`  | `session_id`      |
| gemini-cli  | `BeforeTool`           | `tool_name` | `tool_input`  | `session_id`      |
| cursor      | `beforeShellExecution` | _(derived)_ | _(top level)_ | `conversation_id` |

`copilot-cli` is registered in its **PascalCase** dialect deliberately: the
camelCase one omits the event name entirely, and an adapter that cannot read the
event cannot dispatch on it.

`cursor-bom.json` is the same Cursor payload with a leading UTF-8 BOM — the
Windows shape that broke strict parsers and, staff-confirmed, silently degraded
guards to allow-all. It must decode identically.

## The write matrix (CLOUD-779)

`*-write.json` is the second row of fixtures: one write-shaped call per host,
each **in that host's own spelling**, all naming the same path. They exist
because the tool layer had no neutral vocabulary — `Envelope` normalized the
shape of a call and not the word for it — so a gate keyed on a tool name was a
gate against one host.

| Host        | Its word for "write this file" | On `main`, 2026-08-20 |
| ----------- | ------------------------------ | --------------------- |
| claude-code | `Write`                        | refused               |
| cursor      | `write`                        | **allowed**           |
| gemini-cli  | `WriteFile`                    | **allowed**           |
| copilot-cli | `StrReplaceEditor`             | **allowed**           |
| codex-cli   | `NotebookEdit`                 | refused               |

The three allows were measured against a `[[verb]]` table naming Claude Code's
four write tools — the table a consumer actually writes. Nothing reported them,
because a rule that matches nothing is indistinguishable from a rule with nothing
to match. `Envelope::operation` is the neutral layer that closes them, and
`raw_tool` is where the host's own word stays addressable.

`cursor-shell-write.json` is the other half: a `beforeShellExecution` naming no
write target through the tool at all, because its targets live in the command
text. It is `Operation::Execute`, and the same gate judges it — which is what
stops the shell path and the tool path from being two implementations that drift.

The spellings come from `Harness::write_tools`, which is the M1 survey's output,
not from re-derivation. There is no `exit-code` fixture here for the same reason
there is none above: it is a contract, not a host.

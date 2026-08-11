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

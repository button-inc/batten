# Memory Maintenance

## Discovery Model

- Core principle: progressive discovery through references, building a graph of memories.
- Initially, agents are provided with the list of all memories (names only).
- Agents should read `mem:core` as the top-level entry point (graph root).
  This memory should contain references to other memories covering major project domains.
  The referenced memories shall, in turn, shall contain references to even more specific memories, and so on.
  The depth of the graph shall depend on the project complexity.
- Use topics/folders to group related memories in order to make the content structure explicit.
  Folders can mirror project structure (e.g. modules like frontend/backend) or topics like debugging, architecture, etc.
- Memory references must use a mem: prefix inside backticks, e.g. `mem:frontend/core`.
  The surrounding text should clearly indicate when to read the memory/which content to expect.
  The text should provide more precise guidance than the memory name alone,
  i.e. avoid a reference like "frontend debugging: `mem:frontend/debugging` and instead make clear which aspects of frontend debugging are covered.
- Memories themselves should not contain information about when to read them; this is the responsibility of the referring memory.

## Style

Dense agent notes, not prose docs. Prefer invariants, terse bullets.
Avoid obvious context, rationale, and examples unless they prevent likely mistakes.
Keep guidance durable and generalizable, not task-local.

## Add/update threshold

Add or update memories only with stable, non-obvious project conventions that avoid complex rediscovery in the future.
Do not add: quick-read facts; generic language/framework knowledge; one-off task notes; volatile line-level details; behavior likely to change soon.

## Memories are formatted, and the Serena tools do not format them

`.serena/memories/*.md` are in prettier's glob, and the `hk` gate checks them.
The Serena write/edit tools do **not** run prettier, so a memory edit leaves the
tree unformatted and the next `verify` fails on it.

**Edit memories BEFORE `mise run fmt` where you can — but the ordering is a
convenience now, not a cost.** Measured twice in one session (CLOUD-50,
CLOUD-51): both times the memory edit landed after the format run, both times
`verify` failed on `prettier --check` several minutes in, and on the second one
it cost a whole `land` lap. Re-running `fmt` is what that ordering was avoiding.

**THE PREMISE UNDER THAT ADVICE WAS FALSE FOR ITS WHOLE LIFE, AND IS TRUE NOW**
(CLOUD-681). `fmt` is `hk fix --all`, and hk runs a step's CHECK when the step
declares no fixer — so with all three hooks sharing one list, a format pass ran
58 steps of which 7 were fixers, `test:bats` and the cargo build included.
Measured before and after on one machine: **931s → 2s**. So the guidance this
section used to give — reach for `mise exec -- prettier --write <file>` as "the
cheap fix, seconds against a ~3.5-minute `verify`" — was recommending a
single-file escape from an operation that was itself fifteen minutes of gate,
which is the exact trap it existed to help a reader avoid. Just run `mise run
fmt`; it is seconds, and it formats whatever else you touched.

The ordering advice survives for a smaller reason: a memory edited after the
format run still leaves the tree unformatted, and noticing that at `verify` is
later than noticing it now.

## Maintenance Actions

- Renaming memories: References are updated automatically if handled via Serena's memory rename tool.
- Checking for stale memories (e.g. after deletion): Call `serena memories check` for a report.

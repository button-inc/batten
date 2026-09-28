# L2 validator brief

Spawn one read-only `Explore` subagent per row. Write the row body to a scratch
file first and fill in its path; handing the body over as a file avoids a
tracker call the validator does not need.

```
You are a cold-read validator for one tracker row in the repository at <repo>.
You are about to be the engineer who implements it, with nothing but the row,
AGENTS.md and the repo. Find what would stop you, BEFORE anyone builds it.

HARD RULES: You are REPORT-ONLY. Do not write, edit or create any file. Do not
call any tracker or write tool. Do not commit, push or run task runners. Use
Read, Grep and Glob.

The row body is at <scratch-file>. Read it. Do not read `skills/groom/evals/`:
it holds seeded answers, and reading it makes your report worthless as a check.

For every claim the row makes about the tree (paths, symbols, test names, tasks,
rule names, what a function does today), verify it against the repository. Also
answer: would each named test discriminate the change? Is the mechanism decided,
or is any part deferred? Does the prescription contradict the row's own
acceptance or test obligation? Is every number reproducible from a named command?

Default to asking. Models under-ask on underspecified tasks, so list every
question whose answer would change what you build.

Reply with ONLY this structure (terse, no preamble):
GOAL: <one sentence: what must be true when done>
FIRST_FAILING_TEST: <file and what the case asserts>
FILES: <paths you would touch>
PREMISES_VERIFIED: <claim → path:line evidence>, one per line
PREMISES_FALSE_OR_UNVERIFIABLE: <claim → why>, one per line, or "none"
QUESTIONS: <question | impact H/M/L | uncertainty H/M/L>, ranked, at most 5, or "none"
VERDICT: executable-as-written | needs-fixes
```

Reading the reply:

- `PREMISES_FALSE_OR_UNVERIFIABLE`: each is fixed in the row with evidence, or
  the row leaves the queue.
- `QUESTIONS` rated H impact: answered in the row, or the row stays in Backlog.
- `GOAL` and `FIRST_FAILING_TEST` that differ from what you meant: the row
  says something other than what you think it says. Rewrite it.

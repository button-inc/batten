# Refusal shapes measured 2026-09-26/28 (CLOUD-1916…1960), each with its route

Each cost at least one refused call before the route was found. Read the refusal
token, take the route; never hunt for a spelling that slips past.

| Refusal                                | Shape that trips it                                                                             | Route                                                                                                                                                                    |
| -------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tool select other`                    | `grep`/`sed`/`ls`/`wc`/`find`/`tail` on a repo or `target/` path, Read on `.serena/memories/**` | Grep/Read; a scratchpad `python3` script; `read_memory`                                                                                                                  |
| `redirect write unread`                | `>file 2>&1` on a backgrounded call                                                             | drop it; the harness file is the log                                                                                                                                     |
| `task run blocked`                     | the word `mise` in a foreground call (even `mise -n`, even inside a `python3 -c` string)        | `run_in_background`                                                                                                                                                      |
| `receipt read other … turn mint ahead` | Edit/Write after a rebase or replay moved HEAD                                                  | for an unprotected path, a `python3` write in Bash; the receipt is re-minted by the next `verify`                                                                        |
| `claim read unread`                    | the first edit on a fresh branch                                                                | file/groom the row, `get_issue` via `batten mcp call`, pipe `capture find` to `mise run claim-check` (Todo first)                                                        |
| `path write refused`                   | `batten.toml`, `policy/**`                                                                      | ONE `override request`+`spend` pair per edit, inline — a scratchpad wrapper script is refused `program-unknown`                                                          |
| `rule-removed` (config-lint)           | renaming a `[[rule]]` id                                                                        | a new row + module, never a rename; admitting a weakening needs the groomed body AND a trailer on an EARLIER commit, so pre-commit can never admit it in the same commit |
| `pending subject`                      | a `:` in the conventional-commit scope, e.g. `fix(test:cargo)`                                  | `fix(tasks): …`; the pointer is not a verdict token (CLOUD-1960)                                                                                                         |
| `diff ship early`                      | a comment-only diff (a `#MUTANT` line counts)                                                   | carry it on the next change's PR                                                                                                                                         |

Four that pass the hook and fail later — green until measured:

- **A `#MUTANT` row is split on `|`.** A sed carrying `||` reads as five fields and
  sweeps `malformed-row`: the mutation never ran. Use `[[:punct:]][[:punct:]]`. A
  `task-` gate sweeps only with `MUTANT_TASKS=mise.toml`; run
  `MUTANT_TASKS=mise.toml MUTANT_GATES=<gate> batten mutate sweep` before
  claiming a mutant is caught.
- **A `[[rule]]` spelled as a verdict must be its sole raiser**; a module raising
  two verdicts needs a row id that is neither.
- **`policy test` loads each module as its own bundle**, so an
  `import data.batten.<other>` resolves to nothing and every case goes silent.
  Copy.
- **`with data.batten.patterns as X` replaces the whole map**, dropping the
  `md-*` patterns a scrub reads. Bind one key:
  `with data.batten.patterns["<id>"] as …`.

And one that is a posture, not a refusal: **never call `unsubscribe_pr_activity`
by hand** — the connector marks it `always_ask`, so it stops the human, and
`land`'s entry gate drops the subscription itself.

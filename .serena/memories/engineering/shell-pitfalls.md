# Shell pitfalls that fail green

Two constructs that read as correct, pass their own tests, and decide the wrong
way on another machine or under load. Both have a gate in the shared hk `gate`.

## Never hand awk a regex through `-v`

The value is escape-processed by the assignment before awk sees it as a pattern,
and what that does to a backslash is **undefined across implementations**: gawk
strips `\(` to `(` with a warning, mawk keeps it. The same pattern is a literal
paren on one machine and a capturing group on the other.

`ready-lint` matched its §8 label that way. Green on mawk here, matching
**nothing** on the gawk CI runner — so the clause that catches a blocker claimed
without a relation went back to passing silently, and three tests that predated
the change went red with it. **A gate that cannot match its own label does not
fail; it passes.**

Two consequences worth keeping:

- **Local green is not evidence** when the two environments run different
  implementations of the same tool. This machine has mawk; the runner has gawk,
  and neither is wrong — the case is undefined.
- The fix is a split, not a workaround: let `grep` find what the pattern matches,
  and let awk work in **literal** patterns; or inline the regex in the awk
  program, where no assignment processing happens.

Mechanism: `mise run awk-regex-check` (in the shared hk `gate`) reports a `-v`
name the program then uses in regex position — `~ name` or `match(…, name)`.
The predicate is the **use**, not the value: a literal without a backslash is
safe today and unsafe the moment someone adds one, and a variable's runtime
content is invisible to any static check. `-v` for a plain value — compared with
`==`, printed, counted — stays fine and is most of its use.

## Never pipe a producer into an early-exiting `grep` under `pipefail`

`producer | grep -q P` can report **failure on a match**. grep exits at the
first hit; a producer still writing dies of SIGPIPE, and `pipefail` promotes 141
to the pipeline's status. Same for `-l` (stops at the first matching file) and
`-m N`.

It is a **race**, and that is what makes it survive review: whether the producer
is still writing when grep exits depends on output size and scheduling. Measured
here on a two-commit `git log` range — 2 failures in 300 runs. A large producer
loses nearly always; a small one loses rarely, passes every test written for it,
and misfires months later.

Two instances landed before the class was named, both failing toward the verdict
nobody checks:

- `landed-check` read `git log … | grep -q "$id"` and reported a **clean board**
  over three issues whose refs were on `main`.
- `issue-guard` asked the same way whether any commit names an issue, and
  **denied `gh pr ready`** on a branch whose every commit carried
  `Refs: CLOUD-186` — with a reason asserting the opposite of what it had found.
  The guard blocked its own PR, and the deny was not reproducible afterwards.

The fix needs no new tool: read the producer into a variable and match from a
here-string — `x=$(producer); grep -q P <<<"$x"`. A here-string has no upstream
process, so there is no status to promote.

Mechanism: `mise run pipefail-grep-check` (in the shared hk `gate`), scoped to
files that actually enable `pipefail` and to the early-exiting flags only — a
`| grep` that consumes its whole input is honest. Flag clusters are judged by
their letters (`-qxF` is `-q`), because an enumeration of spellings is what rots.

**Why**

A bot proposed this change and no human refined it, which is exactly the case
CLOUD-693 exists for: the row is derived from the pull request's own manifest
diff so the merge moves the board like any other landing. Nothing here was
authored by an agent, and nothing here is a judgement.

Pull request: #{{pr}} (`{{branch}}`, opened by `{{login}}`).

Manifests touched:

{{manifests}}

**Refinement — Ready**

_Refinement gate: Definition of Ready & Done. This body carries only specializations._

- **Source of truth (§1).** The manifest diff on #{{pr}}. It is the one
  description of this change that cannot disagree with the change, which is why
  nothing here re-types the versions it carries.
- **Computable predicate (§2).** Every required check green on the head SHA,
  decided by `mise run checks-green` — the same predicate that gates every other
  landing, asked of the SHA that fast-forwards.
- **Effect (§3).** No command-surface change: a dependency or toolchain bump
  moves no verb, no flag and no effect row.
- **Output & exit (§5).** Unchanged — this row proposes no new output.
- **Commit / bump (§6).** `{{type}}` → no bump.
- **Test obligation (§7).** The existing suite, unchanged and unskipped: a bump
  whose breakage this repo covers reds CI, and one it does not is a coverage gap
  to file rather than a reason to hold the bump.
- **Blockers (§8).** None.

**Acceptance**

- #{{pr}} lands on `main` by fast-forward with every required check green,
  through `auto-bot-land.yml` and with no human in the loop.
- This row moves to In Review by the merge, from the `Closes` key in the pull
  request body.

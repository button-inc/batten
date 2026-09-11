# Decision records: git is the amendment history

Read when: recording an architectural decision, or about to add a `status:`,
`superseded-by:`, `-v2`, `-amended` or "see the current version" pointer to any
document in this repository.

## The rule

**A reader must see only the current correct state of the world.**

- **One file per decision, always rewritten in place.** Never a chain.
- **`git log` / `git blame` is the amendment history**, reachable only by
  explicitly spelunking. History exists, costs nothing to keep, and is invisible
  until asked for. Git already does versioned-document-with-history better than
  any convention layered on top.
- **No `status: superseded` field**, because a live file is the only kind there
  is. A decision that no longer holds is a file that no longer says it.
- **A gate, or it is not a process**: no decision record may carry a supersession
  marker, a version suffix in its filename, or a pointer to another record "for
  the current version."

## Why, measured

Superseded documents, `-amended` suffixes and a folder of near-duplicates make a
doc tree **actively worse than no doc tree**: a reader cannot tell which file is
live, and an agent will confidently quote the dead one. In one 2026-09-10 session
this shape cost two wrong conclusions before the pattern was named — see
`mem:evidence-hierarchy`.

## Home

`.serena/memories/decision/<slug>`, beside the operational memories.

Chosen because it needs **no change to non-negotiable rule 7** (`no-docs-tree`
fails a tracked `docs/` path and sends research to the tracker), and because that
directory is already checked in, already read on demand, and already the surface
a future session loads. Routing is `mem:core`'s existing table — the mechanism in
use, not a second one invented alongside it.

Writes go through Serena's memory tools; `protected-mutation` denies every other
route, and `rename_memory` is the only one that rewrites `mem:` referrers.

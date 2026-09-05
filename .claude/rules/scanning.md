---
paths:
  - "crates/**/*.rs"
  - "mise-tasks/*"
  - "tests/*.bats"
  - "hk.pkl"
  - ".github/workflows/*.yml"
---

# Moved to `rules/scanning.md`

**The authority is [`rules/scanning.md`](../../rules/scanning.md). This file is a
pointer and carries no rule of its own.**

Batten adjudicates for six harnesses (`Harness`, `crates/batten/src/hook.rs`) and
five of them cannot read this directory. The doctrine therefore lives at the
repository root, where `AGENTS.md` — itself neutral, with `CLAUDE.md` a symlink to
it — routes every harness to it in one hop.

What stays here is the vendor-specific half and nothing else: the frontmatter
above is Claude Code's own `paths:` trigger, which is a loading mechanism no
neutral location has. It fires on the same paths it always did and sends the
reader one file further. Deleting this file would cost that trigger; putting the
rule back in it would cost the other five harnesses (CLOUD-1152).

# Harness configuration: decided for every harness, registered by batten

These load when you write a harness's own configuration — `.claude/settings*.json`,
`.cursor/hooks.json`, `.github/hooks/*.json`, `.gemini/settings.json`,
`.codex/hooks.json`, in the tree or under `$HOME` — or are about to link or copy
one somewhere else.

## Making each harness work is vendor-specific; batten behaving the same on all of them is not

Batten adjudicates for six harnesses (`Harness`, `crates/batten/src/hook.rs`). A
stall repaired in one harness's config file — a permission grant that does not
bind, a hook that does not fire — is rarely a property of that harness, and the
repair reaches only the harness whose file it touched. The other five keep
paying, silently.

**A change to one harness's config is incomplete until it is applied to the
analogous surface on the others, or scoped to one on purpose with the reason
stated** — the way the `.claude/rules/*.md` stubs state theirs. Making the six
permission models equivalent is NOT the demand: they are not, and batten does not
own them. The demand is that the change to one is _decided_ about the others.

This is the CLOUD-1152 shape one surface over. Doctrine moved to the root because
five harnesses cannot read `.claude/`; config has no root, so the discipline is a
decision recorded per change rather than a location.

## The mechanism

`[[pattern]]` rows `harness-config-<harness>` in `batten.toml` declare each
harness's configuration surface. `config_check::handler::validate_harness_surfaces` refuses the family at
load when it leaves out a harness that keeps its registration in a file, so a new
harness cannot rot behind it. Four mediated-call modules read the family, one
class each, because the boundary speaks a module's first violation only:

| class               | module                                | severity | says                                                                     |
| ------------------- | ------------------------------------- | -------- | ------------------------------------------------------------------------ |
| `hook wire wrong`   | `policy/harness-config-route.rego`    | deny     | a linked, copied or hand-written hook registration: run the verb below   |
| `hook edit early`   | `policy/harness-config-advisory.rego` | warn     | a Claude Code settings write: the host's `update-config` skill first     |
| `grant edit early`  | `policy/harness-grant-advisory.rego`  | warn     | a permission list changed: `mem:serena-setup` owns the forms that bind   |
| `hook edit partial` | `policy/harness-config-neutral.rego`  | warn     | the harnesses whose declared surface the call did not reach, as subjects |

## A hook registration is batten's to write

**Never link, copy or hand-write batten's hook registration into a harness
surface.** Run `batten startup --repair` from the directory being registered; it
writes the registration there (CLOUD-2752). A symlink points at one checkout's
file and outlives it; a copy is a second authority nothing reconciles. Measured
2026-11-24: a resumed container rooted the session outside the checkout, no hook
ran for seven hours, and the repair was a symlink and then a hand copy. The
refusal names the verb so the route is a literal, not a judgement.

The refusal is decided by **what lands** on a surface, never by how the source
is spelled: `cat <cs> > <rs>`, `cat <cs> | tee <rs>`, `git show HEAD:<cs> >
<rs>`, a relative or `$PWD` source behind a `cd`, a whole `.claude` directory
copied or linked, and any of them inside `sh -c` are all a registration when the
content arriving registers the hook. A copy whose content registers none (a
permissions-only `settings.local.json`) is not. A write tool is refused only when
it ADDS a registration: an edit of a surface that already registers the hook and
keeps it changes something else, and the vendor route is that edit's route.

## What this does not gate

`hook edit partial` reports; it never requires the other harnesses to change in
the same commit. A harness with no surveyed vendor route (every one but Claude
Code today) gets the neutrality line and no vendor pointer: the route is unknown,
not absent. Shell writes are read from `input.call["write-targets"]` — a
redirection, `tee`, and the destination of `ln`/`cp`/`mv`/`install`, a shell's
`-c` script included — so a write through any other program is not seen, and
what a redirect receives is read only from `cat`, `git show`, `echo` and
`printf`: content from any other producer is unread, and an unread copy falls
back to its spelling.

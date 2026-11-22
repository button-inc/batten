---
name: crate-split
description: Cutting a set of modules out of a large Rust crate into its own workspace package, along a level boundary, with every path respelled and no re-export shim — choosing the set, running `cut-crate`, declaring the new crate's allowed reach, and landing it. Use when a crate is being split, when a module set should become its own crate, when CLOUD-2799/2800/2801 or any crate cut is picked up, or when a build is slow because one crate holds everything.
---

# Crate split: a cut along a level, gated, then landed

A crate boundary is the one dependency rule the compiler enforces: a module
cycle inside a crate is legal, a cycle between crates is not. So a cut is worth
making only where it stops edges from coming back, and the most important
property of a crate is which crates it does **not** (transitively) depend on
(Kladov, _Fast Rust Builds_). Build parallelism and incremental cost follow from
that, never the other way round.

## The loop

Copy this checklist per cut and tick it:

```
Cut <name> from <package>:
- [ ] 1 choose a candidate set below the cycle
- [ ] 2 run cut-crate; grow or shrink the set until it is not refused
- [ ] 3 read the remainder; respell each site by hand
- [ ] 4 declare the new crate's reach (crate-allow pattern)
- [ ] 5 build, test, lint the workspace; tighten the ratchets
- [ ] 6 commit, push, land
```

### 1. Choose a set below the cycle

A cut is legal only along a level boundary: a component's level is one more
than the highest level of what it uses (Lakos, _Large-Scale C++ Software
Design_, §1.10). In practice: start from modules that use no other module of
the crate (leaves), then add only what they use. `batten modules metrics`
reports each crate's largest cycle; a candidate set must not intersect it.
The codemods example reads the same graph as Lakos levels and as the edges
whose cut shrinks the largest cycle most:
`mise exec -- cargo run -q -p batten-codemods --example codemod -- levels
crates/<package>/src` and `… -- suggest crates/<package>/src 20`. Modules on
the lowest levels, outside the cycle, are the first candidates.

Prefer a set that **owns a domain with its behaviour** (the gix layout: one
crate per concept, types and the functions over them together) over a set that
is "everything below some line". A crate of bare types with the behaviour left
above it moves the coupling, it does not cut it (CLOUD-2799 rev 2).

### 2. Run `batten modules cut`; the refusal is the closure

```
mise exec -- batten modules cut --dry-run \
  crates/<package> <name> <module> [<module>…]
```

Run it backgrounded at the workspace root. It prints `refused <path>:<line>
crate::<m>` for every site in a moved file that reaches an unmoved module `m`,
and writes nothing (exit 2). Each refusal is the set telling you what it
needs:

- add `m` to the set and run again, **if** `m` is itself below the cycle; or
- drop the module that reaches it, and cut it in a later, higher crate.

A set is closed when the run is not refused; `--dry-run` then lists each path
the cut writes or removes, and the same command without it applies the cut. Never break the edge with a
`pub use` back into the old crate: that is the shim CLOUD-2793 retires, and a
new crate depending on the crate it was cut from is the cycle the cut exists
to prevent.

### 3. Read the remainder

A successful run prints `remainder <path>:<line>` for each site it could not
respell: a use group mixing moved and unmoved modules (`use crate::{a, c}`), or
a file the parser rejected. Split each group by hand. The count reaches zero
before you build.

What the respell sees: every `crate::m` in the package and `<old>::m`
elsewhere, in code and inside macro token trees, never in comments or strings.
It does not see a path built from pieces by a macro, or a rustdoc intra-doc
link in prose; `cargo doc` and `cargo check` find those.

### 4. Declare the new crate's reach

The `crate reach wrong` rule (`policy/crate-reach.rego`, CLOUD-2798) refuses a
package with no `crate-allow-<name>` pattern in `batten.toml`, and a reached
workspace package its pattern does not admit. Add the new package's row (an
anchored regex over the member names it may reach, `^$` for none) and widen
the rows of the packages that now reach it. The row is the reviewable record
of the cut; `mise run crate-reach-record` then `batten check --rule 'crate
reach wrong'` proves the graph matches it.

### 5. Build, test, lint, ratchet

`cargo check --workspace --all-targets`, then the full suite, then clippy. An
unused dependency the cut left in the old package is removed now. A
`modules ratchet` that reports a crate scoring **better** is tightened
(`env BATTEN_BIN=batten mise run -q modules-ratchet`) and committed with the
cut; one reporting **worse** means the cut added an edge, so go back to step 2.

### 6. Land

One commit per cut: the move, the respell, the manifests, the reach row, the
tightened lock. Push, then `mise run land`.

## Doing it badly

- **A `pub use` per moved module** "so nothing breaks": the shim, and the
  coupling stays where it was.
- **Cutting types away from their behaviour**: the new crate is a vocabulary
  every caller still needs the old crate to use.
- **A text replace of `crate::m`**: rewrites comments and strings, and misses
  `assert!(crate::m::x())`, where the lexer splits `::` into two `:` tokens.
- **Skipping the reach row**: the next `Cargo.toml` edit can turn the wide
  graph back into a deep one, and nothing says so.

## Prior art

- Aleksey Kladov, _Large Rust Workspaces_ and _Fast Rust Builds_: flat
  `crates/*`, one crate per concept, depth is what costs build time.
- rust-analyzer's `ARCHITECTURE.md`: each crate's API boundary is written down,
  and lower crates never name higher ones.
- John Lakos, _Large-Scale C++ Software Design_ §1.10 and _Large-Scale C++
  Volume I_ §3.7: levelization, and cumulative component dependency as the
  measure a cut lowers.
- Alexis King, _Parse, don't validate_: a crate's types carry the invariant its
  behaviour relies on, which is why they move together.

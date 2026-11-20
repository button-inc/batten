---
name: codemod
description: Migrating many call sites at once with a lossless Rust codemod instead of one edit per site — when a mechanical rewrite spans more than a handful of files, how to drive `crate::codemod` in one pass, what it can and cannot see, and the gate that keeps the migrated form from regrowing. Use when a change is "replace X with Y everywhere", when a count of sites is above ~10, or when about to make the same Edit for the third time.
---

# Codemods: one pass, counted, then gated

A migration of N sites by hand is N tool calls, N chances to miss one, and no
proof the count reached zero. A codemod is one program, one run, and a number.
The substrate is `crates/batten-base/src/codemod.rs` (CLOUD-1580): `ra_ap_syntax`'s
lossless tree, so every byte outside an edit prints back identical, and a file
the parser rejects is **could-not-look**, never silently skipped.

## When to reach for it

- The same Edit is about to be made a third time.
- `Grep` counts more than ~10 sites of one shape.
- The shape is syntactic: a method name, a call path, an attribute. If the
  change needs a judgement per site, it is not a codemod.

## The loop

1. **Test first, on a fixture built to break a splicer.** In
   `crates/batten/tests/it/codemod.rs`, put the target spelling inside a string,
   a comment, a `use`, a longer path (`x::fs::read`), a method of the same name
   and a macro argument — before the real call. Assert the real call changes
   and every decoy is kept byte-for-byte. A text replace must fail this test.
2. **Add the primitive to `codemod.rs` if none fits.** Existing ones:
   `rename_method_calls` (method name), `redirect_calls` (call callee path,
   including inside macro token trees), `ensure_use` (a top-level import,
   once). Pure: text in, text out.
3. **Write the migration as a RECIPE**, never a throwaway driver: a named entry
   in `batten_codemods::RECIPES` (`crates/batten-codemods`, never released) (its edition, the files it skips, and an
   `apply` built only from primitives). Every migration this repository runs
   is kept: it is the shape of a codemod a consumer runs from a preset, and
   the tree it already migrated is its regression test.
4. **Run it backgrounded** through the pinned toolchain (`mise exec -- cargo
run --release -q -p batten-codemods --example codemod -- <recipe>`), which walks the
   tree once, writes only changed files and prints `files read, rewritten,
refused` and nothing else. Then count what is left with `Grep`. The
   remainder is the codemod's blind spot: read each one. **Run it a second
   time: it must rewrite 0 files.** A recipe that is not idempotent on its own
   output is not finished.
5. **Clean the fallout mechanically.** `mise exec -- cargo clippy --fix
--allow-dirty --workspace --all-targets` removes imports the rewrite
   orphaned, then `cargo fmt`. **Watch the cfg split**: clippy fixes the lib
   build first, so an import only `#[cfg(test)]` code still used is removed
   and the test build then fails. Re-add it inside `mod tests`, not at the top.
   **Exclude files with a second compilation context.** A file `build.rs`
   includes by `#[path]` (`mutation_markers.rs`) is compiled outside the crate,
   so a `crate::` path there is an edge the layering gate catches.
6. **Keep the recipe, and test it.** The primitive, the recipe and a test of
   the recipe on a decoy fixture all stay; `batten-codemods`' `codemod` example is the one
   driver every recipe shares.
7. **Gate the regrowth.** A migration without a gate decays. Add a
   `non_increasing` ratchet row in `batten.toml` counting the retired shape
   over the migrated glob, so the next write that reintroduces it is refused
   at the call.

## What it can see, and what it cannot

The matcher compares **spellings**, per file, with no name resolution:

| case                                        | seen |
| ------------------------------------------- | ---- |
| `fs::read(p)`, `std::fs::read( p )`         | yes  |
| `assert_eq!(fs::read(p)…)` (macro argument) | yes  |
| `use std::fs as f; f::read(p)`              | no   |
| `use std::fs::read; read(p)`                | no   |
| a path a macro builds from pieces           | no   |

The compiler resolves names in macro arguments only after expanding them. The
semantic route is rust-analyzer's own: load the workspace with
`ra_ap_load_cargo` and match with `ra_ap_ide_ssr`
(`std::fs::read($p) ==>> crate::fsio::read($p)`), which matches by resolved
item and maps hits in expanded macros back to source tokens. It costs seconds
of workspace load and still abstains where a macro synthesises the path. Reach
for it when the spelling remainder is large or aliased; for a remainder of a
few, read them.

## Doing it badly

- **One Edit per site** "to be careful": slower, and it proves no count.
- **`sed` over the tree**: hits comments and strings; the fixture exists to
  show this.
- **Trusting a zero without reading the remainder**: the grep's blind spots
  are the codemod's.
- **A one-off driver deleted after its run**: the migration is lost, and the
  next consumer making the same move writes it again. Save it as a recipe.
- **Landing without the ratchet row.**

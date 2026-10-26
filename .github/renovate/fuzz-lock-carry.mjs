// Carry the root lock's resolution into the fuzz lock across a cargo bump
// (CLOUD-2538).
//
// Renovate runs this as a `postUpgradeTasks` command once per `cargo` branch,
// after it has rewritten the root `Cargo.lock` and before it commits, and
// commits what this writes to `fuzz/Cargo.lock` onto its own branch. The fuzz
// workspace is detached, so the bump never re-resolves it, and
// `the_fuzz_lock_resolves_shared_crates_as_the_root_does` refuses a fuzz pin
// the root lock moved past: without this, every bump of a crate the two locks
// share would land red.
//
//   node .github/renovate/fuzz-lock-carry.mjs
//
// THE ROOT LOCK IS THE SEED, NEVER A FRESH RESOLVE. A blanket `cargo update`
// under `fuzz/` picks each crate's newest version on its own and split
// `unicode-ident` from `unicode-properties`, which `ra-ap-rustc_lexer` refuses
// at compile time. Seeded, cargo keeps every pin the fuzz graph shares, prunes
// what the harness does not reach, and adds only the harness's own crates.

import { copyFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

copyFileSync("Cargo.lock", "fuzz/Cargo.lock");
execFileSync(
  "cargo",
  ["metadata", "--manifest-path", "fuzz/Cargo.toml", "--format-version", "1"],
  { stdio: ["ignore", "ignore", "inherit"] },
);
process.stdout.write("fuzz-lock-carry: fuzz/Cargo.lock re-seeded from Cargo.lock\n");

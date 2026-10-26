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
// what the harness does not reach, and resolves nothing new.
//
// THE HARNESS'S OWN PINS RIDE ALONG. The root lock has no entry for the crates
// only the fuzz harness reaches, so a seed of the root lock alone would have
// cargo re-resolve them to their newest release inside an unrelated bump. The
// old fuzz lock's entries for every name the root lock lacks are kept, so they
// move only when a bump names them.
//
// A FAILED RESOLVE WRITES NOTHING: the old lock is put back, so Renovate never
// commits a half-carried seed.

import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const NAME = /^name = "([^"]+)"$/m;
const nameOf = (block) => block.match(NAME)?.[1];

// A lock's header and its `[[package]]` blocks, in order.
function blocks(text) {
  const [header, ...packages] = text.split(/\n(?=\[\[package\]\]\n)/);
  return { header, packages: packages.map((block) => block.trimEnd()) };
}

// The seed cargo resolves from: the root lock, plus the old fuzz lock's sourced
// entries for every name the root lock does not carry.
export function seed(rootText, fuzzText) {
  const root = blocks(rootText);
  const carried = new Set(root.packages.map(nameOf));
  const kept = blocks(fuzzText).packages.filter(
    (block) => /^source = /m.test(block) && !carried.has(nameOf(block)),
  );
  return `${[root.header.trimEnd(), ...root.packages, ...kept].join("\n\n")}\n`;
}

function cargoResolve(dir) {
  execFileSync(
    "cargo",
    ["update", "--workspace", "--manifest-path", "fuzz/Cargo.toml"],
    { cwd: dir, stdio: ["ignore", "ignore", "inherit"] },
  );
}

export function carry({ dir = ".", resolve = cargoResolve } = {}) {
  const lock = join(dir, "fuzz/Cargo.lock");
  const before = readFileSync(lock, "utf8");
  writeFileSync(lock, seed(readFileSync(join(dir, "Cargo.lock"), "utf8"), before));
  try {
    resolve(dir);
  } catch (error) {
    writeFileSync(lock, before);
    throw error;
  }
  process.stdout.write("fuzz-lock-carry: fuzz/Cargo.lock re-seeded from Cargo.lock\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  carry();
}

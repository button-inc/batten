// Carry a reviewed licence row forward across a GitHub Action bump (CLOUD-2300).
//
// Renovate runs this as a `postUpgradeTasks` command on every `github-actions`
// update, after it has rewritten the pin and before it commits, and commits what
// this writes to `mise-tasks/sbom-actions.tsv` onto its own branch. So the row
// lands in the same pull request as the bump: no second lane, no second PR, and
// nothing written to a bot branch by anyone but the bot.
//
//   node .github/renovate/sbom-carry.mjs <depName> <currentDigest> <newDigest>
//
// THE RULE IS THE TABLE HEADER'S, UNCHANGED: a licence verdict is a person's,
// read from the upstream file, and it carries to a new commit only when every
// licence file at that commit is BYTE-IDENTICAL to the one the verdict was read
// at. Nothing here derives a licence. Anything else — no reviewed row, a licence
// file added, removed or changed, no licence file found at all, a read that
// failed — writes NOTHING, so `pin table missing` stays red on the bump and a
// person reads the file.
//
// THE CANDIDATE SET IS LISTED, NEVER GUESSED. `sbom-actions-currency.yml` probed
// seven fixed names, and `renovatebot/github-action` ships lowercase `license`:
// every probe missed at both commits, and "both absent" read as "identical" — a
// carry with nothing read. Here the commit's own tree is listed, every top-level
// `LICENSE*`, `LICENCE*`, `COPYING*` or `NOTICE*` is compared by blob id, and an
// empty set is "unreviewed", never "identical".

import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const TABLE = "mise-tasks/sbom-actions.tsv";
const PIN = /^[0-9a-f]{40}$/;
const LICENCE = /^(licen[cs]e|copying|notice)([.-].*)?$/i;

function say(line) {
  process.stdout.write(`sbom-carry: ${line}\n`);
}

// The licence files at one commit, as `path -> blob id`, or null when the tree
// could not be read. Blob ids are git's content hashes, so equal ids ARE equal
// bytes, and nothing is downloaded to compare them.
async function licenceFiles(api, repo, sha) {
  const headers = { accept: "application/vnd.github+json" };
  const token = process.env.GITHUB_COM_TOKEN ?? process.env.GITHUB_TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;
  let response;
  try {
    response = await fetch(`${api}/repos/${repo}/git/trees/${sha}`, { headers });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  const tree = await response.json();
  if (!Array.isArray(tree.tree) || tree.truncated) return null;
  const files = new Map();
  for (const entry of tree.tree) {
    if (entry.type === "blob" && LICENCE.test(entry.path)) files.set(entry.path, entry.sha);
  }
  return files;
}

function identical(a, b) {
  if (a.size === 0 || a.size !== b.size) return false;
  for (const [path, blob] of a) if (b.get(path) !== blob) return false;
  return true;
}

const keyOf = (line) => line.split("\t")[0];
const repoOf = (key) => key.split("@")[0].split("/").slice(0, 2).join("/");

// One answer per call, for the caller and the tests: `carried`, `unreviewed`,
// `changed`, `unread` or `skipped`. Only `carried` writes.
export async function carry(depName, current, next, { table = TABLE, api = "https://api.github.com" } = {}) {
  if (!depName || !PIN.test(current ?? "") || !PIN.test(next ?? "")) {
    say("not a digest bump; nothing to carry");
    return "skipped";
  }
  const repo = repoOf(depName);
  const text = readFileSync(table, "utf8");
  const lines = text.split("\n");
  // Every reviewed row for this repository at the old commit: a sub-path action
  // (`actions/cache/restore`) is keyed apart from its repository's root and
  // carries with it, because the licence files are the repository's.
  const reviewed = lines.filter(
    (line) =>
      !line.startsWith("#") &&
      line.split("\t").length >= 3 &&
      keyOf(line).endsWith(`@${current}`) &&
      repoOf(keyOf(line)) === repo,
  );
  if (reviewed.length === 0) {
    say(`${repo}@${current} has no reviewed row; a person must read its licence`);
    return "unreviewed";
  }
  const [before, after] = await Promise.all([licenceFiles(api, repo, current), licenceFiles(api, repo, next)]);
  if (before === null || after === null) {
    say(`${repo}: the licence files could not be listed; nothing carried`);
    return "unread";
  }
  if (before.size === 0 && after.size === 0) {
    say(`${repo}: no licence file at either commit, so there is nothing to compare; a person must read it`);
    return "changed";
  }
  if (!identical(before, after)) {
    say(`${repo}: the licence files differ between ${current} and ${next}; a person must read them`);
    return "changed";
  }
  const present = new Set(lines.map(keyOf));
  const added = reviewed
    .map((line) => line.replace(`@${current}\t`, `@${next}\t`))
    .filter((line) => !present.has(keyOf(line)));
  if (added.length > 0) {
    writeFileSync(table, `${text.replace(/\n*$/, "\n")}${added.join("\n")}\n`);
  }
  say(`${repo}: carried ${added.length} row(s) ${current} -> ${next} (licence files byte-identical)`);
  return "carried";
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const [depName, current, next] = process.argv.slice(2);
  await carry(depName, current, next);
}

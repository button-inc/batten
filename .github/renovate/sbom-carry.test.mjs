// The carry's every answer, against a fixture standing in for GitHub's git-trees
// API (CLOUD-2300). Run by `crates/batten/tests/it/ci_hygiene.rs` so `test:cargo`
// gates it; `node --test .github/renovate/sbom-carry.test.mjs` runs it alone.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { carry } from "./sbom-carry.mjs";

const OLD = "a".repeat(40);
const NEW = "b".repeat(40);

// `trees` maps `owner/repo@sha` to that commit's top-level entries.
async function withForge(trees, body) {
  const server = createServer((request, response) => {
    const match = request.url.match(/^\/repos\/([^/]+\/[^/]+)\/git\/trees\/([0-9a-f]+)$/);
    const tree = match && trees[`${match[1]}@${match[2]}`];
    response.writeHead(tree ? 200 : 404, { "content-type": "application/json" });
    response.end(JSON.stringify(tree ? { tree, truncated: false } : { message: "Not Found" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await body(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

function table(rows) {
  const path = join(mkdtempSync(join(tmpdir(), "sbom-carry-")), "sbom-actions.tsv");
  writeFileSync(path, `# header\n${rows.join("\n")}\n`);
  return path;
}

const blob = (path, sha) => ({ path, type: "blob", sha });
const ROW = `acme/act@${OLD}\tMIT\tCopyright (c) 2020 Acme`;

test("identical licence files carry every reviewed row of the repository", async () => {
  const path = table([ROW, `acme/act/sub@${OLD}\tMIT\tCopyright (c) 2020 Acme`]);
  const same = [blob("LICENSE", "1".repeat(40)), blob("README.md", "2".repeat(40))];
  const answer = await withForge({ [`acme/act@${OLD}`]: same, [`acme/act@${NEW}`]: same }, (api) =>
    carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "carried");
  const text = readFileSync(path, "utf8");
  assert.match(text, new RegExp(`acme/act@${NEW}\tMIT\tCopyright \\(c\\) 2020 Acme`));
  assert.match(text, new RegExp(`acme/act/sub@${NEW}\t`));
  assert.match(text, new RegExp(`acme/act@${OLD}\t`), "the reviewed row is kept");
});

test("a changed licence file writes nothing", async () => {
  const path = table([ROW]);
  const before = readFileSync(path, "utf8");
  const answer = await withForge(
    { [`acme/act@${OLD}`]: [blob("LICENSE", "1".repeat(40))], [`acme/act@${NEW}`]: [blob("LICENSE", "9".repeat(40))] },
    (api) => carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "changed");
  assert.equal(readFileSync(path, "utf8"), before);
});

test("a licence file added at the new commit writes nothing", async () => {
  const path = table([ROW]);
  const old = [blob("LICENSE", "1".repeat(40))];
  const answer = await withForge(
    { [`acme/act@${OLD}`]: old, [`acme/act@${NEW}`]: [...old, blob("NOTICE", "3".repeat(40))] },
    (api) => carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "changed");
});

// THE HOLE THE DAILY JOB HAD: lowercase `license`, missed by a fixed probe list,
// read as "absent at both commits" and so as identical. Here it is listed.
test("a lowercase licence file is found, and a change to it is caught", async () => {
  const path = table([ROW]);
  const answer = await withForge(
    { [`acme/act@${OLD}`]: [blob("license", "1".repeat(40))], [`acme/act@${NEW}`]: [blob("license", "4".repeat(40))] },
    (api) => carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "changed");
});

test("no licence file at either commit is never identical", async () => {
  const path = table([ROW]);
  const readme = [blob("README.md", "2".repeat(40))];
  const answer = await withForge({ [`acme/act@${OLD}`]: readme, [`acme/act@${NEW}`]: readme }, (api) =>
    carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "changed");
});

test("a repository with no reviewed row at the old commit writes nothing", async () => {
  const path = table([`other/act@${OLD}\tMIT\tNONE`]);
  const answer = await withForge({}, (api) => carry("acme/act", OLD, NEW, { table: path, api }));
  assert.equal(answer, "unreviewed");
});

test("a tree that cannot be read writes nothing", async () => {
  const path = table([ROW]);
  const answer = await withForge({ [`acme/act@${OLD}`]: [blob("LICENSE", "1".repeat(40))] }, (api) =>
    carry("acme/act", OLD, NEW, { table: path, api }),
  );
  assert.equal(answer, "unread");
});

test("a bump that is not a digest pin carries nothing", async () => {
  const path = table([ROW]);
  assert.equal(await carry("acme/act", "v1", "v2", { table: path, api: "http://127.0.0.1:9" }), "skipped");
});

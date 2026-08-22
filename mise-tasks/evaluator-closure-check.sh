#!/usr/bin/env bash
#MISE description="Gate: no IO-bearing crate is reachable from the evaluator's node in the resolved dependency graph (CLOUD-831)"
#
# CLOUD-831. `crates/batten/src/policy.rs` admits consumer-authored code to the
# MEDIATED CALL on one claim: a policy module "cannot open a file, start a
# process, or reach the network". That claim is the security boundary the moment
# a module decides a tool call, and until this gate landed it rested on a single
# unenforced line of `Cargo.toml` — `default-features = false`, keeping regorus's
# `http` and `jsonschema` out of the closure.
#
# THE DRIFT IS NOT AN EDIT, which is why a `forbid` row over the manifest text
# would not do. **Cargo unifies features across the graph**: a second crate in
# this workspace, or any dependency, taking `regorus` with default features
# unions them back on — with no edit to the line that states the pin and no diff
# a reviewer of that line would see. A renovate bump that changes regorus's own
# default feature set does the same. So the predicate has to read the RESOLVED
# GRAPH, which is what this does.
#
# ─── THE SCOPE IS THE EVALUATOR'S SUB-CLOSURE, NOT THE WORKSPACE'S ───────────
#
# This is the whole correctness argument and it was measured before it was
# written, because the obvious spelling is wrong. Walking from the workspace
# members instead:
#
#   from `regorus`             41 packages, none of the nine named
#   from the workspace members 281 packages, `globset` AND `jsonschema` present
#
# `jsonschema` and `globset` are DIRECT dependencies of `batten` itself, entering
# by paths that have nothing to do with the evaluator — the schema surface and
# the glob matcher. So the manifest's claim is true and the wider predicate is
# false: it would deny on `main` today, on its first run, forever. Measured over
# the 5 lockfile-touching commits reachable from HEAD, the wider spelling fired
# on all 5 and every firing was a false positive (100%); the predicate shipped
# here fired 0 times, which is the intended state for a supply-chain tripwire
# rather than a detector (CLOUD-751's replay).
#
# Recorded so the wider spelling is not reintroduced as a "simplification".
#
# ─── ACTIVATED EDGES, NOT THE WHOLE RESOLVE ──────────────────────────────────
#
# `macos-link-check` already learned this one the expensive way — see its header
# on `defmt`, an unactivated optional dependency that made it refuse a link
# `darwin-link` then completed. `cargo metadata`'s resolve lists every package
# the resolver CONSIDERED, including optional dependencies nothing turned on.
# Scanning that asks "could some configuration of this tree reach the network"
# where the gate means "does this one".
#
# The activation reading is deliberately IDENTICAL to `macos-link-check`'s, down
# to the weak-dependency rule, because the two gates ask the same structural
# question of the same graph and a second, subtly different walk is how a pair
# like this drifts. If one is corrected, correct both.
#
# The measured spread that makes this matter here: whole resolve from `regorus`
# is 46 packages, activated is 41. Neither carries any of the nine, so the gate
# agrees today either way — the filter is what keeps it agreeing when an optional
# IO feature lands upstream and nobody enables it.
#
# NO `--filter-platform`, and that is deliberate rather than an omission. The
# pin is a claim about what a policy module can reach on any platform this crate
# ships to, so narrowing the graph to one target would let an IO crate arrive
# behind a `cfg` for a platform the gate does not run on. `macos-link-check`
# filters because its question IS about one target; this one is not.
#
#MUTANT closure-walks-the-workspace|s/^frontier = \[i for i in roots\]$/frontier = [m for m in members if m in nodes]/|not the evaluator's
#MUTANT closure-scans-unactivated|s/^            if (entry.get('rename') or entry\['name'\]) in enabled:$/            if True:/|unactivated optional IO dependency
set -euo pipefail

cd "${EVALUATOR_ROOT:-$(git rev-parse --show-toplevel)}"

# The evaluator's package name. Named once: it is the node the walk starts from
# AND the word the refusal uses, and two spellings of it is how a rename turns
# this gate silent instead of red.
readonly EVALUATOR=regorus

# The nine `Cargo.toml`'s pin names. Not a heuristic and not "crates that look
# networky": this is the list the manifest comment claims is absent, restated
# here as the thing that decides. If the manifest's list changes, this changes
# with it — `rules-drift`'s lesson is that a restated constant with nothing
# holding the two in agreement is a defect waiting, so the manifest comment
# points AT this file rather than repeating the list a third time.
readonly IO_CRATES='reqwest jsonschema hyper rustls openssl-sys native-tls ring globset glob'

# The graph normally comes from cargo. `BATTEN_EVALUATOR_METADATA` substitutes a
# recorded one, and exists so this gate can be shown able to FAIL (CLOUD-418):
# the live tree is clean by construction — that is the point of the gate — so a
# suite that could only run against it would assert a pass and never a refusal.
# Read-only, and never set outside `tests/evaluator-closure-check.bats`.
if [[ -n "${BATTEN_EVALUATOR_METADATA:-}" ]]; then
	metadata=$(cat "$BATTEN_EVALUATOR_METADATA") || {
		echo "::error:: evaluator-closure-check: could not read ${BATTEN_EVALUATOR_METADATA}" >&2
		exit 1
	}
else
	# `--locked` because the question is about the COMMITTED resolution. A gate
	# allowed to update the lockfile answers "what would upstream give me today",
	# which is a property of the world rather than of this commit — the exact
	# split `lock-complete` was carved out of `lock-check` to fix.
	metadata=$(cargo metadata --locked --format-version 1 2>/dev/null) || {
		echo "::error:: evaluator-closure-check: could not resolve the dependency graph — is the lockfile current? Run \`mise run lock-check\`." >&2
		exit 1
	}
fi

report=$(printf '%s' "$metadata" | python3 -c "
import json, sys

meta = json.load(sys.stdin)
evaluator = sys.argv[1]
io_crates = set(sys.argv[2].split())

packages = {p['id']: p for p in meta['packages']}
nodes = {n['id']: n for n in (meta.get('resolve') or {}).get('nodes', [])}
members = set(meta.get('workspace_members', []))


def activated_keys(package, enabled):
    # Three spellings reach a dependency and all three must be read, or an
    # activated dep looks dormant: the implicit feature (a bare 'foo'), the
    # namespaced form ('dep:foo'), and enabling one of the dep's own features
    # ('foo/bar'). The WEAK form ('foo?/bar') is deliberately not one - it
    # applies only if something else already activated the dep.
    keys = set(enabled)
    declared = package.get('features', {})
    for feature in enabled:
        for token in declared.get(feature, []):
            if token.startswith('dep:'):
                keys.add(token[4:])
            elif '/' in token:
                head = token.split('/', 1)[0]
                if not head.endswith('?'):
                    keys.add(head)
    return keys


def edges(node_id):
    node = nodes.get(node_id)
    package = packages.get(node_id)
    if node is None or package is None:
        return
    enabled = activated_keys(package, set(node.get('features', [])))
    is_member = node_id in members
    for dep in node.get('deps', []):
        target = packages.get(dep['pkg'])
        if target is None:
            continue
        kinds = {k.get('kind') for k in dep.get('dep_kinds', [{}])}
        if kinds == {'dev'} and not is_member:
            continue
        matching = [d for d in package.get('dependencies', []) if d['name'] == target['name']]
        if not matching:
            # An edge the manifest does not explain: keep it rather than drop
            # it. Unexplained means unmeasured, and unmeasured fails closed.
            yield dep['pkg']
            continue
        for entry in matching:
            if not entry.get('optional'):
                yield dep['pkg']
                break
            if (entry.get('rename') or entry['name']) in enabled:
                yield dep['pkg']
                break


roots = [i for i, p in packages.items() if p['name'] == evaluator and i in nodes]
if not roots:
    # NOT a pass. The evaluator vanishing from the graph means the question
    # could not be asked, and reporting 'nothing found' there is the vacuous
    # pass this repo names CLOUD-251.
    print('ABSENT')
    sys.exit(0)

reached = set()
frontier = [i for i in roots]
while frontier:
    current = frontier.pop()
    if current in reached:
        continue
    reached.add(current)
    frontier.extend(edges(current))

# Pointer-only (non-negotiable rule 4): the crate NAME and nothing else. Never a
# dependency tree, never a path through the graph, never a version chain.
found = sorted({packages[i]['name'] for i in reached} & io_crates)
print('COUNT %d' % len(reached))
for name in found:
    print('FOUND %s' % name)
" "$EVALUATOR" "$IO_CRATES") || {
	echo "::error:: evaluator-closure-check: could not inspect the dependency graph" >&2
	exit 1
}

if [[ "$report" = ABSENT ]]; then
	echo "::error:: evaluator-closure-check: no \`${EVALUATOR}\` node in the resolved graph, so the closure could not be walked at all. This is could-not-look, not a pass." >&2
	exit 1
fi

count=$(printf '%s\n' "$report" | sed -n 's/^COUNT //p')
found=$(printf '%s\n' "$report" | sed -n 's/^FOUND //p')

if [[ -n "$found" ]]; then
	echo "::error:: an IO-bearing crate is reachable from the evaluator, so a policy module can no longer be claimed to acquire nothing — and that claim is what admits consumer-authored code to the mediated call (crates/batten/src/policy.rs):" >&2
	printf '%s\n' "$found" | while IFS= read -r name; do printf '  %s\n' "$name" >&2; done
	echo "Cargo unifies features across the graph, so this may have arrived without any edit to the \`regorus\` feature list. Find who enabled it (\`cargo tree -i <crate>\`), and close it there — the feature list in Cargo.toml is where the pin is stated, not where it is decided." >&2
	exit 2
fi

# The count is REPORTED, never asserted, and the split is deliberate. Which
# crates are absent is a property of THIS COMMIT and belongs in a gate; how many
# packages upstream happens to resolve to is a property of the world and would
# fire on every legitimate bump. `Cargo.toml`'s comment cites this line as where
# its number comes from, so the number has one source rather than a hand-count
# somebody re-takes and gets differently.
echo "evaluator-closure-check: none of the ${EVALUATOR} closure's ${count} packages is one of the nine IO-bearing crates the manifest pins out"

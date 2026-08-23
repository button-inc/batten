#!/usr/bin/env bash
#MISE description="Gate: no dependency that would need a real macOS SDK to link, which would break the SDK-free macOS release build"
#
# The macOS release artifacts are linked on Linux by zig, with no Apple SDK
# present. That works only while nothing in the tree links a macOS *system
# framework* (CoreFoundation, Security, …): such a crate needs SDKROOT pointing
# at a genuine macOS SDK, which reintroduces both a toolchain dependency and
# Apple's licensing question.
#
# The failure this prevents is a LATE one. `cross-check` runs `cargo check`,
# which stops at codegen-to-metadata and never links, so it cannot see this
# class of breakage at all — the first symptom would be the release workflow
# failing after a tag was already cut. This gate moves that signal to the moment
# the dependency is added.
#
# Predicate, over the dependency graph RESOLVED FOR macOS (`--filter-platform`),
# so a macOS-only transitive dep is seen and a Linux-only one is not:
#
#   1. any package declaring a `links` key — the manifest's own statement that
#      it links a native library, which is general and needs no list; plus
#   2. a named set of crates that link Apple frameworks from a build script
#      WITHOUT declaring `links`, which rule 1 cannot see.
#
# Rule 2 is a list and therefore incomplete by construction — a crate nobody has
# listed slips past. That residual gap is closed by actually linking the target,
# which `darwin-link` does for the Darwin triples; this gate is the fast,
# specific, early half of that pair, not a replacement for it.
#
# BOTH RULES READ WHAT IS BUILT, NOT WHAT RESOLVED (CLOUD-718). `cargo metadata`
# lists every package the resolver considered, and that includes optional
# dependencies nothing ever turned on. Scanning that list asks "could some
# configuration of this tree link native code" where the gate means "does this
# one", and the difference is not academic: adding `gix` put `defmt` in the
# package list — an embedded-logging crate, an unactivated optional dependency
# of `jiff`, reaching no Apple framework and never compiled — and this gate
# refused a link that `darwin-link` then completed on the same tree. A gate that
# fails on a crate the compiler never sees is not measuring the thing it names.
#
# So the scan walks the resolve graph from the workspace members and follows
# only edges that are actually activated, and the ONLY direction that costs
# anything is the one this fixes: a package reachable in the build is still read
# by both rules, and the real link remains the backstop for whatever a metadata
# reading cannot see.
# Reverting the filter to the whole resolve is the defect this fixes: an
# optional dependency nobody enabled reads as linked, and the gate refuses a
# link that succeeds.
#MUTANT scans-resolved-not-built|s/^frontier = \[m for m in members if m in nodes\]$/frontier = list(nodes)/|an optional dependency nobody enabled is not reported
# And the weak-dependency reading must stay OUT: 'foo?\/bar' does not activate
# 'foo', and treating it as though it does walks back to the same over-scan.
#MUTANT weak-dep-activates|s@head = token.split('/', 1)\[0\]@head = token.split('/', 1)[0].rstrip('?')@|A WEAK REFERENCE IS NOT AN ACTIVATION
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT sdk-dependency-passes|s/^if \[\[ -n "\$findings" \]\]; then$/if false; then/|the same optional dependency, once enabled, is reported

set -uo pipefail

# The target whose resolved graph we inspect. Apple Silicon is the platform a
# maintainer is most likely to run, and both Darwin triples share these deps.
readonly TARGET=aarch64-apple-darwin

# Crates that pull in an Apple system framework. Extend as new ones are met —
# and when you do, prefer proving it with a link (cross-check) over trusting
# this list.
readonly FRAMEWORK_CRATES='^(security-framework|security-framework-sys|core-foundation|core-foundation-sys|native-tls|openssl-sys|cocoa|objc|objc2|system-configuration|system-configuration-sys)$'

# Crates whose `links` key names a library they VENDOR AND COMPILE THEMSELVES,
# reaching no Apple system framework — so rule 1's proxy is wrong about them.
#
# Rule 1 reads `links` as "declares it links a native library", and treats that
# as "needs SDKROOT pointing at a genuine macOS SDK". For a crate that ships C
# sources and builds them with `cc`, the second does not follow from the first:
# there is no system library to find, so there is no SDK to need.
#
# ADDING A NAME HERE REQUIRES A LINK, never a reading of the crate. `darwin-link`
# runs `cargo zigbuild --target aarch64-apple-darwin` with no Apple SDK present,
# which is the only evidence that settles it — the same standard FRAMEWORK_CRATES
# above states for its own list, applied in the opposite direction.
#
# Measured 2026-08-21, adding a tree-sitter-backed structural matcher to the
# graph: this gate refused `tree-sitter` and `tree-sitter-language`, and
# `darwin-link` then linked the same tree with no SDK present — "invoking
# xcrun --sdk macosx --show-sdk-path failed: No such file or directory"
# followed by a clean link. A gate that refuses what the linker accepts is
# measuring something other than what it names.
#
# The fail-safe is unchanged in the direction that matters: an UNKNOWN `links`
# crate is still a finding, so this narrows the gate rather than opening it, and
# `darwin-link` remains the backstop for whatever a metadata reading cannot see.
readonly VENDORED_LINKS='^(tree-sitter|tree-sitter-language)$'

# The graph normally comes from cargo. `BATTEN_LINK_CHECK_METADATA` substitutes
# a recorded one, and exists so the reachability filter can be shown able to
# FAIL: the live tree is clean by construction (that is the point of the gate),
# so a suite that can only run against it asserts a pass and never a refusal.
# The fixtures are the two directions this filter has to separate — a built
# `links` crate and an unactivated optional one — which cannot both be produced
# by editing the real manifest. Read-only, and never set outside the suite.
if [[ -n "${BATTEN_LINK_CHECK_METADATA:-}" ]]; then
	metadata=$(cat "$BATTEN_LINK_CHECK_METADATA") || {
		echo "::error:: macos-link-check: could not read ${BATTEN_LINK_CHECK_METADATA}" >&2
		exit 1
	}
else
	metadata=$(cargo metadata --format-version 1 --filter-platform "$TARGET" 2>/dev/null) || {
		echo "::error:: macos-link-check: could not resolve the dependency graph for ${TARGET}" >&2
		exit 1
	}
fi

findings=$(printf '%s' "$metadata" | python3 -c "
import json, re, sys

meta = json.load(sys.stdin)
pattern = re.compile(sys.argv[1])
# Rule 1's exemption: a \`links\` crate that vendors and compiles its own C.
# Narrowing only — an unknown \`links\` crate is still a finding.
vendored = re.compile(sys.argv[2])

packages = {p['id']: p for p in meta['packages']}
nodes = {n['id']: n for n in (meta.get('resolve') or {}).get('nodes', [])}
members = set(meta.get('workspace_members', []))


def activated_keys(package, enabled):
    # Three spellings reach a dependency and all three must be read, or an
    # activated dep looks dormant: the implicit feature (a bare 'foo'), the
    # namespaced form ('dep:foo'), and enabling one of the dep's own features
    # ('foo/bar'). The WEAK form ('foo?/bar') is deliberately not one - it
    # applies only if something else already activated the dep, and reading it
    # as an activation drifts back toward the whole-resolve scan this replaces.
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
        # A dev-dependency of a *dependency* is never built. One of a workspace
        # member is: the test binaries link too.
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


built = set()
frontier = [m for m in members if m in nodes]
while frontier:
    current = frontier.pop()
    if current in built:
        continue
    built.add(current)
    frontier.extend(edges(current))

for package_id in sorted(built, key=lambda i: packages[i]['name']):
    package = packages[package_id]
    if package.get('links') and not vendored.match(package['name']):
        print(f\"{package['name']} v{package['version']}: declares links={package['links']!r}\")
    elif pattern.match(package['name']):
        print(f\"{package['name']} v{package['version']}: links an Apple system framework\")
" "$FRAMEWORK_CRATES" "$VENDORED_LINKS") || {
	echo "::error:: macos-link-check: could not inspect the dependency graph" >&2
	exit 1
}

if [[ -n "$findings" ]]; then
	echo "::error:: a dependency needs a real macOS SDK to link, which the SDK-free macOS release build cannot supply:" >&2
	printf '%s\n' "$findings" | while IFS= read -r line; do printf '  %s\n' "$line" >&2; done
	echo "Either drop it, feature-gate it off the default build (a rustls-style" >&2
	echo "alternative usually exists), or accept an SDK and revisit how macOS is built." >&2
	exit 1
fi

echo "macos-link-check: nothing in the ${TARGET} graph needs a macOS SDK to link"

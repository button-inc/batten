#!/usr/bin/env bats
# subject: mise-tasks/macos-link-check.sh
#
# The gate that keeps the SDK-free macOS build buildable. Its whole value is
# firing BEFORE a release, so the cases below pin both directions: it passes on
# the tree as it stands, and it actually fails when a framework-linking crate
# appears — a gate that only ever passes is indistinguishable from no gate.

setup() {
	CHECK="${BATS_TEST_DIRNAME}/../mise-tasks/macos-link-check.sh"
	cd "${BATS_TEST_DIRNAME}/.." || return 1
}

@test "the repo as it stands has no SDK-requiring dependency" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing in the aarch64-apple-darwin graph"* ]]
}

@test "the framework crate list covers the ones that actually bit us" {
	# native-tls is the concrete crate that forces a real SDK: it is what a
	# default-featured HTTP client pulls in, and it reaches Security.framework
	# through security-framework. If this list ever loses these names the gate
	# silently stops guarding the case it was written for.
	for crate in native-tls security-framework core-foundation openssl-sys; do
		grep -q "$crate" "$CHECK" || {
			echo "framework crate list dropped $crate"
			return 1
		}
	done
}

@test "the graph is resolved for macOS, not for the host" {
	# --filter-platform is load-bearing: without it a macOS-only transitive
	# dependency is invisible on a Linux host, which is every CI run.
	grep -q 'filter-platform' "$CHECK"
	grep -q 'aarch64-apple-darwin' "$CHECK"
}

@test "a package declaring a native links key is caught without being listed" {
	# Rule 1 is the general half: it needs no list, so a crate nobody has heard
	# of is still caught if its manifest declares that it links native code.
	grep -q "package.get('links')" "$CHECK"
}

# --- the filter reads what is BUILT, not what merely RESOLVED (CLOUD-718) -----
#
# These run against recorded metadata rather than the live tree, and that is not
# convenience: the live tree is clean by construction, so a suite that can only
# run against it asserts a pass and never a refusal. The two directions below
# differ by ONE enabled feature on one package, which is the whole distinction
# the filter exists to draw.

@test "an optional dependency nobody enabled is not reported" {
	# The defmt/jiff shape: a crate declaring `links` sits in the resolve as an
	# unactivated optional dependency. It is never compiled, so a gate about
	# linking must stay silent. Measured 2026-08-20: adding `gix` produced
	# exactly this and failed a link `darwin-link` completed on the same tree.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/dormant-optional.json" \
		run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"nativebits"* ]]
}

@test "the same optional dependency, once enabled, is reported" {
	# The guard on the case above: same fixture, same crate, one feature turned
	# on. If this passes, the filter has not narrowed rule 1 — it has switched
	# it off.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/enabled-optional.json" \
		run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nativebits"* ]]
	[[ "$output" == *"declares links"* ]]
}

@test "A WEAK REFERENCE IS NOT AN ACTIVATION: dep-question-mark leaves the dep dormant" {
	# Same shape as the two above, except the enabled feature names the optional
	# dependency through cargo's WEAK form: `dep?/feature` says "if something
	# else activated it, turn this feature on too", which is the one syntax that
	# mentions a dependency without building it. Reading it as an activation
	# drifts back toward the whole-resolve scan CLOUD-718 replaced, and no
	# fixture exercised it until `mutant` was pointed at the arm that does
	# (CLOUD-480).
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/weak-optional.json" \
		run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"nativebits"* ]]
}

@test "rule 2 still fires through the reachability walk" {
	# The named-crate half has to survive the same filter: a framework crate on
	# a non-optional edge is built, so it is still caught.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/framework-crate.json" \
		run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"security-framework"* ]]
	[[ "$output" == *"Apple system framework"* ]]
}

@test "a vendored-C links crate is exempt from rule 1" {
	# `vendored-links.json` is `enabled-optional.json` with ONE substitution:
	# the crate is named `tree-sitter` instead of `nativebits`. Same graph, same
	# built edge, same `links` key — so the only thing that can change the
	# verdict is the name, which is exactly what the exemption keys on.
	#
	# Measured 2026-08-21: adding a tree-sitter-backed structural matcher made
	# this gate refuse `tree-sitter` and `tree-sitter-language`, and
	# `darwin-link` then linked the same tree with no SDK present ("invoking
	# xcrun --sdk macosx --show-sdk-path failed: No such file or directory").
	# A gate that refuses what the linker accepts measures something other than
	# what it names.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/vendored-links.json" \
		run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"tree-sitter"* ]]
}

@test "an unvetted links crate is still reported, so the exemption is a list not a switch" {
	# The anti-vacuity guard on the case above, and the one that matters: the
	# exemption is an allowlist requiring a `darwin-link` proof per entry, so a
	# crate nobody has vetted still reds. If this passes, rule 1 was switched
	# off rather than narrowed — the same failure mode the enabled/dormant pair
	# above exists to catch, facing the other way.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/enabled-optional.json" \
		run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nativebits"* ]]
}

@test "every vendored-links entry names a crate, so the pattern cannot be widened to a wildcard" {
	# The exemption is only safe while it is a closed list: a wildcard slipped
	# into it would exempt every `links` crate silently, and the sibling cases
	# above would still pass because both fixtures name real crates.
	#
	# Assert the WHOLE grammar, not a denylist of operators. An earlier form
	# stripped only `.`, `*` and `+`, which let
	# `^(tree-sitter|z[a-z]{0,99})$` through — it rejects `nativebits`, so the
	# sibling cases above stay green, while silently exempting every `z...`
	# crate. Caught in review on the PR that introduced it.
	#
	# A crate name is `[a-z0-9_-]+` per cargo, so an anchored alternation of
	# literals is fully expressible as a positive match. Anything else — a
	# character class, a brace, a backslash, a quantifier — fails to match at
	# all, which is the point: the test says what the pattern MAY be rather
	# than enumerating what it may not.
	run grep -cE "^readonly VENDORED_LINKS='\^\([a-z0-9_-]+(\|[a-z0-9_-]+)*\)\\\$'\$" "$CHECK"
	[ "$output" -eq 1 ]
}

@test "the walk starts at the workspace members" {
	# The reachability walk is what makes 'built' mean anything; seeded with
	# every node instead, it degenerates to the whole-resolve scan this replaced.
	grep -q 'frontier = \[m for m in members if m in nodes\]' "$CHECK"
}

#!/usr/bin/env bats
#
# The gate that keeps the SDK-free macOS build buildable. Its whole value is
# firing BEFORE a release, so the cases below pin both directions: it passes on
# the tree as it stands, and it actually fails when a framework-linking crate
# appears — a gate that only ever passes is indistinguishable from no gate.

setup() {
	CHECK="${BATS_TEST_DIRNAME}/../mise-tasks/macos-link-check"
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

@test "rule 2 still fires through the reachability walk" {
	# The named-crate half has to survive the same filter: a framework crate on
	# a non-optional edge is built, so it is still caught.
	BATTEN_LINK_CHECK_METADATA="${BATS_TEST_DIRNAME}/fixtures/link-check/framework-crate.json" \
		run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"security-framework"* ]]
	[[ "$output" == *"Apple system framework"* ]]
}

@test "the walk starts at the workspace members" {
	# The reachability walk is what makes 'built' mean anything; seeded with
	# every node instead, it degenerates to the whole-resolve scan this replaced.
	grep -q 'frontier = \[m for m in members if m in nodes\]' "$CHECK"
}

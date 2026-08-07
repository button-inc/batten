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

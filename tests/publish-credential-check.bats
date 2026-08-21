#!/usr/bin/env bats
# subject: mise-tasks/publish-credential-check
# CLOUD-109's gate: this repository cannot publish to a registry with a
# long-lived credential.
#
# The case that matters is the IMPLICATION, and it is the reason this gate is
# the ticket's honest deliverable rather than an edit to today's workflow. While
# `publish = false` the OIDC permission is not required — requiring it would
# require a permission no step uses. The moment `publish` becomes true it is,
# and the two cases below that flip it are what prove the gate is not vacuously
# green on a repository that never publishes.
#
# The other load-bearing case is the ABSENT key: release-plz publishes by
# default, so a config saying nothing publishes. A gate reading a missing key as
# `false` would go quiet in exactly the situation it exists for.
#
# Fixtures are a scratch tree rather than the real one, so each case differs
# from green in a single named way and no test can mutate the repository it runs
# from.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/publish-credential-check"
	ROOT="$BATS_TEST_TMPDIR/repo"
	export BATTEN_RELEASE_PLZ_CONFIG="$ROOT/release-plz.toml"
	export BATTEN_WORKFLOW_DIR="$ROOT/.github/workflows"
	mkdir -p "$BATTEN_WORKFLOW_DIR"
	printf '[workspace]\npublish = false\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	release_workflow
	cat >"$BATTEN_WORKFLOW_DIR/ci.yml" <<-'EOF'
		name: ci
		on: [pull_request]
		jobs:
		  final:
		    runs-on: ubuntu-latest
		    steps:
		      - run: mise run ci
	EOF
}

# The release workflow, with whatever extra permission lines a case wants.
release_workflow() {
	{
		cat <<-'EOF'
			name: release-plz
			on:
			  push:
			    branches: [main]
			permissions:
			  contents: write
			  pull-requests: write
		EOF
		for line in "$@"; do
			printf '  %s\n' "$line"
		done
		cat <<-'EOF'
			jobs:
			  release-plz:
			    runs-on: ubuntu-latest
			    steps:
			      - run: mise run release
		EOF
	} >"$BATTEN_WORKFLOW_DIR/release-plz.yml"
}

@test "the tree as it stands passes: no registry credential, publishing off" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"publish=false"* ]]
	[[ "$output" == *"no long-lived registry credential"* ]]
}

@test "THE DEFECT: a workflow gaining CARGO_REGISTRY_TOKEN fails" {
	printf '      env:\n        CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n' \
		>>"$BATTEN_WORKFLOW_DIR/release-plz.yml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"registry-token"* ]]
}

@test "an alternate-registry token is caught too, whatever the registry is named" {
	printf '      env:\n        CARGO_REGISTRIES_INTERNAL_TOKEN: ${{ secrets.X }}\n' \
		>>"$BATTEN_WORKFLOW_DIR/ci.yml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"registry-token"* ]]
	[[ "$output" == *"ci.yml"* ]]
}

@test "a hand-rolled cargo login is the same defect spelled differently" {
	printf '      - run: cargo login "$TOKEN"\n' >>"$BATTEN_WORKFLOW_DIR/release-plz.yml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo-login"* ]]
}

@test "the finding is a pointer — a path and a rule id, never the matched line" {
	printf '      env:\n        CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n' \
		>>"$BATTEN_WORKFLOW_DIR/release-plz.yml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-plz.yml:"* ]]
	[[ "$output" != *"secrets.CARGO_REGISTRY_TOKEN"* ]]
}

@test "THE POINT: turning publishing on without id-token: write fails" {
	printf '[workspace]\npublish = true\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-oidc-permission"* ]]
}

@test "turning publishing on WITH id-token: write passes" {
	printf '[workspace]\npublish = true\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	release_workflow "id-token: write"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"publish=true"* ]]
}

@test "the permission is not satisfied by the phrase appearing in a comment" {
	printf '[workspace]\npublish = true\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	release_workflow "# someday: id-token: write"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-oidc-permission"* ]]
}

@test "publishing off does NOT require the permission — a dead grant is not the ask" {
	release_workflow
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "THE SILENT CASE: no publish key reads as publishing, because that is the default" {
	printf '[workspace]\ngit_tag_enable = true\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-oidc-permission"* ]]
}

@test "an unreadable config is exit 2 — could not look, never a clean tree" {
	rm "$BATTEN_RELEASE_PLZ_CONFIG"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"whether this repository publishes is unknown"* ]]
}

@test "a workflow directory with no workflows is exit 2, not a vacuous pass" {
	rm "$BATTEN_WORKFLOW_DIR"/*.yml
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"scans nothing"* ]]
}

@test "publishing on with no release workflow at all is exit 2" {
	printf '[workspace]\npublish = true\n' >"$BATTEN_RELEASE_PLZ_CONFIG"
	rm "$BATTEN_WORKFLOW_DIR/release-plz.yml"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"does not exist"* ]]
}

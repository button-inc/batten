#!/usr/bin/env bats
# The gate that ships with CLOUD-258's fix: a release must carry one archive per
# target the dist matrix builds.
#
# Both directions matter, and so does the third. A missing archive is exit 1 —
# the board is behind reality. An unreadable release or matrix is exit 2 — "I
# could not look" — because reporting a shipping release as broken on a network
# blip is the failure mode that gets a scheduled gate switched off.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/release-assets-check"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH
	# The matrix is read from the workflow, never restated here — the fixture
	# below is the same list-item shape the real file uses.
	export BATTEN_RELEASE_WORKFLOW="$BATS_TEST_TMPDIR/workflow.yml"
	cat >"$BATTEN_RELEASE_WORKFLOW" <<-'EOF'
		        include:
		          - target: x86_64-unknown-linux-gnu
		            build-tool: cargo
		          - target: aarch64-apple-darwin
		            build-tool: zigbuild
	EOF
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# `gh release view --json assets` answers with the named asset list; anything
# else answers the tag name. A case that wants the lookup to fail says so.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
[ ! -f "$BATS_TEST_TMPDIR/gh.fails" ] || exit 1
case "\$*" in
  *tagName*) printf 'v9.9.9\n' ;;
  *assets*)  cat "$BATS_TEST_TMPDIR/assets" ;;
esac
EOF
	chmod +x "$STUB/gh"
	printf '%s\n' "$@" >"$BATS_TEST_TMPDIR/assets"
}

complete() {
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json
}

@test "a release carrying every target's archive passes" {
	complete
	run "$CHECK" v9.9.9
	[ "$status" -eq 0 ]
	[[ "$output" == *"all 2 matrix targets"* ]]
}

@test "THE DEFECT: a release with only the schema fails, naming every missing target" {
	# v0.0.36 exactly: the schema job succeeded, all seven dist legs died on the
	# attestation, and the release shipped one asset. Nothing said so for six
	# consecutive releases, which is the gap this gate closes.
	stub_gh batten.schema.json
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"x86_64-unknown-linux-gnu"* ]]
	[[ "$output" == *"aarch64-apple-darwin"* ]]
	[[ "$output" == *"2 of 2 targets"* ]]
}

@test "a partial release fails on the missing target and not the present one" {
	# One leg failing must not read as a clean release, and must not smear the
	# leg that worked — the recovery is per-target.
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"aarch64-apple-darwin"* ]]
	[[ "$output" != *"  x86_64-unknown-linux-gnu"* ]]
	[[ "$output" == *"1 of 2 targets"* ]]
}

@test "the failure names the recovery, not merely that it refused" {
	stub_gh batten.schema.json
	run "$CHECK" v9.9.9
	[[ "$output" == *"workflow_dispatch"* ]]
	[[ "$output" == *"clobber"* ]]
}

@test "no tag given falls back to the latest release" {
	complete
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"v9.9.9"* ]]
}

@test "an EMPTY tag argument falls back too, which is what the schedule passes" {
	# The scheduled run has no `inputs.tag`, and the tag reaches the task through
	# env — quoted, so it arrives as an empty first argument rather than as no
	# argument at all. Without this the weekly run is the one path no case covers.
	complete
	run "$CHECK" ""
	[ "$status" -eq 0 ]
	[[ "$output" == *"v9.9.9"* ]]
}

@test "an unreadable release exits 2 — could not look is not a verdict" {
	# The distinction that keeps a scheduled gate trusted: a network blip must
	# never report a shipping release as broken.
	complete
	: >"$BATS_TEST_TMPDIR/gh.fails"
	run "$CHECK" v9.9.9
	[ "$status" -eq 2 ]
}

@test "a matrix with no targets exits 2 rather than passing vacuously" {
	# A gate that checks nothing must not report green — the silent false green
	# this repo has met in several disguises.
	complete
	printf 'jobs:\n  dist:\n' >"$BATTEN_RELEASE_WORKFLOW"
	run "$CHECK" v9.9.9
	[ "$status" -eq 2 ]
	[[ "$output" == *"must not report green"* ]]
}

@test "an unreadable workflow exits 2, not 1" {
	complete
	export BATTEN_RELEASE_WORKFLOW="$BATS_TEST_TMPDIR/absent.yml"
	run "$CHECK" v9.9.9
	[ "$status" -eq 2 ]
}

@test "the real workflow's matrix is readable by this parser" {
	# The fixtures above prove the logic; this proves the parser is pointed at a
	# shape the committed workflow actually has. Without it the whole suite could
	# pass while the gate read zero targets in production.
	run bash -c "sed -nE 's/^[[:space:]]*-[[:space:]]+target:[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*\$/\1/p' .github/workflows/release-artifacts.yml | sort -u | wc -l"
	[ "$status" -eq 0 ]
	[ "$output" -ge 7 ]
}

@test "upload precedes attestation in the committed workflow" {
	# THE ORDERING (CLOUD-258). Attesting first let a plan-gated optional step
	# suppress the artifact itself, and every release from v0.0.31 to v0.0.36
	# shipped no binary because of it. Asserted on order, because both steps are
	# present either way and only the order decides whether anything ships.
	run awk '/name: Upload to the release/ { print "upload"; }
	         /attest-build-provenance/ { print "attest"; }' \
		.github/workflows/release-artifacts.yml
	[ "$status" -eq 0 ]
	[ "$(echo "$output" | head -1)" = "upload" ]
}

@test "no install-action step names a tool mise.toml already pins" {
	# CLOUD-259. A second provisioning path for a mise-pinned tool is the repo's
	# own rule violated, and it is not merely redundant: install-action dropped
	# zig, and its two fallbacks (cargo-binstall, cargo install) are dead ends for
	# a non-crate, so the step could only fail. Both Darwin legs died there while
	# mise had zig 0.16 pinned and installed. `cross` is not in mise.toml, so it
	# is not a finding.
	# Scoped to the `tool:` values install-action is actually given — the word
	# "zig" also appears in the matrix's build-tool name and in prose, and a bare
	# grep would fail on those forever.
	local requested
	requested=$(sed -nE 's/^[[:space:]]*tool:[[:space:]]*(.+)$/\1/p' \
		.github/workflows/release-artifacts.yml | tr ',' '\n' | tr -d ' ')
	local tool
	while read -r tool; do
		[ -n "$tool" ] || continue
		if grep -qxF -- "$tool" <<<"$requested"; then
			echo "install-action is asked for '$tool', which mise.toml pins"
			return 1
		fi
	done < <(
		sed -nE 's/^[[:space:]]*"?([A-Za-z0-9:._/-]+)"?[[:space:]]*=[[:space:]]*".*/\1/p' mise.toml |
			sed 's#^.*/##'
	)
}

@test "the attestation cannot fail the leg while the repo is private" {
	# The claim is deferred, not dropped: the step stays wired and starts
	# succeeding on its own when the repo goes public.
	run grep -A2 'attest-build-provenance' .github/workflows/release-artifacts.yml
	[ "$status" -eq 0 ]
	[[ "$output" == *"continue-on-error: true"* ]]
}

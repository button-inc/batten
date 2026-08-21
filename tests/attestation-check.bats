#!/usr/bin/env bats
# subject: mise-tasks/attestation-check
# attestation-check's decision table (CLOUD-583). The case that carries the whole
# design is `THE GAP IS NOT A VERDICT`: `gh attestation verify` exits 1 both for
# an artifact with no provenance and for a repository the platform never offered
# any to, and a gate that cannot tell those apart reds every release for a reason
# no branch causes.
#
# Driven against a stubbed `gh`, because the two halves cannot both be real here:
# this repository's endpoint answers 404 (measured), so the available-platform
# branch and every verdict under it would be unreachable. The 404 branch IS
# exercised for real — `mise run attestation-check` against the live repository
# is what the issue's blocker correction is measured with — and the stub is what
# covers the other half.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/attestation-check"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	# A repository whose origin remote is a github.com URL, so the slug is derived
	# the way the task derives it rather than being injected.
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	git -C "$ROOT" init -q
	git -C "$ROOT" remote add origin https://github.com/example-org/example-repo.git
	export ATTESTATION_CHECK_ROOT="$ROOT"
	export ATTESTATION_GH="$STUB/gh"
	export GH_TOKEN=stub-token

	echo 404 >"$BATS_TEST_TMPDIR/status"
	stub_gh
}

# A `gh` whose four sub-behaviours are set independently by sentinel files:
#   status          the attestations endpoint's status line (default 404)
#   verify.fails    `attestation verify` exits 1
#   download.fails  `release download` exits 1
#   release.empty   the release carries no archive
# Every `attestation verify` call appends the BASENAME of the file it was handed
# to `verified`, which is what pins "the binary, not the archive".
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
set -uo pipefail
case "\$1 \${2:-}" in
"api "*)
	echo "HTTP/2.0 \$(cat "$BATS_TEST_TMPDIR/status") Some Status"
	echo ""
	echo '{"attestations":[]}'
	exit 0
	;;
"release view")
	echo "v9.9.9"
	exit 0
	;;
"release download")
	[ ! -f "$BATS_TEST_TMPDIR/download.fails" ] || exit 1
	dir=""
	want=""
	for arg in "\$@"; do
		if [ "\$want" = dir ]; then dir="\$arg"; want=""; continue; fi
		[ "\$arg" = "--dir" ] && want=dir
	done
	[ -n "\$dir" ] || exit 1
	if [ -f "$BATS_TEST_TMPDIR/release.empty" ]; then exit 0; fi
	work="\$dir/.mk"
	mkdir -p "\$work"
	printf 'not a real binary\n' >"\$work/batten"
	tar -czf "\$dir/batten-v9.9.9-x86_64-unknown-linux-gnu.tar.gz" -C "\$work" batten
	rm -rf "\$work"
	exit 0
	;;
"attestation verify")
	basename "\$3" >>"$BATS_TEST_TMPDIR/verified"
	[ ! -f "$BATS_TEST_TMPDIR/verify.fails" ] || exit 1
	echo "Loaded 1 attestation from GitHub API"
	exit 0
	;;
esac
exit 1
EOF
	chmod +x "$STUB/gh"
}

@test "THE GAP IS NOT A VERDICT: a 404 endpoint reports the platform gap and exits 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"attestation-unavailable"* ]]
	# The failure rule id must not appear: nothing here is a claim about an
	# artifact, and reporting one would red every release until CLOUD-585 lands.
	[[ "$output" != *"attestation-unverified"* ]]
	# And nothing was downloaded or verified — the gap short-circuits the world.
	[ ! -f "$BATS_TEST_TMPDIR/verified" ]
}

@test "the gap names the repository it asked about, derived from the remote" {
	run "$CHECK"
	[[ "$output" == *"example-org/example-repo"* ]]
}

@test "with the platform available and provenance present, the run passes" {
	echo 200 >"$BATS_TEST_TMPDIR/status"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"carry verifiable provenance"* ]]
}

@test "with the platform available and provenance absent, the run fails" {
	echo 200 >"$BATS_TEST_TMPDIR/status"
	: >"$BATS_TEST_TMPDIR/verify.fails"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"attestation-unverified"* ]]
	# The message must say this is a release to fix rather than a gap to report:
	# the two failures have opposite responses.
	[[ "$output" == *"release to fix"* ]]
}

@test "THE SUBJECT IS THE BINARY, NOT THE ARCHIVE" {
	# `release-artifacts.yml` attests `steps.dist.outputs.binary`, deliberately, so
	# repackaging cannot launder the claim. Verifying the .tar.gz would compute a
	# digest nothing ever attested — a failure that means nothing.
	echo 200 >"$BATS_TEST_TMPDIR/status"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/verified")" = "batten" ]
}

@test "a release carrying no archive is exit 2, not a green verdict about nothing" {
	echo 200 >"$BATS_TEST_TMPDIR/status"
	: >"$BATS_TEST_TMPDIR/release.empty"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"about nothing"* ]]
}

@test "a download that fails is exit 2 — could not look is not a verdict" {
	echo 200 >"$BATS_TEST_TMPDIR/status"
	: >"$BATS_TEST_TMPDIR/download.fails"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
}

@test "a status that is neither 200 nor 404 is exit 2, naming the code" {
	echo 500 >"$BATS_TEST_TMPDIR/status"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"500"* ]]
	[[ "$output" == *"posture is unknown"* ]]
}

@test "output is pointer-only — no attestation body reaches the log" {
	echo 200 >"$BATS_TEST_TMPDIR/status"
	run "$CHECK"
	[[ "$output" != *"Loaded 1 attestation"* ]]
	[[ "$output" != *"attestations\":"* ]]
}

@test "the precondition holds when the verifier resolves" {
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
	[[ "$output" == *"precondition holds"* ]]
}

@test "THE SEVERITY SPLIT: the precondition holds while the platform gap is open" {
	# This is why the batten.toml row can be `deny` at all. The endpoint answers
	# 404 in this case, as it does for the real repository; if this ever failed,
	# the deny row would be enforcing the platform's posture and every landing
	# would stop for a reason no branch causes.
	echo 404 >"$BATS_TEST_TMPDIR/status"
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
}

@test "the precondition makes no network call" {
	# It is what runs on the landing path, so it must answer from local facts
	# only (the CLOUD-410 split). A stub that fails every API call proves it.
	cat >"$STUB/gh" <<'EOF'
#!/usr/bin/env bash
[ "$1" != "api" ] || exit 7
exit 0
EOF
	chmod +x "$STUB/gh"
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
}

@test "an absent verifier is exit 2 in precondition mode" {
	export ATTESTATION_GH="$BATS_TEST_TMPDIR/no-such-gh"
	run "$CHECK" --precondition
	[ "$status" -eq 2 ]
	[[ "$output" == *"no verifier"* ]]
}

@test "a missing credential does NOT fail the precondition — cannot-look is not a deny" {
	# The row this mode backs is `deny`, so anything ambient in it blocks every
	# environment that differs. Measured: an earlier version required GH_TOKEN here
	# and reported a violation inside `tests/prebuilt-lint.bats`' fixture repos,
	# which carry no credential and no remote.
	unset GH_TOKEN
	unset GITHUB_TOKEN || true
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
}

@test "a missing credential IS exit 2 in the world half — a 404 could not be told from a denial" {
	unset GH_TOKEN
	unset GITHUB_TOKEN || true
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"GH_TOKEN"* ]]
}

@test "no github.com remote is exit 2 in the world half, and irrelevant to the precondition" {
	git -C "$ROOT" remote remove origin
	run "$CHECK" --precondition
	[ "$status" -eq 0 ]
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no github.com origin remote"* ]]
}

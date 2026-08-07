#!/usr/bin/env bats
# The completeness half of the old lock-check, asked directly of the committed
# bytes instead of by regenerating over the network and diffing.
#
# The regression that motivates the whole suite: regenerate-and-diff detects
# drift only. `mise lock` never removes or repairs an existing entry, so a
# lockfile that is stably wrong passes forever — and one was. The real
# cargo-zigbuild residue is case 2 below.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/lock-complete"
	LOCK="$BATS_TEST_TMPDIR/mise.lock"
}

# A complete entry for one tool, for whichever platforms are named.
tool_with() {
	local name=$1
	shift
	printf '[[tools.%s]]\nversion = "1.0.0"\nbackend = "aqua:x/%s"\n\n' "$name" "$name" >>"$LOCK"
	local p
	for p in "$@"; do
		printf '[tools.%s."platforms.%s"]\nchecksum = "sha256:abc"\nurl = "https://example.invalid/%s"\n\n' "$name" "$p" "$p" >>"$LOCK"
	done
}

@test "the repo's real lockfile is complete today" {
	run "$GATE" "$BATS_TEST_DIRNAME/../mise.lock"
	[ "$status" -eq 0 ]
}

@test "the shipped residue: a platform key mise does not emit is caught" {
	tool_with zigbuild linux-x64 linux-arm64 macos-arm64
	printf '[tools.zigbuild."platforms.linux-x64-zigbuild"]\nchecksum = "blake3:abc"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install-time residue"* ]]
}

@test "a required platform with a block but no url is caught" {
	tool_with t linux-arm64 macos-arm64
	printf '[tools.t."platforms.linux-x64"]\nprovenance = "github-attestations"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"has no url"* ]]
}

@test "a required platform missing entirely is caught" {
	tool_with t linux-x64 linux-arm64
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"macos-arm64"* ]]
}

@test "a url-less stub on a NON-required platform passes — mise emits those, upstream ships no artifact" {
	# The near-miss this gate was nearly built with: zizmor's musl entries carry
	# only provenance, and `mise lock` regenerates them. Failing on those would
	# fail the repo for a decision upstream made — the same defect as the gate
	# this replaces.
	tool_with t linux-x64 linux-arm64 macos-arm64
	printf '[tools.t."platforms.linux-x64-musl"]\nprovenance = "github-attestations"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 0 ]
}

@test "a tool that locks no platform at all is exempt, not a failure" {
	# npm, pipx and core:rust resolve at install time and lock no URLs.
	printf '[[tools.rust]]\nversion = "1.85.0"\nbackend = "core:rust"\n\n' >"$LOCK"
	printf '[[tools."npm:prettier"]]\nversion = "3.0.0"\nbackend = "npm:prettier"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 0 ]
}

@test "the required set is overridable, and actually changes the verdict" {
	tool_with t linux-x64 linux-arm64
	BATTEN_LOCK_PLATFORMS="linux-x64 linux-arm64" run "$GATE" "$LOCK"
	[ "$status" -eq 0 ]
	BATTEN_LOCK_PLATFORMS="linux-x64 windows-x64" run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
}

@test "quoted and unquoted tool names are both parsed" {
	printf '[[tools."aqua:o/n"]]\nversion = "1"\nbackend = "aqua:o/n"\n\n' >"$LOCK"
	printf '[tools."aqua:o/n"."platforms.linux-x64"]\nurl = "https://example.invalid/a"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"aqua:o/n"* ]]
}

@test "it makes no network call and does not touch the lockfile" {
	tool_with t linux-x64 linux-arm64 macos-arm64
	local before after
	before=$(cksum <"$LOCK")
	run "$GATE" "$LOCK"
	after=$(cksum <"$LOCK")
	[ "$before" = "$after" ]
	# The whole point of the replacement: no `mise lock`, no fetch, no write.
	# Executable lines only — the header comment discusses `mise lock` at length.
	local code
	code=$(grep -vE '^[[:space:]]*#' "$GATE")
	! grep -qE 'mise lock|curl |wget |git fetch' <<<"$code"
}

@test "output is a pointer — file:line, never a checksum or url" {
	tool_with t linux-x64 linux-arm64
	run "$GATE" "$LOCK"
	[[ "$output" == *"$LOCK:"* ]]
	[[ "$output" != *"sha256:"* ]]
	[[ "$output" != *"https://"* ]]
}

@test "a missing lockfile exits 2, distinct from an incomplete one" {
	run "$GATE" "$BATS_TEST_TMPDIR/absent.lock"
	[ "$status" -eq 2 ]
}

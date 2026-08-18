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

@test "a tool that locks no platform is exempt only if its backend cannot lock one" {
	# npm, pipx and core:rust resolve through their own package manager and lock
	# no URLs, so locking nothing is the whole truth about them.
	printf '[[tools.rust]]\nversion = "1.85.0"\nbackend = "core:rust"\n\n' >"$LOCK"
	printf '[[tools."npm:prettier"]]\nversion = "3.0.0"\nbackend = "npm:prettier"\n\n' >>"$LOCK"
	printf '[[tools."pipx:serena-agent"]]\nversion = "1.6.1"\nbackend = "pipx:serena-agent"\n\n' >>"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 0 ]
}

@test "an asset-fetching backend that locks no platform is unlocked, not exempt" {
	# CLOUD-281, verbatim: this is the entry that passed for its whole life.
	printf '[[tools."ubi:rust-cross/cargo-zigbuild"]]\nversion = "0.23.0"\nbackend = "ubi:rust-cross/cargo-zigbuild"\n\n' >"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"locks no platform"* ]]
	[[ "$output" == *"unverified download"* ]]
}

@test "the exemption is an allowlist, so an unrecognised backend must lock" {
	# Fail-closed: a backend nobody has classified is checked, not waved through.
	printf '[[tools."newthing:o/n"]]\nversion = "1"\nbackend = "newthing:o/n"\n\n' >"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]

	printf '[[tools."github:o/n"]]\nversion = "1"\nbackend = "github:o/n"\n\n' >"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
}

@test "a tool that locks no platform and declares no backend is a failure" {
	printf '[[tools.mystery]]\nversion = "1"\n\n' >"$LOCK"
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"declares no backend"* ]]
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

# CLOUD-227. The header always claimed "the committed bytes"; the code read the
# working tree, so the verdict was a property of whatever the machine had
# installed. `mise install` writes the residue key on every cold provisioning
# run (CLOUD-223), which made this gate red in every agent sandbox and — because
# the only CI job that runs it deliberately does not install cargo-zigbuild —
# green in CI, for the same commit.
# Sets REPO and points LOCK at its tracked lockfile. Not a command
# substitution: that would run it in a subshell, where the LOCK it sets to
# redirect tool_with would be discarded and the fixture written elsewhere.
scratch_repo() {
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init -q
	git -C "$REPO" config user.email t@example.invalid
	git -C "$REPO" config user.name t
	LOCK="$REPO/mise.lock"
	tool_with t linux-x64 linux-arm64 macos-arm64
	git -C "$REPO" add mise.lock
	git -C "$REPO" commit -qm lock
}

@test "with no argument it gates the index, not the working tree" {
	scratch_repo
	# Exactly what a cold `mise install` leaves behind, unstaged.
	printf '[tools.t."platforms.linux-x64-t"]\nchecksum = "blake3:abc"\n\n' >>"$LOCK"

	# The worktree copy is bad — the old gate failed here, on nobody's change.
	run "$GATE" "$LOCK"
	[ "$status" -eq 1 ]

	# The bytes a commit would carry are clean, and that is the verdict.
	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"mise.lock"* ]]
}

@test "with no argument a residue key that IS staged still fails" {
	scratch_repo
	printf '[tools.t."platforms.linux-x64-t"]\nchecksum = "blake3:abc"\n\n' >>"$LOCK"
	git -C "$REPO" add mise.lock

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install-time residue"* ]]
	# Pointers name the tracked path, never the temp file the index was read into.
	[[ "$output" == *"mise.lock:"* ]]
	[[ "$output" != *"$BATS_TEST_TMPDIR/tmp"* ]]
}

@test "with no argument and no mise.lock in the index, exit 2" {
	mkdir -p "$BATS_TEST_TMPDIR/bare"
	git -C "$BATS_TEST_TMPDIR/bare" init -q
	run bash -c "cd '$BATS_TEST_TMPDIR/bare' && '$GATE'"
	[ "$status" -eq 2 ]
}

# --- lockfile-writes-enabled (CLOUD-223) ---------------------------------
#
# The residue clauses above are only half a mechanism while any `mise install`
# can write a residue key. This is the other half: the setting that permits the
# write must stay off, and off in the INDEX, so the verdict is a property of the
# commit rather than of whatever the machine's config happens to say.

stage_settings() {
	printf '[settings]\nlockfile = %s\n' "$1" >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml
}

@test "mise.toml re-enabling lockfile writes is a violation" {
	scratch_repo
	stage_settings true

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install-time lockfile writes"* ]]
	[[ "$output" == *"mise.toml:2:"* ]]
}

@test "lockfile = false passes, and the lockfile clauses keep their own header" {
	scratch_repo
	stage_settings false

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]

	# Both clauses failing at once: the setting must not swallow the header the
	# residue pointers print under, which keying it off `fail` would have done.
	stage_settings true
	printf '[tools.t."platforms.linux-x64-t"]\nchecksum = "blake3:abc"\n\n' >>"$LOCK"
	git -C "$REPO" add mise.lock
	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"install-time lockfile writes"* ]]
	[[ "$output" == *"cannot be installed from"* ]]
	[[ "$output" == *"install-time residue"* ]]
}

@test "a lockfile key outside [settings] is not the setting" {
	scratch_repo
	# Any table that is not [settings] exercises the awk's `/^\[/` reset. It used
	# to be [tools], which the unlocked-tool clause now reads as a tool named
	# `lockfile` — an overload, not a second assertion.
	printf '[env]\nlockfile = true\n' >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "fixture mode does not consult mise.toml at all" {
	scratch_repo
	stage_settings true

	# An explicit path names the bytes under test; the setting belongs to the
	# repo the gate runs in, which a fixture run makes no claim about.
	run bash -c "cd '$REPO' && '$GATE' '$LOCK'"
	[ "$status" -eq 0 ]
}

# --- unlocked-tool (CLOUD-333) --------------------------------------------
#
# Every clause above judges an entry that is PRESENT in mise.lock, so the gate
# was blind to a [tools] key with no entry at all — and that is the one failure
# a local run structurally cannot see: nothing here installs `--locked`, so the
# tool installs fine forever, and CI dies at the install step in whichever jobs
# name it. Measured on PR #272: a fully green `mise run verify`, then `msrv` and
# `commit-lint` red for a cargo-msrv pin neither of them owns.

# scratch_repo stages a lockfile holding exactly one tool, `t`. This stages a
# mise.toml declaring whichever tools are named, so the gap between the two is
# the fixture.
stage_tools() {
	{
		printf '[settings]\nlockfile = false\n\n[tools]\n'
		local name
		for name in "$@"; do
			printf '"%s" = "1.0.0"\n' "$name"
		done
	} >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml
}

@test "the shape that escaped: a [tools] entry with no mise.lock entry is caught" {
	scratch_repo
	stage_tools t "aqua:foresterre/cargo-msrv"

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"has no mise.lock entry"* ]]
	[[ "$output" == *"aqua:foresterre/cargo-msrv"* ]]
	# The pointer names mise.toml, where the tool was declared, and its line.
	[[ "$output" == *"mise.toml:6:"* ]]
}

@test "a declared tool that IS locked passes — the clause fires on the gap, not on the table" {
	scratch_repo
	stage_tools t

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "npm, pipx and rust are exempt from the presence rule too" {
	# The same three backends the url clause excuses: they resolve through their
	# own package manager and lock no URLs.
	scratch_repo
	stage_tools t "npm:prettier" "pipx:serena-agent" rust

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "the presence exemption is an allowlist, so a bare name other than rust must lock" {
	# Fail-closed: `core:<name>` is not on the list, and node/pkl/zig/uv/hk/zizmor
	# all lock today, so requiring them is the true direction as well as the safe
	# one.
	scratch_repo
	stage_tools t node

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"has no mise.lock entry"* ]]
	[[ "$output" == *"node"* ]]
}

@test "unlocked-tool output is a pointer — no checksum, no url" {
	scratch_repo
	stage_tools t "aqua:o/n"

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" != *"sha256:"* ]]
	[[ "$output" != *"https://"* ]]
}

@test "a comment inside [tools] is not a tool" {
	scratch_repo
	{
		printf '[settings]\nlockfile = false\n\n[tools]\n'
		printf '# aqua:not/a-tool = "1.0.0"\n'
		printf '  # indented = "1.0.0"\n'
		printf '"t" = "1.0.0"\n'
	} >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "fixture mode does not consult mise.toml for the presence rule either" {
	scratch_repo
	stage_tools t "aqua:foresterre/cargo-msrv"

	# An explicit path names the lockfile bytes under test and makes no claim
	# about the repo's mise.toml — the same boundary the settings clause keeps.
	run bash -c "cd '$REPO' && '$GATE' '$LOCK'"
	[ "$status" -eq 0 ]
}

@test "a workflow using mise-action without MISE_LOCKFILE is caught" {
	scratch_repo
	stage_settings false
	mkdir -p "$REPO/.github/workflows"
	printf 'jobs:\n  a:\n    steps:\n      - uses: jdx/mise-action@abc\n' >"$REPO/.github/workflows/w.yml"
	git -C "$REPO" add .github/workflows/w.yml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"installs UNLOCKED"* ]]
	[[ "$output" == *".github/workflows/w.yml"* ]]
}

@test "the same workflow with MISE_LOCKFILE set passes" {
	scratch_repo
	stage_settings false
	mkdir -p "$REPO/.github/workflows"
	printf 'env:\n  MISE_LOCKFILE: "true"\njobs:\n  a:\n    steps:\n      - uses: jdx/mise-action@abc\n' >"$REPO/.github/workflows/w.yml"
	git -C "$REPO" add .github/workflows/w.yml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "a workflow that does not use mise-action needs nothing" {
	scratch_repo
	stage_settings false
	mkdir -p "$REPO/.github/workflows"
	printf 'jobs:\n  a:\n    steps:\n      - run: echo hi\n' >"$REPO/.github/workflows/w.yml"
	git -C "$REPO" add .github/workflows/w.yml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

# --- stale-lock (CLOUD-593) ------------------------------------------------
#
# `unlocked-tool` above asks whether a row is THERE. This asks whether it says
# the same thing as the pin, which is the only question `mise install --locked`
# actually answers — and the row being present is exactly what makes a stale one
# invisible: `[settings] lockfile = false` means nothing local ever installs
# `--locked`, so it installs fine here forever.
#
# Measured on the branch that added this clause: `[tools] rust` moved to 1.97.1,
# `mise.lock` still said 1.85.0, `mise run verify` was fully green, and all nine
# required checks went red at the install step on `rust@1.97.1 is not in the
# lockfile` — every job, not only the ones that use rust, because `--locked`
# validates the whole file.

# A mise.toml pinning one tool at a stated version, against scratch_repo's
# lockfile row for `t` at 1.0.0.
stage_pin() {
	{
		printf '[settings]\nlockfile = false\n\n[tools]\n'
		printf '"t" = "%s"\n' "$1"
	} >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml
}

@test "a pin naming a version its lock entry does not is caught, and both are named" {
	scratch_repo
	stage_pin 2.0.0

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pinned 2.0.0"* ]]
	[[ "$output" == *"has 1.0.0"* ]]
	[[ "$output" == *"mise.toml:5:"* ]]
}

@test "a partial pin the lock EXTENDS passes — satisfaction, not equality" {
	# The majority of this repo's table: `node = "24"` locks 24.19.0 and
	# `"aqua:cli/cli" = "2.97"` locks 2.97.0. A raw comparison would refuse the
	# real tree on most of its own pins.
	scratch_repo
	stage_pin 1.0

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "the extension must be at a component boundary, not a string prefix" {
	# `1.9` must not be satisfied by `1.97.1`. Without the trailing dot this is
	# the plausible wrong spelling, and it silently accepts a pin the installer
	# would reject.
	scratch_repo
	printf '[[tools.t]]\nversion = "1.97.1"\nbackend = "aqua:x/t"\n\n' >"$LOCK"
	printf '[tools.t."platforms.linux-x64-t"]\nchecksum = "sha256:abc"\nurl = "https://example.invalid/linux-x64"\n\n' >>"$LOCK"
	printf '[tools.t."platforms.linux-arm64-t"]\nchecksum = "sha256:abc"\nurl = "https://example.invalid/linux-arm64"\n\n' >>"$LOCK"
	printf '[tools.t."platforms.macos-arm64-t"]\nchecksum = "sha256:abc"\nurl = "https://example.invalid/macos-arm64"\n\n' >>"$LOCK"
	git -C "$REPO" add mise.lock
	stage_pin 1.9

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pinned 1.9"* ]]
}

@test "an inline-table pin is read, not only the bare-string form" {
	# `rust = { version = "1.97.1", components = "..." }` is the spelling the
	# measured defect was written in, and the one a bare-string reader misses.
	scratch_repo
	{
		printf '[settings]\nlockfile = false\n\n[tools]\n'
		printf '"t" = { version = "2.0.0", components = "clippy" }\n'
	} >"$REPO/mise.toml"
	git -C "$REPO" add mise.toml

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pinned 2.0.0"* ]]
}

@test "a pin that is not a plain dotted version is skipped rather than guessed at" {
	# A range or a channel name is not comparable by this rule, and refusing a
	# spelling the gate does not understand is the larger of the two errors.
	scratch_repo
	stage_pin "latest"

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 0 ]
}

@test "stale-lock output is a pointer — no checksum, no url" {
	scratch_repo
	stage_pin 2.0.0

	run bash -c "cd '$REPO' && '$GATE'"
	[ "$status" -eq 1 ]
	[[ "$output" != *"sha256:"* ]]
	[[ "$output" != *"example.invalid"* ]]
}

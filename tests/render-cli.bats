#!/usr/bin/env bats
# subject: mise-tasks/render/cli.sh
# render:cli's decision table (CLOUD-171): does the publish-time CLI reference
# get produced, named, and kept out of the tree?
#
# Two halves, and they cost differently. `--names` must answer with no build and
# no network at all — `release-assets-check` and `reference-check` both ask it,
# and an answer that needed a compile would make asking expensive enough to stop
# asking. Every other case needs the real binary, so the fixture points
# CARGO_TARGET_DIR back at the real target dir and compiles nothing the suite
# has not already built.
#
# The last case runs against the real repository, so the suite also asserts the
# committed surface still renders.

setup() {
	RENDER="$BATS_TEST_DIRNAME/../mise-tasks/render/cli.sh"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	OUT="$BATS_TEST_TMPDIR/out"
	export RENDER_CLI_OUT_DIR="$OUT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "--names answers the asset path" {
	run "$RENDER" --names
	[ "$status" -eq 0 ]
	[ "$output" = "reference=$OUT/batten-cli-reference.md" ]
}

@test "--names builds nothing and creates nothing" {
	# The property that makes asking cheap: two callers ask this on every gate
	# run, and an answer behind a compile is one they would stop asking for.
	#
	# Asserted with a cargo that records being called, rather than by emptying
	# PATH — an unreachable PATH breaks the `#!/usr/bin/env bash` lookup itself,
	# so the task would exit 127 and the case would pass for the wrong reason.
	stub="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$stub"
	printf '#!/usr/bin/env bash\ntouch "%s/cargo-was-called"\nexit 0\n' "$BATS_TEST_TMPDIR" >"$stub/cargo"
	chmod +x "$stub/cargo"
	run env PATH="$stub:$PATH" "$RENDER" --names
	[ "$status" -eq 0 ]
	[[ "$output" == reference=* ]]
	[ ! -f "$BATS_TEST_TMPDIR/cargo-was-called" ]
	[ ! -d "$OUT" ]
}

@test "an unrecognised argument is a usage error, not a silent render" {
	run "$RENDER" v0.0.1
	[ "$status" -eq 1 ]
	[[ "$output" == *"takes no arguments"* ]]
	[ ! -f "$OUT/batten-cli-reference.md" ]
}

@test "the render writes the reference and names it on stdout" {
	run "$RENDER"
	[ "$status" -eq 0 ]
	[ "$output" = "reference=$OUT/batten-cli-reference.md" ]
	[ -s "$OUT/batten-cli-reference.md" ]
}

@test "the KEY=VALUE line is the only thing on stdout" {
	# The release workflow appends this straight to \$GITHUB_OUTPUT, so a second
	# line would become a second output — or corrupt the file.
	run "$RENDER"
	[ "$status" -eq 0 ]
	[ "${#lines[@]}" -eq 1 ]
}

@test "a render that emits nothing is a failure, not an empty artifact" {
	# The failure a publish step structurally cannot see: an empty file uploads
	# exactly as well as a full one, and the release then carries a reference
	# that says nothing.
	stub="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$stub"
	printf '#!/usr/bin/env bash\nexit 0\n' >"$stub/cargo"
	chmod +x "$stub/cargo"
	run env PATH="$stub:$PATH" "$RENDER"
	[ "$status" -eq 1 ]
	[[ "$output" == *"rendered empty"* ]]
	[ ! -f "$OUT/batten-cli-reference.md" ]
}

@test "a failed render leaves no artifact behind" {
	# Rendered into a scratch file and moved on success, so a failure cannot
	# leave a truncated file that every later step treats as the artifact.
	printf 'a previous good render\n' >"$OUT/batten-cli-reference.md" 2>/dev/null || {
		mkdir -p "$OUT"
		printf 'a previous good render\n' >"$OUT/batten-cli-reference.md"
	}
	stub="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$stub"
	printf '#!/usr/bin/env bash\nexit 3\n' >"$stub/cargo"
	chmod +x "$stub/cargo"
	run env PATH="$stub:$PATH" "$RENDER"
	[ "$status" -eq 1 ]
	[ "$(cat "$OUT/batten-cli-reference.md")" = "a previous good render" ]
}

@test "the reference is git-ignored, so it cannot be committed by accident" {
	# The design's load-bearing claim — "never committed" — stated as a property
	# of .gitignore rather than of anyone's discipline.
	unset RENDER_CLI_OUT_DIR
	names=$("$RENDER" --names)
	run git -C "$REPO" check-ignore -q "${names#reference=}"
	[ "$status" -eq 0 ]
}

@test "this repo's surface renders — the task on the real tree" {
	unset RENDER_CLI_OUT_DIR
	run "$RENDER"
	[ "$status" -eq 0 ]
	[[ "$output" == reference=* ]]
}

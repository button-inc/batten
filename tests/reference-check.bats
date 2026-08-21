#!/usr/bin/env bats
# subject: mise-tasks/reference-check
# reference-check's decision table (CLOUD-171): do the rendered CLI reference and
# the command spec name exactly the same flags, in both directions?
#
# The gate renders the reference itself, so a fixture cannot supply a doctored
# one by writing a file — there is nothing on disk for it to read. What CAN be
# doctored is the render, so most cases stub `mise-tasks/render/cli` with a
# script that emits a reference of the suite's choosing, and the gate is pointed
# at that copy of the task directory.
#
# Both violation directions get a case, because they are different failures: a
# flag the surface declares and the reference omits tells a reader it does not
# exist; a flag the reference names and the surface lacks tells them to type
# something that will not parse.
#
# The last case drops the stub and runs against the real repository, so the
# suite also asserts the committed surface and its renderer still agree.

setup() {
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	REAL="$REPO/mise-tasks/reference-check"
	export CARGO_TARGET_DIR="$REPO/target"

	# A copy of the task dir whose `render/cli` the suite controls. The gate
	# resolves its sibling from its own dirname, so copying the checked file
	# beside a stubbed renderer is what swaps one out.
	TASKS="$BATS_TEST_TMPDIR/mise-tasks"
	mkdir -p "$TASKS/render"
	cp "$REAL" "$TASKS/reference-check"
	CHECK="$TASKS/reference-check"
	export REFERENCE_ROOT="$REPO"
}

# Write a stub renderer that answers --names and emits $1 as the reference body.
stub_render() {
	cat >"$TASKS/render/cli" <<-STUB
		#!/usr/bin/env bash
		set -euo pipefail
		out="\${RENDER_CLI_OUT_DIR:-reference}/batten-cli-reference.md"
		if [ "\${1:-}" = "--names" ]; then echo "reference=\$out"; exit 0; fi
		mkdir -p "\$(dirname "\$out")"
		cat >"\$out" <<'BODY'
		$1
		BODY
		echo "reference=\$out"
	STUB
	chmod +x "$TASKS/render/cli"
}

# Every flag the real surface declares, rendered as the table rows the gate
# parses — the honest reference, which the doctored cases then perturb.
full_reference() {
	local rows
	rows=$(cargo run --quiet -p batten -- spec --format json |
		jq -r '[recurse(.subcommands[]?) | .flags[]?.name] | unique | .[] | "| `" + . + "` | x | x | x | x |"')
	printf '| Name | Long | Short | Takes a value | Description |\n%s\n' "$rows"
}

@test "a reference naming every declared flag passes" {
	stub_render "$(full_reference)"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"name the same"* ]]
}

@test "a flag the reference omits is reported with its name" {
	# The reader is told a flag does not exist.
	stub_render "$(full_reference | grep -v '`json`')"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"json reference-omits-flag"* ]]
}

@test "a flag the reference invents is reported with its name" {
	# The direction a "did we document everything" check misses entirely: the
	# reader is told to type something that will not parse.
	stub_render "$(
		full_reference
		printf '| `no-such-flag` | x | x | x | x |\n'
	)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-such-flag reference-invents-flag"* ]]
}

@test "both directions are reported in one run, not just the first" {
	stub_render "$(
		full_reference | grep -v '`json`'
		printf '| `no-such-flag` | x | x | x | x |\n'
	)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"reference-omits-flag"* ]]
	[[ "$output" == *"reference-invents-flag"* ]]
}

@test "output is pointer-only — no line of the reference echoed" {
	stub_render "$(
		full_reference
		printf '| `no-such-flag` | a very distinctive invented description | x | x | x |\n'
	)"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"a very distinctive invented description"* ]]
}

@test "a reference naming no flags at all is could-not-look, never a pass" {
	# A parser pointed at the wrong shape reads as full coverage of nothing.
	# That must be exit 2, not exit 0 and not exit 1.
	stub_render "nothing here resembles a flag table"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"names no flags at all"* ]]
}

@test "a renderer that fails is could-not-look, never a pass" {
	cat >"$TASKS/render/cli" <<-'STUB'
		#!/usr/bin/env bash
		if [ "${1:-}" = "--names" ]; then echo "reference=reference/batten-cli-reference.md"; exit 0; fi
		exit 1
	STUB
	chmod +x "$TASKS/render/cli"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not be rendered"* ]]
}

@test "an absent renderer is could-not-look, never a pass" {
	rm -f "$TASKS/render/cli"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot run"* ]]
}

@test "the gate leaves no reference behind in the tree it judges" {
	# It renders to compare, which is exactly the shape `derived-check`'s header
	# refuses to let a gate do to the tree it is judging.
	stub_render "$(full_reference)"
	rm -rf "$REPO/reference"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[ ! -e "$REPO/reference/batten-cli-reference.md" ]
}

@test "this repo's reference covers its surface — the gate on the real tree" {
	run "$REAL"
	[ "$status" -eq 0 ]
}

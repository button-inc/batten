#!/usr/bin/env bats
# derived-check's decision table (CLOUD-27, CLOUD-69): does every committed
# artifact derived from the command surface — the shell completions and the man
# pages — still match what the binary emits?
#
# The gate has to run `cargo run`, so a fixture cannot be a bare directory — it
# needs a real workspace. Each fixture is therefore a scratch root that symlinks
# the manifest and sources of the real repo and holds its *own* copies of
# `completions/` and `man/`, which are the only things a test mutates.
# CARGO_TARGET_DIR points back at the real target dir so the fixture compiles
# nothing the suite has not already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/derived-check"
	PAGES="$BATS_TEST_DIRNAME/../mise-tasks/man-pages"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp -R "$REPO/completions" "$ROOT/completions"
	cp -R "$REPO/man" "$ROOT/man"
	export DERIVED_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "committed artifacts matching the surface exit 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"committed artifacts match the surface"* ]]
}

@test "a drifted completion is reported with a pointer" {
	printf 'complete -c batten -l invented-flag\n' >>"$ROOT/completions/batten.fish"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"completions/batten.fish:0 derived-drift"* ]]
}

@test "a drifted man page is reported with a pointer" {
	# The half that did not exist before CLOUD-69: the gate covered a third of
	# what house-style §11 claims, so a man page could say anything.
	printf '.SH INVENTED\n' >>"$ROOT/man/batten-check.1"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"man/batten-check.1:0 derived-drift"* ]]
}

@test "a missing artifact is reported rather than silently skipped" {
	# The failure this catches: a shell or a verb dropped from the committed set
	# while the loop still claims to cover it. Absent must be a violation, never
	# a no-op.
	rm -f "$ROOT/completions/batten.zsh"
	rm -f "$ROOT/man/batten-spec.1"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"completions/batten.zsh:0 derived-missing"* ]]
	[[ "$output" == *"man/batten-spec.1:0 derived-missing"* ]]
}

@test "a page the surface no longer derives is reported as an orphan" {
	# The direction a per-artifact diff structurally cannot see. Removing a verb
	# deletes its row from the derived list and leaves its page on disk, still
	# installable and still documenting a command that no longer parses — and
	# every byte-for-byte comparison above passes, because nothing asks about it.
	touch "$ROOT/man/batten-removed-verb.1"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"man/batten-removed-verb.1:0 derived-orphan"* ]]
}

@test "output is pointer-only — no artifact body echoed" {
	printf 'complete -c batten -l a-very-distinctive-invented-flag\n' >>"$ROOT/completions/batten.fish"
	printf '.SH A-VERY-DISTINCTIVE-INVENTED-SECTION\n' >>"$ROOT/man/batten-doctor.1"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"a-very-distinctive-invented-flag"* ]]
	[[ "$output" != *"A-VERY-DISTINCTIVE-INVENTED-SECTION"* ]]
}

@test "the gate leaves the tree it judges unmodified" {
	# A gate that rewrites what it is judging cannot fail twice: the second run
	# would pass, laundering the drift into a clean result.
	printf 'complete -c batten -l invented-flag\n' >>"$ROOT/completions/batten.fish"
	before="$(cat "$ROOT/completions/batten.fish")"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[ "$(cat "$ROOT/completions/batten.fish")" = "$before" ]
	run "$CHECK"
	[ "$status" -eq 1 ]
}

@test "every committed page's filename matches the .TH title inside it" {
	# The two authorities for a page's name are the shell rule in `man-pages`
	# (which decides the FILE) and `render::page_name` in the binary (which
	# decides the `.TH` TITLE). man(1) resolves a page by its title, so a
	# disagreement means `man batten-config-show` finds nothing while both sides
	# report green. This is the gate on the pair rather than the intention.
	for page in "$ROOT"/man/*.1; do
		title=$(sed -n 's/^\.TH \([^ ]*\) .*/\1/p' "$page" | head -n1)
		[ "$title" = "$(basename "$page" .1)" ]
	done
}

@test "the derived page list names the root page with an empty command path" {
	# The root page is asked for by `batten generate man` with NO argument, so
	# its row must carry an empty path — an empty *token* would be a path that
	# names no command and the render would fail.
	run env MAN_PAGES_ROOT="$ROOT" "$PAGES"
	[ "$status" -eq 0 ]
	[[ "${lines[0]}" == "man/batten.1"$'\t' ]]
	[[ "$output" == *"man/batten-config-show.1"$'\t'"config show"* ]]
}

@test "this repo's committed artifacts match its surface — the gate on the real tree" {
	# The self-consumption case: run against the actual repository, so the suite
	# also asserts the committed artifacts are current.
	unset DERIVED_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}

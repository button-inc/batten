#!/usr/bin/env bats
# The producer half of CLOUD-278: the manifest a release publishes, hashed from
# the release's own assets read back after upload.
#
# The properties that matter are the ones a packager depends on. The manifest is
# consumable by the ordinary tool with no flags (`sha256sum -c`), it is a
# function of the release rather than of who cut it (two runs, identical bytes),
# it never hashes itself, and it is never written empty — a manifest covering
# nothing is indistinguishable from no manifest, and publishing one would satisfy
# every name-level check while pinning not a single byte.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/checksums"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH
	# Out of tree: the task writes, and a suite that writes the tree it is run
	# from leaves the next gate judging its own leftovers.
	export CHECKSUMS_OUT_DIR="$BATS_TEST_TMPDIR/out"
	RELEASE="$BATS_TEST_TMPDIR/release"
	mkdir -p "$RELEASE"
	cd "$BATS_TEST_TMPDIR" || return 1
}

# `gh release download` copies the fixture release into --dir; anything else
# answers the tag name. A case that wants either to fail says so.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
[ ! -f "$BATS_TEST_TMPDIR/gh.fails" ] || exit 1
case "\$*" in
  *"release download"*)
    [ ! -f "$BATS_TEST_TMPDIR/download.fails" ] || exit 1
    dir=""
    while [ \$# -gt 0 ]; do
      [ "\$1" != --dir ] || dir="\$2"
      shift
    done
    mkdir -p "\$dir"
    cp "$RELEASE"/. "\$dir/" -R
    ;;
  *tagName*) printf 'v9.9.9\n' ;;
esac
EOF
	chmod +x "$STUB/gh"
	local name
	for name in "$@"; do
		printf 'bytes of %s\n' "$name" >"$RELEASE/$name"
	done
}

release() {
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json
}

@test "--names answers with no tag, no network and no download" {
	# The gate asks this to learn the asset name. It must cost nothing and work
	# from anywhere, so it is answered before the tag lookup — with no gh on PATH
	# at all here, which is the strongest form of that assertion.
	run "$TASK" --names
	[ "$status" -eq 0 ]
	[ "$output" = "sums=$CHECKSUMS_OUT_DIR/SHA256SUMS" ]
}

@test "the manifest covers every asset the release carries" {
	release
	# stderr dropped deliberately: stdout is appended straight to $GITHUB_OUTPUT,
	# so "only the KEY=VALUE line" is the property, not "it appears somewhere".
	run bash -c "'$TASK' v9.9.9 2>/dev/null"
	[ "$status" -eq 0 ]
	[ "$output" = "sums=$CHECKSUMS_OUT_DIR/SHA256SUMS" ]
	run wc -l <"$CHECKSUMS_OUT_DIR/SHA256SUMS"
	[ "$output" -eq 3 ]
	grep -qF 'batten.schema.json' "$CHECKSUMS_OUT_DIR/SHA256SUMS"
}

@test "the manifest never lists itself" {
	# A release already carrying a manifest is the ordinary case — every re-run
	# after the first. Hashing the previous run's output would make the file
	# unreproducible from the release it describes.
	release
	printf 'a stale manifest\n' >"$RELEASE/SHA256SUMS"
	run "$TASK" v9.9.9
	[ "$status" -eq 0 ]
	run grep -c SHA256SUMS "$CHECKSUMS_OUT_DIR/SHA256SUMS"
	[ "$status" -eq 1 ]
}

@test "two runs over one release produce identical bytes" {
	# What makes the published artifact a function of the release rather than of
	# when or where it was cut: LC_ALL=C ordering, and nothing else in the file.
	release
	run "$TASK" v9.9.9
	[ "$status" -eq 0 ]
	cp "$CHECKSUMS_OUT_DIR/SHA256SUMS" "$BATS_TEST_TMPDIR/first"
	run "$TASK" v9.9.9
	[ "$status" -eq 0 ]
	cmp "$BATS_TEST_TMPDIR/first" "$CHECKSUMS_OUT_DIR/SHA256SUMS"
}

@test "sha256sum -c accepts the manifest with no flags, in a directory of assets" {
	# The acceptance criterion, and the reason the format is sha256sum's own
	# rather than anything this repo invented: a Homebrew formula, an aqua entry
	# and a hand-downloading adopter all reach for the ordinary tool.
	release
	run "$TASK" v9.9.9
	[ "$status" -eq 0 ]
	cp "$CHECKSUMS_OUT_DIR/SHA256SUMS" "$RELEASE/"
	run bash -c "cd '$RELEASE' && sha256sum -c SHA256SUMS"
	[ "$status" -eq 0 ]
}

@test "corrupting one byte of one asset makes that check fail" {
	release
	run "$TASK" v9.9.9
	[ "$status" -eq 0 ]
	cp "$CHECKSUMS_OUT_DIR/SHA256SUMS" "$RELEASE/"
	printf 'tampered\n' >"$RELEASE/batten.schema.json"
	run bash -c "cd '$RELEASE' && sha256sum -c SHA256SUMS"
	[ "$status" -ne 0 ]
	[[ "$output" == *"batten.schema.json"* ]]
}

@test "a release carrying no assets writes no manifest" {
	# A manifest covering nothing satisfies every name-level check while pinning
	# nothing — the vacuous pass, in its producer-side disguise.
	stub_gh
	run "$TASK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"indistinguishable from no manifest"* ]]
	[ ! -f "$CHECKSUMS_OUT_DIR/SHA256SUMS" ]
}

@test "an unreadable release exits 2, not 1" {
	# Could-not-look is not a verdict: this runs on the release path, where a
	# transient failure must not be recorded as a release with nothing in it.
	release
	: >"$BATS_TEST_TMPDIR/download.fails"
	run "$TASK" v9.9.9
	[ "$status" -eq 2 ]
	[[ "$output" == *"lookup failure"* ]]
}

@test "no tag given falls back to the latest release" {
	release
	run "$TASK"
	[ "$status" -eq 0 ]
	[ -f "$CHECKSUMS_OUT_DIR/SHA256SUMS" ]
}

@test "an EMPTY tag argument falls back too, which is what the workflow passes" {
	# The release job passes "$TAG" quoted, so the argument always arrives — as an
	# empty string on any path where the input is unset.
	release
	run "$TASK" ""
	[ "$status" -eq 0 ]
	[ -f "$CHECKSUMS_OUT_DIR/SHA256SUMS" ]
}

@test "no tag resolvable exits 2 rather than hashing nothing" {
	release
	: >"$BATS_TEST_TMPDIR/gh.fails"
	run "$TASK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no tag given"* ]]
}

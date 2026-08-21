#!/usr/bin/env bats
# subject: mise-tasks/release-assets-check
# The gate that ships with CLOUD-258's fix: a release must carry one archive per
# target the dist matrix builds.
#
# Both directions matter, and so does the third. A missing archive is exit 1 —
# the board is behind reality. An unreadable release or matrix is exit 2 — "I
# could not look" — because reporting a shipping release as broken on a network
# blip is the failure mode that gets a scheduled gate switched off.

setup() {
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
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
		        run: gh release upload "$TAG" schema/batten.schema.json schema/batten.local.schema.json "$SPDX" "$CDX" --clobber
	EOF
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# `gh release view --json assets` answers with the named asset list, `gh release
# download` copies the fixture release into --dir, and anything else answers the
# tag name. A case that wants either lookup to fail says so.
#
# The fixture release is a DIRECTORY OF REAL FILES, not merely a name list
# (CLOUD-278): the manifest rules hash bytes, so a stub that could only answer
# names would leave the half that reads them untested.
stub_gh() {
	RELEASE="$BATS_TEST_TMPDIR/release"
	rm -rf "$RELEASE"
	mkdir -p "$RELEASE"
	local name
	for name in "$@"; do
		printf 'bytes of %s\n' "$name" >"$RELEASE/$name"
	done
	printf '%s\n' "$@" >"$BATS_TEST_TMPDIR/assets"
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
    cp "$RELEASE"/* "\$dir/"
    ;;
  *tagName*) printf 'v9.9.9\n' ;;
  *assets*)  cat "$BATS_TEST_TMPDIR/assets" ;;
esac
EOF
	chmod +x "$STUB/gh"
}

# The manifest the release job publishes: `sha256sum` over the release's own
# assets, attached as one more asset. Named arguments override the default of
# "everything the release currently carries".
add_manifest() {
	local names=("$@")
	if [ "${#names[@]}" -eq 0 ]; then
		mapfile -t names < <(LC_ALL=C sort "$BATS_TEST_TMPDIR/assets")
	fi
	(cd "$RELEASE" && LC_ALL=C sha256sum -- "${names[@]}" >SHA256SUMS)
	grep -qxF SHA256SUMS "$BATS_TEST_TMPDIR/assets" ||
		printf 'SHA256SUMS\n' >>"$BATS_TEST_TMPDIR/assets"
}

# An entry for a file the release does not carry. Hand-written rather than
# hashed, because the whole point is that the named bytes are not there.
add_manifest_entry() {
	printf '%064d  %s\n' 0 "$1" >>"$RELEASE/SHA256SUMS"
}

# The per-target binary SBOM one composed leg publishes (CLOUD-263), DERIVED the
# way the gate derives it rather than spelled out: the name carries the crate
# version, so a literal here would rot at the next release bump — the same reason
# the matrix above is read from the workflow instead of restated.
binary_sbom() { # $1 = target
	"$BATS_TEST_DIRNAME/../mise-tasks/sbom-binary" --names "$1" | sed -nE 's#^sbom=.*/##p'
}

complete() {
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json \
		batten.local.schema.json \
		batten.spdx.json \
		batten.cdx.json \
		batten-cli-reference.md \
		"$(binary_sbom x86_64-unknown-linux-gnu)" \
		"$(binary_sbom aarch64-apple-darwin)"
	add_manifest
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

@test "THE CLOUD-262 GAP: every archive present but no SBOM still fails" {
	# The non-target assets had no coverage at all: the schema has shipped since
	# CLOUD-33 with nothing asserting it arrived, and the SBOM would have inherited
	# the same blindness. A release can be complete per-target and still be missing
	# everything that is not per-target.
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json \
		batten.local.schema.json \
		"$(binary_sbom x86_64-unknown-linux-gnu)" \
		"$(binary_sbom aarch64-apple-darwin)"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.spdx.json"* ]]
	[[ "$output" == *"batten.cdx.json"* ]]
	[[ "$output" == *"3 of 7 non-target assets"* ]]
	# The per-target half must stay clean — the two failures are independent.
	[[ "$output" != *"targets have no asset"* ]]
}

@test "the non-target list comes from BOTH sources, not just one" {
	# Both schemas are literal operands on the upload line; the two SBOM names come
	# from `sbom --names`. If either source silently produced nothing, this release
	# would pass while missing an asset.
	#
	# EVERY literal, not the first one: the scrape splits the line on spaces, so a
	# parser that stopped at one operand would still satisfy every assertion this
	# suite made before the override schema joined it (CLOUD-33).
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.schema.json"* ]]
	[[ "$output" == *"batten.local.schema.json"* ]]
	[[ "$output" == *"batten.spdx.json"* ]]
	[[ "$output" == *"batten-cli-reference.md"* ]]
	[[ "$output" == *"7 of 7 non-target assets"* ]]
}

@test "an upload line the parser cannot read exits 2 rather than covering nothing" {
	# The half that can silently go to zero. Reformat the upload line and the
	# schema stops being demanded, with a green result to say everything is fine.
	complete
	sed_i '/gh release upload/d' "$BATTEN_RELEASE_WORKFLOW"
	run "$CHECK" v9.9.9
	[ "$status" -eq 2 ]
	[[ "$output" == *"must not report green"* ]]
}

@test "an asset name that contains another's does not satisfy it" {
	# The non-target half matches with -x for this reason: the per-target half
	# matches on a substring, and reusing that here would let
	# `batten.spdx.json.sig` stand in for `batten.spdx.json`.
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json \
		batten.local.schema.json \
		batten.spdx.json.sig \
		batten.cdx.json \
		batten-cli-reference.md
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.spdx.json"* ]]
}

@test "the authority schema does not stand in for the override schema" {
	# The pair CLOUD-33 shipped one half of. `-x` is what keeps them distinct:
	# `batten.schema.json` is a proper substring of nothing here, but
	# `batten.local.schema.json` contains `schema.json`, and a substring match
	# in either direction would let one published artifact answer for two.
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json \
		batten.spdx.json \
		batten.cdx.json \
		batten-cli-reference.md \
		"$(binary_sbom x86_64-unknown-linux-gnu)" \
		"$(binary_sbom aarch64-apple-darwin)"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.local.schema.json"* ]]
	[[ "$output" == *"1 of 7 non-target assets"* ]]
}

@test "the real workflow publishes the non-target assets this gate derives" {
	# The fixtures prove the logic; this proves it is pointed at the committed
	# workflow's actual shape, so the suite cannot pass while production derives
	# an empty list.
	#
	# BOTH schemas by name (CLOUD-33). `mise run schema` writes two artifacts and
	# the upload line published one of them for the whole life of CLOUD-239's
	# split — a gate deriving its expectations FROM that line could not notice,
	# because an asset never uploaded is never expected. Naming them here is what
	# turns "whatever the workflow uploads" into "these two, or fail".
	unset BATTEN_RELEASE_WORKFLOW
	run bash -c "grep -F 'gh release upload' .github/workflows/release-artifacts.yml | tr ' ' '\n' | sed -nE 's#^\"?([A-Za-z0-9_./-]+\.json)\"?\$#\1#p' | sed 's#^.*/##' | sort -u"
	[ "$status" -eq 0 ]
	[[ "$output" == *"batten.schema.json"* ]]
	[[ "$output" == *"batten.local.schema.json"* ]]
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

# --- the checksum manifest (CLOUD-278) ---------------------------------------

@test "a complete release with a valid manifest reports the verified count" {
	complete
	run "$CHECK" v9.9.9
	[ "$status" -eq 0 ]
	[[ "$output" == *"manifest covering all 9 asset(s) (sha256 verified)"* ]]
}

@test "THE CLOUD-278 GAP: every asset present but no manifest fails" {
	# What every release carried before this: seven archives, a schema, two SBOM
	# documents, and no checksum of any kind — so no packaging channel could pin
	# a single one of them.
	stub_gh batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.schema.json \
		batten.local.schema.json \
		batten.spdx.json \
		batten.cdx.json \
		batten-cli-reference.md \
		"$(binary_sbom x86_64-unknown-linux-gnu)" \
		"$(binary_sbom aarch64-apple-darwin)"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"SHA256SUMS checksums-missing"* ]]
	# The other two halves must stay clean — this release is complete but unpinned.
	[[ "$output" != *"targets have no asset"* ]]
	[[ "$output" != *"non-target assets are absent"* ]]
}

@test "a manifest that omits an asset the release carries fails, naming only it" {
	complete
	# Re-cut the manifest over everything but the schema, the way a manifest
	# written before a later job's upload would read.
	add_manifest batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz \
		batten-9.9.9-aarch64-apple-darwin.tar.gz \
		batten.local.schema.json \
		batten.spdx.json \
		batten.cdx.json \
		batten-cli-reference.md \
		"$(binary_sbom x86_64-unknown-linux-gnu)" \
		"$(binary_sbom aarch64-apple-darwin)"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten.schema.json checksums-omits"* ]]
	[[ "$output" != *"batten.cdx.json checksums-omits"* ]]
	[[ "$output" == *"1 checksum-manifest violation(s)"* ]]
}

@test "a manifest entry naming no asset on the release fails" {
	# The stale-manifest shape: a per-target workflow_dispatch re-run renames an
	# archive and the manifest keeps describing the set it was cut over.
	complete
	add_manifest_entry batten-9.9.9-x86_64-pc-windows-gnu.zip
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten-9.9.9-x86_64-pc-windows-gnu.zip checksums-orphan"* ]]
}

@test "a manifest whose only entry is itself is the vacuous case, not a pass" {
	# With the manifest excluded from both sides this leaves nothing to compare,
	# and a release carrying nothing else would agree with it perfectly.
	complete
	printf '%064d  SHA256SUMS\n' 0 >"$RELEASE/SHA256SUMS"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"SHA256SUMS checksums-self"* ]]
	[[ "$output" == *"SHA256SUMS checksums-empty"* ]]
	[[ "$output" == *"covers nothing"* ]]
}

@test "corrupting one byte of one asset fails, naming only that asset" {
	# The acceptance criterion, asserted over THIS gate rather than over
	# sha256sum: names alone would still agree, so only reading the bytes catches
	# an asset replaced by a --clobber re-upload after the manifest was cut.
	complete
	printf 'tampered\n' >"$RELEASE/batten-9.9.9-aarch64-apple-darwin.tar.gz"
	run "$CHECK" v9.9.9
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten-9.9.9-aarch64-apple-darwin.tar.gz checksums-mismatch"* ]]
	[[ "$output" != *"x86_64-unknown-linux-gnu.tar.gz checksums-mismatch"* ]]
	[[ "$output" == *"1 checksum-manifest violation(s)"* ]]
}

@test "a download that fails exits 2 — could not look is not a verdict" {
	# Same distinction the release lookup already draws: reporting a shipping
	# release as corrupt on a network blip is what gets a scheduled gate ignored.
	complete
	: >"$BATS_TEST_TMPDIR/download.fails"
	run "$CHECK" v9.9.9
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
}

@test "the manifest name comes from checksums --names, not from this gate" {
	# One authority for the name. The literal scrape recognises `.json` operands
	# only, so widening it to admit an extensionless asset was the alternative
	# this deliberately avoids.
	run mise-tasks/checksums --names
	[ "$status" -eq 0 ]
	[ "$output" = "sums=checksums/SHA256SUMS" ]
}

@test "the real workflow publishes the manifest this gate demands" {
	# The fixtures prove the logic; this proves production actually uploads it, so
	# the suite cannot pass while every release ships unpinned.
	run grep -c 'mise run checksums' .github/workflows/release-artifacts.yml
	[ "$status" -eq 0 ]
	[ "$output" -ge 1 ]
	run grep -F 'gh release upload "$TAG" "$SUMS" --clobber' .github/workflows/release-artifacts.yml
	[ "$status" -eq 0 ]
}

@test "the manifest job runs after everything that uploads an asset" {
	# It hashes the release's own assets read back after upload, so a job that
	# published after it would be left uncovered with nothing to say so.
	run sed -nE 's/^[[:space:]]*needs:[[:space:]]*(.+)$/\1/p' .github/workflows/release-artifacts.yml
	[ "$status" -eq 0 ]
	[[ "$output" == *"dist"* ]]
	[[ "$output" == *"schema"* ]]
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

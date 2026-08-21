#!/usr/bin/env bats
# subject: mise-tasks/sbom-binary.sh
# sbom-binary's decision table (CLOUD-263). The case that carries the design is
# `THE NEGATIVE SELF-TEST`: an inventory of a binary that carries no dependency
# data is an empty document that exits 0, which is the vacuous green CLOUD-258
# taught this repo to distrust — so the count assertion is what the gate IS, and
# a widened one would pass every unwrapped build forever.
#
# Driven against a stubbed `syft` rather than the real one for the reason the
# acceptance names: the real tool cannot be made to return a chosen count, so
# nothing would prove the bar is `> 1` rather than `>= 0`. The real path is
# covered by the release legs themselves and was measured by hand on a
# `mise run dist` binary (85 packages) before this suite was written.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/sbom-binary.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	printf 'version = "9.9.9"\n' >"$ROOT/Cargo.toml"
	lockfile
	printf 'binary bytes\n' >"$ROOT/batten"
	export SBOM_BINARY_ROOT="$ROOT"
	export SBOM_BINARY_OUT_DIR="$ROOT/dist"

	echo 2 >"$BATS_TEST_TMPDIR/count"
	stub_syft
}

# A Cargo.lock declaring the crates the stub recovers, plus one it does not: the
# subset bound must pass while the lockfile is strictly larger, which is the real
# shape (189 declared against 85 recovered, measured).
lockfile() {
	{
		printf '[[package]]\nname = "alpha"\nversion = "1.0.0"\n\n'
		printf '[[package]]\nname = "beta"\nversion = "2.0.0"\n\n'
		printf '[[package]]\nname = "only-a-dev-dependency"\nversion = "3.0.0"\n\n'
	} >"$ROOT/Cargo.lock"
}

# A `syft` that writes both outputs and recovers `count` rust-crate artifacts.
# Sentinels:
#   syft.fails   exit non-zero, so nothing can be judged
#   syft.foreign the last recovered crate is absent from Cargo.lock
#   syft.file    also emit a non-rust-crate artifact for the binary itself, which
#                is what makes an unfiltered count read 1 on an empty binary
stub_syft() {
	cat >"$STUB/syft" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[ ! -f "$BATS_TEST_TMPDIR/syft.fails" ] || exit 1

spdx=""
scan=""
want=0
for arg in "\$@"; do
	if [ "\$want" = 1 ]; then
		case "\$arg" in
		spdx-json=*) spdx="\${arg#spdx-json=}" ;;
		syft-json=*) scan="\${arg#syft-json=}" ;;
		esac
		want=0
		continue
	fi
	[ "\$arg" = "--output" ] && want=1
done

n=\$(cat "$BATS_TEST_TMPDIR/count")
names=(alpha beta)
versions=(1.0.0 2.0.0)
if [ -f "$BATS_TEST_TMPDIR/syft.foreign" ]; then
	names=(alpha not-in-the-lockfile)
fi

artifacts=""
i=0
while [ "\$i" -lt "\$n" ]; do
	[ -z "\$artifacts" ] || artifacts="\$artifacts,"
	artifacts="\$artifacts{\"name\":\"\${names[\$i]}\",\"version\":\"\${versions[\$i]}\",\"type\":\"rust-crate\"}"
	i=\$((i + 1))
done
if [ -f "$BATS_TEST_TMPDIR/syft.file" ]; then
	[ -z "\$artifacts" ] || artifacts="\$artifacts,"
	artifacts="\$artifacts{\"name\":\"batten\",\"version\":\"9.9.9\",\"type\":\"binary\"}"
fi

mkdir -p "\$(dirname "\$spdx")" "\$(dirname "\$scan")"
echo "{\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"batten\",\"packages\":[]}" >"\$spdx"
echo "{\"artifacts\":[\$artifacts]}" >"\$scan"
EOF
	chmod +x "$STUB/syft"
}

asset() { echo "$ROOT/dist/batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"; }

@test "a binary whose crates are all in the lockfile passes, and writes the asset" {
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 0 ]
	[[ "$output" == *"packages=2"* ]]
	[ -f "$(asset)" ]
}

@test "THE NEGATIVE SELF-TEST: an empty inventory must not report green" {
	# A build that lost its `cargo auditable` wrapper recovers zero rust-crate
	# packages — measured on a plain `--profile dist` binary — and the document is
	# still valid, still parses, and still exits 0 from syft.
	echo 0 >"$BATS_TEST_TMPDIR/count"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-binary-vacuous"* ]]
	[[ "$output" == *"(0 rust-crate"* ]]
}

@test "ONE package is the other vacuous shape, and also fails" {
	# The binary cataloging only itself. The issue predicted this count; the
	# measurement found 0 instead, and both must fail or the bar means nothing.
	echo 1 >"$BATS_TEST_TMPDIR/count"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-binary-vacuous"* ]]
}

@test "the count is filtered to rust-crate, so a self-artifact cannot pad it" {
	# syft reports the scanned FILE as an artifact on some inputs. Counting every
	# artifact would read 1 on a binary with no dependency data — the vacuous case
	# wearing a passing number.
	echo 0 >"$BATS_TEST_TMPDIR/count"
	: >"$BATS_TEST_TMPDIR/syft.file"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-binary-vacuous"* ]]
}

@test "a refused inventory leaves no asset behind" {
	# The asset is a release artifact. Publishing one the gate refused would put
	# the document a consumer reads outside what any check ever approved.
	echo 0 >"$BATS_TEST_TMPDIR/count"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 1 ]
	[ ! -f "$(asset)" ]
}

@test "a crate absent from Cargo.lock fails, naming counts and not the crate" {
	: >"$BATS_TEST_TMPDIR/syft.foreign"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 1 ]
	[[ "$output" == *"sbom-binary-foreign"* ]]
	[[ "$output" == *"1 of 2"* ]]
	# rule 4: a package name is document content.
	[[ "$output" != *"not-in-the-lockfile"* ]]
}

@test "SUBSET, NOT EQUALITY: a lockfile larger than the recovery passes" {
	# The lockfile spans build- and dev-dependencies for every target while the
	# audit section records only what was linked for the one target built — 189
	# against 85, measured. Equality would be wrong on every leg.
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 0 ]
}

@test "the asset name comes from dist's stem rule, so seven legs cannot race" {
	run "$CHECK" --names aarch64-apple-darwin
	[ "$status" -eq 0 ]
	[[ "$output" == *"batten-v9.9.9-aarch64-apple-darwin.spdx.json"* ]]
}

@test "output is pointer-only — no document body reaches the log" {
	: >"$BATS_TEST_TMPDIR/syft.foreign"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[[ "$output" != *"SPDXRef"* ]]
	[[ "$output" != *"rust-crate\""* ]]
}

@test "a syft that cannot run is exit 2 — could not look is not a verdict" {
	: >"$BATS_TEST_TMPDIR/syft.fails"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 2 ]
	[[ "$output" == *"unverified"* ]]
}

@test "a missing binary is exit 2, not a refusal of the release" {
	run "$CHECK" "$ROOT/no-such-binary" x86_64-unknown-linux-gnu
	[ "$status" -eq 2 ]
	[[ "$output" == *"nothing to inventory"* ]]
}

@test "a missing Cargo.lock is exit 2 — there is nothing to hold the crates against" {
	rm -f "$ROOT/Cargo.lock"
	run "$CHECK" "$ROOT/batten" x86_64-unknown-linux-gnu
	[ "$status" -eq 2 ]
	[[ "$output" == *"must not report green"* ]]
}

@test "no target is a usage error, never a pass" {
	run "$CHECK" "$ROOT/batten"
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
}

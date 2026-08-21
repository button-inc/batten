#!/usr/bin/env bats
# subject: install.sh
# The single-binary install path (CLOUD-65).
#
# The clause worth testing is the REFUSAL. An installer that verifies a digest
# when one is present and installs anyway when it is not has never verified
# anything, and that failure is invisible in the happy path — which is the only
# path anyone runs by hand. So every case below that ends in exit 1 also asserts
# that nothing reached the destination.
#
# The fixture API is a `file://` tree rather than a stubbed `curl`: the script's
# whole job is talking to an HTTP API, and stubbing the transport would leave
# its request shape, its redirect handling and its config-on-stdin token path
# untested while the suite went green. curl reads `file://` with the same
# `--config` machinery, so what runs here is the real code path minus the
# network.
#
# The payload shape is PRETTY-PRINTED, matching what api.github.com actually
# answers with (measured: 403 lines for v0.0.61). An earlier version of this
# script parsed the compact form and failed on the first real request, which is
# why the fixture commits to the awkward shape rather than the convenient one.

setup() {
	INSTALL="$BATS_TEST_DIRNAME/../install.sh"
	FIX="$BATS_TEST_TMPDIR/api"
	DEST="$BATS_TEST_TMPDIR/bin"
	TARGET=x86_64-unknown-linux-musl
	mkdir -p "$FIX/repos/button-inc/batten/releases/tags" "$FIX/releases/assets"

	# The payload a release carries: one archive holding `batten` at its root,
	# which is what `mise-tasks/dist.sh` produces.
	mkdir -p "$BATS_TEST_TMPDIR/stage"
	printf '#!/bin/sh\necho fixture-batten\n' >"$BATS_TEST_TMPDIR/stage/batten"
	tar -czf "$FIX/releases/assets/1" -C "$BATS_TEST_TMPDIR/stage" batten
	DIGEST=$(sha256sum "$FIX/releases/assets/1" | cut -d' ' -f1)

	export BATTEN_API="file://$FIX"
	export BATTEN_TARGET="$TARGET"
	export BATTEN_INSTALL_DIR="$DEST"
	# The token path is exercised by the fixtures that set it; unset here so a
	# leaked ambient credential cannot change a verdict.
	export BATTEN_GITHUB_TOKEN=""
	export GH_TOKEN=""
	export GITHUB_TOKEN=""
}

# Writes the release payload. `$1` is the digest to advertise for the asset —
# the empty string omits the field entirely, which is the "no digest" case.
release_json() {
	rj_digest_line=""
	[ -z "$1" ] || rj_digest_line="    \"digest\": \"sha256:$1\","
	cat >"$FIX/repos/button-inc/batten/releases/latest" <<EOF
{
  "url": "file://$FIX/releases/89",
  "tag_name": "v9.9.9",
  "author": {
    "login": "someone"
  },
  "assets": [
    {
      "url": "file://$FIX/releases/assets/1",
      "id": 1,
      "name": "batten-v9.9.9-$TARGET.tar.gz",
      "uploader": {
        "login": "someone"
      },
      "content_type": "application/gzip",
$rj_digest_line
      "browser_download_url": "file://$FIX/releases/download/v9.9.9/batten-v9.9.9-$TARGET.tar.gz"
    },
    {
      "url": "file://$FIX/releases/assets/2",
      "id": 2,
      "name": "batten-v9.9.9-aarch64-apple-darwin.tar.gz",
      "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
EOF
	cp "$FIX/repos/button-inc/batten/releases/latest" \
		"$FIX/repos/button-inc/batten/releases/tags/v9.9.9"
}

# --- the pure query surface, which is what install-check compares -------------

@test "--targets lists the targets a POSIX installer can serve" {
	run "$INSTALL" --targets
	[ "$status" -eq 0 ]
	[[ "$output" == *"x86_64-unknown-linux-musl"* ]]
	[[ "$output" == *"aarch64-apple-darwin"* ]]
	# Windows ships a .zip for a platform with no POSIX shell.
	[[ "$output" != *"windows"* ]]
}

@test "--asset-name is name-vversion-target with a per-target extension" {
	run "$INSTALL" --asset-name 1.2.3 x86_64-unknown-linux-musl
	[ "$status" -eq 0 ]
	[ "$output" = "batten-v1.2.3-x86_64-unknown-linux-musl.tar.gz" ]
	run "$INSTALL" --asset-name 1.2.3 x86_64-pc-windows-gnu
	[ "$status" -eq 0 ]
	[ "$output" = "batten-v1.2.3-x86_64-pc-windows-gnu.zip" ]
}

@test "the query flags install nothing" {
	release_json "$DIGEST"
	run "$INSTALL" --targets
	[ "$status" -eq 0 ]
	[ ! -e "$DEST/batten" ]
}

# --- the install path ---------------------------------------------------------

@test "a release whose digest matches installs the binary" {
	release_json "$DIGEST"
	run "$INSTALL"
	[ "$status" -eq 0 ]
	[[ "$output" == *"installed=$DEST/batten"* ]]
	[[ "$output" == *"version=v9.9.9"* ]]
	[[ "$output" == *"verified=sha256"* ]]
	[ -x "$DEST/batten" ]
	run "$DEST/batten"
	[ "$output" = "fixture-batten" ]
}

@test "BATTEN_VERSION selects a tag rather than the latest release" {
	release_json "$DIGEST"
	rm "$FIX/repos/button-inc/batten/releases/latest"
	BATTEN_VERSION=v9.9.9 run "$INSTALL"
	[ "$status" -eq 0 ]
	[ -x "$DEST/batten" ]
}

@test "THE DEFECT: a digest that does not match the bytes installs nothing" {
	release_json 0000000000000000000000000000000000000000000000000000000000000000
	run "$INSTALL"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sha256 mismatch"* ]]
	[ ! -e "$DEST/batten" ]
}

@test "THE DEFECT: an asset the API reports no digest for is refused, not installed unverified" {
	release_json ""
	run "$INSTALL"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no sha256 digest"* ]]
	[ ! -e "$DEST/batten" ]
}

@test "a release carrying no asset for this target is exit 1, naming the asset" {
	release_json "$DIGEST"
	BATTEN_TARGET=aarch64-unknown-linux-musl run "$INSTALL"
	[ "$status" -eq 1 ]
	[[ "$output" == *"batten-v9.9.9-aarch64-unknown-linux-musl.tar.gz"* ]]
	[ ! -e "$DEST/batten" ]
}

@test "a target no release leg builds is refused before any request" {
	release_json "$DIGEST"
	BATTEN_TARGET=sparc-unknown-none run "$INSTALL"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not one this script installs"* ]]
}

@test "an unreadable release is exit 2 — could not look, not a broken release" {
	run "$INSTALL"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read the release list"* ]]
	[ ! -e "$DEST/batten" ]
}

@test "a payload with no tag_name is exit 2, never a guessed version" {
	printf '{ "message": "Not Found" }\n' >"$FIX/repos/button-inc/batten/releases/latest"
	run "$INSTALL"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no tag_name"* ]]
}

@test "the compact payload shape parses too — neither wire form is assumed" {
	release_json "$DIGEST"
	compact=$(tr -d '\n' <"$FIX/repos/button-inc/batten/releases/latest" | sed 's/  */ /g')
	printf '%s\n' "$compact" >"$FIX/repos/button-inc/batten/releases/latest"
	run "$INSTALL"
	[ "$status" -eq 0 ]
	[ -x "$DEST/batten" ]
}

@test "--help explains the surface and exits 0" {
	run "$INSTALL" --help
	[ "$status" -eq 0 ]
	[[ "$output" == *"BATTEN_INSTALL_DIR"* ]]
}

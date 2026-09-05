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
	# ON PATH, because that is what a real install is: since the off-PATH case
	# became a refusal rather than a warning, a fixture installing somewhere
	# unreachable would exercise that refusal in every success case instead of the
	# success it means to assert. The case below that WANTS the refusal names its
	# own directory.
	mkdir -p "$DEST"
	PATH="$DEST:$PATH"
	export PATH
	# One attempt: a case asserting a refusal must not pay the backoff three times.
	export BATTEN_RETRIES=1
	# The token path is exercised by the fixtures that set it; unset here so a
	# leaked ambient credential cannot change a verdict.
	export BATTEN_GITHUB_TOKEN=""
	export GH_TOKEN=""
	export GITHUB_TOKEN=""
	export GITHUB_PERSONAL_ACCESS_TOKEN=""
	# Same reason, one variable class over: this container sets BOTH CA names, so a
	# case declaring one of them was reading the ambient other and asserting about
	# the environment rather than the fixture. Measured — it is what made the
	# SSL_CERT_FILE case fail while the CURL_CA_BUNDLE one passed.
	export CURL_CA_BUNDLE=""
	export SSL_CERT_FILE=""
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

@test "THE DEFECT: installing off PATH is a refusal, not a warning over exit 0" {
	# This printed to stderr and exited 0, which is the silent-absence case: a
	# container's setup step reports success, a hook registration naming `batten`
	# bare resolves to nothing, and the hook fails open — so an unreachable binary
	# and an absent one produce identical, quiet results. Every registration names
	# it bare, so a binary the shell cannot resolve is not an installed binary.
	release_json "$DIGEST"
	off="$BATS_TEST_TMPDIR/nowhere"
	BATTEN_INSTALL_DIR="$off" run "$INSTALL"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not on PATH"* ]]
	[[ "$output" == *"$off"* ]]
}

@test "the off-PATH refusal has an opt-out, for a deliberate destination" {
	# A staging directory, a container image layer, a package build: installing
	# somewhere unreachable on purpose is legitimate, and the refusal above must not
	# make it impossible — only silent-by-default impossible.
	release_json "$DIGEST"
	off="$BATS_TEST_TMPDIR/deliberate"
	BATTEN_INSTALL_DIR="$off" BATTEN_ALLOW_OFF_PATH=1 run "$INSTALL"
	[ "$status" -eq 0 ]
	[[ "$output" == *"installed=$off/batten"* ]]
	[ -x "$off/batten" ]
}

@test "a declared CA bundle reaches curl, for a proxy that re-terminates TLS" {
	# A corporate or agent proxy presents its own CA, so a bare curl cannot verify
	# the chain and the whole one-liner dies on a TLS error before anything is
	# fetched. Measured in one such container: with the bundle honoured the install
	# completes straight through the proxy with no NO_PROXY fencing at all.
	#
	# Asserted over the CONFIG curl receives, not over a transfer outcome: the
	# fixture API is a `file://` URL, so no TLS happens and a bogus bundle would
	# change nothing — a case built that way passes whether or not the value is ever
	# passed, which is the shape that cannot fail.
	release_json "$DIGEST"
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nexit 1\n' "$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	ca="$BATS_TEST_TMPDIR/proxy-ca.pem"
	printf 'ca bytes\n' >"$ca"
	PATH="$stub:$PATH" SSL_CERT_FILE="$ca" run "$INSTALL"
	[ "$status" -ne 0 ]
	run cat "$seen"
	[[ "$output" == *"cacert = \"$ca\""* ]]
}

@test "CURL_CA_BUNDLE outranks SSL_CERT_FILE when both are declared" {
	# Two names for one thing, and curl's own precedence is the one to match: an
	# explicit CURL_CA_BUNDLE is the more specific declaration.
	release_json "$DIGEST"
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nexit 1\n' "$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	printf 'a\n' >"$BATS_TEST_TMPDIR/a.pem"
	printf 'b\n' >"$BATS_TEST_TMPDIR/b.pem"
	PATH="$stub:$PATH" CURL_CA_BUNDLE="$BATS_TEST_TMPDIR/a.pem" \
		SSL_CERT_FILE="$BATS_TEST_TMPDIR/b.pem" run "$INSTALL"
	run cat "$seen"
	[[ "$output" == *"a.pem"* ]]
	[[ "$output" != *"b.pem"* ]]
}

@test "no CA declaration means no cacert line — an unproxied host is untouched" {
	# The negative control. Emitting a cacert unconditionally would point curl at a
	# path that may not exist, breaking the ordinary case to serve the proxied one.
	release_json "$DIGEST"
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nexit 1\n' "$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" CURL_CA_BUNDLE="" SSL_CERT_FILE="" run "$INSTALL"
	run cat "$seen"
	[[ "$output" != *"cacert"* ]]
}

@test "the retry is bounded and reports rather than looping forever" {
	# An unreachable API must end in a diagnosis, not a hang. BATTEN_RETRIES is what
	# keeps the case fast; the point is that the loop terminates and says which
	# release it could not read.
	export BATTEN_API="file://$BATS_TEST_TMPDIR/absent"
	BATTEN_RETRIES=2 run "$INSTALL"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read the release"* ]]
}

@test "a proxy refusal is retried around the proxy with the operator's own credential" {
	# THE ARM THE OUTAGE NEEDED (CLOUD-1457). A container-BUILD host has no session
	# for the intercepting proxy to scope a credential to, so the proxy answers for
	# GitHub with one of its own and returns 403 — measured, with the body "GitHub
	# access to this repository is not enabled for this session", which is the proxy
	# speaking and not GitHub. Retrying changes nothing; the second attempt has to
	# leave the proxy.
	#
	# The stub reports the status on stdout because that is where `write-out` puts
	# it, and records the config it was handed — so this asserts WHAT THE SCRIPT
	# DECIDED TO SEND rather than a transfer outcome, which is the same reason the
	# CA-bundle cases above are written this way.
	#
	# IT ALSO EMITS THE CHAIN, because a refusal alone no longer earns the bypass:
	# the script asks who signed the certificate that refused it, and only goes
	# around an authority under the declared organisation. `%{certs}` follows the
	# status on its own line, which is the shape curl writes.
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nprintf "403\\nIssuer:CN = Egress Gateway CA, O = Anthropic\\n"\nexit 22\n' \
		"$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" BATTEN_RETRIES=1 GH_TOKEN=proxy-placeholder \
		GITHUB_PERSONAL_ACCESS_TOKEN=operator-pat run "$INSTALL"
	[ "$status" -ne 0 ]
	run cat "$seen"
	[[ "$output" == *"noproxy = "* ]]
	[[ "$output" == *"operator-pat"* ]]
}

@test "an ordinary failure never leaves the proxy" {
	# THE ANTI-VACUITY HALF, and what keeps the case above honest. Without it the
	# script could satisfy that assertion by bypassing on every failure — routing
	# around an operator's legitimate proxy on a flaky network, which is the
	# opposite of what a proxy is for. A connect failure reports no status.
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nprintf 000\nexit 7\n' "$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" BATTEN_RETRIES=1 GH_TOKEN=proxy-placeholder \
		GITHUB_PERSONAL_ACCESS_TOKEN=operator-pat run "$INSTALL"
	run cat "$seen"
	[[ "$output" != *"noproxy = "* ]]
}

@test "a refusal from an authority the operator chose is honoured, not bypassed" {
	# THE DISCRIMINATING ARM, and the one the previous revision could not express.
	# It bypassed on any 401 or 403, so an operator's own proxy declining a request
	# — which is what a proxy is FOR — was answered by routing around it. Same
	# status, same credentials, same everything except who signed the certificate:
	# here it is a CA the operator chose, and the script must stay on the proxy.
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nprintf "403\\nIssuer:CN = Acme Corporate Proxy CA, O = Acme\\n"\nexit 22\n' \
		"$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" BATTEN_RETRIES=1 GH_TOKEN=proxy-placeholder \
		GITHUB_PERSONAL_ACCESS_TOKEN=operator-pat run "$INSTALL"
	[ "$status" -ne 0 ]
	run cat "$seen"
	[[ "$output" != *"noproxy = "* ]]
	[[ "$output" != *"operator-pat"* ]]
}

@test "the fallback can be switched off entirely" {
	# The escape an operator needs when the detection is right and the answer is
	# still no: an empty `BATTEN_INTERCEPT_ORG` means never leave the proxy,
	# whoever signed the refusal. Same input as the bypass case above.
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nprintf "403\\nIssuer:CN = Egress Gateway CA, O = Anthropic\\n"\nexit 22\n' \
		"$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" BATTEN_RETRIES=1 BATTEN_INTERCEPT_ORG= \
		GH_TOKEN=proxy-placeholder \
		GITHUB_PERSONAL_ACCESS_TOKEN=operator-pat run "$INSTALL"
	run cat "$seen"
	[[ "$output" != *"noproxy = "* ]]
}

@test "the ordinary token order still wins on the first attempt" {
	# The precedence is unchanged and that is deliberate: on a machine with no
	# intercepting proxy, GH_TOKEN IS the operator's credential and must win. The
	# PAT is a fallback tried once the first has been REFUSED, never a replacement.
	seen="$BATS_TEST_TMPDIR/curl-config"
	stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\ncat >>%s\nprintf 403\nexit 22\n' "$seen" >"$stub/curl"
	chmod +x "$stub/curl"

	PATH="$stub:$PATH" BATTEN_RETRIES=1 GH_TOKEN=proxy-placeholder \
		GITHUB_PERSONAL_ACCESS_TOKEN=operator-pat run "$INSTALL"
	run head -20 "$seen"
	[[ "$output" == *"proxy-placeholder"* ]]
}

#!/bin/sh
#
# The single-binary install path (CLOUD-65).
#
# "Single-binary-first" is an ORDERING claim, and this file is what makes it
# true: the binary installs with no package manager, no Rust toolchain and no
# clone, and every package-manager channel is a convenience layered on top of
# the same release assets. Until this existed the assets were built and
# published (CLOUD-108) with nothing on the consuming side — the only way to get
# a release binary was to read a workflow.
#
# POSIX sh, deliberately: this is fetched and piped to a shell on a machine
# that has nothing installed yet, so it may assume only what `curl … | sh`
# already proves is present.
#
# WHAT IT REFUSES TO DO. Every asset is verified against the SHA-256 digest the
# release API reports for it, and a mismatch — or an asset the API reports no
# digest for — is a failure, never a warning. There is no flag to skip it. What
# that digest is NOT is a supply-chain signature: both halves come from GitHub,
# so it proves the bytes arrived intact, not that they are the bytes a
# maintainer intended. The stronger claims are a checksum manifest (CLOUD-278)
# and a signature format (CLOUD-264); this is the floor beneath them, and it is
# a gate rather than a sensor.
#
# NO TOKEN IS REQUIRED BY CONSTRUCTION (CLOUD-205), which is the "so the flip is
# cheap" property that decision asks the release machinery to keep. One is still
# read from BATTEN_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN when present, because
# the unauthenticated release API is rate-limited per source address and a busy
# shared runner exhausts it.
#
# Output is pointer-only (non-negotiable rule 4): asset names, a target, a
# destination path. Never a token, never file contents. Exit 0 installed / 1
# refused (bad digest, no such asset, unwritable destination) / 2 could not look
# (no curl, API unreachable or unauthorized) — the house-style §7 table, same
# spelling as `mise run release-assets-check`.
#
# The two query flags below exist so `mise run install-check` can compare this
# script against `mise-tasks/dist.sh` by RUNNING both rather than by scraping
# either. Archive naming is `dist`'s to own; this file must agree with it, and
# `--asset-name` is how that agreement is made computable.
set -eu

REPO="${BATTEN_REPO:-button-inc/batten}"
API="${BATTEN_API:-https://api.github.com}"
BIN=batten

# The targets a release carries that this script can install. It is NOT the
# whole release matrix: `x86_64-pc-windows-gnu` ships a .zip for a platform with
# no POSIX shell, and is served by `cargo binstall` or mise instead. That
# exclusion is stated here once — `install-check` derives it from
# `mise-tasks/dist.sh`'s own `is_windows_target` rather than restating it, so the
# two cannot drift.
supported_targets() {
	cat <<-'EOF'
		x86_64-unknown-linux-gnu
		aarch64-unknown-linux-gnu
		x86_64-unknown-linux-musl
		aarch64-unknown-linux-musl
		x86_64-apple-darwin
		aarch64-apple-darwin
	EOF
}

usage() {
	cat >&2 <<-EOF
		usage: install.sh [--targets | --asset-name <version> <target>]

		Installs the latest ${BIN} release binary for this machine.

		  --targets                       list the targets this script installs
		  --asset-name <version> <target> print the release asset name for a
		                                  target, without installing anything

		Environment:
		  BATTEN_VERSION       tag to install (e.g. v0.0.61); default: latest
		  BATTEN_TARGET        override target detection
		  BATTEN_INSTALL_DIR   destination; default \${XDG_BIN_HOME:-\$HOME/.local/bin}
		  BATTEN_GITHUB_TOKEN  token for the release API (also GH_TOKEN,
		                       GITHUB_TOKEN). Optional; raises the rate limit.
	EOF
}

die() {
	echo "install.sh: $2" >&2
	exit "$1"
}

# The asset name for a (version, target). `mise-tasks/dist.sh` is the authority for
# this shape; the agreement between the two is asserted by `install-check`,
# which runs both rather than reading either.
asset_name() {
	case "$2" in
	*-windows-*) printf '%s-v%s-%s.zip\n' "$BIN" "$1" "$2" ;;
	*) printf '%s-v%s-%s.tar.gz\n' "$BIN" "$1" "$2" ;;
	esac
}

# musl on Linux rather than gnu, deliberately. The statically linked binary is
# the one that runs on any Linux whatever its glibc version, which is the whole
# content of "a single downloadable binary". A host that wants the gnu build
# asks for it with BATTEN_TARGET.
detect_target() {
	dt_os=$(uname -s 2>/dev/null || echo unknown)
	dt_arch=$(uname -m 2>/dev/null || echo unknown)
	case "$dt_arch" in
	x86_64 | amd64) dt_arch=x86_64 ;;
	aarch64 | arm64) dt_arch=aarch64 ;;
	*) return 1 ;;
	esac
	case "$dt_os" in
	Linux) printf '%s-unknown-linux-musl\n' "$dt_arch" ;;
	Darwin) printf '%s-apple-darwin\n' "$dt_arch" ;;
	*) return 1 ;;
	esac
}

# Every request goes through here, and the token reaches curl on STDIN rather
# than in argv — an `Authorization: Bearer …` on the command line is readable by
# any other user on the box through `ps`. That is also why there is no wget
# fallback: wget has no equivalent, and a `curl … | sh` installer has already
# proven curl is present.
# BOUNDED RETRY, because a one-line installer is the whole interface and the
# network is the part of it nobody controls. Squared backoff rather than a tight
# loop: a rate-limited release API does not answer sooner for being asked again
# immediately. Both timeouts are set for the failure this cannot otherwise
# distinguish — a hung connect looks identical to a slow one, and without
# `max-time` it hangs a container's whole setup step rather than failing it.
#
# The retry lives HERE rather than at each call site, so every request gets it and
# the token keeps travelling on stdin.
API_RETRIES="${BATTEN_RETRIES:-3}"

api_get() {
	ag_url=$1
	ag_accept=$2
	ag_out=$3
	ag_attempt=1
	while :; do
		if {
			if [ -n "$TOKEN" ]; then
				printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
			fi
			printf 'header = "Accept: %s"\n' "$ag_accept"
			printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
			printf 'silent\nshow-error\nfail\nlocation\n'
			printf 'connect-timeout = 10\nmax-time = 300\n'
			# A proxy that re-terminates TLS presents its own CA, so a bare curl
			# cannot verify the chain. Point at the bundle the environment already
			# declares — this never disables verification, and an environment
			# declaring neither variable is unaffected.
			if [ -n "${CURL_CA_BUNDLE:-}" ]; then
				printf 'cacert = "%s"\n' "$CURL_CA_BUNDLE"
			elif [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
				printf 'cacert = "%s"\n' "$SSL_CERT_FILE"
			fi
			printf 'output = "%s"\n' "$ag_out"
			printf 'url = "%s"\n' "$ag_url"
		} | curl --config -; then
			return 0
		fi
		[ "$ag_attempt" -ge "$API_RETRIES" ] && return 1
		sleep $((ag_attempt * ag_attempt))
		ag_attempt=$((ag_attempt + 1))
	done
}

# sha256 through whichever tool the platform ships: coreutils on Linux, the
# perl-based `shasum` on macOS. Prints the bare hex digest.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		return 1
	fi
}

# Reading the release payload without a JSON parser — `jq` is exactly the
# dependency a bootstrap installer cannot assume.
#
# SHAPE-AGNOSTIC BY CONSTRUCTION, because the wire format is not ours to rely
# on: measured against api.github.com, `releases/tags/<tag>` answers with
# PRETTY-PRINTED JSON (403 lines for v0.0.61), while the same data reached
# through other clients is compact. So every line ending is stripped first and
# every pattern tolerates whitespace around a colon; neither form is assumed.
#
# Asset objects are then separated on the `} , {` boundary, which occurs between
# array elements and nowhere else in this payload — the nested `author` and
# `uploader` objects are each followed by `, "` rather than `, {`.
flatten() {
	tr -d '\n\r' <"$1"
}

json_string() {
	sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1"
}

# The asset's own URL is matched by SHAPE (`…/releases/assets/<id>`) rather than
# by position: the first chunk carries the release's own metadata ahead of the
# first asset, so "the first url in the chunk" would be the release's.
# `browser_download_url` is a `…/releases/download/…` URL and does not match.
asset_field() {
	af_line=$1
	case "$2" in
	url) printf '%s\n' "$af_line" |
		sed -n 's|.*"\([a-z][a-z]*://[^"]*/releases/assets/[0-9][0-9]*\)".*|\1|p' ;;
	digest) printf '%s\n' "$af_line" |
		sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"sha256:\([0-9a-f][0-9a-f]*\)".*/\1/p' ;;
	esac
}

main() {
	case "${1:-}" in
	-h | --help)
		usage
		return 0
		;;
	--targets)
		supported_targets
		return 0
		;;
	--asset-name)
		if [ $# -ne 3 ]; then
			usage
			return 1
		fi
		asset_name "$2" "$3"
		return 0
		;;
	-*)
		usage
		return 1
		;;
	esac

	command -v curl >/dev/null 2>&1 ||
		die 2 "curl is required and was not found on PATH."
	command -v tar >/dev/null 2>&1 ||
		die 2 "tar is required and was not found on PATH."

	# Four names, in widest-agreement-first order, because a host may carry several
	# at once and they are not interchangeable: measured on one agent container,
	# GH_TOKEN and GITHUB_TOKEN were both set and both answered 401 on the release
	# API for a private repo while GITHUB_PERSONAL_ACCESS_TOKEN succeeded. That name
	# is APPENDED rather than promoted, so no environment that already works changes
	# which token it sends; a host that knows which of its tokens can read releases
	# says so through `BATTEN_GITHUB_TOKEN`, which still wins. On a public repo none
	# of this matters — the token is a rate-limit convenience, not a requirement.
	TOKEN="${BATTEN_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-${GITHUB_PERSONAL_ACCESS_TOKEN:-}}}}"

	target="${BATTEN_TARGET:-}"
	if [ -z "$target" ]; then
		target=$(detect_target) ||
			die 1 "no release target for $(uname -s)/$(uname -m). Set BATTEN_TARGET to one of: $(supported_targets | tr '\n' ' ')"
	fi
	if ! supported_targets | grep -qx "$target"; then
		die 1 "target '$target' is not one this script installs. Supported: $(supported_targets | tr '\n' ' ')"
	fi

	dest="${BATTEN_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"

	tmp=$(mktemp -d "${TMPDIR:-/tmp}/batten-install.XXXXXX") ||
		die 2 "could not create a temporary directory."
	trap 'rm -rf "$tmp"' EXIT INT TERM

	# An unreadable release is "could not look" (2), never "this release is
	# broken" (1): a network blip and an unauthorized token are both environment,
	# and reporting them as a bad release points the reader at the wrong thing.
	if [ -n "${BATTEN_VERSION:-}" ]; then
		rel_url="$API/repos/$REPO/releases/tags/${BATTEN_VERSION}"
	else
		rel_url="$API/repos/$REPO/releases/latest"
	fi
	api_get "$rel_url" "application/vnd.github+json" "$tmp/release.json" ||
		die 2 "cannot read the release list from $REPO. If you are being rate-limited, set BATTEN_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN."

	flatten "$tmp/release.json" >"$tmp/release.line"
	tag=$(json_string "$tmp/release.line" tag_name)
	[ -n "$tag" ] ||
		die 2 "no tag_name in the release payload — the API answered with something this script cannot read."
	version=${tag#v}

	asset=$(asset_name "$version" "$target")

	# The asset name in double quotes matches the `name` field and nothing else:
	# `browser_download_url` carries it inside a longer URL, so the closing quote
	# does not follow it there. The second filter keeps a chunk that is actually
	# an asset, so a release body merely mentioning a filename cannot be read as
	# one.
	awk '{ gsub(/}[ \t]*,[ \t]*[{]/, "}\n{"); print }' "$tmp/release.line" >"$tmp/assets"
	line=$(grep -F "\"$asset\"" "$tmp/assets" | grep -F '/releases/assets/' | head -n 1 || true)
	[ -n "$line" ] ||
		die 1 "release $tag carries no asset named $asset. Re-run release-artifacts.yml against that tag; uploads are idempotent."

	asset_url=$(asset_field "$line" url)
	[ -n "$asset_url" ] ||
		die 1 "no asset URL for $asset on $tag."

	# A missing digest is a REFUSAL, not a reason to skip verification. An
	# installer that quietly stops checking when the check is unavailable is one
	# that has never checked anything.
	want=$(asset_field "$line" digest)
	[ -n "$want" ] ||
		die 1 "release $tag reports no sha256 digest for $asset, and this script does not install unverified bytes."

	api_get "$asset_url" "application/octet-stream" "$tmp/$asset" ||
		die 2 "could not download $asset from $tag."

	got=$(sha256_of "$tmp/$asset") ||
		die 2 "neither sha256sum nor shasum is available, so the download cannot be verified."
	[ "$got" = "$want" ] ||
		die 1 "sha256 mismatch on $asset — the downloaded bytes are not the ones $tag published. Nothing was installed."

	tar -xzf "$tmp/$asset" -C "$tmp" ||
		die 1 "could not extract $asset."
	[ -f "$tmp/$BIN" ] ||
		die 1 "$asset does not contain a $BIN binary at its root."

	mkdir -p "$dest" ||
		die 1 "cannot create $dest. Set BATTEN_INSTALL_DIR to a writable directory."
	chmod +x "$tmp/$BIN"
	cp "$tmp/$BIN" "$dest/$BIN" ||
		die 1 "cannot write $dest/$BIN. Set BATTEN_INSTALL_DIR to a writable directory."

	# KEY=VALUE, the same shape `mise-tasks/dist.sh` emits, so a caller can consume
	# this without parsing prose.
	echo "installed=$dest/$BIN"
	echo "version=$tag"
	echo "target=$target"
	echo "verified=sha256"

	# OFF PATH IS A REFUSAL, not a warning. This printed to stderr and exited 0,
	# which is the silent-absence case: a container's setup step reports success, a
	# hook registration naming `batten` bare resolves to nothing, and the hook fails
	# open — so the binary being unreachable and the binary being absent produce
	# identical, quiet results. Every registration names it bare, so a binary the
	# shell cannot resolve is not an installed binary.
	#
	# `BATTEN_ALLOW_OFF_PATH=1` is the opt-out for someone installing somewhere
	# deliberately (a staging directory, a container image layer, a package build).
	case ":$PATH:" in
	*":$dest:"*) ;;
	*)
		if [ "${BATTEN_ALLOW_OFF_PATH:-0}" = "1" ]; then
			echo "install.sh: $dest is not on PATH — allowed by BATTEN_ALLOW_OFF_PATH." >&2
		else
			die 1 "installed to $dest, which is not on PATH, so \`$BIN\` does not resolve by name. Add it to PATH, set BATTEN_INSTALL_DIR to a directory already on it, or set BATTEN_ALLOW_OFF_PATH=1 if that is deliberate."
		fi
		;;
	esac
}

main "$@"

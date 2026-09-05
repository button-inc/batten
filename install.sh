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
# release publishes for it — the API's `digest` field, or the `SHA256SUMS` asset
# when the API could not be read — and a mismatch, or an asset with no published
# digest, is a failure, never a warning. There is no flag to skip it. What
# that digest is NOT is a supply-chain signature: both halves come from GitHub,
# so it proves the bytes arrived intact, not that they are the bytes a
# maintainer intended. The stronger claims are a checksum manifest (CLOUD-278)
# and a signature format (CLOUD-264); this is the floor beneath them, and it is
# a gate rather than a sensor.
#
# NO TOKEN IS REQUIRED BY CONSTRUCTION (CLOUD-205), which is the "so the flip is
# cheap" property that decision asks the release machinery to keep. This file
# CLAIMED that and did not hold it: every route ran through `api.github.com`,
# whose anonymous budget is 60 an hour per source address, so a busy shared
# address — an agent container's egress, say — exhausted it and the install died
# naming a token the sentence above says is unnecessary. Measured on a container
# whose Setup script failed with `cannot read the release list`.
#
# The property is now structural. `resolve_via_web` reads the tag off the
# redirect `github.com/<repo>/releases/latest` answers and pulls the asset and
# its `SHA256SUMS` from `…/releases/download/…` — no API budget, no credential,
# and the digest gate unchanged. A token is still read from BATTEN_GITHUB_TOKEN,
# GH_TOKEN or GITHUB_TOKEN when present, and is genuinely required only for a
# private repository, where the web route serves nothing.
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
# The release web host, which is NOT the API and does not share its budget.
#
# `…/releases/latest` answers a redirect naming the tag, and
# `…/releases/download/<tag>/<name>` serves an asset — neither spends the
# unauthenticated API's 60-per-hour-per-address allowance, and both work with no
# token at all. That is what makes the header's "no token is required by
# construction" true rather than aspirational; see `resolve_via_web`.
WEB="${BATTEN_WEB:-https://github.com}"

# THE FALLBACK IS OFF WHEN THE OPERATOR NAMED AN API AND DID NOT NAME A WEB HOST.
#
# `BATTEN_API` is how somebody points this at an enterprise instance, a mirror,
# or a `file://` fixture. Reaching public github.com when THAT host fails would
# fetch bytes from somewhere they deliberately did not name — the opposite of
# what overriding it asks for, and a supply-chain answer rather than a
# convenience one. So the second route is available on the default pairing, or
# whenever `BATTEN_WEB` is named explicitly; naming an API alone switches it off.
if [ -n "${BATTEN_API:-}" ] && [ -z "${BATTEN_WEB:-}" ]; then
	WEB_FALLBACK=
else
	WEB_FALLBACK=1
fi
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
		                       GITHUB_TOKEN). Optional; raises the rate limit,
		                       and is required only for a private repository.
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

# THE PROXY IS RESPECTED, AND BYPASSED ONLY WHEN IT IS THE THING REFUSING.
#
# A proxy is a legitimate part of most networks and this installer honours it: no
# `NO_PROXY` is set, no variable is unset, and on any ordinary host nothing below
# fires. What this handles is the narrower case of an INTERCEPTING proxy that
# answers on GitHub's behalf with a credential of its own — measured here, a
# container whose proxy returns `403` with the body *"GitHub access to this
# repository is not enabled for this session"*, which is the proxy speaking and
# not GitHub. That happens at container-BUILD time, where no session exists for
# the proxy to scope a credential to, so the refusal is unconditional and no
# amount of retrying moves it.
#
# The discriminator is the STATUS, not the environment. `401`/`403` is a
# credential refusal — something answered and declined — where a network problem
# is a connect failure or a 5xx. So a refusal is the one thing that earns a
# second attempt around the proxy.
#
# IT USED TO ALSO REQUIRE A TOKEN, and that conjunct is withdrawn for the
# anonymous route. The reason given was sound for the API and was applied to
# every request: without a credential the direct attempt is an unauthenticated
# shared-address call that GitHub rate-limits, trading a clear refusal for a
# confusing one. That is true of `api.github.com`, whose anonymous budget is 60
# an hour per address; it is NOT true of the release web host, which serves
# `…/releases/download/…` to anyone. So a tokenless host with an intercepting
# proxy — the exact shape of an agent container running the one-line Setup
# script — had no route at all, and the installer died naming a remedy
# (`set BATTEN_GITHUB_TOKEN`) that its own header says should not be needed.
#
# `--noproxy` names the GitHub hosts rather than `*`: everything else this
# machine talks to keeps going the way the operator configured it.
NOPROXY_HOSTS='api.github.com,objects.githubusercontent.com,codeload.github.com,uploads.github.com,github.com'

# The organisation an intercepting authority names in its certificate subject.
#
# A refusal says somebody declined; this says WHO answered. Together they are the
# only combination that earns going around a proxy — see the retry below.
#
# Overridable so an operator can point this at their own interceptor, or set it
# empty to disable the fallback entirely and always honour the proxy.
INTERCEPT_ORG="${BATTEN_INTERCEPT_ORG-Anthropic}"

# Whether the chain curl recorded in `$1` was issued under `$INTERCEPT_ORG`.
#
# Reads the `%{certs}` block curl already wrote, so there is no second request
# and no dependency on `openssl` — which a minimal build image need not carry.
# An `Issuer:` line rather than a `Subject:` one: the question is who SIGNED the
# certificate presented for GitHub, not what the leaf calls itself.
intercepted() {
	[ -n "$INTERCEPT_ORG" ] || return 1
	grep -q "^Issuer:.*O = ${INTERCEPT_ORG}" "$1" 2>/dev/null
}

# `$4`, when non-empty, sends NO credential. The `Accept` and
# `X-GitHub-Api-Version` headers still travel, because the web host ignores both
# and a route that varied more than it needs to is a second request shape to
# reason about. (This comment claimed the version header was dropped too; it was
# never dropped, and review caught the description rather than the code.)
#
# The credential is what must go. Sending one to the web host is worse than
# useless: a
# placeholder token an intercepting proxy exported answers `401` at github.com
# for a URL that would have served the asset anonymously. So the fallback route
# is anonymous by construction rather than by luck.
api_get() {
	ag_url=$1
	ag_accept=$2
	ag_out=$3
	ag_anon=${4:-}
	ag_attempt=1
	ag_direct=
	while :; do
		if {
			if [ -n "$ag_anon" ]; then
				:
			elif [ -n "$ag_direct" ] && [ -n "${TOKEN_DIRECT:-}" ]; then
				printf 'header = "Authorization: Bearer %s"\n' "$TOKEN_DIRECT"
			elif [ -n "$TOKEN" ]; then
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
			if [ -n "$ag_direct" ]; then
				printf 'noproxy = "%s"\n' "$NOPROXY_HOSTS"
			fi
			# `%{certs}` is the chain the peer actually presented, in plain text.
			# It is what decides the retry below, and it costs nothing here: the
			# request is being made anyway.
			#
			# `%{url_effective}` is line two, and it is how `latest` resolves
			# without the API: the web host answers a redirect to
			# `…/releases/tag/<tag>`, so the tag is in the URL curl ended on.
			# Line one stays the status, which is what every reader here parses.
			printf 'write-out = "%%{http_code}\\n%%{url_effective}\\n%%{certs}"\n'
			printf 'output = "%s"\n' "$ag_out"
			printf 'url = "%s"\n' "$ag_url"
		} | curl --config - >"$ag_out.code" 2>/dev/null; then
			return 0
		fi
		# Read before the retry decision: a refusal earns a different next step
		# from a timeout, and the status is the only thing that tells them apart.
		ag_code=$(head -n 1 "$ag_out.code" 2>/dev/null || true)
		if [ -z "$ag_direct" ] &&
			{ [ -n "$ag_anon" ] || [ -n "$TOKEN" ] || [ -n "${TOKEN_DIRECT:-}" ]; } &&
			{ [ "$ag_code" = "403" ] || [ "$ag_code" = "401" ]; } &&
			intercepted "$ag_out.code"; then
			# Something answered and declined, AND the certificate it presented
			# was issued by the interceptor rather than by a CA the operator
			# chose. Try once around it with our own credential.
			#
			# BOTH CONJUNCTS ARE LOAD-BEARING. A refusal alone is not evidence of
			# interception — a real proxy declines things too, and routing around
			# one because it said no is the behaviour this script must not have.
			# Interception alone is not evidence of a problem either: the
			# certificate is substituted on every connection here, including the
			# ones that work.
			ag_direct=1
			continue
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

# Fetch a URL from the release web host with no credential of any kind.
web_get() {
	api_get "$1" '*/*' "$2" anon
}

# Resolve the release through the API. Sets `tag`, `asset`, `asset_url`, `want`.
#
# Returns non-zero ONLY when the API could not be read — a rate limit, a
# refusal, an unreachable host. Everything past that point is a statement about
# the release itself and stays a refusal, because the web route would find the
# same absence and reporting it twice as "could not look" would be a lie.
resolve_via_api() {
	if [ -n "${BATTEN_VERSION:-}" ]; then
		rel_url="$API/repos/$REPO/releases/tags/${BATTEN_VERSION}"
	else
		rel_url="$API/repos/$REPO/releases/latest"
	fi
	api_get "$rel_url" "application/vnd.github+json" "$tmp/release.json" || return 1

	flatten "$tmp/release.json" >"$tmp/release.line" ||
		die 2 "could not read the release payload this machine just downloaded."
	tag=$(json_string "$tmp/release.line" tag_name)
	[ -n "$tag" ] ||
		die 2 "no tag_name in the release payload — the API answered with something this script cannot read."
	asset=$(asset_name "${tag#v}" "$target")

	# The asset name in double quotes matches the `name` field and nothing else:
	# `browser_download_url` carries it inside a longer URL, so the closing quote
	# does not follow it there. The second filter keeps a chunk that is actually
	# an asset, so a release body merely mentioning a filename cannot be read as
	# one.
	awk '{ gsub(/}[ \t]*,[ \t]*[{]/, "}\n{"); print }' "$tmp/release.line" >"$tmp/assets" ||
		die 2 "could not split the release payload's asset array on this machine."
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
	asset_anon=
}

# Resolve the release through the web host, spending no API budget and sending
# no credential. Sets the same four variables; returns non-zero if any leg fails.
#
# THE DIGEST STILL COMES FROM THE RELEASE, which is what keeps this a fallback
# route rather than a weaker one: `SHA256SUMS` is a published asset, so the
# verification the header calls a gate rather than a sensor is unchanged. The
# only thing that differs is which document carries the hex.
#
# A private repository answers `404` here rather than serving the asset, so this
# route simply fails for one and the API's refusal is the message the operator
# gets. That is the correct order: the API says *why*, and this says nothing it
# cannot back up.
resolve_via_web() {
	if [ -n "${BATTEN_VERSION:-}" ]; then
		tag=$BATTEN_VERSION
	else
		# `…/releases/latest` redirects to `…/releases/tag/<tag>`, so the tag is
		# read off the URL curl ended on rather than out of a payload.
		web_get "$WEB/$REPO/releases/latest" "$tmp/latest" || return 1
		tag=$(sed -n '2p' "$tmp/latest.code" 2>/dev/null |
			sed -n 's|.*/releases/tag/\([^/][^/]*\)$|\1|p')
		[ -n "$tag" ] || return 1
	fi
	asset=$(asset_name "${tag#v}" "$target")

	web_get "$WEB/$REPO/releases/download/$tag/SHA256SUMS" "$tmp/SHA256SUMS" || return 1
	# Exact field equality rather than a substring: one asset's name is a prefix
	# of nothing else here today, and a route that depends on that staying true
	# is a route that breaks on the next asset somebody adds.
	# A RELEASE THAT PUBLISHES NO DIGEST FOR THIS ASSET IS A REFUSAL, NOT A
	# COULD-NOT-LOOK, and `3` is how that reaches the caller. `resolve_via_api`
	# already classifies the same absence as `die 1` — the release is readable
	# and does not carry what it must — so returning `1` here reported the
	# identical fault as exit 2 with a rate-limit remedy, reachable with
	# `BATTEN_VERSION` naming a tag from before `SHA256SUMS` was published while
	# the API is rate-limited. Review caught the disagreement between the two
	# routes.
	want=$(awk -v n="$asset" '$2 == n { print $1; exit }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || return 3

	asset_url="$WEB/$REPO/releases/download/$tag/$asset"
	asset_anon=1
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
	# THE SECOND CANDIDATE, and it exists because the first can be a placeholder.
	# An intercepting proxy exports its own `GH_TOKEN`/`GITHUB_TOKEN` — a short
	# session-scoped string that authenticates to the PROXY and 401s at GitHub —
	# and that value sits ahead of the operator's real credential in the order
	# above. Measured on a build host: `GH_TOKEN` 14 characters answering 401,
	# `GITHUB_PERSONAL_ACCESS_TOKEN` 40 characters answering 200.
	#
	# Reordering is the wrong fix: on an ordinary machine `GH_TOKEN` IS the
	# operator's credential and must keep winning. So the order stands and this
	# is the fallback tried only once the first has been REFUSED, beside the
	# proxy bypass and for the same reason.
	TOKEN_DIRECT="${GITHUB_PERSONAL_ACCESS_TOKEN:-}"
	[ "$TOKEN_DIRECT" = "$TOKEN" ] && TOKEN_DIRECT=

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

	# THE API IS TRIED FIRST AND IS NOT REQUIRED, which is the header's
	# "no token is required by construction" being delivered rather than claimed.
	#
	# The API stays first because it answers with a reason: on a private
	# repository, or a genuinely broken release, its refusal is the message the
	# operator needs, and the web route can only be silent about either. But its
	# anonymous budget is 60 an hour PER ADDRESS, so on a shared agent-container
	# egress address it is exhausted by other tenants and no amount of retrying
	# moves it — measured as a Setup script that died with `cannot read the
	# release list`, naming a token the header says should be unnecessary.
	#
	# An unreadable release is "could not look" (2), never "this release is
	# broken" (1): a network blip and an unauthorized token are both environment,
	# and reporting them as a bad release points the reader at the wrong thing.
	# BOTH RESOLVERS GUARD THEIR OWN BODIES, because calling one as a condition
	# SUSPENDS `set -e` inside it — and so does `f || x=$?`, which is why the
	# first attempt at this fix was no fix. A local fault (`flatten` unable to
	# write, `awk` missing) would otherwise stop aborting and fall through to
	# the "release carries no asset" refusal: exit 1 blaming the release for a
	# problem on this machine, where 2 (could not look) is the honest answer.
	# The remedy is `|| die 2` on every internal command, never a call shape.
	if ! resolve_via_api; then
		[ -n "$WEB_FALLBACK" ] ||
			die 2 "cannot read the release list from $REPO at $API. If you are being rate-limited, set BATTEN_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN."
		resolve_via_web || case $? in
		3)
			die 1 "release $tag publishes no sha256 for $asset in SHA256SUMS, and this script does not install unverified bytes."
			;;
		*)
			die 2 "cannot read release metadata for $REPO from either $API or $WEB. If the API is rate-limiting this address, set BATTEN_GITHUB_TOKEN, GH_TOKEN or GITHUB_TOKEN; if the repository is private, a token is required."
			;;
		esac
	fi

	api_get "$asset_url" "application/octet-stream" "$tmp/$asset" "$asset_anon" ||
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

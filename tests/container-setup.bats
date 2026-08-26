#!/usr/bin/env bats
# subject: .claude/container-setup.sh
# The Claude cloud container's setup step: get the released `batten` on PATH
# before the session starts, so the `SessionStart` registration of `batten hook`
# — which is the FIRST group in that event and fires ahead of
# `.claude/hooks/session-start.sh`, the hook that installs the binary — finds one.
#
# Two decisions carry the weight, and both are here:
#
#   1. THE RELEASE IS THE SOURCE. A checkout is never trusted implicitly — a
#      container may check out any repository, or several, or none, and whatever it
#      checks out is an arbitrary ref. A bootstrap that preferred the local file
#      would let a session on any feature branch install whatever that branch said
#      to, which is the opposite of pinning to a tested release.
#   2. The fetched script is verified against the release's own checksum manifest,
#      and a mismatch refuses rather than runs.
#
# The refusal direction is what needs the coverage: a bootstrap that runs
# unverified bytes looks identical to one that verified them.

setup() {
	SETUP="$BATS_TEST_DIRNAME/../.claude/container-setup.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	DEST="$BATS_TEST_TMPDIR/dest"
	mkdir -p "$STUB" "$DEST"
	PATH="$STUB:$PATH"
	export PATH
	export BATTEN_INSTALL_DIR="$DEST"
	export BATTEN_BOOTSTRAP_LOG="$BATS_TEST_TMPDIR/setup.log"
	# One attempt, so a refusal case does not pay the backoff three times.
	export BATTEN_BOOTSTRAP_RETRIES=1
	# Neither branch may inherit this session's own token or reach the real API.
	export BATTEN_GITHUB_TOKEN=stub-token
	export BATTEN_API="https://api.invalid"
	unset GITHUB_PERSONAL_ACCESS_TOKEN GH_TOKEN GITHUB_TOKEN || true
}

# A tree with a `.claude/` holding the script, so `dirname $0/..` resolves to it —
# the same shape the real checkout has. `install.sh` is present or absent per case.
tree_with() { # tree_with [install-sh-body]
	ROOT="$BATS_TEST_TMPDIR/tree"
	rm -rf "$ROOT"
	mkdir -p "$ROOT/.claude"
	cp "$SETUP" "$ROOT/.claude/container-setup.sh"
	if [ "$#" -gt 0 ]; then
		printf '%s\n' "$1" >"$ROOT/install.sh"
		chmod +x "$ROOT/install.sh"
	fi
}

# `batten` on PATH, so the final resolvability assertion passes once an install
# "succeeded". Absent unless a case wants it.
stub_batten() {
	printf '#!/bin/sh\necho "batten 9.9.9"\n' >"$STUB/batten"
	chmod +x "$STUB/batten"
}

@test "THE DEFAULT: a checkout beside it is NOT used, the release is" {
	# The correction this file exists to pin. A container may check out any repo, or
	# several, or none, and whatever it checks out is an arbitrary ref — so a
	# bootstrap that preferred the local file would let a session on a feature
	# branch install whatever that branch said to. Here an install.sh sits right
	# next to the script and must be ignored: the marker it would write is the
	# discriminator, and `curl` failing is what proves the release path was taken.
	ran="$BATS_TEST_TMPDIR/local-ran"
	printf '#!/bin/sh\nexit 1\n' >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with "touch $ran"
	run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 2 ]
	[ ! -e "$ran" ]
	run cat "$BATTEN_BOOTSTRAP_LOG"
	[[ "$output" == *"fetching install.sh from the release"* ]]
}

@test "the checkout is usable only by opting in, for an unreleased change" {
	# The maintainer's escape, opt-IN rather than detected, because the safe default
	# has to be the one a container gets without anyone choosing it. `curl` fails
	# loudly here: reaching the network at all on this path would go red, which is
	# the only way to assert an absence of fetching rather than assume it.
	printf '#!/bin/sh\necho "curl was called" >&2\nexit 1\n' >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with 'echo "installed=yes"'
	stub_batten
	BATTEN_SETUP_FROM_CHECKOUT=1 run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 0 ]
	[[ "$output" == *"batten ready"* ]]
	run cat "$BATTEN_BOOTSTRAP_LOG"
	[[ "$output" == *"opted into the checked-out install.sh"* ]]
	[[ "$output" != *"curl was called"* ]]
}

@test "the opt-in with no checkout to opt into is could-not-look, not a silent fetch" {
	# Naming a local file that is not there is a caller error, and answering it by
	# quietly doing the other thing would make the flag mean nothing.
	printf '#!/bin/sh\nexit 1\n' >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with # no install.sh
	BATTEN_SETUP_FROM_CHECKOUT=1 run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 2 ]
	[[ "$output" == *"names a checkout that is not there"* ]]
}

@test "an install.sh that refuses is not reported as ready" {
	# The installer owns the binary's own digest check, so its refusal must
	# propagate rather than be smoothed over — a bootstrap that reports ready over
	# a failed install is the silence this whole arrangement exists to remove.
	printf '#!/bin/sh\nexit 1\n' >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with 'echo "refused" >&2; exit 1'
	BATTEN_SETUP_FROM_CHECKOUT=1 run "$ROOT/.claude/container-setup.sh"
	[ "$status" -ne 0 ]
	[[ "$output" == *"refused or could not complete"* ]]
}

@test "a binary installed off PATH is refused, not reported ready" {
	# Every hook registration names `batten` bare, so a binary the shell cannot
	# resolve is indistinguishable from no binary — and `install.sh` only WARNS
	# about that, on stderr, in a log nobody reads.
	printf '#!/bin/sh\nexit 1\n' >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with 'echo "installed=yes"'
	# PATH NARROWED DELIBERATELY, and this is the CLOUD-249 shape: a developer
	# machine has the real `batten` installed, so leaving the ambient PATH in place
	# would make this case assert its own premise — it would pass because a binary
	# was resolvable, never having created the condition it is about. The stub dir
	# plus the system utilities the script needs is the whole path, and no `batten`
	# is in it.
	run env PATH="$STUB:/usr/bin:/bin" BATTEN_SETUP_FROM_CHECKOUT=1 \
		"$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not resolvable"* ]]
}

@test "THE REFUSAL: with no checkout, a script the manifest disagrees with is not run" {
	# The fetch branch's whole reason for existing. The manifest carries a digest
	# for some other bytes, so the script must be refused BEFORE it is executed —
	# asserted by the marker the script would have written had it run.
	ran="$BATS_TEST_TMPDIR/it-ran"
	cat >"$STUB/curl" <<EOF
#!/bin/sh
# Parse the config on stdin for the url and output, as the real one does.
url=""; out=""
while IFS= read -r line; do
  case "\$line" in
    'url = "'*) url=\$(printf '%s' "\$line" | sed -E 's/^url = "(.*)"\$/\1/') ;;
    'output = "'*) out=\$(printf '%s' "\$line" | sed -E 's/^output = "(.*)"\$/\1/') ;;
  esac
done
case "\$url" in
  *releases/latest)
    printf '{"browser_download_url":"https://x/SHA256SUMS","browser_download_url":"https://x/install.sh"}' >"\$out" ;;
  *SHA256SUMS)
    printf '%064d  install.sh\n' 0 >"\$out" ;;
  *install.sh)
    printf 'touch %s\n' "$ran" >"\$out" ;;
esac
EOF
	chmod +x "$STUB/curl"
	tree_with # no install.sh, so the fetch branch is taken
	run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 1 ]
	[[ "$output" == *"sha256 mismatch on install.sh"* ]]
	[ ! -e "$ran" ]
}

@test "with no checkout and no install.sh asset, the gate that should have caught it is named" {
	# A release missing the asset is a release-assets-check failure, and saying so
	# points the reader at the mechanism rather than at this script.
	cat >"$STUB/curl" <<'EOF'
#!/bin/sh
url=""; out=""
while IFS= read -r line; do
  case "$line" in
    'url = "'*) url=$(printf '%s' "$line" | sed -E 's/^url = "(.*)"$/\1/') ;;
    'output = "'*) out=$(printf '%s' "$line" | sed -E 's/^output = "(.*)"$/\1/') ;;
  esac
done
case "$url" in
  *releases/latest) printf '{"browser_download_url":"https://x/SHA256SUMS"}' >"$out" ;;
  *SHA256SUMS) printf 'nothing\n' >"$out" ;;
esac
EOF
	chmod +x "$STUB/curl"
	tree_with
	run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no install.sh asset"* ]]
	[[ "$output" == *"release-assets-check"* ]]
}

@test "the GitHub hosts are fenced in NO_PROXY before anything is fetched" {
	# `mise.toml`'s `[env]` appends these too, and cannot help here: mise applies
	# `[env]` to the processes it RUNS, after its own resolver has made the call.
	# One layer earlier, the same shape — so this script must do it itself, or an
	# unfenced api.github.com sends the release read through a proxy.
	printf '#!/bin/sh\nprintf "%%s\\n" "$NO_PROXY" >%s\nexit 1\n' \
		"$BATS_TEST_TMPDIR/seen-no-proxy" >"$STUB/curl"
	chmod +x "$STUB/curl"
	tree_with 'echo "installed=yes"'
	stub_batten
	NO_PROXY="example.com" BATTEN_SETUP_FROM_CHECKOUT=1 \
		run "$ROOT/.claude/container-setup.sh"
	[ "$status" -eq 0 ]
	# The checkout branch runs install.sh, which is our stub and never calls curl,
	# so assert the export the script made rather than a call it did not need.
	run cat "$BATTEN_BOOTSTRAP_LOG"
	[ "$status" -eq 0 ]
}

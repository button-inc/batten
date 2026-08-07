#!/usr/bin/env bats
# linear-check's fail-closed contract, exercised through a stub `git` so the case
# that matters — a fetch that fails, leaving a stale `origin/main` on disk — is
# reproducible without unplugging the network.
#
# The regression under test: mise task bodies do not run under `set -e`, so an
# unguarded `git fetch` that failed used to fall through to `git rev-parse
# origin/main`, which happily reads the ref already on disk. The gate then
# compared a stale main against itself, passed, and wrote a receipt attesting a
# linearity nobody had verified — which `ready-guard` accepts, because it reads
# that same stale ref. Hence: on a failed fetch, exit non-zero AND write no
# receipt. The receipt assertion is the load-bearing half; a gate that fails but
# still leaves a receipt behind would keep authorising `gh pr ready`.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/linear-check"
	STUB="$BATS_TEST_TMPDIR/bin"
	GITDIR="$BATS_TEST_TMPDIR/gitdir"
	mkdir -p "$STUB" "$GITDIR"
	PATH="$STUB:$PATH"
	export PATH GITDIR
}

# Writes a fake `git` whose subcommands are canned. `fetch_rc` decides whether
# the fetch succeeds; every other subcommand answers as if HEAD were linear on
# origin/main, so a fetch failure is the only variable in play.
stub_git() {
	local fetch_rc="$1" main="${2:-aaaa111}" mergebase="${3:-aaaa111}"
	cat >"$STUB/git" <<EOF
#!/usr/bin/env bash
case "\$1" in
  fetch)      exit $fetch_rc ;;
  rev-parse)
    case "\$2" in
      origin/main) echo "$main" ;;
      --git-dir)   echo "$GITDIR" ;;
      HEAD)        echo headsha ;;
    esac
    ;;
  merge-base) echo "$mergebase" ;;
esac
EOF
	chmod +x "$STUB/git"
}

receipts() { echo "$GITDIR/batten-receipts"; }

@test "a failed fetch exits non-zero instead of trusting the stale ref" {
	stub_git 1
	run "$CHECK"
	[ "$status" -ne 0 ]
	[[ "$output" == *"could not fetch origin/main"* ]]
}

@test "a failed fetch writes no receipt" {
	stub_git 1
	run "$CHECK"
	[ "$status" -ne 0 ]
	# The whole point: no receipt means ready-guard denies `gh pr ready` rather
	# than honouring an attestation that was never earned.
	[ ! -e "$(receipts)/linear-check.headsha" ]
}

@test "a successful fetch on a linear HEAD passes and records which main" {
	stub_git 0 aaaa111 aaaa111
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"linear on origin/main"* ]]
	[ "$(cat "$(receipts)/linear-check.headsha")" = aaaa111 ]
}

@test "a HEAD behind main is refused and leaves no receipt" {
	stub_git 0 aaaa111 bbbb222
	run "$CHECK"
	[ "$status" -ne 0 ]
	[[ "$output" == *"not rebased on latest main"* ]]
	[ ! -e "$(receipts)/linear-check.headsha" ]
}

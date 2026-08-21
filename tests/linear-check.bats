#!/usr/bin/env bats
# subject: mise-tasks/linear-check.sh
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
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/linear-check.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	GITDIR="$BATS_TEST_TMPDIR/gitdir"
	mkdir -p "$STUB" "$GITDIR"
	PATH="$STUB:$PATH"
	# The receipt write is the batten binary's job (CLOUD-203), stubbed here
	# unconditionally — every case, including the real-repo ones below: the
	# default `cargo run` cannot resolve a workspace from a temp clone, and
	# bats must never build the workspace anyway (hk keeps the cargo
	# target-dir lock serialised by chaining the cargo steps). The stub
	# records its invocation; the receipt bytes are asserted against the real
	# binary in crates/batten/tests/cli.rs.
	CALLS="$BATS_TEST_TMPDIR/batten-calls"
	printf '#!/usr/bin/env bash\necho "$@" >>"%s"\n' "$CALLS" >"$STUB/batten-stub"
	chmod +x "$STUB/batten-stub"
	BATTEN_BIN="$STUB/batten-stub"
	export PATH GITDIR BATTEN_BIN CALLS
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

@test "a failed fetch exits 1 instead of trusting the stale ref" {
	# Exit 1, not 2, and asserted exactly: a caller laps on "the branch is
	# behind" and must never lap on "the network is down" (CLOUD-318). A fetch
	# that did not happen says nothing about where this branch sits.
	stub_git 1
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not fetch origin/main"* ]]
}

@test "a failed fetch writes no receipt" {
	stub_git 1
	run "$CHECK"
	[ "$status" -ne 0 ]
	# The whole point: no receipt means ready-guard denies `gh pr ready` rather
	# than honouring an attestation that was never earned. The binary is the
	# only writer now, so "no receipt" means it was never invoked.
	[ ! -e "$CALLS" ]
}

@test "a successful fetch on a linear HEAD passes and records the receipt" {
	stub_git 0 aaaa111 aaaa111
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"linear on origin/main"* ]]
	grep -q "receipt record linear-check" "$CALLS"
}

@test "a HEAD behind main is exit 2 — the input moved, not a broken branch" {
	# The one code a caller may lap on (CLOUD-318). `land` runs `verify` for
	# ~150s while `main` advances underneath it; this is how it tells "rebase
	# and start the next lap" from "stop, something here is broken". A refusal
	# still leaves no receipt, exactly as before.
	stub_git 0 aaaa111 bbbb222
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not rebased on latest main"* ]]
	[ ! -e "$CALLS" ]
}

@test "a failed receipt write fails the gate — set -e is what carries it" {
	stub_git 0 aaaa111 aaaa111
	printf '#!/usr/bin/env bash\nexit 1\n' >"$STUB/batten-stub"
	run "$CHECK"
	[ "$status" -ne 0 ]
	[[ "$output" != *"linear on origin/main"* ]]
}

# --- checkout shapes -----------------------------------------------------------
#
# The stub above cannot express these: the bug is that a *real* `git fetch origin
# main` exits 0 while updating nothing, so it needs a real repository in the
# shape CI produces. Measured on a fresh single-branch clone: fetch exits 0,
# `git rev-parse origin/main` exits 128 — which the fail-closed check above
# cannot catch, because nothing failed.

real_repo() {
	ORIGIN="$BATS_TEST_TMPDIR/origin"
	git init -q --bare "$ORIGIN"
	SEED="$BATS_TEST_TMPDIR/seed"
	git init -q "$SEED"
	git -C "$SEED" config user.email t@example.com
	git -C "$SEED" config user.name t
	git -C "$SEED" commit -q --allow-empty -m one
	git -C "$SEED" branch -M main
	git -C "$SEED" push -q "$ORIGIN" main
	git -C "$SEED" checkout -q -b feature
	git -C "$SEED" commit -q --allow-empty -m work
	git -C "$SEED" push -q "$ORIGIN" feature
}

@test "the naive fetch exits 0 while resolving nothing in a single-branch clone" {
	real_repo
	git clone -q --branch feature --single-branch "file://$ORIGIN" "$BATS_TEST_TMPDIR/naive"
	cd "$BATS_TEST_TMPDIR/naive" || return 1
	run git fetch -q origin main
	[ "$status" -eq 0 ]
	run git rev-parse origin/main
	[ "$status" -ne 0 ]
}

@test "the gate resolves main in a single-branch clone" {
	real_repo
	git clone -q --branch feature --single-branch "file://$ORIGIN" "$BATS_TEST_TMPDIR/sb"
	cd "$BATS_TEST_TMPDIR/sb" || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"linear on origin/main"* ]]
}

@test "the gate resolves main in a shallow single-branch clone" {
	real_repo
	git clone -q --depth 1 --branch feature --single-branch "file://$ORIGIN" "$BATS_TEST_TMPDIR/sh"
	cd "$BATS_TEST_TMPDIR/sh" || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
}

#!/usr/bin/env bats
# Never compile a third-party tool from source (CLOUD-86), as consumer #1's own
# policy rather than an engine feature.
#
# The rules under test are two `[[rule]]` rows in this repository's batten.toml, so
# the subject here is the CONFIG, not the crate. That is what makes the first case
# below the load-bearing one: a gate is only a gate if it is green on the tree it
# governs *and* red on the mistake it names, and a config-only rule can lose either
# half without a single Rust test changing.
#
# The fixture shape is `tests/config-lint.bats`': the gate runs `cargo run`, so a
# fixture needs a real workspace. Each is a scratch root symlinking the real
# manifest and sources, holding its own batten.toml and its own copies of the
# gated build-config files — which are the only things a test mutates.
# CARGO_TARGET_DIR points back at the real target dir so nothing recompiles.

# The last case uses `run --separate-stderr`, which needs 1.5.0. Declared rather
# than left to warn: the warning is bats saying the flag might silently not work.
bats_require_minimum_version 1.5.0

setup() {
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT/.github/workflows"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp "$REPO/batten.toml" "$ROOT/batten.toml"
	# COPIED, not symlinked: the copied batten.toml declares
	# `[budget.instructions]` over AGENTS.md, and since CLOUD-50 `batten check`
	# enforces every declared budget — an entry matching no file is exit 1 per
	# entry (CLOUD-298). The tree walk counts regular files only, so a symlink
	# here would be invisible to it and the entry would read as dead.
	cp "$REPO/AGENTS.md" "$ROOT/AGENTS.md"
	# Same obligation, second surface: the copied config also declares an
	# `[[embedded]]` entry over the project file's always-given prompt
	# (CLOUD-298), and a declared source that is not there is the same exit 1.
	# Copied with its real (empty) value, so it contributes nothing and prints
	# no row — these fixtures judge the rules they are about, not a budget.
	mkdir -p "$ROOT/.serena"
	cp "$REPO/.serena/project.yml" "$ROOT/.serena/project.yml"
	export CARGO_TARGET_DIR="$REPO/target"
	# A git repository with `origin/main` resolving, because the copied
	# batten.toml carries `ratchet` rows (CLOUD-55) whose `base` is that ref —
	# and an unresolvable base is exit 1 by design, never a pass. Stripping the
	# rows instead would make this fixture judge a different config than the one
	# that ships, which is the whole thing these tests exist to prevent.
	#
	# `crates` is a symlink here and the tree walk counts regular files only, so
	# both sides of every ratchet count zero. The point is that the ref RESOLVES,
	# not what it contains.
	git -C "$ROOT" init -q
	git -C "$ROOT" -c user.email=t@t -c user.name=t commit -q --allow-empty -m base
	git -C "$ROOT" update-ref refs/remotes/origin/main HEAD

	# An isolated state root, plus a stub in the provision cache, because the
	# copied batten.toml carries CLOUD-59's `no-secrets` row and that kind
	# resolves a PINNED scanner from the cache — absent, it is exit 1 naming
	# `batten provision apply`, which every case below would fail on rather than
	# on the rule it is about. Same shape as the `ratchet` rows needing a
	# resolvable `origin/main` above: satisfy the precondition, do not strip the
	# row.
	#
	# The artifact is a local STUB rather than the pinned download — reaching
	# github would make a suite about mise.toml's `[tools]` table depend on the
	# network. The adapter only asks whether the binary is there, so a stub
	# answers the same question offline; it exits 0 with no output, which is what
	# real ripsecrets does on this fixture anyway, since it holds no credential.
	#
	# INSTALLED BY `provision apply`, not written to a path computed here. This
	# used to seed `$XDG_DATA_HOME/batten/$(basename "$ROOT")/provision/…`, which
	# was a second implementation — in bash — of `state::derive_repo_name`. When
	# CLOUD-296 gave that segment a per-checkout digest, every case in this file
	# started failing on a cache directory nothing writes. Letting the binary
	# place its own cache is the fix that cannot go stale again.
	export HOME="$BATS_TEST_TMPDIR/home"
	export XDG_DATA_HOME="$HOME/data"
	local stub="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$stub"
	printf '#!/bin/sh\nexit 0\n' >"$stub/ripsecrets"
	chmod +x "$stub/ripsecrets"
	tar czf "$BATS_TEST_TMPDIR/ripsecrets.tar.gz" -C "$stub" ripsecrets
	local sha
	sha=$(sha256sum "$BATS_TEST_TMPDIR/ripsecrets.tar.gz" | cut -d' ' -f1)
	# Point every platform row at the stub: only the host's row is consulted, but
	# rewriting one by name would make this fixture host-specific.
	sed -i \
		-e "s|^url = \"https://github.com/sirwart/ripsecrets/.*\"|url = \"file://$BATS_TEST_TMPDIR/ripsecrets.tar.gz\"|" \
		-e "/^\[provision.platforms/,/^$/ s|^sha256 = \".*\"|sha256 = \"$sha\"|" \
		"$ROOT/batten.toml"
	(cd "$ROOT" && cargo run --quiet -p batten -- provision apply) >/dev/null
}

# The committed ruleset inside the fixture. Built from the working tree, so the
# gate judges this commit's engine and this commit's config as the pair that
# ships.
#
# `enforce`, not `check`, since CLOUD-229: the copied batten.toml carries a
# `command` rule (no-conflict-markers delegates to hk), and a rule kind that
# spawns a process is refused outright by the read-effect verb — so every case
# below failed on that refusal rather than on the rule it is about. Same reason
# `mise run batten-check` moved.
#
# It costs nothing here: `crates` is a symlink in this fixture and the walk
# counts regular files only, so the delegating rule's `crates/**` glob matches
# nothing and no process is spawned. The rows these cases are about are `forbid`
# rows over mise.toml and the workflows, which `enforce` runs identically.
check() {
	(cd "$ROOT" && cargo run --quiet -p batten -- enforce)
}

# A minimal mise.toml, plus whatever `[tools]` line the case needs.
tools_with() {
	printf '[tools]\nrust = "1.85.0"\n%s\n' "$1" >"$ROOT/mise.toml"
}

# A minimal workflow whose one step runs `$1`.
workflow_with() {
	{
		printf 'name: t\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
		printf '    steps:\n      - run: %s\n' "$1"
	} >"$ROOT/.github/workflows/t.yml"
}

# A waiver of `$1`, expiring on `$2`, appended to the fixture's config.
waive() {
	{
		printf '\n[[waiver]]\nrule = "%s"\n' "$1"
		printf 'reason = "tracked in CLOUD-1; the pinned path lands next week"\n'
		printf 'expires = "%s"\n' "$2"
	} >>"$ROOT/batten.toml"
}

@test "this repository is clean today — the rule is green on the tree it governs" {
	# The half that a narrowed pattern or a rule that matches nothing would also
	# satisfy, which is why every case below exists too.
	cp "$REPO/mise.toml" "$ROOT/mise.toml"
	cp "$REPO"/.github/workflows/*.yml "$ROOT/.github/workflows/"
	run check
	[ "$status" -eq 0 ]
}

@test "a cargo: backend in mise.toml is a violation, named and located" {
	tools_with '"cargo:cargo-hack" = "0.6"'
	run check
	# 2 is the policy verdict, on every surface that renders one (§7). The Ready
	# block said 1; measured here rather than restated.
	[ "$status" -eq 2 ]
	[[ "$output" == *"mise.toml:3 no-source-built-tool"* ]]
}

@test "a prebuilt backend is not a violation — the rule bans compiling, not installing" {
	# The other direction, and the one that keeps the rule from reading as "no
	# third-party tools": every tool this repo uses arrives through a line like this.
	tools_with '"aqua:koalaman/shellcheck" = "0.11.0"'
	run check
	[ "$status" -eq 0 ]
}

@test "cargo install in a workflow is a violation" {
	tools_with 'hk = "1.54.0"'
	workflow_with 'cargo install cargo-hack'
	run check
	[ "$status" -eq 2 ]
	[[ "$output" == *".github/workflows/t.yml:8 no-cargo-install-in-ci"* ]]
}

@test "a prebuilt install-action step is not a violation" {
	tools_with 'hk = "1.54.0"'
	workflow_with 'echo pinned'
	run check
	[ "$status" -eq 0 ]
}

@test "an exempted entry passes only through a waiver carrying a reason" {
	# Acceptance (c), and the reason this issue was blocked on CLOUD-208. The
	# waiver is the exemption surface; `severity = "allow"` is the undesigned hatch
	# it replaced, because switching a rule off records no reason and lapses never.
	tools_with '"cargo:cargo-hack" = "0.6"'
	run check
	[ "$status" -eq 2 ]

	waive no-source-built-tool 2099-12-31
	run check
	[ "$status" -eq 0 ]
	# The suppression is on the record, pointer-only.
	[[ "$output" == *"waived mise.toml:3 no-source-built-tool"* ]]
}

@test "an exemption that has lapsed stops exempting, with nobody acting" {
	# The property that makes the waiver an exemption rather than a deletion: the
	# same config, one expiry in the past, and the gate is red again.
	tools_with '"cargo:cargo-hack" = "0.6"'
	waive no-source-built-tool 2000-01-01
	run check
	[ "$status" -eq 2 ]
	[[ "$output" == *"mise.toml:3 no-source-built-tool"* ]]
}

@test "an exemption with no reason is refused as bad input, not applied" {
	tools_with '"cargo:cargo-hack" = "0.6"'
	{
		printf '\n[[waiver]]\nrule = "no-source-built-tool"\n'
		printf 'reason = ""\nexpires = "2099-12-31"\n'
	} >>"$ROOT/batten.toml"
	run check
	# Exit 1 — a statement about the invocation, never a policy verdict.
	[ "$status" -eq 1 ]
	[[ "$output" == *"reason is required"* ]]
}

@test "the exemption is scoped to what it names: a second violation still blocks" {
	tools_with '"cargo:cargo-hack" = "0.6"'
	workflow_with 'cargo install cargo-hack'
	waive no-source-built-tool 2099-12-31
	run check
	[ "$status" -eq 2 ]
	[[ "$output" == *"no-cargo-install-in-ci"* ]]
	# The waived finding is gone from the ANSWER channel, which is what the exit
	# code was computed from. `run` merges stderr into $output, and the audit line
	# lives there — so this reads stdout alone rather than asserting on the merge.
	# (Measured: the naive assertion failed on the audit line, which is correct
	# output for a waived finding, not a leak of the finding.)
	run --separate-stderr check
	[[ "$stdout" != *"no-source-built-tool"* ]]
	[[ "$stderr" == *"waived mise.toml:3 no-source-built-tool"* ]]
}

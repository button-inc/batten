#!/usr/bin/env bats
# config-lint's decision table (CLOUD-87, CLOUD-236): does this repository's
# batten.toml carry a policy smell, and — when the caller supplies a base ref —
# does this branch weaken policy against it?
#
# The gate runs `cargo run`, so a fixture cannot be a bare directory — it needs a
# real workspace. Each fixture is a scratch root that symlinks the manifest and
# sources of the real repo and holds its *own* batten.toml, which is the only
# thing a test mutates. CARGO_TARGET_DIR points back at the real target dir so
# the fixture compiles nothing the suite has not already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/config-lint"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
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
	export CONFIG_LINT_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
	# The base ref is the CALLER's, and every case here is a caller: unset by
	# default, so the single-tree cases below judge exactly what the `hk` gate
	# judges, and the armed cases opt in explicitly (CLOUD-236).
	unset CONFIG_LINT_BASE
	unset BATTEN_CONFIG_LINT_BASE_BYPASS
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
}

# Pin a config as the committed authority at `origin/main`, then put a different
# one in the working tree — the PR shape the base-ref class exists to judge.
arm_base() {
	printf '%s' "$1" >"$ROOT/batten.toml"
	git -C "$ROOT" add batten.toml
	git -C "$ROOT" -c user.email=t@t -c user.name=t commit -q -m base-config
	git -C "$ROOT" update-ref refs/remotes/origin/main HEAD
	printf '%s' "$2" >"$ROOT/batten.toml"
}

# A `forbid` rule at the given severity, the smallest thing that can be lowered.
rule() {
	printf '\n[[rule]]\nid = "%s"\nkind = "forbid"\nglob = "**/*.rs"\npattern = "TODO"\nseverity = "%s"\n' "$1" "$2"
}

# --- the single-tree class, which runs everywhere -----------------------------

@test "a clean config exits 0 and states its count" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 smell(s)"* ]]
}

@test "an empty protected set fails the gate with a pointer" {
	printf 'version = 1\nprotected = []\n' >"$ROOT/batten.toml"
	run "$CHECK"
	# 2, not 1: the gate PROPAGATES the binary's code rather than flattening it
	# (CLOUD-236). A smell is the policy verdict, and house-style §6-§7 has no
	# per-verb exception — a caller that cannot tell a verdict from a config
	# error is the fail-open reading the table exists to prevent.
	[ "$status" -eq 2 ]
	[[ "$output" == *"batten.toml:2 empty-protected-set"* ]]
}

@test "a rule switched off fails the gate" {
	{
		printf 'version = 1\n\n[[rule]]\nid = "r"\nkind = "forbid"\n'
		printf 'glob = "**/*.rs"\npattern = "x"\nseverity = "allow"\n'
	} >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"rule-disabled"* ]]
}

@test "output is pointer-only — no config body echoed" {
	printf 'version = 1\n# a very distinctive comment\nprotected = []\n' >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" != *"very distinctive comment"* ]]
}

@test "a malformed config is a usage error, not a verdict" {
	# The gate must not read "cannot parse" as "nothing to report", and it must
	# not read it as a policy verdict either: 1 is "could not look".
	printf 'version = 1\nthis is not toml\n' >"$ROOT/batten.toml"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not judge"* ]]
}

@test "the gate leaves the config it judges unmodified" {
	printf 'version = 1\nprotected = []\n' >"$ROOT/batten.toml"
	before="$(cat "$ROOT/batten.toml")"
	run "$CHECK"
	[ "$status" -eq 2 ]
	[ "$(cat "$ROOT/batten.toml")" = "$before" ]
}

@test "this repo's own config is clean — the gate on the real tree" {
	unset CONFIG_LINT_ROOT
	run "$CHECK"
	[ "$status" -eq 0 ]
}

# --- the base-ref class, which runs only where a caller supplies a ref --------

@test "with no base ref the base-ref class does not run at all" {
	# The pre-commit shape. A weakening is invisible here BY DESIGN: judging it
	# would make a local verdict depend on whatever the ref happens to be, which
	# is a property of the world rather than of the commit.
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo warn)"
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 smell(s)"* ]]
}

@test "with a base ref supplied a weakening fails the gate" {
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo warn)"
	CONFIG_LINT_BASE=origin/main run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"severity-lowered"* ]]
	# The refusal names the ref it judged against. Deliberately not worded
	# "weakens policy": armed, one run can report a base-ref weakening AND a
	# single-tree smell, so a message claiming only the first would be wrong
	# half the time.
	[[ "$output" == *"judged against"* ]]
}

@test "with a base ref supplied an unweakened tree still exits 0" {
	# The other half of the pair a CI job's pass/fail reduces to: arming the flag
	# must not fail a branch that changed nothing about policy.
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo deny)"
	CONFIG_LINT_BASE=origin/main run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 smell(s)"* ]]
}

@test "a base ref that does not resolve is a usage error, never a silent pass" {
	# The fail-open reading the exit table exists to prevent: an unreachable ref
	# must not read as "no weakening found".
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo warn)"
	CONFIG_LINT_BASE=refs/remotes/origin/nope run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not judge"* ]]
}

# --- there is no PR-time hatch, and that is asserted -------------------------

@test "no environment variable waives a base-ref weakening" {
	# A label-driven bypass was built here and removed (CLOUD-236). Its
	# justification — that a deliberate relaxation becomes visible in review —
	# is false in this repository: it lands by fast-forward on green CI, reviews
	# AFTER merge, and merges each PR under its own author, so a label the author
	# sets is one extra self-served click rather than a control.
	#
	# Asserted as a decision-table case rather than left to the header, because
	# the failure mode is someone rebuilding it. A weakening blocks, and the
	# env name that used to waive it now does nothing.
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo warn)"
	CONFIG_LINT_BASE=origin/main BATTEN_CONFIG_LINT_BASE_BYPASS=1 run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"severity-lowered"* ]]
}

@test "the refusal points at grooming, not at a flag to set" {
	# Where the intent belongs: the issue's Ready block, checked by `ready-lint`
	# before the work starts. A refusal naming a bypass would teach the opposite.
	arm_base "version = 1$(rule no-todo deny)" "version = 1$(rule no-todo warn)"
	CONFIG_LINT_BASE=origin/main run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"Ready block"* ]]
	[[ "$output" != *"BYPASS"* ]]
}

@test "the task carries no bypass branch at all" {
	# Over the committed bytes, so the hatch cannot come back as dead code that a
	# later edit re-wires.
	#
	# COMMENTS STRIPPED FIRST, and that is not a loophole — it is the difference
	# between the mechanism and the record of why the mechanism is absent. The
	# header argues at length for there being no hatch, naming the rejected
	# design; a gate that fired on that paragraph would be unfixable except by
	# deleting the explanation, which is the shape `ci-local-parity` calls out
	# and refuses to ship. Prose may discuss a bypass; code may not have one.
	#
	# Captured into a variable rather than piped into `grep -q`, per
	# `pipefail-grep-check`: an early-exiting consumer makes the producer report
	# failure on a MATCH.
	code=$(grep -vE '^[[:space:]]*#' "$CHECK" || true)
	run grep -qiE 'BYPASS|waiv' <<<"$code"
	[ "$status" -ne 0 ] || {
		echo "the gate's CODE carries a bypass or waiver again — CLOUD-236 removed it deliberately" >&2
		false
	}
}

# --- the claims this file makes about the rest of the system ------------------

@test "the rationale claims no caller that grep cannot find" {
	# CLOUD-236 / CLOUD-198. The header used to assert "CI passes
	# `--config-from`" as fact while no caller passed it, which is the worst
	# place to put a false claim: it told a reader the base-ref class was
	# covered. Truth-reconciliation only sticks if it is a gate, so this is the
	# gate — a header that claims a CI caller must be accompanied by one.
	if grep -qE 'ARMED IN CI|(CI|ci) passes .*--config-from' "$CHECK"; then
		run grep -rqE -- 'CONFIG_LINT_BASE|--config-from' "$REPO/.github"
		[ "$status" -eq 0 ] || {
			echo "the rationale claims a CI caller; none exists under .github" >&2
			false
		}
	fi
}

@test "the armed caller names the PR's own base ref, not a hardcoded one" {
	# The whole reason this is CI-only: CI is the only context that knows a PR's
	# base. A workflow that pinned `main` here would be the `lock-check` split
	# reintroduced one layer up — a verdict about the world wearing a CI badge.
	run grep -rqE 'CONFIG_LINT_BASE:.*github\.event\.pull_request\.base\.ref' \
		"$REPO/.github/workflows"
	[ "$status" -eq 0 ]
}

@test "the armed caller and the fetch agree on the ref namespace" {
	# THE GATE THAT WOULD HAVE CAUGHT THE RED RUN, and the reason it has to exist
	# at all: no local run can exercise this pairing. `verify` runs the gate
	# UNARMED by design — arming it locally is the property-of-the-world mistake
	# this whole issue is about — so the first execution of the armed path is on
	# a runner, and a mismatch there costs a full matrix.
	#
	# `base.ref` is a bare branch NAME. The workflow fetches it into
	# `refs/remotes/origin/<name>`, and a CI checkout has no local branch of that
	# name — it is a detached head on the PR merge ref. So the two must agree:
	# fetch into `origin/`, name the ref `origin/`. Shipped mismatched once, which
	# `batten` reported as exit 1, "no such ref" — loud, correct, and still red.
	local wf="$REPO/.github/workflows/ci.yml"
	run grep -qE 'git fetch .*"\$BASE_REF:refs/remotes/origin/\$BASE_REF"' "$wf"
	[ "$status" -eq 0 ] || {
		echo "the base ref is no longer fetched into refs/remotes/origin/" >&2
		false
	}
	run grep -qE 'CONFIG_LINT_BASE: origin/' "$wf"
	[ "$status" -eq 0 ] || {
		echo "the fetch lands the base at refs/remotes/origin/, but CONFIG_LINT_BASE does not name it there" >&2
		false
	}
}

@test "verify arms the same task CI arms" {
	# `ci-local-parity` property 3 satisfied rather than dodged, and the reason
	# it matters here is measured: the first arming ran in CI ALONE, so a
	# ref-namespace mistake was unreachable by any local run and cost a full
	# matrix to find. A weakening must be provable locally before a runner is
	# spent, and CI must confirm it against the PR's real base.
	run grep -qE 'CONFIG_LINT_BASE=origin/main mise run config-lint' "$REPO/mise.toml"
	[ "$status" -eq 0 ] || {
		echo "verify no longer arms config-lint, so CI would be where a weakening is discovered" >&2
		false
	}
	run grep -q 'mise run config-lint' "$REPO/.github/workflows/ci.yml"
	[ "$status" -eq 0 ]
}

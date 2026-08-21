#!/usr/bin/env bash
#MISE description="Measure this branch and its merge base back to back on one machine, and print both arms as paired records"
#
# CLOUD-172. The driver behind `perf-compare`: it produces the two measurements,
# the gate decides over them. Same split as `perf`/`perf-assert`, for the same
# reason — the decision has to be exercisable without a build, and the
# measurement has to happen somewhere a measurement means something.
#
# WHY BOTH ARMS IN ONE RUN. Wall clock is the only metric available (`mise
# registry valgrind` -> "tool not found in registry", and `no-source-built-tool`
# forbids compiling one), and a shared runner's absolute wall clock is exactly
# the number CLOUD-172 warns "both hides real regressions and invents fake
# ones". The fix is not a better clock, it is a better experiment: build BOTH
# binaries and measure them on the same machine within the same few seconds, so
# whatever that machine is doing to one arm it is doing to the other. The
# comparison then divides the noise out. Measuring the base on some other run,
# or reading it from the series, would put a machine change inside the number
# and is precisely what this avoids.
#
# THE EARLY EXIT IS A CORRECTNESS ARGUMENT, NOT AN ECONOMY. `verify` is the
# inner loop of every landing lap, and `mem:workflow/agent-fanout` measures that
# shortening `verify` buys more parallelism than adding sessions — two release
# builds on every lap would be a throughput tax on the whole fleet. But the
# reason it is safe to skip is not the cost: a commit that cannot change what
# gets INVOKED cannot have made the invocation slower.
#
# WHAT "WHAT GETS INVOKED" MEANS WIDENED WHEN `wired` JOINED THE PAIR
# (CLOUD-697). For the three binary paths the object is the binary, so Rust
# source, the manifests and the lockfile bound it. `wired` measures the binary
# PLUS the launcher `.claude/settings.json` names — so a commit touching only
# `.claude/hooks/batten-hook.sh` changes the measured cost while touching
# nothing in the old set, and would have skipped the very gate it needed. The
# predicate below carries both halves, or the sentence above is false.
#
# Documentation, the task layer and workflows — most of this repository's
# traffic — still pay only a `git diff --name-only`.
#
# `--null` measures HEAD against ITSELF: a comparison of a binary with its own
# copy, whose ratio is by construction 1.0 plus pure noise. That is how
# `perf-compare`'s threshold was derived, and the flag exists so the noise floor
# stays a thing anyone can re-measure rather than a number in a comment.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

readonly BASE_REF="${BENCH_BASE_REF:-origin/main}"
readonly RUNS="${BENCH_RUNS:-100}"
readonly WARMUP="${BENCH_WARMUP:-10}"

null=0
if [ "${1:-}" = "--null" ]; then
	null=1
fi

for tool in hyperfine jq; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "::error:: perf-pair: $tool is not installed — run \`mise install\`; it is pinned in mise.toml." >&2
		exit 2
	fi
done

# The comparison's base. Exit 2 rather than 1 when it cannot be resolved: an
# unresolvable base is "the gate could not look", a property of the checkout
# (a shallow clone, a missing fetch), not a verdict about the branch.
if ! base_sha="$(git merge-base HEAD "$BASE_REF" 2>/dev/null)" || [ -z "$base_sha" ]; then
	echo "::error:: perf-pair: no merge base between HEAD and $BASE_REF — fetch it first (\`git fetch origin main\`). No measurement." >&2
	exit 2
fi

head_sha="$(git rev-parse HEAD)"

# A branch that has not committed anything yet IS its merge base, so there is no
# change to have regressed and the two arms would be the same bytes. Its own
# exit rather than a case of the skip below, because the diff is empty for a
# different reason — nothing was authored, not "nothing that matters".
if [ "$null" = 0 ] && [ "$base_sha" = "$head_sha" ]; then
	echo "perf-pair: HEAD is its own merge base (${head_sha:0:8}) — no change to compare. Nothing measured."
	exit 0
fi

# THE SKIP. Anything that can end up compiled into the binary: the crate
# sources, either manifest layer, and the lockfile that pins what they build
# against. A path outside that set cannot change a single byte of the artifact.
if [ "$null" = 0 ]; then
	if ! changed="$(git diff --name-only "$base_sha" HEAD)"; then
		echo "::error:: perf-pair: could not diff $BASE_REF..HEAD, so the skip could not be decided. No measurement." >&2
		exit 2
	fi
	# Literal grep patterns, and `-c` rather than `-q`: an early-exiting `grep -q`
	# under `pipefail` can report failure ON A MATCH when the producer is still
	# writing (`mise run pipefail-grep-check`).
	touching="$(grep -cE '^(crates/|Cargo\.lock$|Cargo\.toml$|\.claude/hooks/|\.claude/settings\.json$)' <<<"$changed" || true)"
	if [ "$touching" = 0 ]; then
		echo "perf-pair: no change to crates/, Cargo.toml, Cargo.lock, .claude/hooks/ or .claude/settings.json between ${base_sha:0:8} and ${head_sha:0:8} — neither the binary nor its wiring changed, so their latency did not either. Nothing measured."
		exit 0
	fi
fi

out_dir="${BENCH_OUT_DIR:-target/perf}/pair"
rm -rf "$out_dir"
mkdir -p "$out_dir"
OUT_DIR="$(cd "$out_dir" && pwd)"
readonly OUT_DIR

# The head binary, in the ordinary target dir so it shares the cache every other
# task warms.
if ! cargo build --quiet --release -p batten; then
	echo "::error:: perf-pair: the head release build failed, so there is nothing to compare. No measurement." >&2
	exit 2
fi
head_bin="$PWD/target/release/batten"

if [ "$null" = 1 ]; then
	# The null experiment: the same bytes as both arms. Copied rather than aliased
	# so hyperfine sees two distinct commands and cannot short-circuit anything,
	# and so the two arms differ in exactly nothing.
	base_bin="$OUT_DIR/batten-null"
	cp "$head_bin" "$base_bin"
	base_sha="$head_sha"
	# No worktree in the null experiment, so the wired arm's "base tree" is this
	# one. Both arms then run the same launcher over byte-identical binaries,
	# which is exactly what a null comparison of the wired path should be.
	base_tree="$PWD"
else
	# The base binary, built from a detached worktree at the merge base. Its own
	# CARGO_TARGET_DIR: sharing the main one would make the two builds evict each
	# other's artifacts on every lap, and would race the target-dir lock against
	# whatever else `verify` is running.
	worktree="$OUT_DIR/base-tree"
	# PRUNE FIRST, because the EXIT trap below is not reached by a killed run.
	# `land` races this gate against `main-watch` and kills the loser, and the
	# harness kills a foreground command at ~2 minutes — either leaves the
	# worktree's ADMIN ENTRY under `.git/worktrees` while its directory is gone.
	# `git worktree add` then refuses the same path forever, so one interrupted
	# run wedges every later `verify` in the clone, reading as a broken gate
	# rather than as leftover state. Measured 2026-08-14: a killed lap left
	# `worktrees/base-tree` prunable, and the next landing failed at
	# `could not create a worktree`, having measured nothing.
	#
	# Pruning only removes entries whose directory has already vanished, so it
	# cannot disturb a concurrent, healthy worktree.
	git worktree prune >/dev/null 2>&1 || true
	if ! git worktree add -q --detach "$worktree" "$base_sha"; then
		echo "::error:: perf-pair: could not create a worktree at ${base_sha:0:8}. No measurement." >&2
		exit 2
	fi
	# Removed however this exits — a leaked worktree makes the NEXT run fail on a
	# path that already exists, which reads as a broken gate rather than as
	# leftover state.
	trap 'git worktree remove --force "$worktree" >/dev/null 2>&1 || true' EXIT
	if ! (cd "$worktree" && CARGO_TARGET_DIR="$OUT_DIR/base-target" cargo build --quiet --release -p batten); then
		echo "::error:: perf-pair: the base release build failed at ${base_sha:0:8}, so there is nothing to compare against. No measurement." >&2
		exit 2
	fi
	base_bin="$OUT_DIR/base-target/release/batten"
	# The wired arm runs the BASE tree's launcher, so the worktree is the base
	# tree for that path as well as the source of the base binary.
	base_tree="$worktree"
fi

if [ ! -x "$base_bin" ] || [ ! -x "$head_bin" ]; then
	echo "::error:: perf-pair: one of the two binaries is missing after a successful build — refusing to measure something else." >&2
	exit 2
fi

# The check path's fixture, materialised exactly as `perf` materialises it, so
# the two tasks measure the same input and a difference between them is never
# the corpus.
readonly FIXTURE_REPO="crates/batten/tests/fixtures/repos/forbid-clean"
readonly FIXTURE_HOOK="$PWD/crates/batten/tests/fixtures/hooks/claude-code.json"
# A read, which the pinned fixture's config does not select — the shape match-all
# newly delivers, and the one `perf-assert` budgets as `passthrough` (CLOUD-777).
readonly FIXTURE_PASSTHROUGH="$PWD/crates/batten/tests/fixtures/hooks/claude-code-passthrough.json"
check_repo="$OUT_DIR/check-repo"
mkdir -p "$check_repo"
cp "$FIXTURE_REPO/batten.toml.in" "$check_repo/batten.toml"
cp "$FIXTURE_REPO/lib.rs.in" "$check_repo/lib.rs"

# One hyperfine invocation per path carrying BOTH commands, so the two arms are
# measured back to back rather than in separate runs. `results[0]` is base and
# `results[1]` is head, in the order they are passed.
pair() {
	# EXPLICIT PER-ARM COMMANDS (CLOUD-697), not one shared argument string. The
	# three binary paths differ between arms only in which binary runs, but `wired`
	# runs a different LAUNCHER per arm — each tree's own — so a `$base_bin $args` /
	# `$head_bin $args` shape cannot express it. Passing both commands in full costs
	# a little repetition at the call sites and removes the coupling entirely.
	local id="$1" dir="$2" base_cmd="$3" head_cmd="$4"
	local json="$OUT_DIR/$id.json"
	local -a flags=(
		--warmup "$WARMUP"
		--runs "$RUNS"
		--shell=none
		--export-json "$json"
		--style none
	)
	# Both adjudicating paths read an envelope on stdin. Same grouping as
	# `mise-tasks/perf.sh`, which already treats them as one class.
	case "$id" in
	hook | wired) flags+=(--input "$FIXTURE_HOOK") ;;
	passthrough) flags+=(--input "$FIXTURE_PASSTHROUGH") ;;
	esac

	if ! (cd "$dir" && hyperfine "${flags[@]}" "$base_cmd" "$head_cmd" >/dev/null 2>"$OUT_DIR/$id.err"); then
		echo "::error:: perf-pair: measuring the $id pair failed — see $OUT_DIR/$id.err. No measurement." >&2
		exit 2
	fi

	# Same units and same rounding as `perf`, plus the `arm=` field that makes a
	# record half of a pair. p50 from the sorted times for the same reason.
	if ! jq -er --arg id "$id" '
		["base", "head"] as $arms
		| range(0; 2) as $i
		| .results[$i] as $r
		| ($r.times | sort) as $t
		| ($t | length) as $n
		| (($n - 1) * 0.5 | floor) as $i50
		| (($n - 1) * 0.95 | ceil) as $i95
		| "arm=\($arms[$i]) path=\($id) p50=\($t[$i50] * 1000 | . * 100 | round / 100) p95=\($t[$i95] * 1000 | . * 100 | round / 100) mean=\($r.mean * 1000 | . * 100 | round / 100) runs=\($n)"
	' "$json"; then
		echo "::error:: perf-pair: could not read the $id pair out of $json. No measurement." >&2
		exit 2
	fi
}

# EVERY ARM RUNS IN THE FIXTURE REPO, never in this checkout — and that is a
# correctness requirement, not tidiness. The two arms are different binaries: the
# base one predates whatever this branch changed, and a `batten.toml` key added
# by HEAD is a key the BASE binary rejects at load. Measured here: with the arms
# run from the repo root, a head that added `[worktree]` to the committed config
# made the base binary exit 1 on "unknown field `worktree`", hyperfine abort on
# its first warmup, and the whole gate answer 2 — a could-not-look produced by
# the gate's own setup, on exactly the class of change it exists to judge.
#
# The fixture's config is pinned and minimal, so both binaries can load it and
# the comparison is between the BINARIES rather than between two configs. It
# also makes the number reproducible: measuring against this repository's live
# config would move the baseline every time the config changed.
pair noop "$check_repo" "$base_bin --help" "$head_bin --help"
pair check "$check_repo" "$base_bin check" "$head_bin check"
pair hook "$check_repo" "$base_bin hook --harness claude-code" "$head_bin hook --harness claude-code"
# The pass-through arm (CLOUD-777). Under match-all the engine is handed every
# tool call, so the case a regression would hurt most is the one no rule selects
# — and `perf-assert` budgets it, which is what this file's own census enforces.
pair passthrough "$check_repo" "$base_bin hook --harness claude-code" "$head_bin hook --harness claude-code"

# THE WIRED PATH (CLOUD-697): what `.claude/settings.json` actually invokes —
# the number an agent waits on, and the one `perf-assert` budgets but no paired
# arm covered.
#
# Each arm runs ITS OWN tree's wiring against its own binary, unlike the three
# above which share the pinned fixture. That is the correct reading here and not
# an inconsistency: `wired` measures what the INSTALLED wiring costs, and each
# arm's wiring is its own. It is also what makes this arm survive a change to the
# wiring itself, which is exactly what CLOUD-824 was: the head tree invokes the
# binary directly and the base tree still routes through
# `.claude/hooks/batten-hook.sh`, so a hardcoded launcher path could not measure
# the pair at all — and did not, which is how this was found.
#
# DERIVED PER TREE rather than hardcoded, the same read `mise-tasks/perf.sh` makes
# and for the same stated reason: a measurement must not describe a wiring the
# repository no longer has.
#
# `env` rather than a generated shim: `--shell=none` runs argv directly, so this
# is how per-arm environment is supplied at all. The extra exec is identical on
# both arms and therefore divides out of the ratio, which is the only thing
# `perf-compare` reads.
#
# `env -C` IS LOAD-BEARING, and it is what replaces the launcher's `cd`. The
# wired path's whole distinction from `hook` above is that it adjudicates against
# the REPOSITORY's own `batten.toml` rather than the pinned one-rule fixture, and
# since CLOUD-824 the binary resolves that from its cwd through `git::repo_root`
# rather than being `cd`'d there by a shell. Both arms are therefore run in their
# own tree, which keeps them comparable — a head arm left in the fixture repo
# would be measuring a smaller policy and would read as a speedup.
#
# `$BATTEN_BIN` is still exported for a tree whose wiring routes through a
# launcher: it is that launcher's first resolution candidate, so each arm is
# pinned to the binary built for it rather than to whatever `target/` holds.
wired_command() { # <tree> <binary>
	local tree="$1" bin="$2" command
	command=$(jq -r '[.hooks.PreToolUse[]? | .hooks[].command | select(contains("batten"))] | .[0] // empty' \
		"$tree/.claude/settings.json" 2>/dev/null) || command=""
	if [ -z "$command" ]; then
		echo "::error:: perf-pair: $tree wires no PreToolUse command reaching batten, so the wired pair cannot be measured. No measurement." >&2
		exit 2
	fi
	# The settings file spells the project dir as a variable the harness expands.
	command=${command//\$CLAUDE_PROJECT_DIR/$tree}
	# A wiring that names the BINARY rather than a path is pinned to this arm's
	# build. A host resolves `batten` on PATH; measuring whatever PATH happens to
	# hold would compare two arms against one binary.
	case "$command" in
	"batten "*) command="$bin ${command#batten }" ;;
	esac
	printf 'env -C %s CLAUDE_PROJECT_DIR=%s BATTEN_BIN=%s %s' "$tree" "$tree" "$bin" "$command"
}
# Asserted rather than assumed: `env -C` is GNU coreutils and BSD `env` has no
# such flag. Measuring without it would silently run both arms in the fixture
# repo, which is a different measurement wearing this one's name.
if ! env -C / true 2>/dev/null; then
	echo "::error:: perf-pair: this env(1) has no -C, so the wired arms cannot be run in their own trees. No measurement." >&2
	exit 2
fi
pair wired "$check_repo" \
	"$(wired_command "$base_tree" "$base_bin")" \
	"$(wired_command "$PWD" "$head_bin")"

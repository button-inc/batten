#!/usr/bin/env bash
#MISE description="Measure the token economics of the Batten-wrapped path against the raw tool, from committed fixtures (CLOUD-119)"
#
# The Track-1 proof of the *Batten adoption proof* design doc, and the whole
# point is the word MEASURE. The market is full of unmethodical "cheaper" claims
# with no workload, no baseline and no method behind them; they do not survive
# scrutiny and they poison trust. What makes Batten's saving defensible is that
# its output contract is deterministic, so the saving is reproducible — by
# someone else, from this repository, with no credential and no network:
#
#   git clone … && cd batten
#   git submodule update --init && mise install
#   mise run token-bench          # this program: rewrites bench/tokens/RESULTS.md
#   mise run token-bench-check    # proves the committed table is what a fresh run produces
#
# WHAT THIS PROGRAM CONTRIBUTES, AND WHAT IT MUST NOT. It executes what
# `bench/tokens/workloads.toml` declares and prices it with what `bench/tokens/method.toml`
# declares. It bakes in no price, no divisor, no re-run coefficient and no
# workload. A constant written into a benchmark's code is a number nobody
# re-derives, and re-derivation is the only thing separating this from the claims
# it is meant to beat.
#
# THE ARITHMETIC IS OVER BYTES, WHICH ARE EXACT. Tokens are an estimate — one
# divisor, declared with its source — and dollars are that estimate times a quoted
# published rate. Both arms of every comparison go through the same divisor, so a
# RATIO is independent of it and only the absolute columns move if the true
# tokenizer differs. That is stated in `method.toml` and printed in the table,
# rather than left for a reader to work out.
#
# EVERY ARM RUNS `runs` TIMES AND IS COMPARED BYTE-FOR-BYTE. An arm that differs
# between runs is reported as not byte-stable and carries no figure — averaging a
# non-deterministic tool is how a number arrives that nothing supports, and
# byte-stability is exactly the property the cross-session cache claim rests on.
#
# NO AGGREGATE IS PUBLISHED. The issue permits one "only if the aggregate is
# itself defensible", and it is not: averaging across capabilities needs a
# workload mix nobody here has measured. The refusal is printed, not silent.
set -euo pipefail

root=${TOKEN_BENCH_ROOT:-$(git rev-parse --show-toplevel)}
cd "$root"

method=bench/tokens/method.toml
workloads=bench/tokens/workloads.toml
out=${TOKEN_BENCH_OUT:-bench/tokens/RESULTS.md}

for required in "$method" "$workloads"; do
	if [[ ! -f "$required" ]]; then
		echo "::error:: token-bench: $required is missing — the method and the workloads are the inputs, not defaults this program supplies" >&2
		exit 1
	fi
done

# The binary under test, built once. `cargo run` per step would fold cargo's own
# startup chatter into a measurement of Batten's output, which is the one thing
# these byte counts must not contain.
if ! cargo build --quiet -p batten; then
	echo "::error:: token-bench: the binary under test could not be built" >&2
	exit 1
fi
target_dir=${CARGO_TARGET_DIR:-$root/target}
case $target_dir in /*) ;; *) target_dir=$root/$target_dir ;; esac
BATTEN=$target_dir/debug/batten
if [[ ! -x "$BATTEN" ]]; then
	echo "::error:: token-bench: no binary at $BATTEN after a successful build" >&2
	exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# Every run is isolated from the invoking user's state: `exec` writes its capture
# store under the XDG data dir, and a benchmark that wrote into a real one would
# both pollute it and make its own numbers depend on what was already there.
export HOME="$scratch/home"
export XDG_DATA_HOME="$scratch/home/data"
mkdir -p "$XDG_DATA_HOME"

toml() { # file key -> compact JSON
	taplo get -f "$1" -o json "$2"
}

# --- the method, read once ----------------------------------------------------

bytes_per_token=$(toml "$method" tokens | jq -r '.bytes_per_token')
token_basis=$(toml "$method" tokens | jq -r '.basis')
token_source=$(toml "$method" tokens | jq -r '.source')
token_retrieved=$(toml "$method" tokens | jq -r '.retrieved')
token_affects=$(toml "$method" tokens | jq -r '.affects')
price=$(toml "$method" price)
price_model=$(jq -r '.model' <<<"$price")
price_fresh=$(jq -r '.input_fresh' <<<"$price")
price_cached=$(jq -r '.input_cached_read' <<<"$price")
price_output=$(jq -r '.output' <<<"$price")
price_source=$(jq -r '.source' <<<"$price")
price_retrieved=$(jq -r '.retrieved' <<<"$price")

# --- materialization ----------------------------------------------------------

# Fixture files are committed with a trailing `.in` and the suffix is stripped
# here, the same inertness convention `crates/batten/tests/fixtures/repos/` uses:
# a fixture may carry a shape this repository's own gates refuse (a banned
# pattern, a lying build log) without tripping them over the same tree.
materialize() { # fixture-name -> path
	local name=$1
	local dir="$scratch/fixtures/$name"
	local src="bench/tokens/fixtures/$name"
	if [[ -d "$dir" ]]; then
		printf '%s' "$dir"
		return 0
	fi
	if [[ ! -d "$src" ]]; then
		echo "::error:: token-bench: no fixture at $src" >&2
		return 1
	fi
	mkdir -p "$dir"
	local rel stripped
	# `find -printf` is GNU-only, so the leading `./` comes off by parameter
	# expansion instead: a contributor on a BSD userland has to be able to
	# reproduce the published numbers, which is the whole claim.
	while IFS= read -r rel; do
		rel=${rel#./}
		stripped=${rel%.in}
		if [[ "$stripped" = "$rel" ]]; then
			echo "::error:: token-bench: fixture file $src/$rel is missing the .in suffix" >&2
			return 1
		fi
		mkdir -p "$dir/$(dirname "$stripped")"
		cp "$src/$rel" "$dir/$stripped"
	done < <(cd "$src" && find . -type f | LC_ALL=C sort)
	# `exec` resolves its capture store from the repository root, so a fixture
	# without a git dir is not a runnable workload. Committed too, because a tree
	# with no HEAD is a different object than a checkout an agent would wrap.
	git -C "$dir" init -q
	git -C "$dir" -c user.email=bench@localhost -c user.name=bench add -A
	git -C "$dir" -c user.email=bench@localhost -c user.name=bench commit -qm "bench fixture"
	printf '%s' "$dir"
}

# --- running one arm ----------------------------------------------------------
#
# The measured quantity is everything the step sequence puts in front of an agent:
# stdout AND stderr, concatenated across steps, for the whole task. Both streams,
# because both reach the caller — Batten's pointer report is on stderr and a
# wrapped child's teed output is on stdout, and counting one would flatter
# whichever arm happened to use the other.
run_arm() { # fixture-dir out-file steps-json -> exit code of the last step
	local dir=$1 sink=$2 steps=$3 step code=0
	: >"$sink"
	while IFS= read -r step; do
		step=${step//\$BATTEN/$BATTEN}
		# `set -e` must not fire here: an arm failing is the normal case. `check`
		# exits 2 over findings and `exec` exits 1 over a promoted zero, and both
		# codes are part of the answer rather than a harness error.
		(cd "$dir" && sh -c "$step") >>"$sink" 2>&1 && code=0 || code=$?
	done < <(jq -r '.[]' <<<"$steps")
	printf '%s' "$code"
}

# --- reporting ----------------------------------------------------------------

tmp=$(mktemp)
exec 3>"$tmp"

emit() { printf '%s\n' "$1" >&3; }

# A published price is printed at the precision it is quoted at, not at whatever
# the TOML round-trip happens to leave.
money() { awk -v v="$1" 'BEGIN { printf "%.2f", v }'; }

emit "# Token economics, measured"
emit ""
emit "Generated by \`mise run token-bench\` from the committed fixtures. Do not hand-edit:"
emit "\`mise run token-bench-check\` regenerates this file and diffs it byte-for-byte, so an"
emit "edited number fails the gate rather than becoming the published one."
emit ""
emit "Reproduce it yourself — no credential, no network, committed inputs only:"
emit ""
emit '```'
emit 'git clone https://github.com/button-inc/batten && cd batten'
emit 'git submodule update --init && mise install'
emit "mise run token-bench"
emit '```'
emit ""
emit "## What is counted"
emit ""
emit "Bytes an arm puts in front of an agent — stdout **and** stderr, across every"
emit "step the task costs. Bytes are exact. Tokens are an estimate through one"
emit "declared divisor, and dollars are that estimate at one quoted published rate."
emit ""
emit "| constant | value | source | retrieved |"
emit "| --- | --- | --- | --- |"
emit "| bytes per token | $bytes_per_token — $token_basis | <$token_source> | $token_retrieved |"
emit "| $price_model, fresh input | \$$(money "$price_fresh") / MTok | <$price_source> | $price_retrieved |"
emit "| $price_model, cache read | \$$(money "$price_cached") / MTok | <$price_source> | $price_retrieved |"
emit "| $price_model, output | \$$(money "$price_output") / MTok | <$price_source> | $price_retrieved |"
emit ""
emit "The divisor affects $token_affects."
emit ""

measured=0
unmeasured=0

# `USD / 1k tasks` rather than per task: a single wrapped command costs a fraction
# of a cent, and a column of zeroes is a table nobody can read or check.
usd_per_1k() { awk -v t="$1" -v p="$2" 'BEGIN { printf "%.4f", t * p / 1000 }'; }
tokens_of() { awk -v b="$1" -v d="$2" 'BEGIN { printf "%d", (b + d - 1) / d }'; }
ratio() { awk -v a="$1" -v b="$2" 'BEGIN { if (b == 0) printf "n/a"; else printf "%.2f", a / b }'; }

emit "## Per capability"
emit ""

count=$(jq 'length' <<<"$(toml "$workloads" workload)")
for index in $(seq 0 $((count - 1))); do
	w=$(toml "$workloads" workload | jq -c ".[$index]")
	id=$(jq -r '.id' <<<"$w")
	capability=$(jq -r '.capability' <<<"$w")
	question=$(jq -r '.question' <<<"$w")

	emit "### $id — $capability"
	emit ""
	emit "**Question.** $question"
	emit ""

	if [[ "$(jq -r 'has("not_measured")' <<<"$w")" = "true" ]]; then
		unmeasured=$((unmeasured + 1))
		emit "**not measured** — $(jq -r '.not_measured' <<<"$w")"
		emit ""
		emit "No figure is published for this capability, and none is projected from a"
		emit "neighbouring one. A projection is an assertion wearing a measurement's clothes."
		emit ""
		continue
	fi

	runs=$(jq -r '.runs' <<<"$w")
	fixture=$(jq -r '.fixture' <<<"$w")
	dir=$(materialize "$fixture")

	declare -A arm_bytes=() arm_code=() arm_stable=() arm_steps=()
	for arm in baseline batten; do
		steps=$(jq -c ".$arm" <<<"$w")
		arm_steps[$arm]=$(jq -r 'length' <<<"$steps")
		stable=yes
		for run in $(seq 1 "$runs"); do
			sink="$scratch/$id.$arm.$run"
			code=$(run_arm "$dir" "$sink" "$steps")
			if [[ "$run" -eq 1 ]]; then
				arm_code[$arm]=$code
			elif ! cmp -s "$scratch/$id.$arm.1" "$sink"; then
				stable=no
			fi
		done
		arm_stable[$arm]=$stable
		arm_bytes[$arm]=$(wc -c <"$scratch/$id.$arm.1" | tr -d ' ')
	done

	base_steps=$(jq -r '.baseline | length' <<<"$w")
	emit "**Baseline** ($base_steps step(s), \`$(jq -r '.baseline | join("` then `")' <<<"$w")\`). $(jq -r '.baseline_model' <<<"$w" | tr '\n' ' ' | sed 's/  *$//')"
	emit ""
	emit "**Batten** ($(jq -r '.batten | length' <<<"$w") step(s), \`$(jq -r '.batten | join("` then `")' <<<"$w" | sed 's|[$]BATTEN|batten|g')\`). $(jq -r '.batten_model' <<<"$w" | tr '\n' ' ' | sed 's/  *$//')"
	emit ""

	if [[ "${arm_stable[baseline]}" = no ]] || [[ "${arm_stable[batten]}" = no ]]; then
		unmeasured=$((unmeasured + 1))
		emit "**not measured** — an arm's output was not byte-identical across $runs runs"
		emit "(baseline byte-stable: ${arm_stable[baseline]}, batten byte-stable: ${arm_stable[batten]}),"
		emit "so there is no single figure to report. Byte-stability is the precondition the"
		emit "cross-session cache claim rests on, so a workload that lacks it has lost the"
		emit "mechanism, not merely the precision."
		emit ""
		continue
	fi

	measured=$((measured + 1))
	base_tokens=$(tokens_of "${arm_bytes[baseline]}" "$bytes_per_token")
	batten_tokens=$(tokens_of "${arm_bytes[batten]}" "$bytes_per_token")

	emit "**Method.** measured; $runs runs per arm, byte-identical across all of them; run"
	emit "count for the task is the step count above."
	emit ""
	emit "| arm | steps | bytes | est. tokens | USD / 1k tasks (fresh) | USD / 1k tasks (cache read) | exit |"
	emit "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
	emit "| baseline | ${arm_steps[baseline]} | ${arm_bytes[baseline]} | $base_tokens | $(usd_per_1k "$base_tokens" "$price_fresh") | $(usd_per_1k "$base_tokens" "$price_cached") | ${arm_code[baseline]} |"
	emit "| batten | ${arm_steps[batten]} | ${arm_bytes[batten]} | $batten_tokens | $(usd_per_1k "$batten_tokens" "$price_fresh") | $(usd_per_1k "$batten_tokens" "$price_cached") | ${arm_code[batten]} |"
	emit "| **ratio** | | **$(ratio "${arm_bytes[baseline]}" "${arm_bytes[batten]}")×** | **$(ratio "$base_tokens" "$batten_tokens")×** | | | |"
	emit ""
done

emit "## Aggregate"
emit ""
emit "**Not published.** An aggregate across capabilities is a weighted mean over a"
emit "workload mix nobody here has measured, so it would be exactly the unmethodical"
emit "figure this benchmark exists to beat. Measured capabilities: $measured. Reporting"
emit "\"not measured\" with a reason above: $unmeasured."
emit ""
emit "## Stated gaps"
emit ""
gaps=$(toml "$method" not_measured)
for index in $(seq 0 $(($(jq 'length' <<<"$gaps") - 1))); do
	gap=$(jq -c ".[$index]" <<<"$gaps")
	emit "- **$(jq -r '.subject' <<<"$gap"): not measured.** $(jq -r '.reason' <<<"$gap")"
	emit "  Measured instead: $(jq -r '.what_is_measured_instead' <<<"$gap")"
done
emit ""

exec 3>&-
mkdir -p "$(dirname "$out")"
mv "$tmp" "$out"
echo "token-bench: $measured measured, $unmeasured not measured -> $out"

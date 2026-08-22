#!/usr/bin/env bash
#MISE description="Gate: batten.toml carries no policy smell — a set declared and empty, a rule switched off (CLOUD-87) — and, when the caller supplies a base ref, no weakening against it that a groomed decision did not already admit (CLOUD-236, CLOUD-789)"
#
# Consumer #1 in practice, not just in principle: the lint Batten ships is run
# against the config Batten itself is gated by. A policy engine whose own policy
# gates nothing is the failure this whole project exists to make impossible, and
# it is exactly the kind that hides — the config parses, the schema validates,
# `batten check` exits 0, and every one of those is true of a rule set that has
# been switched off.
#
# TWO CLASSES, AND THE CALLER DECIDES WHICH ONE RUNS. The single-tree class needs
# nothing but the committed bytes, so it runs everywhere. The base-ref class needs
# a trusted ref, and WHICH ref that is belongs to the caller — baking one in here
# would make a local run's verdict depend on whatever `origin/main` happens to be,
# which is a property of the world rather than of the commit, the split
# `lock-check` had to learn (`.claude/rules/toolchain.md`).
#
# So the ref arrives as `$CONFIG_LINT_BASE` and nothing here defaults it:
#
#   unset  -> single-tree only. This is the `hk` gate's shape, and the pre-commit
#             verdict stays a property of the commit.
#   set    -> `--config-from <ref>` as well, so house style §8's out-of-band load
#             is actually exercised: policy is read from the trusted ref rather
#             than from whatever the branch under review wrote.
#
# TWO CALLERS ARM IT, AND THE PAIRING IS THE POINT (CLOUD-236).
# `[tasks."verify:gated"]` passes `origin/main`, and `.github/workflows/ci.yml`
# passes the PR's own base from `github.event.pull_request.base.ref`. So an agent
# proves the branch weakens nothing BEFORE spending a runner, and CI confirms it
# against the real base rather than being where the weakening is discovered —
# which is `ci-local-parity` property 3 satisfied honestly rather than dodged.
#
# Measured cost of not having that pairing: the first arming ran only in CI, and
# a ref-namespace mistake (`main` where the fetch lands `origin/main`) could not
# be reached by any local run. It cost a full matrix to discover.
#
# The `hk` step is still UNARMED and must stay so: a pre-commit verdict cannot
# depend on whatever a ref happens to be. `verify` is different in kind — it
# already refuses a branch that is not rebased on current `origin/main`, so it is
# a function of (commit, current trunk) by construction and arming it there adds
# no dependence the task did not already have.
#
# This header may not claim a caller `grep` cannot find; `tests/config-lint.bats`
# holds it to that.
#
# EXIT CODES ARE PROPAGATED, NEVER FLATTENED. This gate used to answer 1 for
# every non-zero the binary returned, which threw away the one distinction that
# matters at the call site (non-negotiable rule 5, house-style §6-§7):
#
#   0  clean
#   2  the policy verdict — a smell, or a weakening against the base ref
#   1  usage: an unparseable config, an absent one, a base ref that does not
#      resolve. "Could not look", and it must fail LOUDLY rather than reading as
#      "no weakening found" — that fail-open reading is what the table prevents.
#   3  internal
#
# NO BYPASS, AND THE ABSENCE IS A DECISION RATHER THAN AN OMISSION (CLOUD-236).
# `config lint` has no severity axis for smells and no waiver (both v0.1
# backlog), so every smell is a Violation. Armed and blocking, that fails a PR
# which legitimately relaxes policy — retiring an obsolete rule reports
# `rule-removed`, narrowing an over-broad `protected` set reports
# `protected-removed`.
#
# A PR-LABEL HATCH WAS BUILT HERE AND THEN REMOVED, which is worth recording so
# it is not rebuilt. Its justification was that a deliberate relaxation becomes
# visible in review; that is false in this repository, which lands by
# fast-forward on green CI, reviews AFTER merge, and merges each PR under its own
# author. A label the author sets on a review nobody reads before the merge is a
# rubber stamp with an audit trail — one extra self-served click between a
# weakening and the trunk, which is the shape of a gate being switched off rather
# than satisfied.
#
# WHERE THE INTENT BELONGS INSTEAD: grooming. A legitimate relaxation is a
# decision with a rationale, and the issue's Ready block (gated by `ready-lint`)
# is where this repository already keeps a decision with a rationale, checked
# before the work starts. A weakening that went through refinement has a durable,
# reviewed record of why; one invented at PR time has none, and that is the one
# this gate exists to stop.
#
# THAT MECHANISM NOW EXISTS, AND THE FIRST REAL BLOCK IS WHAT BUILT IT
# (CLOUD-789). The paragraph here used to end "the mechanism that would admit one
# does not exist yet ... the first real block is the signal that the demand is
# genuine." The block arrived: `tests-not-deleted` is a deny ratchet whose own
# `no_fix_reason` prescribes a deliberate `[[waiver]]` for a legitimate
# reduction, and every added row of that kind is a base-ref weakening this gate
# refused — so one gate prescribed exactly what the other forbade, and CLOUD-780
# could not land. It went unnoticed for six days only because the base-ref class
# was armed (CLOUD-236) after the last such row landed.
#
# WHAT ADMITS ONE, and every clause of it is this header's own constraint:
#
#   * The GROOMED BODY names it — a `**Weakens:** `<smell-id>` at `<key>``
#     clause, in the label-at-line-start shape `ready-lint`'s own anchors use.
#     `claim-check` copies it into the branch's claim receipt as a `weakens`
#     line, at the one moment a gate holds the groomed body and the work has not
#     started.
#   * A COMMIT names it — a `Weakens: <smell-id> <key>` trailer on a commit in
#     `origin/main..HEAD`. Two sources rather than one because they answer in
#     different places: the receipt lives under `$GIT_DIR` and dies with the
#     container, so CI never sees it, while a commit travels — the same reason
#     the board discipline puts the issue key in git rather than in a tracker
#     write (`mem:workflow/board-states`).
#   * They AGREE. Where both are readable, a trailer naming something the groom
#     did not is refused, and the trailer alone admits nothing.
#
# So the strong half runs where the receipt is — `verify`, before a runner is
# ever spent — and CI confirms the committed half. That is the division of
# labour the whole workflow rests on: CI confirms what you proved.
#
# It is NOT a flag, and that distinction is the mechanism rather than a wording
# preference: nothing an author can set at PR time reaches it. Writing the clause
# after the claim moves the tracker's `updatedAt`, which the receipt already
# pins, so the admission was groomed before the work started or it is not there.
set -euo pipefail

cd "${CONFIG_LINT_ROOT:-$(git rev-parse --show-toplevel)}"

base="${CONFIG_LINT_BASE:-}"
args=(config lint)
if [[ -n "$base" ]]; then
	args+=(--config-from "$base")
fi

# `cargo run` rather than an installed binary, so the gate always judges the
# working tree's engine and config together — the pair that ships.
rc=0
output=$(cargo run --quiet -p batten -- "${args[@]}" 2>&1) || rc=$?

if [[ "$rc" = 0 ]]; then
	# The binary's last line is already the `config-lint: N smell(s)` summary;
	# echoing it verbatim keeps one wording rather than two that can disagree.
	echo "${output##*$'\n'}"
	exit 0
fi

# The binary already emits pointer-only lines (`batten.toml:<loc> <id>`); pass
# them through rather than re-deriving a message here.
echo "$output" >&2

if [[ "$rc" != 2 ]]; then
	echo "::error:: config-lint: could not judge batten.toml (exit $rc) — this is not \"no weakening found\", it is a run that could not take a reading. Fix the config, or the base ref if one was supplied." >&2
	exit "$rc"
fi

# --- the policy verdict, and what a groom already admitted --------------------

# Both sources, read once. Either may be absent — outside a checkout, on a branch
# with no claim, in CI where no receipt was ever written — and absence admits
# NOTHING, so this can only turn a refusal into a pass on evidence it found.
groomed=""
trailers=""
if git_dir=$(git rev-parse --git-dir 2>/dev/null) &&
	branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) &&
	[[ -n "$branch" ]]; then
	# The filename spelling `claim-check` mints under. A mismatch here reads as
	# "no groom recorded", which refuses rather than admits.
	claim="$git_dir/batten-receipts/claim.${branch//\//-}"
	if [[ -r "$claim" ]]; then
		groomed=$(grep -E '^weakens ' "$claim" || true)
		# The issue key is provenance for the human reading a refusal, not part
		# of the pair being matched: which story groomed it does not change
		# whether this smell was groomed.
		groomed=$(sed -E 's/^weakens [A-Za-z]+-[0-9]+ //' <<<"$groomed")
	fi
fi
# git's own trailer parse rather than a grep over the body, so a line quoted
# mid-message cannot pose as a trailer. `origin/main..HEAD` is this branch's own
# commits: a trailer inherited from the trunk would admit the same weakening on
# every branch cut afterwards.
if git rev-parse --verify --quiet origin/main >/dev/null 2>&1; then
	trailers=$(git log --format='%(trailers:key=Weakens,valueonly)' origin/main..HEAD 2>/dev/null || true)
fi

# The binary's pointer lines are `batten.toml:<where> <smell-id>` (§6), so the
# pair a clause must name is exactly what a reader already sees.
pointers=$(grep -E '^batten\.toml:' <<<"$output" || true)

admitted=0
refused=0
while IFS= read -r pointer; do
	[[ -n "$pointer" ]] || continue
	rest=${pointer#batten.toml:}
	smell=${rest##* }
	key=${rest% *}
	# `grep -Fx` over a rebuilt line rather than a pattern built from the
	# pointer: a key path carries `[` and `]`, which a regex reads as a
	# character class.
	if [[ -n "$trailers" ]] && grep -qFx "$smell $key" <<<"$trailers"; then
		if [[ -z "$groomed" ]]; then
			# CI's half: no receipt to consult here, and refusing on its absence
			# would fail every branch whose local run already proved it.
			echo "config-lint: admitted $smell $key (commit trailer; no claim receipt here to check it against)"
			admitted=$((admitted + 1))
			continue
		fi
		if grep -qFx "$smell $key" <<<"$groomed"; then
			echo "config-lint: admitted $smell $key (groomed, and named by a commit)"
			admitted=$((admitted + 1))
			continue
		fi
	fi
	refused=$((refused + 1))
done <<<"$pointers"

if [[ "$refused" -eq 0 ]] && [[ "$admitted" -gt 0 ]]; then
	echo "config-lint: $admitted smell(s), every one admitted by a groomed decision"
	exit 0
fi

if [[ -n "$base" ]]; then
	echo "::error:: config-lint: batten.toml carries a policy smell, judged against \`$base\` — house style §8 loads policy out of band precisely so a branch cannot lower the bar it is judged by. There is no PR-time hatch by design: a deliberate relaxation belongs in the issue's Ready block, groomed before the work starts, and reaches this gate as a \`**Weakens:** \`<smell-id>\` at \`<key>\`\` clause there plus a matching \`Weakens: <smell-id> <key>\` commit trailer — never as something asserted in the change that performs it." >&2
else
	echo "::error:: config-lint: batten.toml carries a policy smell" >&2
fi
exit 2

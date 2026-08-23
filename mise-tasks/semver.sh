#!/usr/bin/env bash
#MISE description="Gate: the API delta on this branch is compatible with the bump release-plz will infer, unless a commit declares the break"
#
# CLOUD-102. release-plz infers the bump from commit TYPES; nothing checked it
# against the actual API delta, so a `fix:` that is really breaking mis-releases.
# Batten lands every commit by fast-forward and its value is a stable contract,
# so the inference deserves a verifier.
#
# THE DEFAULT INVOCATION IS A CHECK THAT CANNOT FAIL, and that is the whole
# reason this is a task rather than one line in `verify`. Measured on 0.0.61:
#
#   $ cargo semver-checks check-release -p batten --baseline-rev origin/main
#   Checking batten v0.0.61 -> v0.0.61 (no change; assume major)
#   Checked [0.000s] 0 checks: 0 pass, 254 skip
#   Summary  no semver update required
#
# Zero checks ran. A branch carries the same version as its baseline — release-plz
# bumps on landing, not before — so the tool assumes a major release is coming and
# every lint is vacuously satisfied. Wired that way this gate would report green
# over any breakage, forever.
#
# `--release-type` is what makes it real: it states the bump being claimed instead
# of inferring one from two identical versions. Measured, the same tree then runs
# 223 checks. `patch` is the honest claim here because below 0.1.0 release-plz
# bumps the patch whatever the commit type says (.claude/rules/commits.md), so
# patch-compatibility is exactly what the next release will assert.
#
# THE TOOLCHAIN IS THE PINNED ONE, AND THAT IS NEW (CLOUD-593, CLOUD-654). It
# used to be a floating rustup `stable`, and the reason was real while it lasted:
# cargo-semver-checks 0.50.0 refuses under 1.85.0 ("rustc version is not high
# enough: >=1.93.0 needed"), and downgrading was not an escape — 0.40.0, the
# 1.85-era release, instead dies resolving this crate's own dependency tree
# (`home@0.5.12 requires rustc 1.88`). So the rustdoc JSON was built by whatever
# `stable` happened to be.
#
# CLOUD-593 coupled the floor to the pin and moved the pin to current stable,
# which removed that premise and then INVERTED it. `rust-version` became 1.97, and
# a rustup `stable` channel resolving anything older now aborts the run outright:
# measured here at rustc 1.94.1, "batten@0.0.80 requires rustc 1.97", exit 101 —
# not a verdict, so `verify` correctly refused rather than passing. A floating
# channel could break this gate again on any given day, in either direction; the
# pin cannot, because it is the compiler the crate is actually built with.
#
# Read from `rustc --version` rather than parsed out of `mise.toml`, deliberately:
# mise puts the pinned toolchain on PATH, so asking the compiler that is actually
# active is a READ of the one authority instead of a fourth COPY of the number —
# the copies are exactly what `msrv-pin-agreement` exists to hold together.
#
# Exit 0 compatible (or a declared break) / 1 an undeclared break / 2 could not
# look — matching the other `*-check` programs, so a caller can tell "this branch
# breaks the contract" from "this gate never ran".
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT undeclared-break-passes|s/^exit 1$/exit 0/|an undeclared break fails

set -uo pipefail

cd "${SEMVER_ROOT:-$(git rev-parse --show-toplevel)}" || exit 2

readonly PACKAGE="${SEMVER_PACKAGE:-batten}"
readonly BASELINE="${SEMVER_BASELINE:-origin/main}"
# The bump release-plz will infer. Overridable so the suite can drive the other
# claims, not so a caller can weaken the gate in passing: a real change of claim
# belongs in this file, beside the reasoning above.
readonly RELEASE_TYPE="${SEMVER_RELEASE_TYPE:-patch}"

# --- the toolchain ------------------------------------------------------------
#
# Guarded by hand, because a task body does not run under `set -e` and a gate that
# could not build its own inputs must never report on them.
toolchain="${SEMVER_TOOLCHAIN:-}"
if [[ -z "$toolchain" ]]; then
	# `rustc 1.97.1 (8bab26f4f 2026-07-14)` -> `1.97.1`, which is also the name
	# rustup gives the toolchain mise installed, so `cargo +1.97.1` resolves it.
	toolchain=$(rustc --version 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$toolchain" ]]; then
	echo "::error:: semver: no rustc on PATH, so the toolchain the comparison must run under could not be determined. This is a checkout problem, not a verdict — run \`mise install\`." >&2
	exit 2
fi
# Read into a variable and match with `<<<` rather than piping into `grep -q`:
# under `pipefail` an early-exiting grep SIGPIPEs its producer, so a MATCH
# reports failure (mem:toolchain-and-hooks). `pipefail-grep-check` gates it.
installed=$(rustup toolchain list 2>/dev/null)
if ! grep -q "^${toolchain}" <<<"$installed"; then
	if ! rustup toolchain install "$toolchain" --profile minimal >&2; then
		echo "::error:: semver: could not install the \`$toolchain\` toolchain cargo-semver-checks needs, so the API delta was never compared. This is a checkout problem, not a verdict." >&2
		exit 2
	fi
fi

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
	echo "::error:: semver: cargo-semver-checks is not on PATH — run \`mise install\`. A gate that cannot look must not report green." >&2
	exit 2
fi

# --- the comparison -----------------------------------------------------------
report=$(mktemp) || exit 2
trap 'rm -f "$report"' EXIT

# `CARGO_TERM_COLOR=never`, overriding `mise.toml [env]`'s `always`, and this is
# load-bearing rather than cosmetic: the report below is PARSED, and a gate that
# parses colour is the CLOUD-199 defect — an anchored pattern that can never
# match because escape sequences sit between the anchor and the word. It was not
# hypothetical here. The first version of this task inherited `always`, its
# `^ *Checked` anchor matched nothing, and the vacuous-run refusal directly below
# reported a clean pass over a run that graded 0 checks. Caught by running the
# probe rather than by reading the code.
CARGO_TERM_COLOR=never cargo "+$toolchain" semver-checks check-release \
	--package "$PACKAGE" \
	--baseline-rev "$BASELINE" \
	--release-type "$RELEASE_TYPE" \
	>"$report" 2>&1
rc=$?

# THE VACUOUS-RUN REFUSAL, and it is the point of the whole task. A run that
# graded nothing has not answered — it is the shape the default invocation
# produces, and reporting it as a pass is how this gate would quietly die. Read
# from the tool's own summary line rather than inferred from the exit code,
# because that line is where "0 checks" is stated.
if grep -qE '^[[:space:]]*Checked .* 0 checks:' "$report"; then
	echo "::error:: semver: cargo-semver-checks ran 0 checks, so nothing was verified. That is the \`no change; assume major\` shape — the comparison needs an explicit --release-type. Not a pass." >&2
	exit 2
fi

if [[ "$rc" = 0 ]]; then
	echo "semver: the API delta on this branch is ${RELEASE_TYPE}-compatible for $PACKAGE (baseline $BASELINE)"
	exit 0
fi

# An exit code that is neither "compatible" nor "incompatible" is a broken run:
# a missing baseline ref, a crate that would not build, a tool that crashed. 100
# is cargo-semver-checks' own "required version bump is larger than claimed".
if [[ "$rc" != 100 ]]; then
	echo "::error:: semver: cargo-semver-checks exited $rc, which is neither verdict — the comparison did not complete, so this is not a pass. Re-run \`mise run semver\` and read its output." >&2
	exit 2
fi

# --- a break is permitted only when it is DECLARED ----------------------------
#
# The same range and the same env convention `[tasks.commit-lint]` uses, so there
# is one definition of "the commits this branch adds" rather than two that drift.
# Absent a range, the branch's own commits since the baseline are that set.
base="${BASE_SHA:-$(git rev-parse "$BASELINE" 2>/dev/null)}"
head="${HEAD_SHA:-HEAD}"

# Pointer, never payload (non-negotiable rule 4): the lint ids the tool named,
# not the rustdoc it read them from.
lints=$(grep -oE '^--- failure [a-z_]+' "$report" | awk '{print $3}' | sort -u | tr '\n' ' ')

declared=""
if [[ -n "$base" ]]; then
	while read -r sha; do
		[[ -n "$sha" ]] || continue
		subject=$(git show -s --format=%s "$sha" 2>/dev/null)
		body=$(git show -s --format=%B "$sha" 2>/dev/null)
		# Conventional Commits spells a break two ways, and both count: a `!`
		# before the colon, or a `BREAKING CHANGE:` footer.
		if grep -qE '^[a-z]+(\([a-z0-9._-]+\))?!:' <<<"$subject" ||
			grep -qE '^BREAKING[ -]CHANGE:' <<<"$body"; then
			declared="$sha"
			break
		fi
	done <<<"$(git rev-list --no-merges "$base..$head" 2>/dev/null)"
fi

if [[ -n "$declared" ]]; then
	echo "semver: breaking change DECLARED by ${declared:0:8} — ${lints}(baseline $BASELINE)"
	exit 0
fi

echo "::error:: semver: this branch breaks the $PACKAGE API but no commit declares it. Failing lint(s): ${lints}" >&2
echo "::error:: semver: mark the break in Conventional Commits — a \`!\` before the colon, or a \`BREAKING CHANGE:\` footer — or keep the change ${RELEASE_TYPE}-compatible." >&2
exit 1

#!/usr/bin/env bash
#MISE description="Gate: the SBOM this tree produces meets the NTIA/CISA minimum elements — the checker's exit code, never its report"
#
# CLOUD-580, adopting `ntia-conformance-checker` (CLOUD-279 verdict 1) rather than
# writing a clause list here. The clause set is the TOOL's, named by its own
# `--comply` flag; this script owns only which artifact is judged, and the two
# `sbom-ntia-*` rows in `batten.toml` own when.
#
# WHY IT IS A SEPARATE QUESTION FROM `sbom-check`. That gate asks whether the
# inventory describes this tree — the cargo count matches `Cargo.lock`, two scans
# agree. This one asks whether the inventory is USABLE by whoever receives it:
# the NTIA 2021 minimum elements and CISA's 2024 FSCT minimum expectation are
# what a procurement review checks, and "we publish an SPDX SBOM" satisfies
# neither by itself. CLOUD-279's M1 measured that gap on v0.0.52, again here on
# 2026-08-14 (243 components, `componentSuppliers` absent on 190, both
# `componentConcludedLicenses` and `componentCopyrightTexts` absent on 243/243),
# and again on 2026-08-23 at v0.0.106 under syft 1.51.0: **340 components,
# no-supplier=282, no-license=340, no-copyright=340**. The shape is unchanged and
# the denominator moved with the lockfile — which is CLOUD-664's point, that the
# denominator is itself wrong, and this line is a count of what the document says
# rather than of what the repository depends on.
#
# WHY THE CONFORMANCE ROW LANDS AS `warn` — the open question CLOUD-580 carried,
# settled by measurement rather than preference. `Cargo.lock` contains ZERO
# license fields (`grep -c license Cargo.lock` = 0) and no supplier field of any
# kind, and syft's cargo cataloger reads exactly that file, so it emits
# `NOASSERTION` for all 243 — there is no syft flag that can invent data its input
# does not carry. Closing the gap therefore means ENRICHING the document from
# `cargo metadata`, which is a different change with its own issue; this one
# RECORDS the conformance level per SHA. A `deny` here would fail `batten
# enforce` -> `verify` and stop every landing in the repo until that other change
# exists, which is a gate deciding a question nobody asked it.
#
# WHAT KEEPS THAT FROM BEING SENSOR-ONLY (non-negotiable rule 2). The `warn` row
# is one of a pair: `sbom-ntia-precondition` is `deny` and holds the half that
# must never quietly stop working — the checker resolves and the document
# derives. So the mechanism is enforced and only the verdict it produces is
# advisory. `--precondition` is that mode.
#
# NO OUTPUT PARSING ANYWHERE (CLOUD-93). The verdict is `sbomcheck`'s exit code.
# The counts this prints come from its JSON report, and they are a MESSAGE, never
# the decision: `tests/ntia-check.bats` drives a stub that writes a conformant
# report and exits non-zero, and asserts this still fails. Counts are also the
# only thing printed — never a component name, never a document byte (rule 4),
# which is why the checker's own `print` report is never allowed near stdout.
#
# It re-runs `mise-tasks/sbom.sh` rather than restating the syft flags — one
# definition of the invocation (§1), the same reason `sbom-check` does, so this
# cannot certify a document a release would not publish. Into a scratch
# directory, so the gate never writes the tree it judges.
#
# Exit 0 pass / 1 nonconformant / 2 could-not-look, matching the other `*-check`
# programs.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT nonconformant-sbom-passes|s/^\texit 1$/\texit 0/|a nonconformant document fails
#
# The precondition's satisfiability arm is the durable half of CLOUD-666, so it
# ships with the mutations that prove it decides. Neutering either one restores
# the state this row closed: a standard nobody can satisfy reporting as a
# document nobody has fixed.
#MUTANT precondition-ignores-the-spec|s/^\t\tif \[\[ "\$doc_spec" = spdx3 \]\]; then$/\t\tif true; then/|THE DURABLE HALF
#MUTANT precondition-guesses-an-absent-spec|s/^\tif \[\[ -z "\$doc_version" \]\]; then$/\tif false; then/|a document declaring no spdxVersion is could-not-look, never a pass
# And the receipt's demotion to advisory. The mutation restores the shipped defect
# — a failed record deciding conformance — which is the false verdict CI reported.
# The braces are LITERAL and therefore UNESCAPED (CLOUD-1034). `\{ … \}` is the
# BRE interval quantifier, so the escaped spelling made sed reject the whole
# expression — `Invalid content of \{\}` — and this row never applied at all, on
# the one mutation guarding a defect that already reached CI.
#MUTANT receipt-failure-decides-conformance|s@^\techo "ntia-check: \${spdx##\*/} conforms, but the replay receipt.*$@\texit 1@|a receipt that cannot be written is reported, never a nonconformance
set -euo pipefail

# Resolved BEFORE the cd: `$0` may be relative, and moving first would leave this
# pointing at a sibling of whatever tree is being judged rather than of this file.
SBOM="$(cd "$(dirname "$0")" && pwd)/sbom.sh"

cd "${NTIA_CHECK_ROOT:-$(git rev-parse --show-toplevel)}"

# The standard to hold the document to. `ntia` ALONE, and that is a measurement
# rather than a preference (CLOUD-666).
#
# `fsct3-min` was here too, on the reasoning that the 2021 NTIA minimum elements
# and CISA's 2024 FSCT tier-3 minimum are different published expectations and
# either alone would let a regression in the other land. That reasoning is sound
# and the second standard was still unsatisfiable for every document this
# producer can emit, so its only effect was to make the gate permanently red:
#
#   1. `fsct_checker.py:94`'s `check_compliance()` requires eleven conditions,
#      one of which is `bool(self.sbom_gen_context)`. No field of the JSON report
#      corresponds to it, so the report cannot explain its own refusal — measured
#      with `supplier`, `licenseConcluded` and `copyrightText` set on every
#      component: all sub-checks true, every nonconformant list empty,
#      `conformanceMessages: []`, and still `isConformant: false`.
#   2. `base_checker.py:407`'s `get_sbom_types()` opens `if not self.doc or
#      self.sbom_spec != "spdx3": return []`, its docstring giving the reason —
#      "In SPDX 3, SBOM type is only available in /Software/Sbom class." So for
#      any SPDX 2.x document the list is empty and the condition is unsatisfiable
#      by construction.
#   3. And syft cannot emit SPDX 3. Re-measured 2026-08-23 on syft **1.51.0**,
#      whose `--output` format list is byte-identical to 1.42.4's: `cyclonedx-json
#      cyclonedx-xml github-json purls spdx-json spdx-tag-value syft-json
#      syft-table syft-text template`. `spdx-json` is SPDX 2.3, and this tree's
#      document reports `spdxVersion: SPDX-2.3` / `sbomSpec: spdx2`. syft
#      1.46.0's "SPDX 3 Support" release note (anchore/syft#4269) is model and
#      parsing support; it added no `-o` format, so there is still nothing to
#      switch to.
#
# So no amount of enrichment reached it, and a permanently-red gate is a sensor
# reporting a constant. Whether FSCT v3 is worth pursuing is a separate decision
# that needs an SPDX 3 producer; recording it as a known non-goal is honest.
#
# Overridable, so the bats suite can drive one — and so re-adding a standard is
# possible. What re-adding one CANNOT do is silently return to this state: the
# precondition below refuses a standard whose required spec this producer's own
# document does not carry.
read -r -a STANDARDS <<<"${NTIA_STANDARDS:-ntia}"

# The standards that require an SPDX 3 document, and the whole reason the
# precondition below can decide anything. Data, not a heuristic: each name here
# is one whose `check_compliance()` reads a field `get_sbom_types()` only
# populates for `sbom_spec == "spdx3"` (point 2 above).
readonly SPDX3_ONLY_STANDARDS=" fsct3-min "

# `BATTEN_BIN` for the same reason `linear-check` takes it: the suite must be able
# to stub the binary rather than build the workspace, since hk deliberately
# serialises the cargo target-dir lock.
read -r -a batten_bin <<<"${BATTEN_BIN:-cargo run --quiet -p batten --}"

# The checker, resolved through a named override rather than off PATH alone — the
# `BATTEN_BIN` idiom, and here it is load-bearing for the test rather than a
# convenience: `sbomcheck` is a mise-managed shim, so a suite cannot make it
# ABSENT by shadowing PATH, and the could-not-look branch would be untestable.
SBOMCHECK_BIN="${SBOMCHECK:-sbomcheck}"

if [[ ! -x "$SBOM" ]]; then
	echo "::error:: ntia-check: cannot execute $SBOM, so no document can be derived and conformance is unverified. That is a checkout problem, not a nonconformant SBOM." >&2
	exit 2
fi

if ! command -v "$SBOMCHECK_BIN" >/dev/null 2>&1; then
	echo "::error:: ntia-check: no checker at '$SBOMCHECK_BIN' (\$SBOMCHECK overrides), so conformance is unverified. Run: mise install pipx:ntia-conformance-checker" >&2
	exit 2
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# The document under test, derived by the one script that decides the syft
# invocation and the asset names. Its stdout is `KEY=VALUE`, so the path is read
# from there rather than rebuilt here.
if ! derived=$(SBOM_OUT_DIR="$scratch/sbom" "$SBOM"); then
	echo "::error:: ntia-check: could not derive the SBOM, so its conformance is unverified." >&2
	exit 2
fi
spdx=$(sed -n 's/^spdx=//p' <<<"$derived")
if [[ -z "$spdx" ]] || [[ ! -f "$spdx" ]]; then
	echo "::error:: ntia-check: sbom did not report a readable SPDX document, so there is nothing to judge." >&2
	exit 2
fi

# --precondition: the mechanism works — the checker resolves and a document
# exists to hand it. Deliberately NOT a conformance verdict: this is the half
# carried by a `deny` row, and it must stay true of a repository whose SBOM is
# not yet conformant.
if [[ "${1:-}" = "--precondition" ]]; then
	if ! "$SBOMCHECK_BIN" --version >/dev/null 2>&1; then
		echo "::error:: ntia-check: sbomcheck is present but does not answer --version, so no verdict it gave could be trusted." >&2
		exit 2
	fi

	# THE CONFIGURATION IS PART OF THE MECHANISM (CLOUD-666). A standard the
	# producer's own document can never satisfy does not report nonconformance —
	# it reports a constant, and for two months it was read as a document nobody
	# had enriched. Only a precondition tells those two apart, which is why this
	# lives on the `deny` row: "could we even ask this question" is exactly what
	# this mode answers, and the answer here is no.
	#
	# The spec is read from the DOCUMENT rather than asked of the producer, so
	# this stays a pure read of the artifact under test — no extra subprocess and
	# no network (§3) — and it keeps deciding correctly if syft ever gains an
	# SPDX 3 emitter, because the document is what would change.
	#
	# ABSENT IS EXIT 2, never a pass. A document with no `spdxVersion` is one
	# whose spec could not be looked at, and a precondition that clears every
	# standard it cannot classify is the silent return this row exists to close.
	doc_version=$(jq -r '.spdxVersion // ""' "$spdx" 2>/dev/null) || doc_version=""
	if [[ -z "$doc_version" ]]; then
		echo "::error:: ntia-check: ${spdx##*/} declares no spdxVersion, so which spec it is cannot be read and no standard can be checked for satisfiability." >&2
		exit 2
	fi
	case "$doc_version" in
	SPDX-3*) doc_spec=spdx3 ;;
	SPDX-2*) doc_spec=spdx2 ;;
	*)
		echo "::error:: ntia-check: ${spdx##*/} declares an spdxVersion this gate cannot classify ($doc_version), so no standard can be checked for satisfiability." >&2
		exit 2
		;;
	esac

	# Written as `case` and a bare `if` rather than the shorter `|| continue`
	# pair, for the reason `claim-check` records about its own `takeover_requested`
	# flag: `|` is the `#MUTANT` field delimiter, so a condition containing `||`
	# cannot be expressed as a mutation — and the satisfiability test is exactly
	# the line that must not lose its proof.
	for standard in "${STANDARDS[@]}"; do
		case "$SPDX3_ONLY_STANDARDS" in
		*" $standard "*) ;;
		*) continue ;;
		esac
		if [[ "$doc_spec" = spdx3 ]]; then
			continue
		fi
		echo "::error:: ntia-check: NTIA_STANDARDS names '$standard', which requires an spdx3 document, and ${spdx##*/} is $doc_spec — no document this producer emits can satisfy it, so its refusal would be a constant rather than a verdict about this tree. Drop it from NTIA_STANDARDS, or change the producer to emit SPDX 3." >&2
		exit 2
	done

	echo "ntia-check: precondition holds — sbomcheck resolves, ${spdx##*/} derives as $doc_spec, and every configured standard is satisfiable by it"
	exit 0
fi

violations=0
# WHICH standards refused, so the summary can name them instead of asserting one
# cause for all of them (CLOUD-666, and the CLOUD-198 class it belongs to).
refused=""
report() { # pointer-only (rule 4): document name, rule id, counts. Never a component.
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

for standard in "${STANDARDS[@]}"; do
	json="$scratch/report-$standard.json"
	# THE VERDICT, and the only thing that is one: the checker's exit status.
	# `--output json --output-file` keeps its human report — which names every
	# nonconformant component — out of this gate's streams entirely.
	rc=0
	"$SBOMCHECK_BIN" "$spdx" --comply "$standard" --output json --output-file "$json" >/dev/null 2>&1 || rc=$?
	if [[ "$rc" -eq 0 ]]; then
		continue
	fi
	# A MESSAGE, never the decision (see the header): counts only, and only when
	# the report is readable, so a checker that wrote nothing still reports its
	# exit code rather than dying on the missing file.
	detail="exit=$rc"
	if [[ -s "$json" ]] && counts=$(jq -r '"components=\(.totalNumberComponents // 0)"
		+ " no-supplier=\(.componentSuppliers.nonconformantComponents // [] | length)"
		+ " no-license=\(.componentConcludedLicenses.nonconformantComponents // [] | length)"
		+ " no-copyright=\(.componentCopyrightTexts.nonconformantComponents // [] | length)"' "$json" 2>/dev/null); then
		detail="$detail $counts"
	fi
	report "${spdx##*/}:0" "sbom-ntia-nonconformant ($standard $detail)"
	refused="${refused}${refused:+ }$standard"
done

if [[ "$violations" -ne 0 ]]; then
	# NAMES THE STANDARD THAT REFUSED, AND ASSERTS NO CAUSE (CLOUD-666).
	#
	# This line used to read "The gap is in what a cargo lockfile can supply (no
	# license or supplier fields exist there), so closing it means enriching the
	# SBOM, not re-running this." That is true of `ntia` and it was printed for
	# every standard — including one whose refusal no enrichment could ever reach.
	# A false cause is worse here than no cause, because it is stated in the one
	# place a reader debugging the gate will stop: it names something real, so
	# there is no reason to doubt it, and the reader goes on enriching fields
	# forever. That is the CLOUD-198 class.
	#
	# So the summary points at the per-standard lines above, which carry the
	# standard and its own counts, and stops explaining on their behalf. A gate
	# whose explanation cannot be wrong is worth more than one whose explanation
	# is usually right.
	echo "::error:: ntia-check: $violations standard(s) refused this document: $refused. Each line above names the standard and its own counts — read the cause from the standard that refused, not from this line." >&2
	exit 1
fi

# The receipt is the binary's job (CLOUD-203), keyed to the exact commit whose
# document conformed — so an amend or a rebase leaves no receipt, which is the
# point: `batten hook` can then answer from the receipt instead of paying a syft
# scan inside the p95 < 100ms budget.
#
# ITS FAILURE IS NOT A VERDICT ABOUT THE DOCUMENT, and letting `set -e` make it one
# is how CLOUD-631's promotion turned a green branch red. `batten receipt record`
# exits 1 where the configured transcript is unreadable, and that is a RUNNER's
# ordinary state — no `.claude/.transcript.jsonl` exists on one — so the unguarded
# call reported `sbom-ntia-conformance` over a document `sbomcheck` had just
# judged conformant. Measured on a pristine clone of this branch: `sbomcheck`
# exits 0, `violations` is 0, the record exits 1, the gate exits 1; dropping an
# empty transcript file in place makes the same record exit 0. It stayed invisible
# because the row was `warn` until this bundle promoted it, and because the suite's
# stub could only succeed.
#
# So it is reported and not obeyed. The asymmetry is the point: a receipt that was
# not written costs the next `batten hook` a syft scan, while a receipt that
# decides conformance costs a false verdict — and this file's whole contract is
# that exit 1 means the document is nonconformant. `verify`'s own receipts are the
# precedent for the other direction, and they differ in exactly the way that
# matters: theirs attest a check RAN, this one only caches an answer already
# printed.
if ! "${batten_bin[@]}" receipt record sbom-ntia; then
	echo "ntia-check: ${spdx##*/} conforms, but the replay receipt could not be recorded — the next hook pays a scan for it. This is not a verdict about the document." >&2
fi
echo "ntia-check: ${spdx##*/} conforms to ${STANDARDS[*]}"

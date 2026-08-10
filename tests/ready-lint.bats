#!/usr/bin/env bats
# ready-lint's decision table (CLOUD-179), driven by get_issue-shaped payloads.
#
# The cases that matter are the ones prose cannot fake: a blocker asserted in §8
# text with no matching `blockedBy` relation, and a §6 bump that disagrees with
# its own commit type. Everything else here exists to pin the deliberate
# non-behaviours — chiefly that an omitted clause is NOT a violation, because the
# Definition of Ready forbids restating clauses and the corpus's best issue
# (CLOUD-33) omits §4.

setup() {
	LINT="$BATS_TEST_DIRNAME/../mise-tasks/ready-lint"
}

# Writes a get_issue payload to $PAYLOAD: $1 description, rest are blockedBy ids.
payload() {
	local desc="$1"
	shift
	local rel="[]"
	if [ "$#" -gt 0 ]; then
		rel=$(printf '%s\n' "$@" | jq -R '{id: .}' | jq -sc .)
	fi
	PAYLOAD="$BATS_TEST_TMPDIR/payload.json"
	jq -nc --arg d "$desc" --argjson r "$rel" \
		'{id: "CLOUD-999", description: $d, relations: {blockedBy: $r}}' >"$PAYLOAD"
}

# Runs the lint over the payload just built.
lint() { run bash -c "'$LINT' <'$PAYLOAD'"; }

# A minimal well-formed block. Only the clauses under test are ever added.
block() {
	cat <<-EOF
		**Why**
		Something needs doing.

		**Refinement — Ready (a summary)**

		* **Source of truth (§1).** One authoritative artifact.
		$*
	EOF
}

@test "a well-formed block passes" {
	payload "$(block '* **Commit / bump (§6).** `ci` → **no bump**.')"
	lint
	[ "$status" -eq 0 ]
}

@test "omitted clauses are not a violation" {
	# The load-bearing non-behaviour: a body carrying only §1 is legal, because
	# the gate document says bodies carry specializations, not restatements.
	payload "$(block '')"
	lint
	[ "$status" -eq 0 ]
}

@test "a blocker cited in §8 with no relation is reported" {
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (the loader this validates).')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"blocker-cited-without-relation (CLOUD-29)"* ]]
}

@test "the same citation passes when the relation actually exists" {
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (the loader this validates).')
	payload "$d" CLOUD-29
	lint
	[ "$status" -eq 0 ]
}

@test "a blocker noted as closed needs no relation" {
	# Linear drops the relation once a dependency resolves, so demanding one here
	# would fail every correctly-refined issue whose blocker has landed.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-21 (closed).')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "§8 None is an explicit, valid answer" {
	local d
	d=$(block '* **Blockers (§8).** None.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a relatedTo mention on the §8 line is not a claim" {
	# Correct prose cross-references the other relation directions; only ids
	# after the blockedBy token are held against the board. Flagging a
	# relatedTo mention would punish exactly the precision §8 asks for.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (loader). `relatedTo` CLOUD-37 — the two share a representation but neither strictly blocks the other.')
	payload "$d" CLOUD-29
	lint
	[ "$status" -eq 0 ]
}

@test "a house-style (§6) cross-reference is not the commit clause" {
	# The §N namespace is overloaded: Ready blocks cite house-style sections as
	# bare (§6)/(§7). Only the "Commit / bump (§6)" label is the clause.
	local d
	d=$(block '* Output is byte-stable and records the promoted disposition (§6).')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "§6 none is an explicit, valid no-commit declaration" {
	# A Linear-only or board-side change lands no commit; demanding a type
	# there would force a lie into the block.
	local d
	d=$(block '* **Commit / bump (§6).** none — Linear-only, no code change, no semver bump.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a closed blocker in Linear's rendered-mention form is exempt" {
	# Linear stores mentions as <issue …>CLOUD-N</issue>, so the (closed)
	# exemption must survive the markup between the id and the marker — an
	# exemption that only matches plain-text fixtures is dead code in production.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` <issue id="abc" href="https://linear.app/x/issue/CLOUD-21/slug">CLOUD-21</issue> (closed).')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a rendered-mention blockedBy claim without a relation is still flagged" {
	# Stripping mention markup must not hide true positives.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` <issue id="abc" href="https://linear.app/x/issue/CLOUD-29/slug">CLOUD-29</issue> (loader).')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"blocker-cited-without-relation (CLOUD-29)"* ]]
}

@test "a cross-reference after the claim sentence is not a claim" {
	# The claim span is one sentence; a trailing parenthetical cross-reference
	# asserts nothing about blocking.
	local d
	d=$(block '* **Blockers (§8).** `blockedBy` CLOUD-29 (loader). Grows in coverage as the tree fills (CLOUD-27).')
	payload "$d" CLOUD-29
	lint
	[ "$status" -eq 0 ]
}

# --- §6 arrows are version-dependent ------------------------------------------
#
# This repo is 0.0.x, so the SemVer arrows do not fire: release-plz bumps the
# patch whatever the type says (measured on CLOUD-226 — a `feat!` with a BREAKING
# CHANGE footer released as v0.0.23). The amended clause therefore asks for the
# honest type plus "patch until 0.1.0", and the pair below pins both directions:
# the honest declaration passes, the retired arrow is the violation.

@test "feat to patch agrees below 0.1.0" {
	local d
	d=$(block '* **Commit / bump (§6).** `feat` → **patch** until `0.1.0`.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a bump promising the retired arrow is reported below 0.1.0" {
	local d
	d=$(block '* **Commit / bump (§6).** `feat` → **minor**.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"bump-disagrees-with-type (feat implies patch below 0.1.0)"* ]]
}

@test "a breaking change promising major is reported below 0.1.0" {
	# The measured case: v0.0.23 shipped a feat! as a patch, so an issue promising
	# major promises something the tool will not do.
	local d
	d=$(block '* **Commit / bump (§6).** `feat!` → **major** (BREAKING CHANGE footer).')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"bump-disagrees-with-type"* ]]
}

@test "a breaking change declaring patch agrees below 0.1.0" {
	local d
	d=$(block '* **Commit / bump (§6).** `feat!` → **patch** until `0.1.0`; the changelog still marks it breaking.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

@test "a no-bump type does not collapse to patch below 0.1.0" {
	# A ci/chore-only change releases nothing at any version. Folding it into the
	# patch regime would demand a bump the tool never produces.
	local d
	d=$(block '* **Commit / bump (§6).** `ci` → **no bump**.')
	payload "$d"
	lint
	[ "$status" -eq 0 ]
}

# Copies the lint next to a synthetic workspace root so the ≥0.1.0 regime is
# exercised through the real code path rather than an env override — a gate's own
# facts must not have a bypass surface.
lint_at_version() {
	local v="$1"
	mkdir -p "$BATS_TEST_TMPDIR/root/mise-tasks"
	printf '[workspace.package]\nversion = "%s"\n' "$v" >"$BATS_TEST_TMPDIR/root/Cargo.toml"
	cp "$LINT" "$BATS_TEST_TMPDIR/root/mise-tasks/ready-lint"
	run bash -c "'$BATS_TEST_TMPDIR/root/mise-tasks/ready-lint' <'$PAYLOAD'"
}

@test "the arrows fire again at 0.1.0 and above" {
	payload "$(block '* **Commit / bump (§6).** `feat` → **minor**.')"
	lint_at_version 1.2.3
	[ "$status" -eq 0 ]
}

@test "patch under a released version is the disagreement" {
	payload "$(block '* **Commit / bump (§6).** `feat` → **patch**.')"
	lint_at_version 1.2.3
	[ "$status" -eq 1 ]
	[[ "$output" == *"bump-disagrees-with-type (feat implies minor)"* ]]
}

@test "an unreadable workspace version exits 2, not a guessed verdict" {
	# Guessing either regime manufactures a violation or launders one, so a gate
	# that cannot establish its own regime must refuse to answer.
	payload "$(block '* **Commit / bump (§6).** `feat` → **patch**.')"
	mkdir -p "$BATS_TEST_TMPDIR/noroot/mise-tasks"
	cp "$LINT" "$BATS_TEST_TMPDIR/noroot/mise-tasks/ready-lint"
	run bash -c "'$BATS_TEST_TMPDIR/noroot/mise-tasks/ready-lint' <'$PAYLOAD'"
	[ "$status" -eq 2 ]
}

@test "an issue with no §6 clause needs no workspace version" {
	# The version is read inside the clause, so a §6-less body lints anywhere.
	payload "$(block '* **Blockers (§8).** None.')"
	mkdir -p "$BATS_TEST_TMPDIR/bare/mise-tasks"
	cp "$LINT" "$BATS_TEST_TMPDIR/bare/mise-tasks/ready-lint"
	run bash -c "'$BATS_TEST_TMPDIR/bare/mise-tasks/ready-lint' <'$PAYLOAD'"
	[ "$status" -eq 0 ]
}

@test "a §6 clause naming no commit type is reported" {
	local d
	d=$(block '* **Commit / bump (§6).** To be decided.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"commit-type-missing"* ]]
}

@test "an open-questions marker blocks Ready" {
	# The questions-are-artifacts protocol is only real because of this gate:
	# without it a question can be written and the issue promoted anyway.
	local d
	d=$(block '**Open questions blocking Ready:**
	1. Where does it live?')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"open-questions-block-ready"* ]]
}

@test "the retired (clause N) dialect is reported, not silently accepted" {
	local d
	d=$(block '* **Effect (clause 3).** read.')
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"non-canonical-clause-notation"* ]]
}

@test "an issue with no Ready block at all is reported" {
	payload 'Just a description.'
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-ready-block"* ]]
}

# --- the parent dialect: `## Refinement gate` ---------------------------------
#
# The gate document tells an epic to "link this document from an epic as the
# refinement gate for its children rather than copying the lists into each
# issue", so a parent's block opens with that heading rather than the leaf's
# `**Refinement — Ready (…)**`. Recognising only the leaf form reported
# no-ready-block on every correctly-refined epic — a false negative that would
# have pushed authors to rename a heading the spec prescribes.

# An epic-dialect body: $1 becomes the body of the refinement-gate section.
epic_block() {
	cat <<-EOF
		Foundational setup for the crate and the command surface.

		---

		## Refinement gate

		Children of this epic are gated by the project-level Definition of Ready & Done.

		$1
	EOF
}

@test "a parent's refinement-gate heading is a Ready block" {
	payload "$(epic_block '* **Source of truth (§1).** The command spec compiled into the binary.')"
	lint
	[ "$status" -eq 0 ]
}

@test "a deeper refinement-gate heading is a Ready block too" {
	payload "$(epic_block '* **Source of truth (§1).** One artifact.' | sed 's/^## Refinement gate/### Refinement gate/')"
	lint
	[ "$status" -eq 0 ]
}

@test "clauses inside a parent block are still checked" {
	# The opener must locate a span the clause rules actually run over — otherwise
	# recognising the heading would trade one vacuous pass for another.
	payload "$(epic_block '* **Commit / bump (§6).** `feat` → **minor**.')"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"bump-disagrees-with-type"* ]]
}

@test "a parent's §8 claim is held to the board like a leaf's" {
	payload "$(epic_block '* **Blockers (§8).** `blockedBy` CLOUD-6 (the pre-implementation blockers).')"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"blocker-cited-without-relation (CLOUD-6)"* ]]
}

@test "prose merely discussing refinement is not a Ready block" {
	# The anchors stay tight: a heading or a bold run at line start, never the
	# bare word mid-sentence.
	payload 'This needs refinement before anyone pulls it. Refinement is pending.'
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"no-ready-block"* ]]
}

@test "unparseable stdin exits 2, not 1" {
	# A caller piping the wrong thing must not look like a failing issue.
	echo 'not json' >"$BATS_TEST_TMPDIR/bad"
	PAYLOAD="$BATS_TEST_TMPDIR/bad"
	lint
	[ "$status" -eq 2 ]
}

@test "output is pointer-only — no issue prose echoed" {
	# Non-negotiable rule 4: issue bodies can carry customer detail, and a lint
	# that echoed them would leak through CI logs.
	local secret='ACME Corp renewal blocker'
	local d
	d=$(block "* **Blockers (§8).** \`blockedBy\` CLOUD-29 ($secret).")
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" != *"$secret"* ]]
}

# --- the §8 span: the claim is not always on the label line -------------------
#
# The corpus dialect is a single-line bullet, and reading only that line made a
# `### Blockers (§8)` heading with the claim in the paragraph below pass this
# clause VACUOUSLY. Observed on a real issue: `blockedBy CLOUD-95` asserted under
# a heading, no relation, reported clean.

# A heading-dialect Ready block: $1 becomes the §8 paragraph.
heading_block() {
	cat <<-EOF
		## Ready

		Something needs doing.

		### Blockers (§8)

		$1

		## Done

		It works.
	EOF
}

@test "a blocker claimed under a §8 HEADING with no relation is reported" {
	payload "$(heading_block '`blockedBy` CLOUD-95 for the substrate.')"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"blocker-cited-without-relation (CLOUD-95)"* ]]
}

@test "the same claim with the relation present passes" {
	payload "$(heading_block '`blockedBy` CLOUD-95 for the substrate.')" CLOUD-95
	lint
	[ "$status" -eq 0 ]
}

@test "a §8 heading claiming nothing is not a violation" {
	payload "$(heading_block 'None.')"
	lint
	[ "$status" -eq 0 ]
}

@test "the span stops at the next heading, so a later section is not §8 text" {
	# A greedier span would swallow Done and flag ids that assert no blocking.
	payload "$(heading_block 'None.')"
	lint
	[[ "$output" != *"blocker-cited-without-relation"* ]]
}

@test "the span stops at the paragraph end, so a following paragraph is not the claim" {
	local desc
	desc=$(
		cat <<-EOF
			## Ready

			Work.

			### Blockers (§8)

			None.

			Separately, CLOUD-77 is where this eventually lives.

			## Done

			It works.
		EOF
	)
	payload "$desc"
	lint
	[ "$status" -eq 0 ]
}

# --- the clause floor (CLOUD-299) ---------------------------------------------
#
# "Validate only the clauses present" needs a floor, or a block with nothing
# present passes as refined. Measured on CLOUD-59, whose block opened with a
# refinement note handed down from another issue and carried no clause at all.
# The floor must not become a checklist, and must not be satisfiable by the
# house-style §N cross-references that share the notation.

# A body whose only block is a refinement NOTE — the CLOUD-59 shape.
note_block() {
	cat <<-EOF
		**Why**
		Secret scanning should be reused, without printing secret bytes.

		**Refinement from the identity decision (CLOUD-123) — secret-class identity:**

		* Identity inputs for secret-class findings are HMAC-keyed.
		* Key loss is a declared orphan event with loud forced re-triage.
	EOF
}

@test "a block that is only a refinement note carries no clause and is reported" {
	payload "$(note_block)"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"ready-block-without-clauses"* ]]
}

@test "a house-style cross-reference in prose does not satisfy the floor" {
	# The §N namespace is overloaded: counting any (§N) would let a pointer to the
	# output contract stand in for a clause, which is the vacuous pass again.
	local desc
	desc=$(
		cat <<-EOF
			**Refinement — Ready (a summary)**

			Output stays pointer-only per house-style (§6), and the gate runs in CI.
		EOF
	)
	payload "$desc"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"ready-block-without-clauses"* ]]
}

@test "a block carrying only §1 clears the floor — it is a floor, not a checklist" {
	# The counterpart assertion to "omitted clauses are not a violation": the floor
	# must not have quietly become the all-eight demand the gate document forbids.
	payload "$(block '')"
	lint
	[ "$status" -eq 0 ]
	[[ "$output" != *"ready-block-without-clauses"* ]]
}

@test "a heading-form label counts as a clause" {
	# `### Blockers (§8)` is the corpus's other dialect. A bold-only anchor would
	# report every heading-dialect body as clause-free.
	payload "$(heading_block 'None.')"
	lint
	[ "$status" -eq 0 ]
	[[ "$output" != *"ready-block-without-clauses"* ]]
}

@test "a clause-free parent block is exempt from the floor" {
	# The gate document tells an epic to link the document rather than copy the
	# lists, so a parent carrying no clause is the prescribed shape. The exemption
	# is keyed on the opener; keying it on the count would exempt empty leaves too.
	payload "$(epic_block '')"
	lint
	[ "$status" -eq 0 ]
}

# --- the non-canonical opener (CLOUD-299) -------------------------------------
#
# Recognised in order to be reported, the same bargain as the `(clause N)`
# notation. Before this, the dialect reported no-ready-block — the right verdict
# for a body with open preconditions, but reached by accident rather than by
# reading its content.

# The `**Definition of ready**` dialect: $* becomes the block body.
defready_block() {
	cat <<-EOF
		**Why**
		A format decision is needed.

		**Definition of ready**

		$*
	EOF
}

@test "the non-canonical ready opener is reported, not treated as no block" {
	payload "$(defready_block '* **Source of truth (§1).** One authoritative artifact.')"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"non-canonical-ready-opener"* ]]
	[[ "$output" != *"no-ready-block"* ]]
}

@test "a non-canonical opener still has its content judged" {
	# The point of recognising the dialect: the verdict becomes about the block's
	# content, so an open-questions marker inside one is now reachable at all.
	local d
	d=$(defready_block '* **Source of truth (§1).** One artifact.')
	d="$d

	Open questions blocking Ready: which signature format the install path verifies."
	payload "$d"
	lint
	[ "$status" -eq 1 ]
	[[ "$output" == *"open-questions-block-ready"* ]]
	[[ "$output" == *"non-canonical-ready-opener"* ]]
}

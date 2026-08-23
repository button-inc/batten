#!/usr/bin/env bash
#MISE description="Gate: an issue's Ready block satisfies the checkable clauses of the Definition of Ready (reads a get_issue payload on stdin)"
#
# CLOUD-179. The Definition of Ready opens by asserting that "Every clause is a
# computable check, not a judgement" — this is the half that makes that true.
# Ready was adjudicated by a human reading prose, which left the refinement gate
# feedforward-only, the exact shape non-negotiable rule 2 calls half a change.
#
# It matters most where agents groom. This repo lands by fast-forward on green
# CI, so nothing human sits between "the agent believes it is done" and "it is on
# main", and CI cannot fail a correct implementation of the wrong thing. The
# Ready block is the only place a specification error is catchable at all.
#
# WHAT THIS DOES NOT DO, deliberately: it never asserts that all eight clauses
# are present. The gate document is explicit that "An issue's own body carries
# only its *specializations* of these clauses, not a restatement of them", and
# CLOUD-33 — the corpus's most thoroughly refined issue — omits §4 entirely and
# is correctly Ready. A lint demanding all eight would fail the best example it
# has. So: validate the clauses that ARE present, and say nothing about absence.
#
# It also does not judge whether the block describes the *right* work. That is
# not computable, and a gate that pretended otherwise would be a judge (CLOUD-93).
#
# Input is a `get_issue(includeRelations: true)` JSON payload, not bare markdown,
# because the §8 check is a cross-check: prose claiming a blocker is only true if
# a matching `blockedBy` relation exists. The description alone cannot prove that.
#
# THE VOCABULARY, so a reader can tell a verdict from a gap without running it:
# exit 1 carries rule ids — `no-ready-block`, `ready-block-without-clauses`,
# `blocker-cited-without-relation`, `deferral-cited-without-relation`,
# `bump-disagrees-with-type`, and the notation/opener reports. Exit 2 carries
# `unjudgeable-relations` (CLOUD-679): the payload cites a dependency and carries
# no `relations` key, so neither cross-check could run. That token is the sibling
# of `graph-check`'s `unjudgeable-blockedby`, and borrowing it rather than
# inventing a second one is the point — CLOUD-251 drew this line for that gate
# and this one, over the same payload, never got it.
# The mutation restores the whole-line read of the break marker, so a clause
# DENYING a break is read as declaring one again — the CLOUD-852 defect. The
# discriminating case is a `no bump` type: a releasable one collapses to the
# same answer either way, so it would pass under the mutation and prove nothing.
#MUTANT break-read-off-the-whole-line|s/\[\[ "\$type_token" == \*.!.\* \]\]/grep -qE "!" <<<"$bump_line"/|denying a break
set -euo pipefail

payload=$(cat)

# Exit 2 is "I could not read the input", distinct from exit 1 "the block is
# wrong" — a caller piping the wrong thing must not look like a failing issue.
if ! description=$(jq -er '.description' <<<"$payload" 2>/dev/null); then
	echo "::error:: stdin is not a get_issue payload with a .description field" >&2
	exit 2
fi

id=$(jq -r '.id // "?"' <<<"$payload")
# ABSENT AND PRESENT-BUT-EMPTY ARE TWO DIFFERENT ANSWERS (CLOUD-679), and for
# this file's whole life they were one empty string. The comment that used to sit
# here said the right thing — "their absence means 'no blockers declared', which
# is a legitimate state" — about the wrong condition: that is true of a payload
# whose `relations` key is PRESENT and carries no edges, and false of one that
# never carried the key. `[.relations.blockedBy[]?.id]` yields `[]` for both, so
# a caller who fetched without `includeRelations` got every §8 and deferral
# citation reported as `blocker-cited-without-relation` — the gate accusing a
# correctly-refined issue of citing a phantom blocker, and implying a remedy
# (add the relation) for a relation that already exists.
#
# Measured 2026-08-19, same bodies, only the key differing: CLOUD-326 produced
# four violations with the key stripped and exit 0 with it injected, and its
# `blockedBy` and both `relatedTo` edges were on the tracker throughout. The
# CLOUD-633 pair is the control — the same run surfaced one GENUINE violation,
# which the fix must not silence.
#
# So presence is read once, and it is `has`, never a count: "no edges" is an
# answer, and only a missing key is a gap. This is CLOUD-251's split, in the
# sibling gate over the same payload — `graph-check` got `unjudgeable-blockedby`
# and this file got nothing.
if jq -e 'has("relations") and (.relations != null)' <<<"$payload" >/dev/null 2>&1; then
	relations_present=1
else
	relations_present=
fi
relations=$(jq -r '[.relations.blockedBy[]?.id] | join(" ")' <<<"$payload" 2>/dev/null || echo "")

violations=0
# Pointer-only per non-negotiable rule 4: line number and rule id, never the
# matched prose. Issue bodies can carry customer detail; a lint that echoed them
# would leak through CI logs.
report() {
	echo "$id:$1 $2" >&2
	violations=$((violations + 1))
}

# "I could not look" is counted SEPARATELY from "the block is wrong", because the
# exit rule below is narrower than CLOUD-251's "2 outranks 1": exit 2 only when
# the missing key is the SOLE reason the verdict is incomplete. A block carrying
# a real defect is wrong regardless of what could not be seen, so mixing the two
# counters would let a §6 disagreement hide behind a gap.
#
# The pointer is emitted once, at the tail, rather than per citation: the gap is
# one fact about the payload, and a line per cited id would report the caller's
# fetch as many findings. Pointer-only per non-negotiable rule 4 — the line and
# the token, never the matched prose.
unjudgeable=0
unjudged_line=""
unjudged() {
	[[ -n "$unjudged_line" ]] || unjudged_line="$1"
	unjudgeable=$((unjudgeable + 1))
}

# --- locate the Ready block ---------------------------------------------------
#
# Canonical notation is §N (CLOUD-179). The older `(clause N)` dialect is still
# on the board, so it is recognised here only to be REPORTED — accepting both
# silently is what lets drift accumulate, and nothing lints today, so the cost of
# converging is at its minimum.
#
# TWO OPENERS, because a parent and a leaf carry different things. A leaf opens
# `**Refinement — Ready (…)**` and states its own specializations. A parent opens
# `## Refinement gate` and points at the gate for its children — which is the
# gate document's own vocabulary for an epic ("link this document from an epic as
# the refinement gate for its children rather than copying the lists into each
# issue"). Matching only the leaf form reported `no-ready-block` on every
# correctly-refined epic on the board, which is the worst kind of false negative:
# it would have pushed authors to rename a heading the spec prescribes, purely to
# satisfy a lint. Measured on CLOUD-7 — identical content passes under the leaf
# opener and fails under the parent's.
#
# The anchors stay tight: a heading or a bold run at the start of a line, never
# the bare word in prose, so a body that merely discusses refinement is still
# blockless.
#
# A FOURTH opener, `**Definition of ready**`, is recognised only to be REPORTED
# (CLOUD-299) — the same bargain as the `(clause N)` notation above. It is the
# dialect four issues on the board actually use, and leaving it unrecognised made
# the anchor wrong in both directions at once: those bodies reported
# no-ready-block, which was the right verdict for the three carrying open
# preconditions but reached by accident. The lint was saying "I found no block"
# where the truth was "your preconditions are unmet", and a body that WAS refined
# under that heading failed identically. Recognising it moves the verdict onto the
# content; naming it converges the corpus instead of letting the dialect spread.
READY_OPENERS='^\*\*Refinement|^#{2,3} +Refinement|^#{2,3} +Ready|^\*\*Definition of [Rr]eady'
# The parent dialect, needed twice: to locate a block, and to exempt it from the
# clause floor below.
PARENT_OPENER='^#{2,3} +Refinement gate'
ready_start=$(grep -niE "$READY_OPENERS" <<<"$description" | head -n1 | cut -d: -f1 || true)
if [[ -z "$ready_start" ]]; then
	echo "$id:0 no-ready-block" >&2
	exit 1
fi

# The opener line itself, read once: it decides both the notation report below and
# the parent exemption on the clause floor.
opener=$(sed -n "${ready_start}p" <<<"$description")
if grep -qiE '^\*\*Definition of [Rr]eady' <<<"$opener"; then
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	report "$ready_start" 'non-canonical-ready-opener (use `**Refinement — Ready`)'
fi

block=$(tail -n "+$ready_start" <<<"$description")
line_of() { # echo the description-relative line number of the first match
	local n
	n=$(grep -niE "$1" <<<"$block" | head -n1 | cut -d: -f1 || true)
	[[ -n "$n" ]] && echo $((ready_start + n - 1)) || echo "$ready_start"
}

# --- the clause floor: a block is a block only if it carries a clause ---------
#
# CLOUD-299. Validating only the clauses PRESENT is deliberate and stays (the gate
# document forbids restating all eight, and CLOUD-33 omits §4 while correctly
# Ready). But "only what is present" needs a floor, or a block with NOTHING
# present is indistinguishable from a refined one. Measured on CLOUD-59: its body
# opens `**Refinement from the identity decision (CLOUD-123) …**` — a constraint
# handed down from another issue, carrying no clause at all — so the opener matched,
# zero clauses were found, zero were checked, and it exited 0 with no §1, §3, §6 or
# §7 anywhere. It sat in the ready queue on that pass.
#
# WHAT COUNTS, and why it is not a bare `(§N)`: the §N namespace is overloaded.
# Ready blocks legitimately cite house-style sections in prose ("pointer-only per
# §6"), so counting any `(§N)` would let a cross-reference satisfy the floor —
# the same vacuous pass in a narrower form. The anchor is therefore the same
# label+tag pair shape the §6 and §8 checks already use, in both corpus dialects:
# a bolded label at line start (`* **Source of truth (§1).**`) or a heading
# carrying the tag (`### Blockers (§8)`). The heading arm is load-bearing, not
# defensive — bodies whose ONLY clause is a `### Blockers (§8)` heading are on the
# board and in this suite's own fixtures.
CLAUSE_LABEL='^[[:space:]]*([*-][[:space:]]*)?\*\*[^*]*\((§|clause )[0-9]+\)|^#{2,6}[[:space:]]+[^#]*\((§|clause )[0-9]+\)'
# `grep -c` exits 1 when the count is zero, which `set -e` would take as fatal;
# the here-string keeps this out of pipefail-grep-check's shape entirely.
clauses=$(grep -cE "$CLAUSE_LABEL" <<<"$block" || true)
# A parent is exempt BY OPENER, never by count. The gate document tells an epic to
# "link this document … rather than copying the lists into each issue", so a
# clause-free parent block is the prescribed shape, not an unrefined one. Keying
# the exemption on the count instead would have exempted every empty leaf too.
if [[ "$clauses" -eq 0 ]] && ! grep -qiE "$PARENT_OPENER" <<<"$opener"; then
	report "$ready_start" "ready-block-without-clauses"
fi

# --- open questions block promotion ------------------------------------------
#
# The questions-are-artifacts protocol: an agent that hits a real ambiguity
# writes it onto the issue and moves on, and the issue stays out of the ready
# queue. That only holds if the marker is a gate — otherwise a question can be
# written and the issue promoted anyway, which is the silent-rot case.
if grep -qiE 'open questions? blocking ready|\(incomplete —' <<<"$block"; then
	report "$(line_of 'open questions? blocking ready|\(incomplete —')" "open-questions-block-ready"
fi

# --- notation drift -----------------------------------------------------------
if grep -qiE '\(clause [0-9]+\)' <<<"$block"; then
	report "$(line_of '\(clause [0-9]+\)')" "non-canonical-clause-notation (use §N)"
fi

# --- §6 commit type and bump must agree --------------------------------------
#
# Anchored on the LABEL + tag pair, never on a bare "(§6)": the §N namespace is
# overloaded — Ready blocks also cite house-style sections as "(§6)"/"per §8",
# where §6 means the output contract, not this clause. Only a line carrying the
# "Commit / bump (§6)" label is the clause; a bare (§6) in prose is a
# cross-reference and none of this gate's business.
#
# THE TYPE TOKEN IS A WHOLE CODE SPAN, NEVER A PREFIX (CLOUD-290). The closing
# backtick used to be optional, so the pattern matched a prefix of any longer
# span and any backticked token beginning with a type word was read as the
# declared type. Measured, on two lines differing only in the bump text:
# "`ci-local-parity`; `feat` → **patch** until 0.1.0" — an honest declaration
# under this regime — was refused as `ci implies no bump`, and
# "`tests/fanout-guard.bats`; `ci` → **no bump**" passed while reading the type
# as `test`. So the defect was loud exactly when the author was right and silent
# exactly when it did no damage, which is why it survived: it is discoverable
# only by experiment. Requiring the closing backtick gives the type token the
# same anchoring the clause LABEL above already has, and for the same reason —
# a token that merely starts like the thing is not the thing. This line is the
# one authority for that grammar; .claude/rules/toolchain.md points here rather
# than restating it, so a copy cannot drift from the parser.
#
# The optional `(scope)` arm is not decoration: `fix(gate)` is a legitimate
# Conventional Commit declaration, and without it the tightened anchor would
# turn a verdict this gate reaches today into `commit-type-missing`. Its shape
# mirrors CONVENTIONAL_RE (mise.toml [env], shared by the commit-msg hook and
# the CI commit linter). The regex is NOT reused verbatim: that one matches a
# whole commit SUBJECT (`^type(scope)?!?: .+`), and this is a token embedded in
# prose — and it is an env var the suite's direct invocations never see.
#
# WHICH ARROWS FIRE DEPENDS ON THE VERSION. §6 was amended (2026-08-07) after
# CLOUD-226 measured a `feat!` carrying a BREAKING CHANGE footer releasing as
# v0.0.23: Cargo gives 0.0.x no compatibility guarantee, so release-plz bumps the
# patch whatever the type says. feat→minor and !→major are real only at 0.1.0 and
# above, and below it an issue promising one states something the tool will not
# do — which is what the clause now forbids. So the gate reads the regime out of
# the commit it is linting rather than hardcoding one set of arrows. Enforcing the
# retired set is not a neutral staleness: it made the honest declaration
# ("`feat` — patch until 0.1.0") the *failing* one, so the gate and the document
# it gates demanded opposite bytes.
BUMP_LABEL='Commit / bump \((§|clause )6\)'
if bump_line=$(grep -iE "$BUMP_LABEL" <<<"$block" | head -n1); then
	# Read lazily, inside the clause: an issue with no §6 clause needs no version,
	# and demanding one would break linting a payload from outside a checkout.
	#
	# The version is a property of this tree, not of the world — no network, no
	# registry lookup — which is what keeps this a gate on the commit rather than
	# a currency check (see .claude/rules/toolchain.md on that split).
	root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
	# The range ends at the next table header — sed searches the end pattern from
	# the line after the start, so `/^\[/` cannot re-match the opening line. A
	# looser end let the span run through [workspace.dependencies], where a `version
	# = "…"` key would have been read as the crate's.
	crate_version=$(sed -n '/^\[workspace\.package\]/,/^\[/p' "$root/Cargo.toml" 2>/dev/null |
		grep -m1 -E '^version = "' | cut -d'"' -f2 || true)
	# A gate that cannot establish its own regime must not guess: guessing either
	# way manufactures a violation or launders one. Exit 2 is already this
	# script's "I could not read what I was given", and an unrunnable gate exiting
	# non-zero is the rule from toolchain.md.
	if [[ -z "$crate_version" ]]; then
		echo "::error:: cannot read the workspace version from $root/Cargo.toml — §6 needs it to know which SemVer arrows fire" >&2
		exit 2
	fi
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	type_token=$(grep -oiE '`(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)([(][a-z0-9._-]+[)])?!?`!?' <<<"$bump_line" | head -n1 || true)
	type=$(sed -E 's/[(][^)]*[)]//' <<<"$type_token" | tr -d '`!' | tr '[:upper:]' '[:lower:]')
	# THE `!` IS READ OFF THE TYPE TOKEN, NEVER OFF THE LINE (CLOUD-852).
	#
	# This was `grep -cE '!|BREAKING CHANGE'` over the whole clause, which has no
	# polarity: the corpus's own way of DENYING a break is to write "Not `!`", and
	# that spelling made the gate read `expected="major"`. Five rows on the board
	# use it (CLOUD-832/833/836/837/647), so the convention is not hypothetical.
	#
	# It went unnoticed because below 0.1.0 the false `major` collapses to `patch`
	# at the collapse arm below, which is exactly where `feat` and `fix` already
	# collapse — so for every releasable type the wrong reason produced the right
	# answer. It
	# surfaces only on a type whose expectation is `no bump`, which does not
	# collapse. Measured 2026-08-21 on one payload with one clause swapped:
	# "Not `!`" reported `bump-disagrees-with-type (refactor implies patch)`, and
	# "Not breaking" exited 0. Nothing else differed.
	#
	# Conventional Commits puts the marker on the type/scope, which is precisely
	# where the regex above already captures it — the old code stripped it with
	# `tr -d '!'` before anything could look. So the token is captured first and
	# read for the marker, and the type is derived from it. The footer form keeps
	# its declarative colon for the same reason: `BREAKING CHANGE:` is the spelling
	# a commit carries, where "no BREAKING CHANGE footer" is prose about one.
	#
	# The bound, stated: this decides whether the clause DECLARES a break. Whether
	# the declaration is true of the library API is `mise run semver`'s answer, and
	# whether an unqualified denial named which surface it meant is CLOUD-842's.
	breaking=0
	if [[ "$type_token" == *'!'* ]] || grep -qE 'BREAKING CHANGE:' <<<"$bump_line"; then
		breaking=1
	fi
	# --- the negative break claim must name a surface (CLOUD-842) -------------
	#
	# `batten` IS BOTH A BINARY AND A LIBRARY, so "breaking" names two different
	# objects and §6 has one word for them:
	#
	#   the CONSUMER surface — `batten.toml` rows, exit codes, output shape —
	#     gated by `derived-check`, `schema-check` and the CLI suites;
	#   the LIBRARY surface — the `pub` Rust API — gated by `mise run semver`.
	#
	# Five rows of the CLOUD-839 bundle declared "not `!`" and every one of them
	# was reasoning CORRECTLY about the first: no `batten.toml` breaks, the bare
	# string `deny` path is preserved, widening `scopes` removes no pairing. All
	# true, and none of it is what `cargo-semver-checks` measures. The change
	# landed as `1f9b41c2 feat(policy)!` — CLOUD-832/833/836/837/647.
	#
	# THE PREDICATE IS ABOUT THE CLAIM'S SHAPE, NEVER ITS TRUTH. At refinement
	# time there is no diff to compare, so "is this actually breaking" is not
	# computable here and a gate that guessed would be a judge (CLOUD-93). What
	# IS decidable from the body alone is whether the denial said which object it
	# denied about. A row may claim either surface; a row claiming neither is
	# claiming both, and it cannot have checked the second.
	#
	# THE QUALIFIER MUST ATTACH TO THE DENIAL, NOT MERELY SHARE THE LINE, and
	# CLOUD-832 is exactly why. Its clause reads
	#   "Not `!`: the string `deny` path is preserved, so no consumer shape breaks"
	# — the word `consumer` IS on that line, forty characters downstream, as part
	# of the reasoning rather than as the scope of the denial. A bare
	# "does `consumer` appear anywhere" test passes the one row this clause exists
	# to refuse, which is the vacuous pass in a narrower disguise. So the surface
	# word must FOLLOW the denial token across nothing but a connective: the
	# repaired spelling is "Not `!` for the consumer surface: …".
	#
	# ONE QUALIFIED DENIAL ON THE LINE IS ENOUGH, and that is deliberate. A
	# corrected clause quotes its own history — the repaired spelling followed by
	# a note about the unqualified one it used to carry — so demanding that EVERY
	# denial token on the line be qualified would refuse the repair this clause
	# exists to produce. The bias is `spec-ref-check`'s, stated there for
	# over-declaring: the loose direction reports LESS, and a gate with false
	# positives gets bypassed.
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	BREAK_DENIAL='not[[:space:]]+`?!`?|not[[:space:]]+breaking|non-?breaking|no[[:space:]]+break[a-z]*'
	# The connective set is an alternation rather than a bracket expression: an
	# em dash is multibyte, and a bracket expression is bytewise in the C locale,
	# so `[-—,:]` would match one of its own bytes and read as a match nobody wrote.
	BREAK_QUALIFIED="(${BREAK_DENIAL})[[:space:]]*(-|—|,|:)?[[:space:]]*(for|to|on|in|of)?[[:space:]]*(the[[:space:]]+)?(consumer|library)"
	# The mutation demotes the refusal to a note, which is the whole failure this
	# clause exists to reverse: the five landed rows were silent, not warned.
	#MUTANT break-claim-refusal-is-a-note|s@report "\$(line_of "\$BUMP_LABEL")" .unqualified-break-claim.*@:@|without naming a surface
	if grep -qiE "$BREAK_DENIAL" <<<"$bump_line" && ! grep -qiE "$BREAK_QUALIFIED" <<<"$bump_line"; then
		# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
		report "$(line_of "$BUMP_LABEL")" 'unqualified-break-claim (say which surface: `consumer` or `library` — `mise run semver` decides the library half)'
	fi
	# "none" is a valid explicit answer — a Linear-only or repo-config change
	# lands no commit at all, and demanding a type there would force a lie.
	declared=$(grep -oiE 'major|minor|patch|no bump|none' <<<"$bump_line" | head -n1 | tr '[:upper:]' '[:lower:]' || true)
	[[ "$declared" = "none" ]] && declared="no bump"

	case "$type" in
	feat) expected="minor" ;;
	fix) expected="patch" ;;
	"") expected="" ;;
	*) expected="no bump" ;;
	esac
	[[ "$breaking" != 0 ]] && expected="major"

	# Below 0.1.0 every release-worthy type collapses to a patch. "no bump" does
	# not collapse: a `ci`/`chore`-only change releases nothing at any version, so
	# folding it into patch would demand a bump the tool never produces — the same
	# error in the other direction.
	why=""
	case "$crate_version" in
	0.0.*)
		if [[ -n "$expected" ]] && [[ "$expected" != "no bump" ]]; then
			expected="patch"
			why=" below 0.1.0"
		fi
		;;
	esac

	if [[ -z "$type" ]]; then
		# An explicit no-commit declaration needs no type; silence does.
		if [[ "$declared" != "no bump" ]]; then
			report "$(line_of "$BUMP_LABEL")" "commit-type-missing"
		fi
	elif [[ -n "$declared" ]] && [[ "$declared" != "$expected" ]]; then
		report "$(line_of "$BUMP_LABEL")" "bump-disagrees-with-type (${type} implies ${expected}${why})"
	fi
fi

# --- §7: a new deny gate reports its firing rate before its severity is chosen -
#
# CLOUD-751. CLOUD-514 demanded a firing rate of a candidate predicate, measured it
# at 99.5% false positives, and rejected it on the number. That is the standard this
# repository should hold every gate to, and it is met almost nowhere — CLOUD-514
# then shipped `filed-here-check` with no firing rate of its own,
# `assertions-not-gutted` chose `warn` over `deny` on a plausible and unmeasured
# judgement, and `no-new-ignores` ships `deny` with no recorded replay.
#
# CLOUD-418 already established that a gate must be SHOWN ABLE TO FAIL. Showing a
# gate can fail on a fixture is a different and weaker claim than knowing how often
# it fires on real history. The practice existed in one issue's body and bound
# nothing; non-negotiable rule 2 applied to the rules themselves.
#
# THE CORPUS IS ALREADY HERE, which is what makes the obligation cheap. This
# repository is agent-authored at ~40 commits/day, so a candidate predicate is
# replayed over its own history in one command — and the measured instance is why
# the row exists: a `ratchet` over `TODO|FIXME` scored 2 firings and 2 false
# positives, 100%, because the repo's own canonical example rule is `no-todo` with
# `pattern = "TODO"`. The design was rejected on the measurement rather than
# shipped on the citation.
#
# PRESENCE AND SHAPE ONLY, NEVER WHETHER THE NUMBER IS GOOD. Judging an acceptable
# false-positive rate is a model verdict and non-negotiable rule 3 forbids it
# (CLOUD-93). The author reports; the reader decides.
#
# THE CONJUNCTION IS WHAT KEEPS THIS OFF THE REST OF THE CORPUS. It fires only on a
# block that BOTH introduces a gate — a fenced `[[rule]]` declaration, or a
# `mise-tasks/<name>-check` path — AND declares `deny` as a severity. A `warn` gate
# is not gated: a `warn` that fires often is noise a reader can weigh, where a
# `deny` that fires often stops the fleet, which is why the obligation attaches to
# `deny` alone. A block introducing no gate is untouched, and that is most of the
# corpus.
#
# WHAT COUNTS AS A REPLAY, and the bound is stated rather than discovered. A line
# naming `replay`, plus a firing count somewhere in the block — a digit beside a
# `fire`/`fired`/`firing` token. Block-wide rather than one-line, because a replay
# is reported as a fenced measurement whose prose header names it and whose body
# carries the numbers: measured on CLOUD-752 ("Replay against this repository's
# history" then "0% firing rate") and CLOUD-753 ("replayed over this repository's
# own history" then "replay over 59 commits: 2 would-fire"), neither of which puts
# both halves on one line.
#
# The mutation drops the deny conjunct, so every gate-introducing block is demanded
# a replay — including the `warn` ones the row deliberately leaves alone.
# The pattern spells the DOUBLE bracket deliberately. `\[ "\$declares_deny" = 1 \]`
# matches inside `[[ ... ]]` from the second bracket, leaving `[true]` — a command
# that does not exist, so the conjunct became permanently FALSE and no block was
# demanded a replay at all. The row read as a mutation of the deny conjunct and
# was the inverse of one; it survived every run until CLOUD-480 enforced it.
#MUTANT replay-demanded-of-a-warn-gate|s@\[\[ "\$declares_deny" = 1 \]\]@true@|a block declaring warn is not gated
# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
# The extension is OPTIONAL, and both spellings have to match. A gate is written
# up as `mise-tasks/x-check` and the file is `mise-tasks/x-check.sh` (CLOUD-865),
# so anchoring on `-check` at the closing backtick silently stopped recognising a
# gate introduction the day the tree grew extensions — a refinement gate that
# quietly waves through the class it exists to catch.
GATE_INTRO='```[^`]*\[\[rule\]\]|`mise-tasks/[a-z0-9][a-z0-9._-]*-check(\.sh|\.bash)?`'
# The same anchor, narrowed to something that matches WITHIN one line: `line_of`
# greps line by line, and the fenced alternative above spans lines by design (it is
# matched with `-z`), so a pointer computed from it would fall back to the block's
# first line and name the wrong place.
# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
GATE_INTRO_LINE='\[\[rule\]\]|`mise-tasks/[a-z0-9][a-z0-9._-]*-check(\.sh|\.bash)?`'
# A severity ASSIGNMENT or a bolded declaration, never the bare word: this row's own
# rule id is `deny-without-replay`, so a bare-word predicate self-trips on the block
# that introduces the rule.
DENY_SEVERITY='severity[[:space:]]*=[[:space:]]*.?deny|\*\*deny\*\*'
REPLAY_NAMED='replay'
REPLAY_COUNT='[0-9][^.]{0,40}fir(e|ed|ing)|fir(e|ed|ing)[^.]{0,40}[0-9]|would-fire'
introduces_gate=0
grep -qzE "$GATE_INTRO" <<<"$block" && introduces_gate=1
declares_deny=0
grep -qiE "$DENY_SEVERITY" <<<"$block" && declares_deny=1
if [[ "$introduces_gate" = 1 ]] && [[ "$declares_deny" = 1 ]]; then
	has_replay=0
	if grep -qiE "$REPLAY_NAMED" <<<"$block" && grep -qiE "$REPLAY_COUNT" <<<"$block"; then
		has_replay=1
	fi
	if [[ "$has_replay" = 0 ]]; then
		# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
		report "$(line_of "$GATE_INTRO_LINE")" 'deny-without-replay (a deny gate reports its firing rate first: replay the predicate over `git rev-list origin/main` and record commits examined, times fired, and how many were false positives)'
	fi
fi

# --- §8 blockers linked, not assumed -----------------------------------------
#
# The highest-value rule here, and the only one prose cannot fake. Clause 8 says
# a dependency must be an explicit `blockedBy` relation "so refinement can
# proceed without silently pre-deciding the blocker". A block CLAIMING blockedBy
# CLOUD-N while carrying no such relation is asserting a dependency the board
# does not know about — which is exactly the failure the clause names.
#
# Claims, not mentions. A well-formed §8 bullet also cross-references the other
# relation directions — "`relatedTo` CLOUD-37 — the two share a representation
# but neither strictly blocks the other" is CORRECT prose whose board relation
# is relatedTo, and flagging it would punish precision. So only ids in the span
# after the first blockedBy token are claims, and the span ends at a
# blocks/relatedTo token or the line's end.
BLOCKERS_LABEL='Blockers \((§|clause )8\)'
# The claim is not always ON the label line. The corpus's usual dialect is a
# single-line bullet — "* **Blockers (§8):** none" — but a `### Blockers (§8)`
# heading with the claim in the paragraph below is equally legitimate markdown,
# and reading only the label line made every such issue pass this clause
# VACUOUSLY. Observed: an issue claiming `blockedBy CLOUD-95` under a heading,
# with no relation, passed clean.
#
# So take the label line plus the first paragraph after it, stopping at the next
# heading or the blank line that ends that paragraph. Bounded on purpose: a
# greedier span would swallow later sections and flag ids that assert nothing
# about blocking.
# grep finds the label, awk takes the span. Splitting them is deliberate: a
# dynamic regex passed through `awk -v` carries backslashes whose escape handling
# is implementation-defined, and an earlier version that did so passed locally
# and failed on the CI runner — silently, by matching nothing, so the clause went
# back to being vacuous. The awk below uses only literal patterns.
blockers_start=$(grep -niE "$BLOCKERS_LABEL" <<<"$block" | head -n1 | cut -d: -f1 || true)
if [[ -n "$blockers_start" ]]; then
	blockers_line=$(sed -n "${blockers_start},\$p" <<<"$block" | awk '
		NR == 1 { print; next }
		/^#/ { exit }
		/^[[:space:]]*$/ { if (seen) exit; next }
		{ seen = 1; print }
	')
	# See the text a human sees. Linear serialises an issue mention as
	# <issue id="…" href="…">CLOUD-N</issue>, so patterns written against the
	# rendered form — "CLOUD-N (closed)" — never match the stored form, and an
	# exemption tested only on plain-text fixtures is dead code in production.
	# Stripping the markup first makes the rendered and stored forms one case.
	blockers_text=$(sed -E 's|</?issue[^>]*>||g' <<<"$blockers_line")
	claim=$(grep -oiE 'blockedBy.*' <<<"$blockers_text" | head -n1 || true)
	# A claim is one sentence. The §8 bullet legitimately carries trailing
	# cross-references — "Grows in coverage as the tree fills (CLOUD-N)" — that
	# assert nothing about blocking, so the claim span ends at the sentence.
	claim="${claim%%. *}"
	# shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
	claim=$(sed -E 's/`?[Bb]locks`?[^A-Za-z].*//; s/`?[Rr]elatedTo`?.*//' <<<"$claim")
	# No blockedBy token — "None.", "no blockers", or pure cross-references —
	# means nothing is claimed, so there is nothing to hold the board to.
	# shellcheck disable=SC2013  # word-splitting is the point: ids are bare tokens
	# THE `(closed)` EXEMPTION IS GONE, and it was dead code resting on a premise
	# this tracker does not have (CLOUD-678). It stripped `CLOUD-N (closed)` from
	# the claim before scanning, on the stated reason that "Linear drops the
	# relation when the dependency resolves, so demanding one would fail every
	# correctly-refined issue whose blocker landed."
	#
	# MEASURED, and it is the opposite: the relation SURVIVES. CLOUD-661 has been
	# Done since 2026-08-18T23:01:59Z and both of its dependents still carry the
	# `blockedBy` edge today. So a blocker noted `(closed)` still has a live
	# relation, the exemption never fired on the case it was written for, and every
	# such citation was already passing through the cross-check below.
	#
	# Removing it only ever NARROWS what passes — it widened, and on a case that
	# cannot occur — and what it bought was a comment documenting behaviour a
	# reader would then rely on. `graph-check`'s `dangling-blocker` arm is where
	# the measurement is recorded in full.
	for cited in $(grep -oE 'CLOUD-[0-9]+' <<<"$claim" | sort -u); do
		# THE SCAN STILL RUNS, THE CROSS-CHECK DOES NOT (CLOUD-679). Finding the
		# citation is what makes "the missing key is the SOLE reason" computable at
		# all: a payload with no key and nothing cited lost nothing, and must stay
		# exit 0 — CLOUD-526 declares that a caller may project everything but
		# `.description` away, and every fixture in `tests/claim-check.bats` is
		# exactly that shape.
		if [[ -z "$relations_present" ]]; then
			unjudged "$(line_of "$BLOCKERS_LABEL")"
			continue
		fi
		case " $relations " in
		*" $cited "*) ;;
		*) report "$(line_of "$BLOCKERS_LABEL")" "blocker-cited-without-relation ($cited)" ;;
		esac
	done
fi

# --- deferral claims linked, not asserted ------------------------------------
#
# CLOUD-197. Same predicate as §8, applied to the other direction of dependency.
# A block claiming an obligation is *someone else's* — "deferred to CLOUD-N",
# "CLOUD-N owns this" — is asserting a hand-off the board does not know about
# unless a relation records it. Prose alone lets an obligation be declared
# somebody else's problem and then belong to nobody.
#
# Unlike §8 this is checked over the WHOLE description, not just the Ready
# block: a deferral is most often written in Done, in an Open questions list, or
# in an out-of-scope note, and those are exactly the places an obligation goes
# to die.
#
# Claims, not mentions — the discipline §8 already establishes. "The same
# failure shape as CLOUD-195" is a comparison, "split out of CLOUD-177" is
# provenance, "see CLOUD-33" is a cross-reference; none hands anything off, and
# flagging them would punish the cross-referencing that makes issues readable.
# So a claim is a hand-off VERB immediately followed by an id, nothing looser.
#
# Any relation direction satisfies it. A deferral is not necessarily a blocker —
# often the receiving issue is `relatedTo` — and demanding `blockedBy`
# specifically would push authors to declare false dependencies to pass a lint.
all_relations=$(jq -r '[.relations[]? | if type == "array" then .[]? else . end | .id? // empty] | join(" ")' <<<"$payload" 2>/dev/null || echo "")

# The rendered and stored forms are one case once the mention markup is gone.
plain=$(sed -E 's|</?issue[^>]*>||g' <<<"$description")

DEFER_RE='(deferred?|deferring|defers) (it |that |this )?to|owned by|belongs to|left to|handed off to|handled by|tracked (separately )?(in|by|under)|moved? to|is now|remains'
while IFS= read -r hit; do
	[[ -n "$hit" ]] || continue
	lineno=${hit%%:*}
	text=${hit#*:}
	# The id must follow the verb, not merely share a line with it: "CLOUD-9
	# blocks this, deferred to CLOUD-10" defers only CLOUD-10.
	# shellcheck disable=SC2013  # word-splitting is the point: ids are bare tokens
	for cited in $(grep -oiE "($DEFER_RE)[^.]{0,40}?(CLOUD-[0-9]+)" <<<"$text" | grep -oE 'CLOUD-[0-9]+' | sort -u); do
		# An issue may not defer to itself; that is a wording slip, not a hand-off.
		[[ "$cited" = "$id" ]] && continue
		# The same gap as §8 above, and it reached further: this rule scans the
		# WHOLE description, so a key-stripped payload reported one phantom hand-off
		# per citation anywhere in the body. CLOUD-326 measured three.
		if [[ -z "$relations_present" ]]; then
			unjudged "$lineno"
			continue
		fi
		case " $all_relations " in
		*" $cited "*) ;;
		*) report "$lineno" "deferral-cited-without-relation ($cited)" ;;
		esac
	done
done < <(grep -niE "($DEFER_RE)[^.]{0,40}?CLOUD-[0-9]+" <<<"$plain" || true)

# THE ORDER IS THE RULE (CLOUD-679). A judgeable violation outranks a gap, which
# is the opposite of CLOUD-251's "2 outranks 1" and deliberately so: the block is
# wrong regardless of what could not be seen, and downgrading it to "could not
# look" would launder a real defect behind a caller's thin fetch. The pointer
# prints on both arms, so nothing this gate noticed is ever swallowed.
if [[ "$violations" -ne 0 ]]; then
	[[ "$unjudgeable" -eq 0 ]] || echo "$id:$unjudged_line unjudgeable-relations" >&2
	echo "::error:: ready-lint: $violations violation(s) in $id — not Ready" >&2
	exit 1
fi
# Exit 2 is this file's existing channel for "I could not read what I was given"
# — the `.description` refusal at the top and the §6 version refusal above — and
# a missing relations key is the same kind of answer. The count and the remedy,
# never a verdict about the block. It never prints "satisfies", so no caller can
# cite this run as a green.
if [[ "$unjudgeable" -ne 0 ]]; then
	echo "$id:$unjudged_line unjudgeable-relations" >&2
	echo "::error:: ready-lint: $id cites $unjudgeable dependenc(ies) and this payload carries no relations key, so neither cross-check could run — refetch with get_issue(includeRelations: true)" >&2
	exit 2
fi
echo "ready-lint: $id satisfies the checkable Ready clauses"

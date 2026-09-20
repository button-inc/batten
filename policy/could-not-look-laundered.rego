# A `batten` call that discards its stderr AND forces success launders a
# could-not-look into a measured negative (CLOUD-1776).
#
# `$(batten <verb> … 2>/dev/null || true)` collapses three unlike states into one
# empty string: the leaf answered nothing, the leaf failed, and this binary has no
# such subcommand. The caller then reads empty as a real negative — and the
# findings it manufactures are SPECIFIC and PLAUSIBLE, which is what makes this
# worse than a fail-open. Measured twice, independently: 21 commits and then 28
# reported as claiming no issue while every one carried a well-formed `Refs:`
# trailer. The second measurement survived the repoint that was supposed to fix
# the first, because the repoint changed WHICH program is called and not how its
# unresolvability is read.
#
# WHY A RETIREMENT CREATES THIS RATHER THAN INHERITING IT. A sibling script could
# not be *unresolvable* — it was a path that either existed or did not, and its
# absence was loud. `batten claim keys` can be unresolvable in a new way: present
# binary, absent subcommand. So the `2>/dev/null || true` that was harmless before
# the port becomes a laundering site after it, and CLOUD-843's campaign has ~130
# remaining retirements each moving a decider behind the same resolver.
#
# ─── THIS JUDGES THE CHANGE, NOT THE STATE, AND THAT IS THE WHOLE DESIGN ──────
#
# `input.tree["base-delta"]`, exactly as `shell-retirement` reads it. Three
# instances are live on `main` today — `closing-key-check.sh:193,195` and
# `deferral-check.sh:117`, all three landed by the retirement this row was filed
# against — and NONE of them is repairable here: `mise-tasks/**` is governed by
# `shell edit refused`, whose landable shapes are retire-whole or leave-alone,
# with no override route and no `bypass_env`.
#
# A state-scoped rule would therefore be red on landing day with no spelling that
# could make it green. The obvious escapes are both worse. A ceiling COUNT is a
# number nothing derives, and it goes stale in the direction that reads healthy.
# An `admits_with` marker is `shell count ahead`'s idiom and unreachable here for
# a sharper reason: writing the marker into those three files IS an edit of a
# governed path, so the admission could not be spelled without the refusal the
# admission exists to clear.
#
# Reading the delta needs none of them. An existing occurrence is grandfathered
# because nothing in this change added it; a new one is refused wherever it
# arrives. The ratchet is exact rather than approximated, it needs no maintenance,
# and it would have refused the commit that put the three there.
#
# ─── WHAT IT DELIBERATELY DOES NOT REFUSE ────────────────────────────────────
#
# `2>/dev/null || true` is not itself the defect and a rule over it alone would be
# noise: 30-odd sites spell it over `git`, `jq`, `rm` and `printf`, where an empty
# result genuinely is the answer. The predicate is the pair — a call to THIS
# engine, whose unresolvability is the new failure mode, that then throws the
# status away.
#
# TWO PATTERNS AND A NEGATION, BECAUSE ONE REGEX MEASURABLY OVER-MATCHES. Tested
# against the corpus rather than reasoned about: `batten` plus `|| true` alone
# also hits `batten-receipts` in a PATH (`graph-check.sh:924`) and the existence
# probe `command -v batten` (`payload-field.sh:72`), where empty IS the answer and
# is what the probe is asking. Requiring whitespace after the callee kills the
# path case — `batten-` is not `batten ` — and the probe needs its own pattern and
# a `not`. With both, the corpus yields exactly the three sites above and nothing
# else.
#
# THE EVASION THIS CANNOT SEE, stated because a ratchet whose gap is undeclared is
# worse than one whose gap is named. The callee must appear as a bare word: this
# does not match variable indirection (`"${batten_bin[@]}"`, live at
# `mcp-allow-check.sh:228`) or a quote-terminated path (`…/target/debug/batten"`).
# Both are real spellings in this corpus, so a new laundering site can be written
# past this rule by naming the binary differently. A `#MUTANT` proves only what a
# case exercises and cannot close that; widening the callee pattern is the repair,
# and it is deliberately not attempted here because every widening tried so far
# re-admitted one of the two false positives above.
#
# The corpus already carries the correct spelling — `landed-check.sh:214` and
# `mcp-allow-check.sh:226-231` both keep the status and branch on it — so this
# names an idiom the repository has, rather than inventing one.
#
#MUTANT-SUITE crates/batten/tests/it/could_not_look_laundered.rs
#MUTANT swallowed-resolver-unread|s@^\tregex.match(data.batten.patterns\["swallowed-resolver-call"\], line)$@\tfalse@|an_added_swallowing_call_is_refused
#MUTANT laundered-delta-unbounded|s@^\tsome line in added_lines(path)$@\tsome line in input.tree.lines[path]@|an_existing_swallowing_call_is_grandfathered
#MUTANT probe-exclusion-dropped|s@^\tnot regex.match(data.batten.patterns\["resolver-existence-probe"\], line)$@\ttrue@|an_existence_probe_is_not_refused

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document and
#   never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.could_not_look_laundered

import rego.v1

rules contains "gate run unsafe"

# ---------------------------------------------------------------------------
# The changed-file set, and the could-not-look channel.
# ---------------------------------------------------------------------------

# `input.tree["base-delta"]` is NULL when the base rev did not resolve, and `null`
# is not `undefined` — `not input.tree["base-delta"]` would be false for it, the
# slip CLOUD-701's review caught in `spawn-adapters`. So the delta is bound
# through a rule that holds only for an object.
#
# NO `else` FALLBACK, and that is the correction this module owes its own draft.
# An `else := {"added": [], …}` looks like the careful thing and is the dead gate:
# empty arrays make `governed` empty, nothing is refused, and the module reads
# CLEAN on exactly the checkout whose base it could not read. Leaving it undefined
# makes every predicate below undefined rather than vacuously green, which is
# `shell-retirement`'s reason in its own words.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# ---------------------------------------------------------------------------
# The lines this change INTRODUCED.
# ---------------------------------------------------------------------------

# An ADDED path contributes every line it has: nothing about it is grandfathered.
added_lines(path) := lines if {
	path in delta.added
	lines := {line | some line in input.tree.lines[path]}
}

# An EDITED path contributes the lines its head has and its base did not.
#
# COULD-NOT-LOOK REFUSES NOTHING HERE, and that is the safe direction for this
# arm rather than the usual one. `base-lines` omits a path whose base blob would
# not read; with the base side unknowable, EVERY head line looks new, so a module
# that fell back to the whole file would refuse a file it never compared. An
# occurrence that predates the change is what this rule exists not to fire on.
added_lines(path) := lines if {
	path in delta.edited
	base := delta["base-lines"][path]
	lines := {line | some line in input.tree.lines[path]; not line in base}
}

# ---------------------------------------------------------------------------
# The refusal.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "gate run unsafe",
	"verdict": "gate run unsafe",
	"subjects": [{"path": path}],
} if {
	some path in governed
	some line in added_lines(path)
	regex.match(data.batten.patterns["swallowed-resolver-call"], line)

	# THE EXISTENCE PROBE IS NOT A LAUNDERING SITE. `command -v batten` asks
	# whether the binary resolves, so an empty answer IS the answer and forcing
	# success is how you ask. Excluded by its own pattern rather than by
	# narrowing the one above, because every narrowing tried re-admitted a
	# different false positive.
	not regex.match(data.batten.patterns["resolver-existence-probe"], line)
}

governed contains path if {
	some path in array.concat(delta.added, delta.edited)
	endswith(path, ".sh")
	startswith(path, "mise-tasks/")
}

# ---------------------------------------------------------------------------
# The could-not-look clause `rules/policy-modules.md` requires.
# ---------------------------------------------------------------------------

# A governed path whose lines were not acquired is a file this rule did not read,
# and saying so is the difference between the engine recording that it could not
# look and this gate reporting a clean change.
violation contains {
	"rule": "gate run unsafe",
	"verdict": "gate run unsafe",
	"subjects": [{"path": path}],
} if {
	some path, cause in input.tree.missing
	cause == "unparsed"
	path in governed
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds `base-delta` and
# `lines` for the globs the row declares — a `with input as` case fabricates the
# very shape the engine may be unable to produce.
# `crates/batten/tests/it/could_not_look_laundered.rs` is that tier.

# The three shapes, spelled as the corpus spells them — leading tab included, so a
# reader can hold them against the real sites. The indentation plays no part in
# the predicate, which is unanchored.
_swallow := "\tserved=$(batten claim keys 2>/dev/null || true)"

_probe := "\t\"$(command -v batten 2>/dev/null || true)\"; do"

_clean := "\tif ! served=$(batten claim keys 2>/dev/null); then"

# An ADDED governed path contributes every line, so a swallowing call in one is
# this change's doing however old the idiom is elsewhere.
test_an_added_swallowing_call_is_refused if {
	some v in violation with input as {"tree": {
		"base-delta": {"added": ["mise-tasks/probe.sh"], "edited": [], "base-lines": {}},
		"lines": {"mise-tasks/probe.sh": [_swallow]},
		"missing": {},
	}}
	v.verdict == "gate run unsafe"
}

# THE RATCHET'S OTHER HALF, and the reason this reads the delta at all. The same
# line, in an EDITED file that already had it, is nothing this change did. Without
# this the rule is a state rule and is red on landing day over three sites it
# cannot repair.
test_an_existing_swallowing_call_is_grandfathered if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": {
			"added": [],
			"edited": ["mise-tasks/probe.sh"],
			"base-lines": {"mise-tasks/probe.sh": [_swallow]},
		},
		"lines": {"mise-tasks/probe.sh": [_swallow]},
		"missing": {},
	}}
}

# An edited file that ADDS the line is refused, which is what keeps the case above
# from being satisfied by a module that never fires on an edit.
test_a_newly_added_line_in_an_edited_file_is_refused if {
	some v in violation with input as {"tree": {
		"base-delta": {
			"added": [],
			"edited": ["mise-tasks/probe.sh"],
			"base-lines": {"mise-tasks/probe.sh": ["# nothing here before"]},
		},
		"lines": {"mise-tasks/probe.sh": [_swallow]},
		"missing": {},
	}}
	v.verdict == "gate run unsafe"
}

# `command -v batten` IS the swallowing shape and is not the defect: it asks
# whether the binary resolves, so empty is the answer rather than a laundered one.
test_an_existence_probe_is_not_refused if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": {"added": ["mise-tasks/probe.sh"], "edited": [], "base-lines": {}},
		"lines": {"mise-tasks/probe.sh": [_probe]},
		"missing": {},
	}}
}

# THE ANTI-VACUITY CASE FOR THE PATTERN ITSELF. A call that KEEPS the status is
# the idiom this rule points at, and refusing it would make the remedy unreachable.
test_a_call_that_keeps_its_status_is_clean if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": {"added": ["mise-tasks/probe.sh"], "edited": [], "base-lines": {}},
		"lines": {"mise-tasks/probe.sh": [_clean]},
		"missing": {},
	}}
}

# A path this rule does not govern is not its business, however it is spelled.
test_an_ungoverned_path_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": {"added": ["crates/batten/src/main.rs"], "edited": [], "base-lines": {}},
		"lines": {"crates/batten/src/main.rs": [_swallow]},
		"missing": {},
	}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — `some .. in null` is a hard evaluation fault that takes the bundle with
# it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"base-delta": null, "lines": {}, "missing": {}}}
}

# A GOVERNED FILE THAT WOULD NOT PARSE IS REPORTED, never read as clean — the
# difference between the engine saying it could not look and this gate saying
# there was nothing to find.
test_an_unparsed_governed_path_is_reported if {
	some v in violation with input as {"tree": {
		"base-delta": {"added": ["mise-tasks/probe.sh"], "edited": [], "base-lines": {}},
		"lines": {},
		"missing": {"mise-tasks/probe.sh": "unparsed"},
	}}
	v.verdict == "gate run unsafe"
}

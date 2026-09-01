# METADATA
# description: |
#   The successor shape for the third-party-validator half of CLOUD-1171, and the
#   demonstration that row owes.
#
#   `pkl-check`, `renovate-config-validator` and `hook-profile-check` each RUN a
#   validator and then adjudicate what it said. The run stays outside — §9's prior
#   art: the tool is a command on PATH and stays one — and only the ADJUDICATION
#   moves here, because `check` is `read` and structurally cannot spawn. Before
#   `input.tree["tool-verdict"]` a module asking what a validator found read
#   undefined, Rego took undefined as *does not hold*, and the gate was
#   byte-identical to a clean tree on the decision surface.
#
#   WHAT COUNTS AS A FINDING IS THIS CONSUMER'S. A validator's own vocabulary —
#   which key means "clean", which names an error — is this repository's fact and
#   lives here, never in `crates/batten` (non-negotiable rule 1). The engine
#   supplies "the verdict recorded under this key" and this module decides what a
#   clean one looks like.
#
#   THREE ANSWERS, AND THE MODULE READS ALL THREE. `null` is could-not-look —
#   nobody declared a tool, or no record store is readable. A declared id ABSENT
#   from the map has no record UNDER ITS KEY: either nothing has run, or what ran
#   was a different version or read different bytes. A record PRESENT and empty is
#   the tool having run and found nothing. This refuses only a present record
#   carrying a finding, because the first two are not verdicts — and a gate that
#   treated them as one would report on a file no validator ever read.
#
#   ABSENT IS NOT A REFUSAL HERE, AND THAT IS A DELIBERATE DIRECTION. A gate that
#   denied on absence would deny on every checkout until a producer exists, which
#   makes the first landing of this family a tree-wide refusal. The row that wants
#   `a verdict is REQUIRED` is a separate predicate over the same key, and it is
#   not this one.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.validator_verdict

import rego.v1

rules contains "validator-verdict-clean"

# The key a producer writes when the validator had nothing to say.
#
# One reserved name rather than "an empty record", because a producer that
# crashed before writing anything would otherwise be indistinguishable from one
# that ran cleanly — and those are the two answers this whole family exists to
# keep apart.
status := "status"

# The rows THIS module adjudicates.
#
# `input.tree["tool-verdict"]` is built from every `[[rule.tools]]` row in the
# config — `rules::tool_facts` flattens across all rules — so it is NOT scoped to
# the rule being evaluated. A sibling row whose record carries a different SHAPE
# therefore reaches this module too, and `findings` counts each of its lines as a
# finding.
#
# Measured while landing CLOUD-1265's third consumer: `hook-profile`'s `hk-plan`
# record is one line per slow-tier step (`<step> included`), and this module read
# those seven step names as seven findings and refused a clean tree.
#
# Selecting by the reserved `status` key was the tempting fix and is the wrong
# one: a record carrying findings and NO status is a producer that crashed before
# writing its marker, which is precisely the state this family exists to catch, so
# a `status`-keyed selector would go silent on it. The ids are named instead.
owned := {"config-validator", "renovate-config"}

# Every declared id whose record exists and carries something other than a clean
# status.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a tool, and
# `some .. in null` is a hard evaluation FAULT in Rego rather than a silent miss.
refused contains id if {
	is_object(input.tree["tool-verdict"])
	some id, verdict in input.tree["tool-verdict"]
	id in owned

	# PRESENT AND JUDGED, which is the only state this refuses. An id whose key
	# has no record is absent from the map entirely and never reaches here.
	count(findings(verdict)) > 0
}

# Everything the record carries except the reserved status line.
#
# A record whose status is anything but `clean` counts its status as a finding
# too: a validator that reported `error` and listed nothing is still a validator
# that reported an error.
findings(verdict) := {key |
	some key, _ in verdict
	key != status
} | {key |
	some key, value in verdict
	key == status
	value != "clean"
}

violation contains {
	"rule": "validator-verdict-clean",
	"verdict": "V-VALIDATOR-VERDICT-UNCLEAN",
	"subjects": [{"count": count(refused)}],
} if {
	count(refused) > 0
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE composes the key from
# the tool, its pin and the input's digest — a `with input as` case fabricates the
# very shape the engine may be unable to produce (CLOUD-845, CLOUD-857), and here
# it would fabricate the KEYING the whole family turns on.
# `crates/batten/tests/tool_verdict_facts.rs` is that tier, and its
# `a_record_from_another_version_does_not_answer` and
# `a_verdict_does_not_survive_its_input` cases are the discriminating ones.

recorded(verdict) := {"tree": {"tool-verdict": {"config-validator": verdict}}}

test_a_clean_record_is_clean if {
	count(violation) == 0 with input as recorded({"status": "clean"})
}

test_a_record_carrying_a_finding_is_refused if {
	some v in violation with input as recorded({"status": "clean", "unresolved-key": "hk.pkl:12"})
	v.verdict == "V-VALIDATOR-VERDICT-UNCLEAN"
}

# A validator that reported an error and listed nothing is still an error, and
# reading it as clean is the false pass this family exists to close.
test_a_non_clean_status_alone_is_refused if {
	some v in violation with input as recorded({"status": "error"})
	v.verdict == "V-VALIDATOR-VERDICT-UNCLEAN"
}

# NOTHING HAS VALIDATED THESE BYTES is not a verdict. The id is absent from the
# map — no record under this key — so there is nothing to refuse.
test_an_id_with_no_record_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": {}}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
# A SIBLING ROW'S RECORD IS NOT THIS MODULE'S TO JUDGE, and this is the case that
# would have caught the measured defect: `hook-profile` records one line per
# slow-tier step, and reading those as findings refused a correctly wired tree.
test_another_rows_record_is_not_read_as_a_finding if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": {"hk-plan": {"batten-check": "included"}}}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": null}}
}

#MUTANT-SUITE crates/batten/tests/it/tool_verdict_facts.rs
#MUTANT-OWNER CLOUD-1265|nothing WRITES a `tool-verdict` record, so this predicate resolves `null` and refuses nothing on any real checkout; the tier it names drives the FACT and never the predicate
#MUTANT unclean-verdict-unread|s@^\tcount(refused) > 0$@\tfalse@|a_declared_key_reads_its_own_record

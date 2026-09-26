# This session has dropped the PR's webhook subscription (ported off
# `mise-tasks/pr-unsubscribed.sh`'s `check` under CLOUD-1717; the predicate is
# CLOUD-518's, the actor CLOUD-790's).
#
# AGENTS.md forbids babysitting a PR through its webhook, and the harness arms a
# subscription on every PR this repo opens with no tool call behind it — measured
# on #397, #402 and #489. `land` runs `mise run pr-unsubscribed check <pr>` on
# every lap, and the landing stops until this session holds a receipt for that
# PR: minted by `drop` (the endpoint accepted the call) or by `record` (the
# agent's own `unsubscribe_pr_activity` answer, naming this PR).
#
# THE TWO PASSING READINGS ARE DIFFERENT FACTS. No session means no
# subscription — a local clone, a CI runner — so there is nothing to drop and
# nothing is refused. A session holding a receipt for this PR has dropped it.
# Only a session WITHOUT one is refused. The producer reads the receipt store,
# which a module cannot; this reads its three answers and decides.
#
# COMPLETE OR TORN: `session`, `pr` and `receipt` each appear exactly once.
#
#MUTANT-SUITE crates/batten/tests/it/pr_unsubscribed.rs
#MUTANT check-always-passes|s@^\tfield("receipt") == "absent"$@\tfalse@|a_pr_this_session_never_unsubscribed_is_refused
#MUTANT off-harness-blocks|s@^\tfield("session") != "-"$@\ttrue@|a_clone_with_no_session_has_nothing_to_drop
#MUTANT torn-record-passes|s@^\tcount(present) != count(readings)$@\tfalse@|a_record_missing_a_reading_is_torn_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.pr_unsubscribed

import rego.v1

rules contains "event watch other"

lines := input.tree.records["pr-unsubscribed"]

readings := {"session", "pr", "receipt"}

values(name) := {columns[1] |
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == name
}

field(name) := value if {
	candidates := values(name)
	count(candidates) == 1
	some value in candidates
}

present contains name if {
	some name in readings
	count([line | some line in lines; startswith(line, sprintf("%s\t", [name]))]) == 1
	field(name)
}

torn if {
	lines
	count(present) != count(readings)
}

violation contains {
	"rule": "event watch other",
	"verdict": "event watch held",
	"subjects": [{"artifact": sprintf("#%s", [field("pr")])}],
} if {
	not torn
	field("session") != "-"
	field("receipt") == "absent"
}

violation contains {
	"rule": "event watch other",
	"verdict": "event read partial",
	"subjects": [{"count": count(present)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

tree(session, pr, receipt) := {"tree": {"records": {"pr-unsubscribed": [
	sprintf("session\t%s", [session]),
	sprintf("pr\t%s", [pr]),
	sprintf("receipt\t%s", [receipt]),
]}}}

test_a_session_without_a_receipt_is_refused if {
	found := violation with input as tree("cse_x", "489", "absent")
	{entry.verdict | some entry in found} == {"event watch held"}
}

test_a_receipt_passes if {
	count(violation) == 0 with input as tree("cse_x", "489", "present")
}

test_no_session_passes if {
	count(violation) == 0 with input as tree("-", "489", "absent")
}

test_a_missing_reading_is_torn if {
	found := violation with input as {"tree": {"records": {"pr-unsubscribed": ["session\tcse_x"]}}}
	{entry.verdict | some entry in found} == {"event read partial"}
}

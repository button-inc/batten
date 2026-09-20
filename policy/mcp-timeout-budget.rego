# CLOUD-668/CLOUD-700, ported off `mise-tasks/mcp-timeout-budget.sh` under
#   CLOUD-1716. CLOUD-266's rule -- "timeouts are uniform boilerplate, not
#   measured budgets, so they bound nothing" -- applied to the one budget nobody
#   had looked at.
#
#   WHAT EXCEEDING IT COSTS, which is why the margin is generous rather than
#   tight. It is not a retry. Serena is absent for the WHOLE session, and the
#   failure is legible only as "the known Serena flakiness": the memory tree
#   becomes unwritable because Serena owns `.serena/memories/**` through the
#   protected-path gate, and the symbol tools go with it so navigation silently
#   degrades to grep.
#
#   THE MEASUREMENT, re-taken 2026-08-19 (CLOUD-700). Two containers on the same
#   commit, one per budget:
#
#     07:06 container, budget 30000    failed at 28162 ms, CONNECT_TIMEOUT
#     14:28 container, budget 120000   SUCCEEDED at 52747 ms
#
#   52747 ms is not an outlier to explain away: it is a cold container paying a
#   first rust-analyzer index while provisioning runs, which is the ordinary
#   shape of a session start here. Against the host default of 30000 it is BELOW
#   the measurement -- a connect that did succeed would have been killed by it.
#
#   THE FLOOR CARRIES ITS OWN BASIS AND BOTH MOVE TOGETHER. `floor_ms` is
#   `worst_ms * multiplier` and `bound measure stale` refuses any disagreement.
#   That is not ceremony: a superseded "16.65s" went on justifying a number
#   derived from 52747 ms precisely because the two could drift apart, and the
#   floor it derived left 1.14x headroom while reading as deliberate.
#
#   THE EFFECT HALF IS NOT PORTED, AND THAT IS STATED RATHER THAN DROPPED.
#   The retired program also read the MCP client's own connection log for
#   `Starting connection with timeout of <n>ms`, because a declaration the host
#   ignores is not a budget -- the 07:06 failure above is exactly that. It is not
#   expressible here: the log lives at
#   `$HOME/.cache/claude-cli-nodejs/<mangled-cwd>/mcp-logs-<server>/<instant>.jsonl`,
#   and `[[rule.external]]` takes a fixed `root` plus `path` with no glob, so
#   neither the working-directory-derived directory nor the timestamped filename
#   can be named. CLOUD-730's question -- why one container picks the declaration
#   up and another does not -- stays open, and nothing here should be read as
#   retiring the settings surface or as answering it.
#
#   WHY THIS IS A SETTINGS GATE AND NOT A `.mcp.json` ONE: `.mcp.json`'s
#   per-server `env` is passed to the CHILD, and this budget governs the PARENT's
#   wait.
#
# The mutation accepts any declared value, dropping the floor comparison. The
# host default 30000 IS a declared value, so a gate that only checks presence
# passes the exact state CLOUD-668 was filed about.
#MUTANT presence-is-not-a-budget|s@^\tdeclared < floor_ms$@\tfalse@|the_host_default_is_refused_although_it_is_declared
# And the floor may not be moved without the measurement that justifies it.
#MUTANT floor-without-basis|s@^floor_ms := 105494$@floor_ms := 60000@|the_floor_agrees_with_its_declared_basis
# A non-numeric declaration must not read as absent: the two have different
# remedies, and collapsing them sends the reader to add a key that is already
# there.
#MUTANT unparsable-reads-as-absent|s@^\tnot numeric_string$@\tfalse@|a_non_numeric_budget_is_named_as_such
#MUTANT-SUITE crates/batten/tests/it/mcp_timeout_budget.rs

package batten

import rego.v1

rules contains "bound guard missing"

# The settings file this repository ships. The repository's OWN copy, not the
# merged wiring under the user's home -- `harness-wiring` owns that subject and a
# reader who conflates them will look for this predicate in the wrong file.
SETTINGS := ".claude/settings.json"

# THE FLOOR AND THE MEASUREMENT THAT JUSTIFIES IT, adjacent so neither can move
# alone. Lowering the floor requires a new row in this module's own measurement
# table above; raising the DECLARED value in the settings file is free.
#
# 105494 rather than a rounded 105000: 52747 x 2 is 105494, and the rounding that
# produced the older value is a small instance of the same drift the arithmetic
# below exists to refuse.
worst_ms := 52747

multiplier := 2

floor_ms := 105494

# What the repository declares, unparsed. Absent where the file could not be read
# at all, which Rego resolves as undefined and therefore as "does not hold" --
# so a tree this could not open reports nothing rather than a missing budget.
declared_raw := input.tree.documents[SETTINGS].env.MCP_TIMEOUT

# The declared budget as a number, or undefined.
#
# A STRING OF DIGITS IS A BUDGET. The settings file is JSON written by hand and
# `"120000"` is what a person types; reading that as unparsable would refuse a
# tree correct in every way a reader can see.
declared := declared_raw if is_number(declared_raw)

declared := to_number(declared_raw) if numeric_string

# THE DIGITS ARE CHECKED BEFORE THE CONVERSION, and that is a fault rather than
# a style. `to_number` FAULTS on a string it cannot read -- it does not resolve
# to undefined -- so a module that lets it see `"soon"` takes the whole
# evaluation down and decides nothing, which is a dead gate arriving through the
# one door this module exists to keep shut.
#
# No inline regex: a pattern is a `[[pattern]]` row, and a digit set is a set.
DIGITS := {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

numeric_string if {
	is_string(declared_raw)
	count(declared_raw) > 0
	every character in split(declared_raw, "") {
		character in DIGITS
	}
}

# The settings file was read. Anchoring on the DOCUMENT rather than on the key
# keeps "no budget declared" distinct from "no file to look in".
readable if {
	input.tree.documents[SETTINGS]
}

# --- the budget itself -------------------------------------------------------

violation contains {
	"rule": "bound guard missing",
	"verdict": "bound state missing",
	"subjects": [{"path": SETTINGS}, {"count": floor_ms}],
} if {
	readable
	not declared_raw
}

violation contains {
	"rule": "bound guard missing",
	"verdict": "bound read wrong",
	"subjects": [{"path": SETTINGS}],
} if {
	readable
	declared_raw
	not is_number(declared_raw)
	not numeric_string
}

violation contains {
	"rule": "bound guard missing",
	"verdict": "bound guard early",
	"subjects": [{"path": SETTINGS}, {"count": floor_ms}],
} if {
	declared < floor_ms
}

# --- the floor's own basis ---------------------------------------------------

violation contains {
	"rule": "bound guard missing",
	"verdict": "bound measure stale",
	"subjects": [{"path": "policy/mcp-timeout-budget.rego"}, {"count": floor_ms}],
} if {
	floor_ms != worst_ms * multiplier
}

# --- could-not-look ----------------------------------------------------------
#
# A declared source that would not parse belongs in the channel rather than being
# silently absent: a module that iterates only what it could read reports green
# over a file it never opened.

# `absent` IS NOT `unparsed`, AND COLLAPSING THEM WOULD MAKE THIS MODULE
# UNUSABLE OUTSIDE THIS REPOSITORY. `NotAcquired` keeps the causes distinct
# precisely so a predicate cannot mistake "could not parse" for "not there": a
# consumer that ships no `.claude/settings.json` is not in breach of a bound it
# never declared, where a file this could not READ is a question left unanswered
# and has to say so.
UNREADABLE := {"unparsed", "unreadable", "unknown-format"}

violation contains {
	"rule": "bound guard missing",
	"verdict": "source parse dead",
	"subjects": [{"path": SETTINGS}],
} if {
	input.tree.missing[SETTINGS] in UNREADABLE
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/mcp_timeout_budget.rs` is the
# tier that proves the ENGINE builds `input.tree.documents` for this dotfile path
# at all -- a `with input as` case fabricates the very shape the engine may be
# unable to produce, which is how a dead clause survives a green suite.

settings(env) := {"tree": {"documents": {".claude/settings.json": {"env": env}}}}

test_the_declared_budget_is_clean if {
	count(violation) == 0 with input as settings({"MCP_TIMEOUT": 120000})
}

test_a_budget_at_the_floor_exactly_is_clean if {
	count(violation) == 0 with input as settings({"MCP_TIMEOUT": 105494})
}

test_the_host_default_is_refused_although_it_is_declared if {
	findings := violation with input as settings({"MCP_TIMEOUT": 30000})
	some finding in findings
	finding.verdict == "bound guard early"
}

test_an_absent_budget_is_refused_as_absent if {
	findings := violation with input as settings({})
	some finding in findings
	finding.verdict == "bound state missing"
}

test_a_non_numeric_budget_is_named_as_such if {
	findings := violation with input as settings({"MCP_TIMEOUT": "soon"})
	some finding in findings
	finding.verdict == "bound read wrong"
}

test_a_numeric_string_is_a_budget if {
	count(violation) == 0 with input as settings({"MCP_TIMEOUT": "120000"})
}

test_a_numeric_string_below_the_floor_is_still_refused if {
	findings := violation with input as settings({"MCP_TIMEOUT": "30000"})
	some finding in findings
	finding.verdict == "bound guard early"
}

test_the_floor_agrees_with_its_declared_basis if {
	floor_ms == worst_ms * multiplier
}

test_an_unreadable_settings_file_is_could_not_look if {
	findings := violation with input as {"tree": {"missing": {".claude/settings.json": "unparsed"}}}
	some finding in findings
	finding.verdict == "source parse dead"
}

# AND A FILE THAT IS SIMPLY NOT THERE IS NOT THAT. A consumer shipping no
# settings file declares no budget and breaches none; reading `absent` as
# unreadable would refuse every adopter on their first run.
test_a_settings_file_that_is_absent_is_not_unreadable if {
	count(violation) == 0 with input as {"tree": {"missing": {".claude/settings.json": "absent"}}}
}

# A tree with no settings document at all reports NOTHING rather than a missing
# budget: this gate answers about a repository that ships the file, and a
# consumer that ships none is not in breach of a bound it never declared.
test_a_tree_without_the_file_reports_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

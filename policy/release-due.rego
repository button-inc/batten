# May the release PR land now? A debounce: `main` quiet for the window, OR the last
# release older than the max wait, OR no release yet (ported off
# `mise-tasks/release-due.sh` under CLOUD-1717; the predicate is CLOUD-319's).
#
# Releases fired once per crate-touching commit — 57 tags, most one or two commits
# apart. The release PR already accumulates every commit since the last tag, so
# what happened too often is LANDING it, and this is the one predicate on that
# edge (`auto-release-land.yml`'s automated `/fast-forward`).
#
# AN OR, NOT AN AND. The quiet window is a trailing-edge debounce; the max wait
# stops a busy `main` from starving the release. Requiring both would mean a repo
# that never goes quiet never ships. Both bounds are EXCLUSIVE now, decided by the
# producer: `record query` keeps a row whose instant is AT the cut-off, so a commit
# or release exactly one window old still holds, and the arm is due only once it
# is strictly older. The retired body was due at the boundary (`age >= window`);
# the one-second inversion errs toward holding, and the tier ledger records it.
#
# THE SPLIT IS §5's, AND SINCE CLOUD-843 IT HAS NO ARITHMETIC IN IT. The body this
# replaced read a clock and recorded two AGES for this module to compare against
# two windows. Two `[[forge.query]]` rows read the newest commit on the trunk and
# the newest release instead, each windowed BY THE PRODUCER'S CLOCK: a row is kept
# only when its instant is inside its window. So `kept=0` over a window that READ
# a row IS "older than the window", `read=0` on the release window IS "no release
# yet", and no timestamp reaches this module at all.
#
# WHY A CONSUMER MODULE AND NOT THE `release-hygiene` PRESET. The debounce is
# generic, but a preset reads no record by NAME — the name is the consumer's, and
# a preset naming it would ship rule 1's violation into every binary — and a
# forge window's lines carry no kind column a preset could narrow on instead. The
# two family names are this repository's `[[forge.query]]` ids, so the decision
# over them lives here.
#
# HOLDING is a finding here (`release ship early`, exit 2 through `check`), which
# `auto-release-land.yml` reads as "not yet" rather than as a failure.
#
# COMPLETE OR TORN: both windows, each closed by exactly one `window` line whose
# `kept` agrees with its rows. A trunk window that read no commit measured
# nothing and is torn too, never quiet.
#
#MUTANT-SUITE crates/batten/tests/it/release_due.rs
#MUTANT busy-main-is-due|s@^\tnot due$@\tfalse@|a_busy_main_inside_the_max_wait_holds
#MUTANT max-wait-ignored|s@^due if kept("release-due-latest") == 0$@due if false@|the_max_wait_interrupts_a_main_that_never_goes_quiet
#MUTANT quiet-ignored|s@^\tkept("release-due-activity") == 0$@\tfalse@|main_quiet_past_the_window_is_due
#MUTANT torn-record-passes|s@^\tcount(whole) != count(families)$@\tfalse@|a_release_due_window_that_is_absent_or_torn_is_partial

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_due

import rego.v1

rules contains "release grade early"

# The two windows, by the `[[forge.query]]` ids that write them.
families := {"release-due-activity", "release-due-latest"}

# The families a record is present for. Guarded, because `some .. in null` FAULTS.
present contains name if {
	is_object(input.tree.records)
	some name in families
	is_array(input.tree.records[name])
}

# One window's closing line, as `key -> value`, or undefined where the record
# carries anything but exactly one.
closing(name) := fields if {
	lines := input.tree.records[name]
	endings := [line | some line in lines; startswith(line, "window\t")]
	count(endings) == 1
	ending := endings[0]
	fields := {pair[0]: pair[1] |
		some field in array.slice(split(ending, "\t"), 1, 100)
		pair := split(field, "=")
		count(pair) == 2
	}
}

# A count off the closing line, or undefined — never a fault: regorus `to_number`
# faults on a non-numeric string, so it is guarded first.
counted(name, key) := to_number(raw) if {
	raw := closing(name)[key]
	regex.match(data.batten.patterns["whole-number"], raw)
}

kept(name) := counted(name, "kept")

# The trunk window must have READ a commit: a `main` with nothing readable on it
# measured nothing, and reading that as "quiet" would land the release on a
# forge answer that was empty. DEFINED ABOVE ITS READER: regorus resolves a rule
# defined below the rule that reads it as undefined (`landing-loop` measured it).
unmeasured(name) if {
	name == "release-due-activity"
	counted(name, "read") == 0
}

# WHOLE MEANS READABLE AND SELF-CONSISTENT, not merely present: one closing line,
# both counts whole numbers, and `kept` equal to the rows actually recorded. A
# window the producer tore mid-write must not read as a quiet trunk.
whole contains name if {
	some name in present
	read := counted(name, "read")
	kept(name) == count([line | some line in input.tree.records[name]; startswith(line, "row\t")])
	read >= kept(name)
	not unmeasured(name)
}

torn if {
	count(present) > 0
	count(whole) != count(families)
}

due if kept("release-due-latest") == 0

due if {
	kept("release-due-activity") == 0
}

violation contains {
	"rule": "release grade early",
	"verdict": "release ship early",
	"subjects": [{"count": kept("release-due-activity")}],
} if {
	count(present) > 0
	not torn
	not due
}

violation contains {
	"rule": "release grade early",
	"verdict": "release measure partial",
	"subjects": [{"count": count(whole)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

# One window of zero or one kept rows, as `record query` closes it.
window(rows, read) := lines if {
	rows == 1
	lines := [
		"row\t{\"at\":\"x\"}",
		sprintf("window\tstate=truncated\tread=%d\tkept=1\ttotal=-\tpages=1\tsince=x", [read]),
	]
} else := [sprintf("window\tstate=whole\tread=%d\tkept=0\tsince=x", [read])]

tree(activity, latest) := {"tree": {"records": {
	"release-due-activity": activity,
	"release-due-latest": latest,
}}}

test_quiet_past_the_window_is_due if {
	count(violation) == 0 with input as tree(window(0, 1), window(1, 1))
}

test_busy_inside_the_max_wait_holds if {
	found := violation with input as tree(window(1, 1), window(1, 1))
	{entry.verdict | some entry in found} == {"release ship early"}
}

test_a_release_older_than_the_max_wait_is_due_on_a_busy_trunk if {
	count(violation) == 0 with input as tree(window(1, 1), window(0, 1))
}

test_no_release_is_due if {
	count(violation) == 0 with input as tree(window(1, 1), window(0, 0))
}

test_a_trunk_window_that_read_no_commit_is_partial if {
	found := violation with input as tree(window(0, 0), window(1, 1))
	{entry.verdict | some entry in found} == {"release measure partial"}
}

test_one_window_alone_is_partial if {
	found := violation with input as {"tree": {"records": {"release-due-activity": window(1, 1)}}}
	{entry.verdict | some entry in found} == {"release measure partial"}
}

test_a_window_whose_count_disagrees_with_its_rows_is_partial if {
	lying := ["window\tstate=whole\tread=1\tkept=1"]
	found := violation with input as tree(lying, window(1, 1))
	{entry.verdict | some entry in found} == {"release measure partial"}
}

test_no_window_at_all_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
	count(violation) == 0 with input as {"tree": {"records": null}}
}

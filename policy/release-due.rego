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
# that never goes quiet never ships. Both bounds are INCLUSIVE.
#
# THE SPLIT IS §5's: the engine has no clock. `[tasks.release-due-record]` reads
# the clock and the forge and records two AGES in seconds — since `main` last
# moved, and since the last release (`none` where there is none) — plus the two
# windows it was given, validated as whole numbers. This compares. HOLDING is a
# finding here (`release ship early`, exit 2 through `check`), which
# `auto-release-land.yml` reads as "not yet" rather than as a failure.
#
# COMPLETE OR TORN: all four readings exactly once.
#
#MUTANT-SUITE crates/batten/tests/it/release_due.rs
#MUTANT busy-main-is-due|s@^\tnot due$@\tfalse@|a_busy_main_inside_the_max_wait_holds
#MUTANT max-wait-ignored|s@^due if seconds("release-age") >= seconds("max-wait")$@due if false@|the_max_wait_interrupts_a_main_that_never_goes_quiet
#MUTANT torn-record-passes|s@^\tcount(present) != count(readings)$@\tfalse@|a_release_due_record_missing_a_reading_is_torn

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

lines := input.tree.records["release-due"]

readings := {"activity-age", "release-age", "quiet", "max-wait"}

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

# A whole number of seconds, or undefined — never a fault: regorus `to_number`
# faults on a non-numeric string, so it is guarded first.
seconds(name) := to_number(raw) if {
	raw := field(name)
	regex.match(data.batten.patterns["whole-number"], raw)
}

due if field("release-age") == "none"

due if seconds("release-age") >= seconds("max-wait")

due if seconds("activity-age") >= seconds("quiet")

violation contains {
	"rule": "release grade early",
	"verdict": "release ship early",
	"subjects": [{"count": seconds("activity-age")}],
} if {
	not torn
	not due
}

violation contains {
	"rule": "release grade early",
	"verdict": "release measure partial",
	"subjects": [{"count": count(present)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

tree(activity, release, quiet, max_wait) := {"tree": {"records": {"release-due": [
	sprintf("activity-age\t%s", [activity]),
	sprintf("release-age\t%s", [release]),
	sprintf("quiet\t%s", [quiet]),
	sprintf("max-wait\t%s", [max_wait]),
]}}}

test_quiet_past_the_window_is_due if {
	count(violation) == 0 with input as tree("1800", "3600", "1800", "86400")
}

test_busy_inside_the_max_wait_holds if {
	found := violation with input as tree("1799", "3600", "1800", "86400")
	{entry.verdict | some entry in found} == {"release ship early"}
}

test_the_max_wait_is_inclusive if {
	count(violation) == 0 with input as tree("60", "86400", "1800", "86400")
}

test_no_release_is_due if {
	count(violation) == 0 with input as tree("60", "none", "1800", "86400")
}

test_a_missing_reading_is_torn if {
	found := violation with input as {"tree": {"records": {"release-due": ["quiet\t1800"]}}}
	{entry.verdict | some entry in found} == {"release measure partial"}
}

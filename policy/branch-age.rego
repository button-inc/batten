# No remote branch outlives its story (CLOUD-349, ported under CLOUD-1717).
#
# Trunk-based development says a review branch "can (and should) be deleted after
# the code review is complete and be very short-lived", and names the hazard this
# measures: a short-lived feature branch "sleepwalking into a long-lived feature
# branch". Its own words on the tooling — "You cannot with tools today, but it
# would be cool if you could have a ticking clock or count down on those branches
# at creation to enforce its 'temporary' intention." This is that clock, after
# the fact.
#
# TWO PROPERTIES, because staleness is the smaller half:
#
#   stale    a branch whose tip is older than the threshold below. The ordinary
#            leftover. Measured 2026-08-11, before `land` learned to delete: 23
#            remote branches, ten of them `release-plz-*` from five days earlier.
#   reused   a branch NAME heading more than one merged pull request AND still
#            present on the remote. The second conjunct is what keeps this a gate
#            rather than a permanent alarm: merged PRs are immutable, so an
#            unintersected count could never be cleared by any action. This is
#            the one a per-PR lifetime metric cannot see —
#            `claude/phase-3-sequential-landing-h26kx0` headed eight consecutive
#            pull requests, each landing inside an hour, while the branch itself
#            lived for days.
#
# THE CLOCK IS THE PRODUCER'S, NOT THIS MODULE'S, and that split is forced rather
# than chosen. `Fact::Instant` is consumed at the boundary and projects `null` to
# every module — the engine calls no `SystemTime::now` on any evaluation path,
# which `clippy.toml`'s `disallowed-methods` and `crates/batten/tests/clock_ban.rs`
# hold it to. So the record carries an AGE IN DAYS that the producer computed,
# and what moves in here is the decision: an age over the threshold is stale.
# CLOUD-1559's reading rule says the same thing from the other side — carry the
# decisions, not the steps. The retired program's civil-calendar day arithmetic
# is a step, and it stays outside with the `gh` call that needs it.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, and it is silence rather than a pass. The
# producer writes nothing when it cannot reach the forge, so `records` carries no
# `branch-age` key, every rule below is undefined and the module says nothing.
# A record that is PRESENT and holds no `ref` line is a different state: the
# producer looked and the remote reported no branches, which the retired program
# refused outright as impossible of a repository with a trunk. That refusal is
# kept, because a silent pass there is the shape where the whole gate evaporates.
#MUTANT-EXEMPT CLOUD-1717|the compiled-binary tier this module's mutations would redden, `crates/batten/tests/it/branch_age.rs`, is not written yet: the module does not decide, because `recorder_records` projects no `record named` family and `input.tree.records["branch-age"]` never reaches it. The four mutations are drafted in this file's history and go back with the tier, in the same delta that retires `mise-tasks/branch-age-check.sh` — the program stays until then, so nothing is uncovered that was covered before.

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.branch_age

import rego.v1

rules contains "branch-stale"

rules contains "branch-reused"

rules contains "branch-listing-empty"

# The source's "a couple of days", as a number.
#
# In the module rather than in config, on `repetition-without-progress`'s
# reasoning one row over: this is the practice's own figure rather than this
# consumer's tuning, and a config knob would invite raising it until nothing
# fires. Moving it costs a diff a reviewer reads.
threshold := 2

# The producer's lines, or nothing. `recorded` being undefined is the
# could-not-look state the header describes, and every rule below inherits it.
recorded := input.tree.records["branch-age"]

# `ref <name> <age-in-days>` — one per branch the remote reports, trunk excluded
# by the producer because the trunk is not a review branch.
refs contains {"name": columns[1], "age": to_number(columns[2])} if {
	some raw in recorded
	columns := split(raw, "\t")
	count(columns) == 3
	columns[0] == "ref"
	regex.match(data.batten.patterns["whole-number"], columns[2])
}

# A line the reader cannot parse is skipped rather than judged — the same posture
# every other record reader here takes, because the producer already refused a
# malformed line and anything unparseable at read time is a torn store.
on_remote contains entry.name if {
	some entry in refs
}

# `merged <name>` — one per merged pull request, so a name heading several
# appears several times and the cardinality is the reading.
merged_heads contains [index, columns[1]] if {
	some index, raw in recorded
	columns := split(raw, "\t")
	count(columns) == 2
	columns[0] == "merged"
}

merge_count(name) := count([pair | some pair in merged_heads; pair[1] == name])

violation contains {
	"rule": "branch-stale",
	"verdict": "branch watch stale",
	"subjects": [{"artifact": entry.name}, {"count": entry.age}],
} if {
	some entry in refs
	age := entry.age
	age > threshold
}

# THE SURVIVOR CONJUNCT IS THE WHOLE GATE. A merged pull request is immutable, so
# a name that headed two of them heads two of them forever; refusing on the count
# alone would be an alarm no action could clear, which is the shape that gets a
# gate switched off. Intersecting with what the remote still carries makes the
# remedy `git push --delete`.
violation contains {
	"rule": "branch-reused",
	"verdict": "branch name duplicate",
	"subjects": [{"artifact": reused}, {"count": merge_count(reused)}],
} if {
	some pair in merged_heads
	reused := pair[1]
	merge_count(reused) > 1
	count([name | some name in on_remote; name == reused]) > 0
}

# A PRESENT RECORD NAMING NO BRANCH IS A REFUSAL, never a clean board. The
# retired program said why: a remote reporting no branches at all "cannot be true
# of a repository with a trunk", so the honest reading is that the listing failed
# in a way that still exited zero. Absent is could-not-look; present-and-empty is
# a lie, and the two must not collapse.
violation contains {
	"rule": "branch-listing-empty",
	"verdict": "branch list empty",
} if {
	recorded
	count(refs) == 0
}

# --- cases ---------------------------------------------------------------

tree(lines) := {"tree": {"records": {"branch-age": lines}}}

test_a_branch_older_than_the_threshold_is_stale if {
	some v in violation with input as tree(["ref\tclaude/old\t9"])
	v.verdict == "branch watch stale"
}

# ONE BELOW THE THRESHOLD IS CLEAN, and an off-by-one here moves the whole
# population the rule fires on.
test_a_branch_at_the_threshold_is_not_stale if {
	count(violation) == 0 with input as tree(["ref\tclaude/fresh\t2"])
}

test_the_threshold_is_the_sources_couple_of_days if {
	count(violation) == 0 with input as tree(["ref\tclaude/fresh\t2"])
	some v in violation with input as tree(["ref\tclaude/old\t3"])
	v.verdict == "branch watch stale"
}

# POINTER, NEVER PAYLOAD: a branch NAME and a COUNT of days, which is what the
# remedy needs and nothing more.
test_the_finding_carries_a_name_and_a_count if {
	some v in violation with input as tree(["ref\tclaude/old\t9"])
	v.subjects == [{"artifact": "claude/old"}, {"count": 9}]
}

test_a_name_heading_two_merged_pull_requests_and_still_on_the_remote_is_reused if {
	some v in violation with input as tree([
		"ref\tclaude/reused\t1",
		"merged\tclaude/reused",
		"merged\tclaude/reused",
	])
	v.verdict == "branch name duplicate"
}

# THE CONJUNCT THAT KEEPS THIS CLEARABLE. Merged pull requests are immutable, so
# without the survivor test this fires forever on history nobody can change.
test_a_reused_name_whose_branch_is_gone_is_not_reported if {
	count(violation) == 0 with input as tree([
		"ref\tclaude/other\t1",
		"merged\tclaude/deleted",
		"merged\tclaude/deleted",
	])
}

test_a_name_heading_one_merged_pull_request_is_not_reused if {
	count(violation) == 0 with input as tree([
		"ref\tclaude/once\t1",
		"merged\tclaude/once",
	])
}

test_a_present_record_naming_no_branch_is_refused if {
	some v in violation with input as tree(["merged\tclaude/gone"])
	v.verdict == "branch list empty"
}

# COULD NOT LOOK IS NOT INNOCENCE, and it is not guilt either. The producer
# writes nothing when the forge is unreachable, and a module that refused there
# would refuse every checkout with no credential.
test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

# A SURVIVING GOOD LINE IS PART OF THE CASE, not scenery: without it the record
# holds no readable ref and `branch list empty` fires, which would let this case
# pass for a reason that has nothing to do with skipping.
test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as tree([
		"ref\tclaude/fresh\t1",
		"ref\tclaude/x\tnot-a-number",
		"nonsense",
	])
}

# No remote branch outlives its story (CLOUD-349, ported under CLOUD-1717, its
# producer retired into forge queries under CLOUD-843).
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
# THREE FAMILIES, EACH A `[[forge.query]]` ROW. `branch-heads` is the remote's
# branches and their tip shas; `branch-tips` is each distinct tip's commit with an
# `age` in UTC calendar days — the one number this module cannot compute, because
# `Fact::Instant` projects `null` here and the engine calls no clock on any
# evaluation path, so the producer measured it; `branch-merged` is recently closed
# pull requests with whether each merged. The join, the trunk exclusion and the
# threshold are the decisions, and they are here.
#
# COULD-NOT-LOOK IS AN ABSENT RECORD, and it is silence rather than a pass.
# `record query` removes a family it could not read, so every rule below needs all
# three present. A `branch-heads` family that is PRESENT and lists no branch at
# all is a different state: the producer looked and the remote reported none,
# which cannot be true of a repository with a trunk. That refusal is kept, because
# a silent pass there is the shape where the whole gate evaporates.
#MUTANT-SUITE crates/batten/tests/it/branch_age.rs
#MUTANT age-unread|s@^\tentry.age > threshold$@\tfalse@|a_recorded_branch_past_the_threshold_is_reported_through_the_engines_own_projection
#MUTANT reuse-needs-no-survivor|s@^\treused in on_remote$@\ttrue@|a_reused_name_still_on_the_remote_is_reported_and_one_already_deleted_is_not
#MUTANT empty-remote-passes|s@^\tcount(heads) == 0$@\tfalse@|a_present_record_naming_no_branch_is_refused_rather_than_read_as_clean
#MUTANT trunk-counted|s@^\tname != trunk$@\ttrue@|the_trunk_is_never_counted_however_old
#MUTANT merged-window-uncapped|s@^merged_window := 200$@merged_window := 100000@|only_the_two_hundred_most_recent_merged_pull_requests_are_counted
#MUTANT unmerged-takes-a-slot|s@^\tis_string(row.merged_at)$@\ttrue@|an_unmerged_pull_request_takes_no_slot_in_the_merged_window

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.branch_age

import rego.v1

rules contains "branch watch stale"

rules contains "branch name duplicate"

rules contains "branch list empty"

# The source's "a couple of days", as a number.
#
# In the module rather than in config, on `repetition-without-progress`'s
# reasoning one row over: this is the practice's own figure rather than this
# consumer's tuning, and a config knob would invite raising it until nothing
# fires. Moving it costs a diff a reviewer reads.
threshold := 2

# This repository's trunk, which is not a review branch and is never counted.
# A consumer fact, which is why this is a consumer module rather than a preset.
trunk := "main"

families := ["branch-heads", "branch-tips", "branch-merged"]

# All three families, or nothing is decided.
recorded if {
	is_object(input.tree.records)
	input.tree.records["branch-heads"]
	input.tree.records["branch-tips"]
	input.tree.records["branch-merged"]
}

# A family's rows, read only when it closed exactly once: `record query` writes a
# family whole or removes it, so a torn one contributes nothing rather than half.
rows(family) := [row |
	lines := input.tree.records[family]
	count([line | some line in lines; startswith(line, "window\t")]) == 1
	some line in lines
	startswith(line, "row\t")
	row := json.unmarshal(trim_prefix(line, "row\t"))
]

# Every branch the remote reported, the trunk included — what `branch list empty`
# counts.
heads contains row.name if {
	recorded
	some row in rows("branch-heads")
	is_string(row.name)
}

# The age the producer measured for each tip sha.
age_of := {row.tip: row.age |
	recorded
	some row in rows("branch-tips")
	is_number(row.age)
}

# `name` and `age` for every review branch whose tip was measured.
refs contains {"name": name, "age": age_of[row["commit.sha"]]} if {
	recorded
	some row in rows("branch-heads")
	name := row.name
	name != trunk
}

on_remote contains entry.name if {
	some entry in refs
}

# The population the retired body read: the 200 most recent MERGED pull
# requests (`gh pr list --state merged --limit 200`). The forge's pulls endpoint
# has no merged-only state, so `branch-merged` reads a wider window of closed
# ones, newest-created first, and the cap is taken HERE, after the unmerged rows
# are dropped — capping the closed rows instead would let every closed-unmerged
# pull request push a merge out of the window (CLOUD-843).
merged_window := 200

# The merged rows, in the order the forge listed them.
merged_rows := [row |
	recorded
	some row in rows("branch-merged")
	is_string(row.merged_at)
]

# One entry per MERGED pull request inside the window, so a name heading several
# appears several times and the cardinality is the reading.
merged_heads contains [index, row["head.ref"]] if {
	some index, row in array.slice(merged_rows, 0, merged_window)
	row["head.ref"] != trunk
}

merge_count(name) := count([pair | some pair in merged_heads; pair[1] == name])

violation contains {
	"rule": "branch watch stale",
	"verdict": "branch watch stale",
	"subjects": [{"artifact": entry.name}, {"count": entry.age}],
} if {
	some entry in refs
	entry.age > threshold
}

# THE SURVIVOR CONJUNCT IS THE WHOLE GATE. A merged pull request is immutable, so
# a name that headed two of them heads two of them forever; refusing on the count
# alone would be an alarm no action could clear, which is the shape that gets a
# gate switched off. Intersecting with what the remote still carries makes the
# remedy `git push --delete`.
violation contains {
	"rule": "branch name duplicate",
	"verdict": "branch name duplicate",
	"subjects": [{"artifact": reused}, {"count": merge_count(reused)}],
} if {
	some pair in merged_heads
	reused := pair[1]
	merge_count(reused) > 1
	reused in on_remote
}

# A PRESENT LISTING NAMING NO BRANCH IS A REFUSAL, never a clean board: a remote
# reporting no branches at all cannot be true of a repository with a trunk, so
# the honest reading is that the listing failed in a way that still answered.
violation contains {
	"rule": "branch list empty",
	"verdict": "branch list empty",
} if {
	recorded
	count(heads) == 0
}

# --- cases ---------------------------------------------------------------

closed := "window\tstate=whole\tread=0\tkept=0"

head(name, sha) := sprintf("row\t{\"commit.sha\":\"%s\",\"name\":\"%s\"}", [sha, name])

tip(sha, age) := sprintf("row\t{\"age\":%d,\"commit.committer.date\":\"2026-08-01T00:00:00Z\",\"tip\":\"%s\"}", [age, sha])

merged(name) := sprintf("row\t{\"head.ref\":\"%s\",\"merged_at\":\"2026-08-01T00:00:00Z\"}", [name])

unmerged(name) := sprintf("row\t{\"head.ref\":\"%s\",\"merged_at\":null}", [name])

tree(heads_rows, tips_rows, merged_rows) := {"tree": {"records": {
	"branch-heads": array.concat(heads_rows, [closed]),
	"branch-tips": array.concat(tips_rows, [closed]),
	"branch-merged": array.concat(merged_rows, [closed]),
}}}

one(name, age) := tree([head("main", "t0"), head(name, "a1")], [tip("t0", 0), tip("a1", age)], [])

test_a_branch_older_than_the_threshold_is_stale if {
	some v in violation with input as one("claude/old", 9)
	v.verdict == "branch watch stale"
}

# AT THE THRESHOLD IS CLEAN, and an off-by-one here moves the whole population
# the rule fires on.
test_a_branch_at_the_threshold_is_not_stale if {
	count(violation) == 0 with input as one("claude/fresh", 2)
}

test_the_threshold_is_the_sources_couple_of_days if {
	count(violation) == 0 with input as one("claude/fresh", 2)
	some v in violation with input as one("claude/old", 3)
	v.verdict == "branch watch stale"
}

# POINTER, NEVER PAYLOAD: a branch NAME and a COUNT of days.
test_the_finding_carries_a_name_and_a_count if {
	some v in violation with input as one("claude/old", 9)
	v.subjects == [{"artifact": "claude/old"}, {"count": 9}]
}

# THE TRUNK IS NOT A REVIEW BRANCH, however old it is.
test_the_trunk_is_never_counted_however_old if {
	count(violation) == 0 with input as tree([head("main", "t0")], [tip("t0", 400)], [])
}

# TWO BRANCHES AT ONE TIP share its age: the tips are fanned out by distinct sha.
test_two_branches_at_one_tip_share_its_age if {
	found := {v.subjects[0].artifact | some v in violation} with input as tree(
		[head("main", "t0"), head("claude/a", "s"), head("claude/b", "s")],
		[tip("t0", 0), tip("s", 5)],
		[],
	)
	found == {"claude/a", "claude/b"}
}

test_a_name_heading_two_merged_pull_requests_and_still_on_the_remote_is_reused if {
	some v in violation with input as tree(
		[head("main", "t0"), head("claude/reused", "r")],
		[tip("t0", 0), tip("r", 1)],
		[merged("claude/reused"), merged("claude/reused")],
	)
	v.verdict == "branch name duplicate"
}

# THE CONJUNCT THAT KEEPS THIS CLEARABLE.
test_a_reused_name_whose_branch_is_gone_is_not_reported if {
	count(violation) == 0 with input as tree(
		[head("main", "t0"), head("claude/other", "o")],
		[tip("t0", 0), tip("o", 1)],
		[merged("claude/deleted"), merged("claude/deleted")],
	)
}

# A CLOSED PULL REQUEST THAT DID NOT MERGE is not a merge.
test_a_closed_unmerged_pull_request_is_not_a_merge if {
	count(violation) == 0 with input as tree(
		[head("main", "t0"), head("claude/once", "c")],
		[tip("t0", 0), tip("c", 1)],
		[merged("claude/once"), unmerged("claude/once")],
	)
}

# THE RETIRED BODY'S 200: a reuse whose merges both fall past the 200 most recent
# merged pull requests is outside the population, exactly as `--limit 200` left it.
test_a_reuse_past_the_two_hundredth_merge_is_outside_the_window if {
	older := [merged(sprintf("claude/f%d", [i])) | some i in numbers.range(1, 200)]
	count(violation) == 0 with input as tree(
		[head("main", "t0"), head("claude/reused", "r")],
		[tip("t0", 0), tip("r", 1)],
		array.concat(older, [merged("claude/reused"), merged("claude/reused")]),
	)
}

# AND AN UNMERGED ONE TAKES NO SLOT: the cap counts merges, not closed rows.
test_unmerged_pull_requests_do_not_push_a_merge_out_of_the_window if {
	closed_only := [unmerged(sprintf("claude/u%d", [i])) | some i in numbers.range(1, 200)]
	some v in violation with input as tree(
		[head("main", "t0"), head("claude/reused", "r")],
		[tip("t0", 0), tip("r", 1)],
		array.concat(closed_only, [merged("claude/reused"), merged("claude/reused")]),
	)
	v.verdict == "branch name duplicate"
}

test_a_present_listing_naming_no_branch_is_refused if {
	some v in violation with input as tree([], [], [merged("claude/gone")])
	v.verdict == "branch list empty"
}

# COULD NOT LOOK IS NOT INNOCENCE, and it is not guilt either.
test_no_record_at_all_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
	count(violation) == 0 with input as {"tree": {"records": {"branch-heads": [closed]}}}
}

# A TORN FAMILY CONTRIBUTES NOTHING rather than half: a heads listing with no
# closing line reads as naming no branch.
test_a_torn_listing_is_not_read_as_a_partial_one if {
	torn := {"tree": {"records": {
		"branch-heads": [head("main", "t0"), head("claude/old", "o")],
		"branch-tips": [tip("t0", 0), tip("o", 9), closed],
		"branch-merged": [closed],
	}}}
	some v in violation with input as torn
	v.verdict == "branch list empty"
	not stale_reported(torn)
}

stale_reported(document) if {
	some v in violation with input as document
	v.verdict == "branch watch stale"
}

# The read-the-review gate (CLOUD-859), as a COUNT predicate over the one
# agent-sourced fact this repository declares.
#
# WHY IT IS WORTH REFUSING, measured rather than argued. Replayed over the 100
# most recently merged pull requests (2026-08-19 to 2026-08-22) this predicate
# fires on 89 — 21 carrying no review from anyone but their own author, 68
# carrying unresolved threads, 163 open threads across the fired set. Readying is
# the event that starts CI, and nothing in `land`'s pre-ready sequence asks about
# review, so an unreviewed head — or one carrying findings nobody answered —
# spends the matrix exactly as readily as a reviewed one. The worst instance is
# #617: reviewed at 15:39:44, merged twelve minutes later carrying three threads
# that are open to this day. Not an unreviewed merge, an unanswered one.
#
# THE COUNT IS THE PREDICATE, and that is a constraint rather than a shortcut.
# `facts::Sourced` stores `{command, seen_at, rows}` and no byte of the buffer —
# non-negotiable rule 4, structural rather than careful — so `reviews`,
# `latestReviews` and `reviewThreads` never reach Rego and a predicate over them
# is unwritable here. What reaches this module is HOW MANY elements the declared
# selection counted. CLOUD-859's §2 specifies a predicate over the payload; it is
# not implementable on this channel, and the row records the reformulation rather
# than this file re-arguing it.
#
# WHERE THE SELECTION LIVES MOVED, and the count's meaning moved with it
# (CLOUD-690). It was a `--jq` projection inside a declared shell command, one
# element per blocking condition. That command is refused 403 by the proxy fronting
# this container, so no record could ever be minted and the gate denied every `gh
# pr ready` — measured, and `land` merged #708 with no record in existence at all.
# The row now names a TOOL and the selection is `counts` + `where` + `blocking`:
# the review threads whose `is_resolved` is `false`, plus one for a page cap
# reached. `rows == 0` still means "every thread on this head is resolved and the
# page was complete".
#
# THE THIRD CONDITION BECAME A SECOND FACT, because it is a different collection.
# The projection also emitted the PR author's login when nothing but the author had
# reviewed — a comparison between two fields, which equality-to-a-literal cannot
# say. `review-happened` counts the reviews instead and `review-absent` below
# refuses on zero. What that does not catch is an author reviewing their own PR:
# deliberate forgery rather than the honest error this threat model names, and the
# same reasoning the fact channel's own forgery control rests on.
#
# WHICH IS ALSO WHY THE THREAD IDS ARE NOT A SUBJECT. §5 asks for them. They are
# not in the engine, so the refusal carries a `count` subject and its class points
# at the read that produces the ids. A subject claiming to name them would be a
# payload this channel refuses to carry, which is worse than the honest count.
#
# THE ABSENT RECORD IS NOT THIS MODULE'S, and the split is deliberate.
# `ready-needs-an-answered-review` is a `receipt` row over both facts: a never-ran
# record, and one minted by a call the declared selector does not name, are
# `Validity::Missing` there — the refusal that carries the remedy asking for the
# read. Deciding it here as well would be two rows refusing one call, and only the
# receipt row is handed the declaration.
#
# AN ABSENT REVIEW IS NOT THAT CASE, and the distinction is why `review-absent`
# below is this module's rather than the receipt row's. "No record" means nobody
# looked; "a record saying zero" means somebody looked and found no review. The
# receipt row cannot tell those apart — a count is not its object — and collapsing
# them would make an unreviewed head indistinguishable from an unread one.
#
# `--undo` IS NOT A READY. `land` re-drafts a PR on a red run, and that is the
# one thing that stops the next push buying another matrix. A predicate anchored
# on `gh pr ready` alone refuses the re-draft, which would leave the tap open on
# exactly the head this gate is trying to keep out of CI.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document. Binding it to the tree
#   schema would type check it against a shape the engine never hands it, which is
#   CLOUD-845's defect introduced on purpose rather than caught.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.review_answered

import rego.v1

rules contains "review-unanswered"

rules contains "review-absent"

# NO BATS SUITE, and that is CLOUD-1059's doing rather than a gap. The suite that
# drove this module end to end asserted the refusal's PROSE, which CLOUD-1050
# deletes; the migration gate refuses an authored Bats suite edited in place, so
# it retired into `crates/batten/tests/review_answered.rs`, which drives the same
# two hook calls over the compiled binary. `mutant` resolves a gate's suite by
# `tests/<gate>.bats`, so there is nothing for it to reach.
#MUTANT-SUITE crates/batten/tests/it/review_answered.rs
# THE CASE IS ONE THIS MODULE DECIDES, and the first spelling named one it does
# not. A ready with NO record at all is refused by the typed `receipt` rows in
# `batten.toml`, not here — both bodies below need a record to reach their
# count — so killing `readying` left that case green. Measured: it survived.
#MUTANT ready-unread|s@^\treadying$@\tfalse@|the_measured_shape_a_head_carrying_unresolved_threads_is_refused_naming_the_count
violation contains {
	"rule": "review-unanswered",
	"verdict": "V-REVIEW-UNANSWERED",
	"subjects": [{"count": record.rows}],
} if {
	readying
	record := input.facts["agent-sourced"]["review-threads-clear"]
	record.rows > 0
}

# THE INVERSE COMPARISON, and it is why this cannot share the class above. Every
# other predicate here refuses on a count being non-zero; this one refuses on a
# count being ZERO, because the collection it counts is reviews and none is the
# blocking state. A reader who saw one class covering both would have to hold two
# opposite readings of the same word.
#
# The subject is still the count, which is `0` in every firing and carries no
# information — kept because the ABI's shape is uniform and a refusal with an
# empty subject list reads as a refusal nobody could locate.
violation contains {
	"rule": "review-absent",
	"verdict": "V-REVIEW-ABSENT",
	"subjects": [{"count": record.rows}],
} if {
	readying
	record := input.facts["agent-sourced"]["review-happened"]
	record.rows == 0
}

# The cheap term first, for `run-shape.rego`'s measured reason: everything else
# here is computed only if a `ready` appears in the command at all.
#
# `contains` RATHER THAN AN ANCHOR, and this reversed twice before it was right.
#
# The draft before this one used `startswith(trim_space(...))`, on the reasoning
# that an anchor keeps PROSE out — a commit message naming `gh pr ready`, which
# this repository writes constantly, and which `run-shape.rego`'s header records
# as a real failure for its own predicate. That anchor was wrong twice over, both
# measured against the real binary rather than argued:
#
# 1. **It bought almost nothing, and the "almost" is measured too.** With only
#    `ready-needs-an-answered-review` declared,
#    `git commit -m "run gh pr ready once ... answered"` is ALLOWED even under
#    `contains`: a quoted span is scrubbed before the engine's `pattern` matcher
#    sees it, so the receipt row does not select that commit, no record is
#    projected, and this module decides nothing about it.
#
#    A HEREDOC IS NOT SCRUBBED, and that is the residue. `git commit -F - <<EOF`
#    over a message naming `gh pr ready` IS selected — measured the hard way, by
#    this gate refusing the commit that wrote this very comment. So prose is
#    excluded one layer up for the `-m` spelling and NOT for the heredoc
#    spelling, which is how this repository actually writes commit messages.
#    That is a defect in the receipt row's selection rather than in this
#    predicate — it fires there before any module runs, and `ready-needs-receipts`
#    on `main` has it today, unrelated to this branch — so it is CLOUD-1066's and
#    an anchor here would not have helped: the call never reaches this module.
#
# 2. **It opened a BYPASS.** `cd /repo && gh pr ready 702` does select the
#    receipt row, so an existing record satisfies the did-you-look half — and the
#    anchor then made this module silent, so the call was ALLOWED with two
#    unresolved threads recorded. Measured exactly that. The earlier comment here
#    called it "only the count half is missed", which was wrong: the count half
#    IS the gate, so missing it is the whole gate.
#
# So the anchor traded a hazard the engine already handles for a live hole. A
# substring over the command has no such hole, and the prose it would judge never
# arrives. CLOUD-199's lesson still applies and points the other way here: the
# false positive this was defending against does not exist, so paying a false
# negative for it was pure loss.
#
# The scrub `run-shape.rego` uses is the answer if prose ever DOES reach this
# module — which would mean the receipt row's `pattern` had been widened. That is
# a change somebody makes deliberately, and it is where the ~50 lines earn their
# place; until then copying them is one concept in two spellings.
readying if {
	contains(input.call.command, "ready")
	contains(input.call.command, "gh pr ready")
	not contains(input.call.command, "--undo")
}

# ---------------------------------------------------------------------------
# The predicate's own tests (CLOUD-835). LOAD-TIME tier only: what proves this
# gate decides is `crates/batten/tests/review_answered.rs`, which drives the binary
# over a real envelope AND a really-recorded fact, because a `with input as` case
# fabricates the very shape the engine may be unable to produce (CLOUD-845).
# ---------------------------------------------------------------------------

# `rows` values, not fixtures: each is a real reading from the row's own replay.
# 4 is #623's open-thread count, 3 is #617's, 7 is #613's.
test_a_head_with_open_threads_is_refused if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 623"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 4},
			"review-happened": {"rows": 1},
		}},
	}
	v.rule == "review-unanswered"
}

test_a_head_with_every_thread_answered_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 620"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 0},
			"review-happened": {"rows": 1},
		}},
	}
}

# THE VACUITY TWIN, #618's shape, and it is a SECOND FACT now. No threads and no
# review: the thread count is a genuine zero, so the predicate above is silent and
# what refuses is the review count. A gate carrying only the first predicate
# passes this head — the unreviewed one, and the worst to pass.
test_zero_threads_and_no_review_reads_as_unreviewed if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 618"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 0},
			"review-happened": {"rows": 0},
		}},
	}
	v.rule == "review-absent"
}

# THE DISCRIMINATING HALF, and without it the case above would pass over a
# predicate that refused every head (CLOUD-418). Identical thread count, one
# review instead of none.
test_one_review_on_a_clear_head_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 618"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 0},
			"review-happened": {"rows": 1},
		}},
	}
}

# BOTH PREDICATES CAN FIRE ON ONE HEAD, and a reader told only "answer the
# threads" on an unreviewed head goes looking for threads that do not exist. The
# set carries two; which of them the engine RENDERS on a mediated call is its own
# ranking, and `review_answered.rs` is where that is asserted.
test_a_head_failing_both_raises_both if {
	raised := {v.rule | some v in violation} with input as {
		"call": {"command": "gh pr ready 618"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 2},
			"review-happened": {"rows": 0},
		}},
	}
	raised == {"review-unanswered", "review-absent"}
}

# `land` re-drafts on a red run, and that is what closes the CI tap. Refusing it
# would leave the tap open on the very head this gate is keeping out of CI.
test_a_redraft_is_not_a_ready if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 623 --undo"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 4},
			"review-happened": {"rows": 1},
		}},
	}
}

test_another_gh_command_is_not_judged if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr view 623 --json reviewDecision"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 4},
			"review-happened": {"rows": 1},
		}},
	}
}

# AN UNREAD PAGE COUNTS, and the `blocking` column is what counts it. GitHub caps
# a connection page at 100, so an unresolved thread beyond the page would leave the
# element count at zero — a false green in the one direction this gate exists to
# prevent. Nothing about that is visible here, which sees only a count; this case
# pins that a guard-inflated count still refuses, so a future reader cannot
# "simplify" the column away as noise.
test_a_truncated_page_still_refuses_because_it_is_counted if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 705"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 1},
			"review-happened": {"rows": 1},
		}},
	}
	v.rule == "review-unanswered"
}

# A COMPOUND COMMAND IS STILL A READY, and this is the case that was missing when
# the anchor was here. `cd /repo && gh pr ready 702` selects the receipt row, so
# an existing record satisfies the did-you-look half — and under an anchor this
# module went silent, allowing the call with unresolved threads recorded. The
# count half IS the gate, so a spelling that skips it skips everything.
test_a_compound_command_is_still_a_ready if {
	some v in violation with input as {
		"call": {"command": "cd /repo && gh pr ready 702"},
		"facts": {"agent-sourced": {
			"review-threads-clear": {"rows": 2},
			"review-happened": {"rows": 1},
		}},
	}
	v.rule == "review-unanswered"
}

# NO PROSE CASE LIVES HERE, deliberately, and its absence is the honest reading.
# A `with input as` case can hand this module a record beside a commit message,
# which the ENGINE never does — the receipt row's anchored `pattern` does not
# select a commit, so no record is projected for one. Asserting prose is allowed
# here would therefore pin a property of a fabricated input rather than of the
# system, and the anchor it justified turned out to open a bypass. The real
# behaviour is asserted end to end in `tests/review-answered.bats`, over the
# binary, where the engine's own selection is what decides.

# An absent record is the receipt row's refusal, not this one's — so this module
# must be silent about it rather than adding a second message.
test_an_absent_record_is_the_receipt_rows_refusal if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 623"},
		"facts": {"agent-sourced": null},
	}
}

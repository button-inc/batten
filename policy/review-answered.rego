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
# is unwritable here. What reaches this module is HOW MANY rows the declared
# command's stdout carried. So the selection lives in the declared command's own
# `--jq` projection, one element per blocking condition, and `rows == 0` is
# exactly "reviewed and addressed". CLOUD-859's §2 specifies a predicate over the
# payload; it is not implementable on this channel, and the row records the
# reformulation rather than this file re-arguing it.
#
# WHICH IS ALSO WHY THE THREAD IDS ARE NOT IN THE MESSAGE. §5 asks for them. They
# are not in the engine, so the finding names the count and points at the command
# that produces the ids. A `msg` claiming to name them would be prose asserting a
# payload this channel refuses to carry, which is worse than the honest count.
#
# THE ABSENT RECORD IS NOT THIS MODULE'S, and the split is deliberate.
# `ready-needs-an-answered-review` is a `receipt` row over the same fact: a
# never-ran record, and one whose command does not match the declaration
# byte-for-byte, are `Validity::Missing` there — the deny that carries the
# `Fix::Run` asking for the command. Deciding it here as well would be two rows
# refusing one call with two messages, and only the receipt row's can name the
# command, because only it is handed the declaration.
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

# THE MUTATIONS, and each corrupts a conjunct no other conjunct already excludes
# — the discrimination `.claude/rules/policy-modules.md` records a survivor for,
# and the first draft of this block earned that warning twice. Field 3 is a bats
# `--filter` and must match a real case name: three descriptions that matched
# nothing all reported `case-already-red`, which is indistinguishable from a
# mutation nobody caught. `@` delimits each sed script because the rows are
# `|`-separated.
#
# TWO ROWS, NOT THREE, AND THE MISSING ONE IS THE INTERESTING PART. A
# `prose-judged` row corrupting the `startswith` anchor below was declared and
# SURVIVED, twice over: first as `command-not-anchored`, which named a case whose
# command carries no `ready` at all so the cheap conjunct excluded it, and then
# as a properly-named case that still could not see the change. The second
# survival is not a bad filter — it is a true statement about this module, and
# measured directly: the engine's `pattern` matcher is ANCHORED, so
# `ready-needs-an-answered-review` does not select
# `git commit -m "... gh pr ready ..."`, `agent_records` therefore projects no
# record for it, and `input.facts["agent-sourced"]` is null whatever this
# module's own narrowing says. No bats case can discriminate a conjunct the
# engine never gives an input reaching. So the row is deleted rather than
# retuned: a declared mutation that cannot be caught is a claim about coverage
# that is not true, which is what `mutant`'s own anti-vacuity terms exist to
# refuse. The anchor's discriminating case lives in the load-time tier below,
# where `with input as` CAN put a record beside a prose command.
#MUTANT count-not-decided|s@\trecord.rows > 0@\trecord.rows > 99999@|a head carrying unresolved threads is refused
#MUTANT redraft-judged|s@\tnot contains(input.call.command, "--undo")@\ttrue@|a re-draft is not a ready

violation contains {
	"rule": "review-unanswered",
	"msg": sprintf(
		"readying this PR would buy a CI matrix on a head carrying %d blocking review condition(s): an unresolved review thread, or no review from anyone but the author. Answer them first — resolve each thread, or force a review with `@coderabbitai full review`, which returns in ~3 minutes and costs no CI because the draft phase is the free phase — then re-run the declared command and retry. Replayed over the last 100 merges this fires on 89, so the common case is that there is something here to read. The thread ids are deliberately absent: the fact channel stores a COUNT and no byte of the buffer (non-negotiable rule 4), so the command that produced this number is also the only thing that can name them",
		[record.rows],
	),
} if {
	readying
	record := input.facts["agent-sourced"]["review-answered"]
	record.rows > 0
}

# The cheap term first, for `run-shape.rego`'s measured reason: everything else
# here is computed only if a `ready` appears in the command at all.
#
# `startswith` RATHER THAN `contains`, and it is DEFENCE IN DEPTH rather than the
# thing that keeps prose out. The distinction is measured, and the first version
# of this comment got it wrong in the flattering direction.
#
# The prose hazard is real in kind: this repository writes `gh pr ready` down
# constantly — in commit messages, in issue bodies, in this file — and
# `run-shape.rego`'s header records exactly this failure for its own predicate,
# answering it with a ~50-line heredoc-and-quote scrub. Copying that scrub here
# would be one concept in two spellings.
#
# But it is NOT reachable here, and the reason is one layer up. Probed directly
# against the real binary with only `ready-needs-an-answered-review` declared:
#
#     gh pr ready 702                                  -> deny
#     git commit -m "run gh pr ready once ... answered" -> allow
#
# The engine's `pattern` matcher is anchored rather than a substring, so that
# receipt row does not select the commit, `agent_records` projects no record for
# it, and `input.facts["agent-sourced"]` is null — this module decides nothing
# about prose whatever it says. So `startswith` buys one thing only: it keeps the
# module's correctness from DEPENDING on another row's pattern. Widen that
# `pattern` and a `contains` here would start judging commit messages; this does
# not. Cheap, and honest about being a second line rather than the first.
#
# THE FALSE NEGATIVE IT ACCEPTS, stated rather than absorbed: a compound
# `cd /repo && gh pr ready 702` is not judged HERE. The receipt row still selects
# it, so the did-you-look half holds and only the count half is missed. CLOUD-199
# is why that direction is the right one: a guard with false positives gets
# bypassed, and then it guards nothing at all.
readying if {
	contains(input.call.command, "ready")
	startswith(trim_space(input.call.command), "gh pr ready")
	not contains(input.call.command, "--undo")
}

# ---------------------------------------------------------------------------
# The predicate's own tests (CLOUD-835). LOAD-TIME tier only: what proves this
# gate decides is `tests/review-answered.bats`, which drives the compiled binary
# over a real envelope AND a really-recorded fact, because a `with input as` case
# fabricates the very shape the engine may be unable to produce (CLOUD-845).
# ---------------------------------------------------------------------------

# `rows` values, not fixtures: each is a real reading from the row's own replay.
# 4 is #623's open-thread count, 3 is #617's, 7 is #613's.
test_a_head_with_open_threads_is_refused if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 623"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 4}}},
	}
	v.rule == "review-unanswered"
}

test_a_head_with_every_thread_answered_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 620"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 0}}},
	}
}

# THE VACUITY TWIN, and the case the whole projection is shaped around. #618
# carries no threads and no review. A predicate that counted only threads would
# read that as zero and pass it as "all addressed"; the declared command emits the
# PR author's login when nothing but the author reviewed, so the honest reading is
# one row and a refusal.
test_zero_threads_and_no_review_reads_as_unreviewed if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 618"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 1}}},
	}
	v.rule == "review-unanswered"
}

# `land` re-drafts on a red run, and that is what closes the CI tap. Refusing it
# would leave the tap open on the very head this gate is keeping out of CI.
test_a_redraft_is_not_a_ready if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 623 --undo"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 4}}},
	}
}

test_another_gh_command_is_not_judged if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr view 623 --json reviewDecision"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 4}}},
	}
}

# THE PROSE CASE, and it is the one that discriminates the anchor. A `contains`
# over the raw string refuses this, and the message is a commit message rather
# than a call — the failure `run-shape.rego` records for its own predicate.
test_a_commit_message_naming_the_command_is_prose_not_a_ready if {
	count(violation) == 0 with input as {
		"call": {"command": "git commit -m \"run gh pr ready once the review is answered\""},
		"facts": {"agent-sourced": {"review-answered": {"rows": 4}}},
	}
}

# An absent record is the receipt row's refusal, not this one's — so this module
# must be silent about it rather than adding a second message.
test_an_absent_record_is_the_receipt_rows_refusal if {
	count(violation) == 0 with input as {
		"call": {"command": "gh pr ready 623"},
		"facts": {"agent-sourced": null},
	}
}

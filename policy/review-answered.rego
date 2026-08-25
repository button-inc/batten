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
# THE THIRD ROW TOOK THREE ATTEMPTS AND THE FIRST TWO ARE THE LESSON. It began as
# `command-not-anchored`, naming a case whose command carries no `ready` at all,
# so the cheap conjunct excluded the input and the mutation could not be seen. It
# was renamed to `prose-judged` — correctly named, and it SURVIVED anyway, because
# the engine never hands this module a prose command with a record beside it, so
# no bats case can discriminate that conjunct at all. Both survivals were true
# statements about the module rather than bad filters.
#
# What finally made it discriminating was deleting the conjunct. `compound-not-judged`
# reinstates the anchor those rows were defending, and the anchor is exactly what
# opened the bypass below — so the mutation now corrupts something a case CAN see:
# `cd /repo && gh pr ready` goes from refused to allowed. A mutation that cannot
# be caught is a coverage claim that is not true; a mutation that reintroduces a
# measured defect is the opposite.
#MUTANT compound-not-judged|s@\tcontains(input.call.command, "gh pr ready")@\tstartswith(trim_space(input.call.command), "gh pr ready")@|a compound command is still a ready
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

# AN UNREAD PAGE COUNTS. GitHub caps a connection page at 100, so the declared
# command emits an extra element when either connection reports `hasNextPage` —
# "I could not see all of it" has to refuse rather than pass, because an
# unresolved thread beyond the page would otherwise leave `rows == 0`, which is a
# false green in the one direction this gate exists to prevent. Nothing about that
# is visible to the module, which sees only a count; this case pins that a
# truncation-inflated count still refuses, so a future reader cannot "simplify"
# the projection's last two clauses away as noise.
test_a_truncated_page_still_refuses_because_it_is_counted if {
	some v in violation with input as {
		"call": {"command": "gh pr ready 705"},
		"facts": {"agent-sourced": {"review-answered": {"rows": 1}}},
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
		"facts": {"agent-sourced": {"review-answered": {"rows": 2}}},
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

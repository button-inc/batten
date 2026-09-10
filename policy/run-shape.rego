# A call whose SHAPE means it cannot do what it is written to do, as policy.
#
# Migrated from `mise-tasks/run-shape-guard` (CLOUD-843 track 2), one family at
# a time as each family's fact reaches the mediated-call document. Four
# predicates now, and what they share is the failure mode rather than the
# subject: each command runs, looks plausible, and cannot possibly achieve what
# it was written for.
#
#   commit-names-no-message-source  git opens $EDITOR and blocks — AFTER
#                                   `githooks(5)` has run `pre-commit` and spent
#                                   the whole gate (~4 minutes, CLOUD-488).
#   unsatisfiable-commit            `git commit -F -` with nothing redirected
#                                   into ITS OWN element reads the harness's
#                                   /dev/null. Same wasted gate, and the measured
#                                   shape is a heredoc binding to a LATER element
#                                   (CLOUD-613).
#   foreground-sleep                the harness kills a foreground call at ~2
#                                   minutes, so a patient poll FAILS rather than
#                                   waits (CLOUD-482, exit 143 and 144 measured).
#   background-timer                a backgrounded `sleep N; tail log` exits on
#                                   the clock, never on the event — and the
#                                   event already notifies (CLOUD-821: 490 such
#                                   calls in one session, 2 changed a decision).
#
# THE BASH IS GONE AND THIS MODULE IS SOLE AUTHORITY. `mise-tasks/run-shape-guard.sh`
# is retired, so the paragraph that used to stand here — both authorities decide
# these families, with one deliberate divergence in the denying direction — is no
# longer a description of the tree and has been removed rather than left reading
# as live. What it recorded that still matters: the guard's `resolve()` never
# reached a sleep inside a loop body (CLOUD-1112), so the whole family passed a
# looped sleep for want of a resolvable sleep rather than for any reason about
# waiting. Reaching the body was the precondition for CLOUD-1337 withdrawing the
# condition exemption; the mechanism is now the body arriving as its own segment
# (CLOUD-1381) rather than `keywords` stepping past a `do` token.
#
# TWO ERAS OF INPUT LIVE HERE, deliberately, and the newer one is the model.
# `commit-names-no-message-source` landed before `hook::segments` was projected,
# so it scrubs `input.call.command` by hand: a heredoc-body pass, two quoted-span
# passes, a list split and a pipe split, all in core builtins. The three
# predicates added by CLOUD-613 read `input.call.segments` instead, where the
# ENGINE has already done every one of those passes. Rewriting the first onto
# segments is a change to a landed verdict rather than an addition, so it is not
# folded in here — but no NEW predicate should copy the hand-rolled version, and
# `rules/policy-modules.md` says so with the parser's own reasons.
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
package batten.run_shape

import rego.v1

rules contains "commit-names-no-message-source"

rules contains "unsatisfiable-commit"

rules contains "foreground-sleep"

rules contains "background-timer"

rules contains "polls-a-local-process"

rules contains "foreground-mise"

rules contains "background-redirect"

# CLOUD-613's three, and none of them is over a program NAME — a mutation on the
# `sleep` or `git` token survives, because every ALLOW row already fails some
# other conjunct. Each of these corrupts the conjunct that carries the verdict.
#MUTANT redirect-binding-ignored|s@^	segment\["input-redirect"\] == false@	true@|a_redirect_bound_to_the_commits_own_element_is_a_message_source
#MUTANT background-not-consulted|s@^	input.call\["run-in-background"\] != true@	true@|a_backgrounded_bare_sleep_raises_only_the_timer
# The mutation restores the exemption this row removed: with the partition term
# forced false, a backgrounded `sleep` loop carrying a condition falls through
# `background-timer` exactly as it did before, and only a case asserting THAT
# shape is refused can see it. Every process-polling row still denies under it,
# via the sibling arm — which is what made the hole survive its own suite.
#MUTANT condition-is-an-exemption|s@^	count(process_probes) == 0@	false@|a_backgrounded_conditioned_sleep_loop_is_refused

# THE FOUR MUTATIONS, and the last three are the ones worth having: they corrupt
# the SCRUBBING and the SPLITTING rather than the flag table, which is where a
# raw-string module goes quietly wrong. `@` delimits each sed script because the
# rows themselves are `|`-separated.
#MUTANT message-flag-cluster-unreferenced|s@short-message-flag-cluster@zzz-no-such-pattern@|every_form_that_can_obtain_a_message_stays_allowed
#MUTANT list-not-split|s@^elements :=.*@elements := [scrubbed]@|a_compound_list_is_judged_per_element
#MUTANT heredoc-body-judged|s@	j < i@	j < -1@|a_git_commit_inside_a_heredoc_body_is_prose
#MUTANT double-quoted-span-judged|s@^scrubbed := quoted_out(single_scrubbed.*@scrubbed := single_scrubbed@|a_quoted_span_carrying_a_list_separator_is_not_a_list
#MUTANT-OWNER CLOUD-989|the mutation applies and alters reachable code, and the case it names cannot observe the change — a downstream guard or a second arm masks it. That is a defect in the DECLARATION, which `SURVIVED` mis-attributes to the suite; CLOUD-989's fork is what reports it correctly, and these are the live instances its own acceptance says it lacked
#MUTANT single-quoted-span-judged|s@^single_scrubbed := quoted_out(code_lines.*@single_scrubbed := code_lines@|a_git_commit_inside_a_quoted_span_is_prose
#MUTANT-SUITE crates/batten/tests/it/run_shape.rs
#MUTANT process-poll-unread|s@^\tcount(process_probes) > 0$@\tfalse@|a_backgrounded_wait_polling_a_process_is_refused
#MUTANT mise-background-unread|s@^\tinput.call\["run-in-background"\] != true$@\ttrue@|a_backgrounded_mise_run_is_allowed
#MUTANT redirect-background-unread|s@^\tinput.call\["run-in-background"\] == true$@\ttrue@|a_foreground_redirect_is_not_this_rule
#MUTANT task-output-poll-unread|s@^\tregex.match(data.batten.patterns\["harness-task-output"\], word)$@\tfalse@|a_backgrounded_wait_polling_a_task_output_file_is_refused
#MUTANT bracket-is-an-exit|s@^\tcondition_program(segment) in {"pgrep", "pkill", "ps", "jobs"}$@\tcondition_program(segment) in {"pgrep", "pkill", "ps", "jobs"}; not contains(segment.raw, "[")@|a_bracketed_pattern_is_refused_just_the_same

violation contains {
	"rule": "commit-names-no-message-source",
	"verdict": "commit write missing",
} if {
	# THE CHEAP TERM FIRST, and it is load-bearing rather than tidy. Everything
	# below — the heredoc scan, both quote passes, the list and pipe splits — is
	# computed only if this holds, and a command with no `commit` in it anywhere
	# cannot be a `git commit`. Measured 2026-08-21 on the wired path: without
	# it every mediated call pays the whole analysis, +1.9ms against a binary
	# that answers in 5.8ms.
	contains(input.call.command, "commit")
	some stage in stages
	git_commit(stage)
	not names_a_message_source(stage)
}

violation contains {
	"rule": "unsatisfiable-commit",
	"verdict": "commit bind missing",
} if {
	some segment in input.call.segments

	# `== false` RATHER THAN `not segment["input-redirect"]`, and the difference
	# is which way this fails. Rego reads an absent key as undefined and `not
	# undefined` HOLDS — so the negated spelling would deny every commit on any
	# engine that stopped emitting the field. The explicit comparison allows
	# there instead, which is the sanctioned direction (a miss under-denies).
	segment["input-redirect"] == false
	git_commit_words(segment.words)
	names_stdin_as_the_source(segment.words)
}

violation contains {
	"rule": "foreground-sleep",
	"verdict": "sleep run blocked",
} if {
	sleeps

	# `!= true` rather than `== false`, and this is the whole of the three-valued
	# read. `null` is "the host said nothing", most hosts say nothing, and the
	# shape refused here is a WAIT — whose posture being unknown is exactly the
	# case to be strict about. The bash spells it `[[ "$background" != true ]]`
	# and the two must not diverge while both are live.
	input.call["run-in-background"] != true
}

violation contains {
	"rule": "background-timer",
	"verdict": "timer run refused",
} if {
	sleeps
	input.call["run-in-background"] == true
	count(process_probes) == 0
}

# A backgrounded wait that polls the LOCAL PROCESS TABLE (CLOUD-1337).
#
# THE CONDITION EXEMPTION IS GONE, AND THIS ARM IS WHAT SURVIVES IT.
#
# `waits_on_condition` used to exempt a `sleep` loop from `background-timer`, on
# reasoning that reads well and does not hold: a loop testing a condition exits on
# the condition rather than on the clock, so a condition NOTHING ELSE REPORTS — a
# CI run, a remote queue, a file another machine writes — looked like a legitimate
# wait. It is not, and AGENTS.md says why in the same breath it bans timers: **the
# exit notification IS the wake-up**, a backgrounded task re-invokes its caller
# when it exits, and the turn in between is the designed state rather than one to
# fill. A hand-rolled poll over ANY condition duplicates a notification the
# harness already guarantees; `ci-wait` and `main-watch` exist for the two
# conditions that genuinely need a poll, and both are tasks that notify on exit.
#
# THE EXEMPTION ASKED WHETHER THERE WAS A CONDITION, NEVER WHAT IT WAS ABOUT, and
# `until` was the escape. AGENTS.md has carried the rule since CLOUD-821, with the
# measurement — "490 in one session, 2 changed a decision" — and the claim that
# the shape is "refused by `run-shape-guard`". With the exemption in place that
# sentence was false for every conditioned wait; `background-timer` now reaches
# them and it is true.
#
# MEASURED 2026-09-09, this session: `until grep -q '#' <file> && ! pgrep -f
# '<pat>'; do sleep 5; done` ran **3h34m**, spending a wake-up every five seconds
# while its own output had been read in the first minute. It was denied in the
# FOREGROUND and, once backgrounded, fell through every arm — the exemption held
# because the loop had a condition. Found by a human reading `ps`, which is the
# second time (CLOUD-1337 was the first).
#
# THIS ARM STAYS SEPARATE rather than collapsing into the wider one, because the
# count it carries is the diagnostic: a compound polling two processes is two
# duplications. The two arms PARTITION on `count(process_probes)`, so one call
# yields one finding.
#
# MEASURED 2026-09-02: eleven of these ran on one container, the oldest 9h35m,
# while exactly one real job existed.
#
# THE NARROWER RULE WAS DRAFTED FIRST AND WOULD HAVE MADE THIS WORSE, which is
# why the wider one is here. Those eleven were also BROKEN: `pgrep -f` reads full
# command lines, a mediated call runs as `bash -c '<the whole text>'`, so the
# pattern was a substring of the polling shell's own command line by construction
# and the probe matched itself forever. Refusing only that is satisfied by
# bracketing the pattern (`[m]ise`) — eleven correctly-functioning watchers
# instead of eleven broken ones, every one still redundant. The waste is the
# wait, not the typo, so a bracketed pattern is refused here too.
violation contains {
	"rule": "polls-a-local-process",
	"verdict": "task watch duplicate",
	"subjects": [{"count": count(process_probes)}],
} if {
	sleeps
	input.call["run-in-background"] == true
	count(process_probes) > 0
}

# EVERY `mise` CALL IS BACKGROUNDED, WITH NO EXEMPTION LIST.
#
# AGENTS.md has carried the rule as a duration — "any command that can exceed ~2
# minutes" — and a duration is a prediction the caller makes about a task it has
# not run. The prediction is wrong in the direction that costs: a foreground call
# is KILLED at ~2 minutes rather than run slowly, so the mis-estimate does not
# cost the difference between the guess and the truth, it costs the whole run
# plus the turn. And on this repo the estimate is over `mise`, whose tasks are
# the gate itself: `verify`, `ci`, `land`, a cold `cargo` build behind any of
# them.
#
# NO CARVE-OUT FOR THE FAST TASKS, deliberately, and `alive` is the one worth
# naming since it is the prescribed liveness probe. Backgrounding it costs one
# turn and returns the same text; a carve-out costs a list that every new task
# has to be judged against, by the same caller whose judgement this rule exists
# to stop consulting. A predicate with no list cannot be argued with, which is
# the property (house style §5).
violation contains {
	"rule": "foreground-mise",
	"verdict": "task run blocked",
} if {
	some program in input.call.programs
	basename(program.program) == "mise"

	# `!= true` for the same three-valued read `foreground-sleep` takes: `null`
	# is "the host said nothing", and an unknown posture over a call that can
	# spend the whole turn is the case to be strict about.
	input.call["run-in-background"] != true
}

# A BACKGROUNDED CALL THAT REDIRECTS ITS OWN OUTPUT WRITES WHERE NOBODY READS.
#
# The harness already captures a backgrounded task's output to a file it names
# back to the caller AND surfaces where the HUMAN watches. A `> log 2>&1` inside
# the command substitutes a second, private file for that one: the notification
# still fires, the output pane is empty, and the human loses the run they were
# meant to be able to see over.
#
# It is also how a verdict gets discarded. `mise run ci > log 2>&1` under a shell
# that is later piped or chained hands the exit status to the redirect's own
# element, which is the `verdict-not-discarded` family in a new spelling.
#
# JUDGED ON THE REDIRECTION TOKENS, which the segment carries as words of its own
# — `>` and its target are two words, `2>&1` is one (CLOUD-1382's parse). An
# INPUT redirect is untouched: reading a file into a backgrounded command
# discards nothing.
violation contains {
	"rule": "background-redirect",
	"verdict": "redirect write unread",
} if {
	input.call["run-in-background"] == true
	some segment in input.call.segments
	some word in segment.words
	output_redirect(word)
}

output_redirect(word) if word in {">", ">>", "&>", "&>>", "2>", "2>>", "2>&1", ">&2", "1>", "1>>"}

# ---------------------------------------------------------------------------
# CLOUD-613's terms, over `input.call.segments`.
#
# The engine has already resolved quoting and DROPPED heredoc bodies by the time
# these read a segment, so none of the scrubbing below is repeated here — a
# `sleep` written inside a commit message or a documentation paragraph is not a
# word of any segment. That is the parser change this row landed, and it is why
# these three are four lines each where the predicate above is sixty.
# ---------------------------------------------------------------------------

# Judged per SEGMENT, so a sleep anywhere in a compound is caught rather than
# only a leading one — `cd x; sleep 90; git log` is the exact measured shape.
#
# A SLEEP IN A LOOP BODY IS REACHED HERE, and the bash it ports does not reach
# it: the boundary gives a loop body its own segment, whose program is the
# `sleep` itself, and `resolve()` walks a string with no notion of a body
# (CLOUD-1112, mechanism updated by CLOUD-1381 — this used to depend on
# `keywords` stepping past a `do` token, which no longer arrives). That is the
# one place these two authorities deliberately
# disagree while both are live, and it is in the DENYING direction — the engine
# refuses a foreground loop the guard allows, so no call gets a weaker answer
# than it did before.
sleeps if {
	some segment in input.call.segments
	basename(segment.words[words_program_index(segment.words)]) == "sleep"
}

# Every reader of the LOCAL process table in this call.
#
# The set is the programs whose whole purpose is answering "is this process still
# alive" — the question the exit notification already answers. `kill -0` is that
# same question spelled as a signal, which is why it is here rather than being
# left out as "not a process lister".
#
# NEVER A PATTERN AND NEVER A PID (non-negotiable rule 4): a probe's operand on
# this surface carries this consumer's task names and paths. The COUNT travels and
# the text does not, which is also why the finding cannot name which wait it was.
#
# Indexed by SEGMENT so two probes in one call count twice — a compound that polls
# a process and then polls another is two duplications, not one.
process_probes contains i if {
	some i, segment in input.call.segments
	condition_program(segment) in {"pgrep", "pkill", "ps", "jobs"}
}

# `kill -0 <pid>` is a liveness test rather than a signal, and it is the spelling
# a caller reaches for once `pgrep` is refused.
process_probes contains i if {
	some i, segment in input.call.segments
	condition_program(segment) == "kill"
	some word in segment.words
	word == "-0"
}

# THE SAME DUPLICATE, READ OFF THE TASK'S OUTPUT FILE INSTEAD OF THE PROCESS
# TABLE (CLOUD-1730). The two arms above ask WHICH PROGRAM the condition runs,
# and that is the wrong half of the question: `pgrep` and `grep -q MARKER
# <task output>` wait on one event — a harness-tracked task exiting — which
# re-invokes the caller whether or not anybody polls. Nothing about which syscall
# observes it changes that the notification is guaranteed.
#
# CLOUD-1337 closed `until` + `ps` and left `until` + `grep`, and the survivor is
# the DEFAULT rather than a corner: the harness's own tooling documents
# `until <condition>; do sleep; done` as the way to wait, and the natural
# condition for "did my backgrounded task finish" is a marker in the file that
# task writes. Reaching for `ps` takes a deliberate detour. Measured 2026-09-09
# on CLOUD-1704's branch: over twenty such watchers in one session, every result
# delivered twice, none changing a decision — against a `PreToolUse` registration
# that was wired, was asked, and answered allow.
#
# SO THIS ARM ASKS ABOUT THE TARGET AND NEVER THE PROGRAM, which is what makes it
# hold against the next spelling. `grep`, `rg`, `awk`, `test -s` and `[ -s ]` all
# reach the same file, and enumerating them would re-run CLOUD-1337's own
# recorded lesson that a narrow draft "would have made this worse".
#
# `waits_on_condition` SURVIVES UNTOUCHED, and must: a loop over a CI run, a
# remote queue or a file another machine writes exits on an event nothing else
# reports, and that is the shape the exemption exists to permit. What is refused
# here is narrower — a condition naming a path this consumer declares as its
# harness's task-output surface, which by construction is a notification the
# caller already gets.
process_probes contains i if {
	some i, segment in input.call.segments
	segment.construct.kind in {"until", "while"}
	some word in segment.words
	regex.match(data.batten.patterns["harness-task-output"], word)
}

# The program a LOOP CONDITION segment invokes.
#
# **The keyword filter this used to carry is gone, and its absence is the point**
# (CLOUD-1381). A condition segment used to begin with `until` or `while`, often
# with a `!` after, so this had to strip those three tokens before
# `words_program_index` could resolve anything -- and it stripped them ANYWHERE
# rather than in a leading run, which was safe only because none of the three is
# a plausible operand of a process probe. That was a workaround for a token
# stream that did not know what a loop was.
#
# A condition is its own segment now, carrying only the test's own words. There
# is nothing to filter, and the rule selects the segments it is about instead of
# every segment that happens to lack a keyword.
#
# **KIND, NOT ROLE, AND NARROWING TO `role == "condition"` WAS A MEASURED
# BYPASS.** The probe does not have to be in the test: a loop can poll from its
# BODY and break, which is the same wait spelled one line down. Before the
# construct projection this rule ran over every segment and `keywords` stepped
# past `do`, so a body probe resolved; keying on the role lost it. Measured over
# both compiled binaries, backgrounded --
# `while true; do pgrep -f mise >/dev/null || break; sleep 20; done` and
# `while :; do sleep 20; pgrep -f mise; done` were exit 2 `task watch duplicate`
# before and exit 0 after. Moving the probe from the condition to the body was a
# one-edit bypass of the gate AGENTS.md cites the "490 in one session"
# measurement for, and the nested spelling still denied, which is what would
# have kept it hidden.
#
# So the selector is the loop NODE, either half of it. `for` stays excluded
# because it is a different kind, which is the narrowing that was actually
# wanted.
condition_program(segment) := name if {
	segment.construct.kind in {"until", "while"}
	name := basename(segment.words[words_program_index(segment.words)])
}

# `git commit`, resolved over WORDS the engine split rather than a string this
# module splits. Same rule as `git_commit` above and deliberately not shared with
# it: that one takes a stage string, and one function taking either would be a
# second parser wearing a signature.
#
# `git -C <path> commit` resolves to the path and is NOT caught, which is the
# same deliberate false negative the bash carries — this repository commits from
# its own root, and a migration that silently fixed it would be changing the
# predicate rather than moving it.
git_commit_words(words) if {
	idx := words_program_index(words)
	basename(words[idx]) == "git"
	subcommands := [w |
		some i, w in words
		i > idx
		not startswith(w, "-")
		not contains(w, ">")
		not contains(w, "<")
	]
	subcommands[0] == "commit"
}

words_program_index(words) := idx if {
	candidates := [i |
		some i, w in words
		not skippable(w)
	]
	idx := candidates[0]
}

# Does this segment tell git to read the message from STDIN? `-F -`, a cluster
# ending in F followed by `-`, `--file -`, or `--file=-`.
#
# The adjacency is the predicate: `-F` alone names a FILE and is fine, and it is
# only the `-` operand that makes stdin the source. `words[i + 1]` is undefined
# past the end, which Rego reads as *does not hold* — so a trailing `-F` allows.
names_stdin_as_the_source(words) if {
	some i, w in words
	regex.match(data.batten.patterns["commit-message-file-flag"], w)
	words[i + 1] == "-"
}

names_stdin_as_the_source(words) if {
	some w in words
	w == "--file=-"
}

# ---------------------------------------------------------------------------
# Scrubbing: heredoc bodies, then quoted spans. Same order as the bash.
#
# EVERYTHING FROM HERE DOWN SERVES `commit-names-no-message-source` ALONE, and
# is the pre-`segments` era described in this file's header. Do not extend it.
# ---------------------------------------------------------------------------

lines := split(input.call.command, "\n")

# Every heredoc opener's line index, mapped to its delimiter word. `<<<` is a
# here-string: it opens no body.
openers[i] := delim if {
	some i, line in lines
	idx := indexof(line, "<<")
	idx >= 0
	substring(line, idx + 2, 1) != "<"
	rest := trim_left(substring(line, idx + 2, -1), "-")
	delim := trim(first_word(rest), "'\"")
	delim != ""
}

default first_word(_) := ""

first_word(s) := w if {
	parts := [p | some p in split(trim_space(s), " "); p != ""]
	w := parts[0]
}

# A line is body text while some opener above it is still unclosed. The
# delimiter line itself reads as closed and survives as the bare word it is —
# harmless, and it keeps this a comprehension rather than the fold Rego has no
# spelling for.
body contains i if {
	some i, _ in lines
	some j, delim in openers
	j < i
	not closed_between(j, i, delim)
}

closed_between(j, i, delim) if {
	some k in numbers.range(j + 1, i)
	trim_space(lines[k]) == delim
}

# Named in two steps rather than nested, so each pass can be corrupted on its
# own: nesting them made the only available mutation empty the whole string,
# which every ALLOW row survives — a mutation that cannot discriminate, in the
# task that exists to refuse exactly that (CLOUD-418).
code_lines := concat("\n", [line |
	some i, line in lines
	not body[i]
])

single_scrubbed := quoted_out(code_lines, "'")

scrubbed := quoted_out(single_scrubbed, "\"")

# Every quoted span becomes one opaque token. Splitting on the quote character
# alternates outside/inside spans, so the even-indexed pieces ARE the code and
# the separator stands in for what was quoted — which is what keeps `a"x"b`
# three tokens rather than one.
quoted_out(s, q) := concat("QUOTED", [part |
	some i, part in split(s, q)
	i % 2 == 0
])

# ---------------------------------------------------------------------------
# The list, its elements, and their pipe stages.
# ---------------------------------------------------------------------------

elements := split(replace(replace(replace(scrubbed, "||", "\n"), "&&", "\n"), ";", "\n"), "\n")

stages := [s |
	some e in elements
	some s in split(e, "|")
]

# ---------------------------------------------------------------------------
# Which program a stage actually runs.
# ---------------------------------------------------------------------------

wrappers := {"env", "command", "nice", "stdbuf", "timeout", "xargs", "sudo", "doas", "nohup", "mise", "exec", "x"}

# SHELL KEYWORDS THAT INTRODUCE A COMMAND, looked through for the same reason
# every wrapper above is: what runs after them is the call being judged.
#
# The retired bash guard's `resolve()` had no such set, and CLOUD-1112 measured
# what that costs: `do sleep 1` resolved to the program `do`, so a sleep in a
# loop body was invisible and the whole family passed a looped sleep for want of
# a resolvable sleep rather than for any reason about waiting. That is why the
# withdrawal of the condition exemption (CLOUD-1337) needed the look-through
# first: without it there would be nothing for the arms below to refuse.
#
# **VESTIGIAL SINCE CLOUD-1381, and said so rather than left reading as live.**
# The engine emits none of these as words any more: each is a NODE, and a
# control-flow body is its own segment tagged with the node it sits in. So this
# look-through skips tokens that no longer arrive, and `sleeps` reaches a loop
# body because the body is a segment rather than because `do` was stepped past.
#
# Kept rather than deleted because `skippable` serves the `stage` path too, which
# reads a pipeline STRING and can still carry these; deleting the set would be a
# behaviour change on a surface this row did not touch. Retiring it belongs with
# whatever retires that path.
#
# The sentence that stood here — that `until`/`while`/`if`/`for` are absent
# because "`waits_on_condition` reads them as words" — was true of the character
# walk and is false now. That rule reads `segment.construct.kind`, and no reading
# of a parse produces those words at all.
keywords := {"do", "then", "else", "elif", "time"}

tokens(stage) := [t | some t in split(trim_space(stage), " "); t != ""]

# The index the program sits at: the first token that is not something a
# wrapper prefix is made of. `echo git commit` therefore does not resolve to
# git, which is the anchoring that stops an unquoted mention reading as a call —
# and `sudo -u root git commit` resolves to `root` and is left alone, the same
# false negative the bash carries, because a wrapper's non-flag argument is
# where its look-through stops.
program_index(stage) := idx if {
	toks := tokens(stage)
	candidates := [i |
		some i, t in toks
		not skippable(t)
	]
	idx := candidates[0]
}

skippable(tok) if {
	some answer in [
		tok in wrappers,
		tok in keywords,
		startswith(tok, "-"),
		contains(tok, "="),
		contains(tok, "@"),
		substring(tok, 0, 1) in {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"},
	]
	answer
}

basename(tok) := b if {
	parts := split(tok, "/")
	b := parts[count(parts) - 1]
}

git_commit(stage) if {
	toks := tokens(stage)
	idx := program_index(stage)
	basename(toks[idx]) == "git"
	words := [w |
		some i, w in toks
		i > idx
		not startswith(w, "-")
		not contains(w, ">")
		not contains(w, "<")
	]
	words[0] == "commit"
}

# ---------------------------------------------------------------------------
# Does this stage name somewhere for git to read a message from?
# ---------------------------------------------------------------------------

long_flags := {"--message", "--file", "--reuse-message", "--reedit-message", "--no-edit", "--fixup", "--squash"}

names_a_message_source(stage) if {
	some t in tokens(stage)
	some flag in long_flags
	startswith(t, flag)
}

# A short cluster — `-m`, `-am`, `-F`, `-C`, `-c`: one `-`, then letters, at
# least one of which selects a message source.
#
# `regex.match` RATHER THAN `contains`, and the difference is a verdict rather
# than a spelling (CLOUD-885). The predicate is "a cluster of LETTERS, one of
# which is a message flag", and `contains` over the tail cannot say "letters":
# `-x=mfoo` carries an `m` and read as naming a message source, so a commit that
# will still block on $EDITOR was allowed through. The anchored class is the
# predicate the comment above already claimed.
names_a_message_source(stage) if {
	some t in tokens(stage)
	regex.match(data.batten.patterns["short-message-flag-cluster"], t)
}

# ---------------------------------------------------------------------------
# The predicate's own tests (CLOUD-835). They are the LOAD-TIME half only: what
# proves this gate decides is `tests/run-shape.bats`, which drives the compiled
# binary over a real envelope, because a `with input as` fabricates its own
# input and can be green over a shape the engine never produces (CLOUD-845).
# ---------------------------------------------------------------------------

test_a_commit_with_no_message_source_is_refused if {
	some v in violation with input as {"call": {"command": "git commit"}}
	v.rule == "commit-names-no-message-source"
}

test_a_commit_that_names_one_is_left_alone if {
	count(violation) == 0 with input as {"call": {"command": "git commit -m x"}}
}

test_a_later_element_is_judged_too if {
	some v in violation with input as {"call": {"command": "cd /tmp && git commit"}}
	v.rule == "commit-names-no-message-source"
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"command": "hg commit"}}
}

test_a_short_cluster_names_a_message_source if {
	count(violation) == 0 with input as {"call": {"command": "git commit -am x"}}
}

# THE DISCRIMINATING CASE for the `regex.match` above (CLOUD-885). `-x=mfoo` is
# not a flag cluster — it carries an `m`, which is all the previous `contains`
# over the tail could see, so a commit that still blocks on $EDITOR was allowed.
# A test that only covered `-m` and `-am` passes under both spellings and proves
# nothing about the change.
test_a_non_cluster_carrying_m_is_not_a_message_source if {
	some v in violation with input as {"call": {"command": "git commit -x=mfoo"}}
	v.rule == "commit-names-no-message-source"
}

# ---------------------------------------------------------------------------
# CLOUD-613's three. Every case carries a `command` as well as `segments`,
# because the first predicate reads the string and would otherwise fire on an
# undefined path and take these cases with it.
# ---------------------------------------------------------------------------

seg(words, terminator, redirect) := {
	"words": words,
	"raw": concat(" ", words),
	"terminator": terminator,
	"input-redirect": redirect,
	"construct": null,
}

# A segment INSIDE a control-flow node, as the engine now projects one
# (CLOUD-1381).
#
# **The keyword is not in `words` here, and that is the whole shape change.** A
# fixture that still wrote `["until", "[", "-f", "x", "]"]` would be encoding a
# token stream the engine cannot produce -- `until` is the NODE, and the
# condition segment carries only the test's own words. Two tiers exist precisely
# because a `with input as` case can fabricate that; the compiled tier in
# `crates/batten/tests/it/run_shape.rs` is what proves these shapes are the ones
# the boundary actually builds.
inner(words, kind, role, terminator) := {
	"words": words,
	"raw": concat(" ", words),
	"terminator": terminator,
	"input-redirect": false,
	"construct": {"kind": kind, "role": role},
}

# THE MEASURED SHAPE (CLOUD-488): the heredoc binds to the LAST element, so
# `land` gets the message and git gets /dev/null.
test_a_commit_whose_heredoc_binds_to_a_later_element_is_refused if {
	some v in violation with input as {"call": {
		"command": "git commit -F - && mise run land <<'EOF'",
		"run-in-background": null,
		"segments": [
			seg(["git", "commit", "-F", "-"], "&&", false),
			seg(["mise", "run", "land", "<<'EOF'"], null, true),
		],
	}}
	v.rule == "unsatisfiable-commit"
}

# THE DISCRIMINATING ALLOW, and it is the same two words in the same order —
# only the BINDING differs. A predicate reading the command string sees one
# string for both of these.
test_a_heredoc_bound_to_this_element_is_a_message_source if {
	count(violation) == 0 with input as {"call": {
		"command": "git commit -F - <<'EOF'",
		"run-in-background": null,
		"segments": [seg(["git", "commit", "-F", "-", "<<'EOF'"], null, true)],
	}}
}

test_a_file_redirect_is_a_message_source_too if {
	count(violation) == 0 with input as {"call": {
		"command": "git commit -F - < msg.txt",
		"run-in-background": null,
		"segments": [seg(["git", "commit", "-F", "-", "<", "msg.txt"], null, true)],
	}}
}

# `-F` naming a FILE is not stdin at all: the `-` operand is the predicate.
test_a_commit_reading_a_named_file_is_untouched if {
	count(violation) == 0 with input as {"call": {
		"command": "git commit -F /tmp/msg.txt",
		"run-in-background": null,
		"segments": [seg(["git", "commit", "-F", "/tmp/msg.txt"], null, false)],
	}}
}

test_the_long_flag_spelling_is_judged_too if {
	some v in violation with input as {"call": {
		"command": "git commit --file=-",
		"run-in-background": null,
		"segments": [seg(["git", "commit", "--file=-"], null, false)],
	}}
	v.rule == "unsatisfiable-commit"
}

test_a_foreground_sleep_is_refused if {
	some v in violation with input as {"call": {
		"command": "sleep 90",
		"run-in-background": null,
		"segments": [seg(["sleep", "90"], null, false)],
	}}
	v.rule == "foreground-sleep"
}

test_a_sleep_in_a_later_segment_is_refused_too if {
	some v in violation with input as {"call": {
		"command": "cd /tmp; sleep 90; git log",
		"run-in-background": false,
		"segments": [
			seg(["cd", "/tmp"], ";", false),
			seg(["sleep", "90"], ";", false),
			seg(["git", "log"], null, false),
		],
	}}
	v.rule == "foreground-sleep"
}

test_a_backgrounded_bare_sleep_is_a_timer if {
	some v in violation with input as {"call": {
		"command": "sleep 590; tail -6 land.log",
		"run-in-background": true,
		"segments": [
			seg(["sleep", "590"], ";", false),
			seg(["tail", "-6", "land.log"], null, false),
		],
	}}
	v.rule == "background-timer"
}

# THE ALLOW THAT MATTERS. This is the form both refusals recommend, and denying
# it is what would get the rule switched off.
# THE MEASURED SHAPE (CLOUD-1337). A backgrounded wait polling the process table
# is refused, because the harness already reports that exit. Eleven of these ran
# on one container, the oldest 9h35m.
test_a_backgrounded_wait_polling_a_process_is_refused if {
	some v in violation with input as {"call": {
		"command": "until ! pgrep -f mise >/dev/null; do sleep 20; done",
		"run-in-background": true,
		"segments": [
			inner(["pgrep", "-f", "mise"], "until", "condition", ";"),
			inner(["sleep", "20"], "until", "body", null),
		],
	}}
	v.verdict == "task watch duplicate"
}

# THE CASE THAT SEPARATES THIS RULE FROM THE WRONG ONE. Those eleven were also
# self-matching, and the fix for a self-match is to bracket the pattern. If that
# were an exit from this gate, the remedy would buy eleven WORKING watchers and no
# less waste. The wait is the defect, so a bracketed pattern is refused too.
test_a_bracketed_pattern_is_refused_just_the_same if {
	some v in violation with input as {"call": {
		"command": "until ! pgrep -f [m]ise >/dev/null; do sleep 20; done",
		"run-in-background": true,
		"segments": [
			inner(["pgrep", "-f", "[m]ise"], "until", "condition", ";"),
			inner(["sleep", "20"], "until", "body", null),
		],
	}}
	v.verdict == "task watch duplicate"
}

# `kill -0` is the same liveness question spelled as a signal, and it is the
# spelling a caller reaches for once `pgrep` is refused.
test_a_liveness_signal_is_the_same_question if {
	some v in violation with input as {"call": {
		"command": "while kill -0 $PID 2>/dev/null; do sleep 5; done",
		"run-in-background": true,
		"segments": [
			inner(["kill", "-0", "$PID"], "while", "condition", ";"),
			inner(["sleep", "5"], "while", "body", null),
		],
	}}
	v.verdict == "task watch duplicate"
}

# THE PARTITION'S OTHER SIDE, and it used to be this family's anti-vacuity
# mirror: a condition the harness does not report — a remote readiness probe
# rather than a local process — was the one wait left allowed. CLOUD-1337 removed
# that allow, so what this case now pins is narrower and still worth pinning: the
# two arms must not BOTH fire, and the one that answers a non-process condition
# must be `background-timer` rather than `polls-a-local-process`. A rule that
# refused every wait under one verdict would fail this.
test_a_wait_on_a_condition_nobody_reports_is_a_timer_not_a_poll if {
	count(violation) == 1 with input as {"call": {
		"command": "until curl -sf https://example.test/ready; do sleep 5; done",
		"run-in-background": true,
		"segments": [
			inner(["curl", "-sf", "https://example.test/ready"], "until", "condition", ";"),
			inner(["sleep", "5"], "until", "body", null),
		],
	}}
	some v in violation with input as {"call": {
		"command": "until curl -sf https://example.test/ready; do sleep 5; done",
		"run-in-background": true,
		"segments": [
			inner(["curl", "-sf", "https://example.test/ready"], "until", "condition", ";"),
			inner(["sleep", "5"], "until", "body", null),
		],
	}}
	v.rule == "background-timer"
}

# A PROCESS READ WITH NO LOOP IS NOT A WAIT. `mise run alive` asks once and
# returns, which is the route this class recommends — refusing it would refuse
# its own remedy.
test_a_process_read_outside_a_loop_is_not_a_wait if {
	count(violation) == 0 with input as {"call": {
		"command": "pgrep -f mise",
		"run-in-background": true,
		"segments": [seg(["pgrep", "-f", "mise"], null, false)],
	}}
}

# THE WITHDRAWN EXEMPTION (CLOUD-1337). This case asserted `count(violation) ==
# 0` for as long as the condition was an exemption. It is inverted rather than
# deleted, because a deleted case documents nothing and this is the exact shape
# the rule now exists to catch: the condition makes the loop exit on the thing
# rather than on the clock, and does not make it stop being a hand-rolled copy of
# a notification the runtime already delivers.
test_a_backgrounded_wait_on_a_condition_is_refused if {
	some v in violation with input as {"call": {
		"command": "until [ -f /tmp/done ]; do sleep 1; done",
		"run-in-background": true,
		"segments": [
			inner(["[", "-f", "/tmp/done", "]"], "until", "condition", ";"),
			inner(["sleep", "1"], "until", "body", null),
		],
	}}
	v.rule == "background-timer"
}

# A FOREGROUND loop spends the turn exactly as a foreground `sleep` does, and it
# is refused for that reason. Reaching it needed `keywords` when a loop body
# arrived as `do sleep 1` and resolved to `do` (CLOUD-1112); since CLOUD-1381 the
# body is its own segment carrying `sleep` as its program, so it is reached
# structurally and the look-through decides nothing here.
test_a_foreground_wait_on_a_condition_is_refused if {
	some v in violation with input as {"call": {
		"command": "until [ -f /tmp/done ]; do sleep 1; done",
		"run-in-background": false,
		"segments": [
			inner(["[", "-f", "/tmp/done", "]"], "until", "condition", ";"),
			inner(["sleep", "1"], "until", "body", null),
		],
	}}
	v.rule == "foreground-sleep"
}

# A `for` LOOP IS A TIMER: it counts iterations rather than testing a condition,
# so it exits on the clock. Backgrounded, that is the shape CLOUD-821 measured.
test_a_backgrounded_counting_loop_is_a_timer if {
	some v in violation with input as {"call": {
		"command": "for i in $(seq 60); do sleep 10; done",
		"run-in-background": true,
		"segments": [inner(["sleep", "10"], "for", "body", null)],
	}}
	v.rule == "background-timer"
}

# THE EXEMPTION'S WORST REACHABLE SHAPE, and the case that says why asking
# WHETHER there is a condition was never the right question (CLOUD-1337). The
# `sleep 5` here waits on nothing at all — the loop beside it has an empty body —
# so the old rule exempted a bare timer for the company it kept. Inverted rather
# than deleted: this is the shape the withdrawal is FOR.
test_a_bare_sleep_beside_a_condition_loop_is_refused if {
	some v in violation with input as {"call": {
		"command": "sleep 5; until [ -f /tmp/done ]; do :; done",
		"run-in-background": true,
		"segments": [
			seg(["sleep", "5"], ";", false),
			inner(["[", "-f", "/tmp/done", "]"], "until", "condition", ";"),
			inner([":"], "until", "body", null),
		],
	}}
	v.rule == "background-timer"
}

# THE DISCRIMINATING CASE for `run-in-background`: both rules deny, so only the
# verdict tells them apart. A `foreground-sleep` that ignored the flag would
# raise TWO violations here.
test_a_backgrounded_bare_sleep_raises_only_the_timer if {
	count(violation) == 1 with input as {"call": {
		"command": "sleep 590; tail -6 land.log",
		"run-in-background": true,
		"segments": [
			seg(["sleep", "590"], ";", false),
			seg(["tail", "-6", "land.log"], null, false),
		],
	}}
}

# THE ANCHORING CASE. `sleep` as an ARGUMENT is not an invocation, and a
# predicate scanning words rather than resolving the program refuses this.
test_a_mention_of_sleep_is_not_a_call if {
	count(violation) == 0 with input as {"call": {
		"command": "echo sleep 90",
		"run-in-background": false,
		"segments": [seg(["echo", "sleep", "90"], null, false)],
	}}
}

# ---------------------------------------------------------------------------
# The two families CLOUD-1722 added: every `mise` call is backgrounded, and a
# backgrounded call keeps its own output.
#
# `programs` rather than `words[0]`, and these cases are where that matters:
# `foreground-mise` anchors on the engine's RESOLVED program, so a fixture must
# carry the key. `sleeps` above reaches for a segment's program through
# `words_program_index`; this family does not, because the mediated document
# already publishes the resolution and CLOUD-1382 says a first word is not a
# first program.
# ---------------------------------------------------------------------------

prog(name, arguments) := {
	"program": name,
	"name": name,
	"arguments": arguments,
	"mediated": true,
}

test_a_foreground_mise_run_is_refused if {
	some v in violation with input as {"call": {
		"command": "mise run verify",
		"run-in-background": false,
		"programs": [prog("mise", ["run", "verify"])],
		"segments": [seg(["mise", "run", "verify"], null, false)],
	}}
	v.rule == "foreground-mise"
}

# THE STRICT SIDE OF THE THREE-VALUED READ, and the ordinary envelope: most hosts
# send no posture at all, and an unknown one over a call that can spend the whole
# turn is the case to be strict about.
#
# `null` RATHER THAN AN ABSENT KEY, and the difference is not cosmetic. The
# schema types this field `["boolean", "null"]`, so the engine always emits it
# and "the host said nothing" arrives as an explicit null. Written with the key
# missing, this case measured GREEN over a refusal that never fired: Rego reads
# an absent key as undefined and `undefined != true` is undefined, so the
# conjunct fails and the whole violation drops. A fixture encoding a document
# the engine cannot produce proves nothing, which is the same lesson `inner`'s
# comment records for the loop keyword.
test_an_unstated_posture_is_refused_too if {
	some v in violation with input as {"call": {
		"command": "mise run ci",
		"run-in-background": null,
		"programs": [prog("mise", ["run", "ci"])],
		"segments": [seg(["mise", "run", "ci"], null, false)],
	}}
	v.rule == "foreground-mise"
}

test_a_backgrounded_mise_run_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "mise run verify",
		"run-in-background": true,
		"programs": [prog("mise", ["run", "verify"])],
		"segments": [seg(["mise", "run", "verify"], null, false)],
	}}
}

# THE ANCHORING CASE, the sibling of `a_mention_of_sleep_is_not_a_call`: `mise`
# as an ARGUMENT is not an invocation of it.
test_a_mention_of_mise_is_not_a_call if {
	count(violation) == 0 with input as {"call": {
		"command": "cat mise.toml",
		"run-in-background": false,
		"programs": [prog("cat", ["mise.toml"])],
		"segments": [seg(["cat", "mise.toml"], null, false)],
	}}
}

test_a_backgrounded_call_redirecting_its_own_output_is_refused if {
	some v in violation with input as {"call": {
		"command": "cargo build > /tmp/log 2>&1",
		"run-in-background": true,
		"programs": [prog("cargo", ["build"])],
		"segments": [seg(["cargo", "build", ">", "/tmp/log", "2>&1"], null, false)],
	}}
	v.rule == "background-redirect"
}

# NOTHING IS CAPTURED FOR A FOREGROUND CALL, so a redirect there discards no
# output anyone was going to read. This is the case that keeps the rule from
# becoming a blanket ban on redirection.
test_a_foreground_redirect_is_not_this_rule if {
	count(violation) == 0 with input as {"call": {
		"command": "cargo build > /tmp/log 2>&1",
		"run-in-background": false,
		"programs": [prog("cargo", ["build"])],
		"segments": [seg(["cargo", "build", ">", "/tmp/log", "2>&1"], null, false)],
	}}
}

# AN INPUT REDIRECT IS UNTOUCHED: reading a file INTO a backgrounded command
# discards nothing. Judged on the redirection TOKENS, and `<` is not one of them.
test_a_backgrounded_input_redirect_is_untouched if {
	count(violation) == 0 with input as {"call": {
		"command": "cargo build < /tmp/answers",
		"run-in-background": true,
		"programs": [prog("cargo", ["build"])],
		"segments": [seg(["cargo", "build", "<", "/tmp/answers"], null, true)],
	}}
}

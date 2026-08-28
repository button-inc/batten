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
# THE BASH STILL RUNS, and that is the ratchet rather than an oversight.
# `shell-retirement` admits DELETING a governed file and refuses SHRINKING one,
# and `run-shape-guard.sh` keeps a fourth family (`cargo-substitutes-for-a-task`)
# whose blocker is CLOUD-856. So the guard cannot lose these three until it can
# lose all four, and both authorities decide them until it does. CLOUD-1108 owns
# that gap; the predicates below are written from the bash's own decision table,
# with ONE deliberate divergence — `keywords` reaches a sleep inside a loop body
# and `resolve()` does not (CLOUD-1112) — which is in the DENYING direction, so
# no call gets a weaker answer from the pair than it had from the guard alone.
#
# TWO ERAS OF INPUT LIVE HERE, deliberately, and the newer one is the model.
# `commit-names-no-message-source` landed before `hook::segments` was projected,
# so it scrubs `input.call.command` by hand: a heredoc-body pass, two quoted-span
# passes, a list split and a pipe split, all in core builtins. The three
# predicates added by CLOUD-613 read `input.call.segments` instead, where the
# ENGINE has already done every one of those passes. Rewriting the first onto
# segments is a change to a landed verdict rather than an addition, so it is not
# folded in here — but no NEW predicate should copy the hand-rolled version, and
# `.claude/rules/policy-modules.md` says so with the parser's own reasons.
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

# CLOUD-613's three, and none of them is over a program NAME — a mutation on the
# `sleep` or `git` token survives, because every ALLOW row already fails some
# other conjunct. Each of these corrupts the conjunct that carries the verdict.
#MUTANT redirect-binding-ignored|s@^	segment\["input-redirect"\] == false@	true@|a heredoc bound to this element IS a message source
#MUTANT background-not-consulted|s@^	input.call\["run-in-background"\] != true@	true@|a backgrounded wait on a condition is the prescribed form
#MUTANT loop-is-not-an-exemption|s@^	not waits_on_condition@	true@|an `until` loop is a wait, not a timer

# THE FOUR MUTATIONS, and the last three are the ones worth having: they corrupt
# the SCRUBBING and the SPLITTING rather than the flag table, which is where a
# raw-string module goes quietly wrong. `@` delimits each sed script because the
# rows themselves are `|`-separated.
#MUTANT message-flag-cluster-unreferenced|s@short-message-flag-cluster@zzz-no-such-pattern@|every form that CAN obtain a message stays allowed
#MUTANT list-not-split|s@^elements :=.*@elements := [scrubbed]@|a compound list is judged per element
#MUTANT heredoc-body-judged|s@	j < i@	j < -1@|a git commit inside a heredoc body is prose
#MUTANT double-quoted-span-judged|s@^scrubbed := quoted_out(single_scrubbed.*@scrubbed := single_scrubbed@|a quoted span carrying a list separator is not a list
#MUTANT single-quoted-span-judged|s@^single_scrubbed := quoted_out(code_lines.*@single_scrubbed := code_lines@|a quoted span carrying a list separator is not a list

violation contains {
	"rule": "commit-names-no-message-source",
	"verdict": "V-COMMIT-WITHOUT-A-MESSAGE-SOURCE",
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
	"verdict": "V-COMMIT-STDIN-UNBOUND",
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
	"verdict": "V-FOREGROUND-SLEEP",
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
	"verdict": "V-BACKGROUND-TIMER",
} if {
	sleeps
	input.call["run-in-background"] == true
	not waits_on_condition
}

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
# it: `keywords` below looks through `do`/`then`/…, and `resolve()` has no such
# set (CLOUD-1112). That is the one place these two authorities deliberately
# disagree while both are live, and it is in the DENYING direction — the engine
# refuses a foreground loop the guard allows, so no call gets a weaker answer
# than it did before.
sleeps if {
	some segment in input.call.segments
	basename(segment.words[words_program_index(segment.words)]) == "sleep"
}

# OVER THE WHOLE CALL, never one segment, because a loop's keyword and its sleep
# are in different segments.
#
# AND IT IS LOAD-BEARING HERE, which it is not in the bash. There the canonical
# `until <test>; do sleep 1; done` was allowed because no sleep resolved at all,
# so this conjunct decided nothing and read as coverage (CLOUD-1112). With the
# loop body reached, this is the only thing standing between that command and a
# refusal — which is what CLOUD-613's acceptance always claimed it was.
#
# `for` is NOT a wait. `for i in $(seq 60); do sleep 10; done` counts iterations
# rather than testing a condition, so it exits on the clock like any timer; the
# bash names it a deliberate non-catch "because narrowing that costs a real
# parser", and it costs none now.
waits_on_condition if {
	some segment in input.call.segments
	some word in segment.words
	word in {"until", "while"}
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
# `run-shape-guard.sh`'s `resolve()` has no such set, and CLOUD-1112 measured
# what that costs: `do sleep 1` resolved to the program `do`, so a sleep in a
# loop body was invisible — and `waits_on_condition` therefore exempted nothing,
# because the canonical `until <test>; do sleep 1; done` was already allowed for
# want of a resolvable sleep rather than for being a wait. The guard's own
# comment claims the opposite ("the one carrying the sleep has no keyword in
# it"), which only parses if that element IS reached.
#
# CLOUD-613's acceptance turns on that allow being LOAD-BEARING, so porting the
# gap would have satisfied the clause vacuously. This is the narrower reading:
# the engine resolves the loop body, and the exemption is what decides it.
#
# `until`/`while`/`if`/`for` are deliberately ABSENT. They introduce a condition
# list rather than the command, and `waits_on_condition` reads them as words —
# skipping them would blind the exemption to the thing it tests for.
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
test_a_backgrounded_wait_on_a_condition_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"command": "until [ -f /tmp/done ]; do sleep 1; done",
		"run-in-background": true,
		"segments": [
			seg(["until", "[", "-f", "/tmp/done", "]"], ";", false),
			seg(["do", "sleep", "1"], ";", false),
			seg(["done"], null, false),
		],
	}}
}

# A FOREGROUND loop spends the turn exactly as a foreground `sleep` does, and it
# is refused for that reason. Reaching it needs `keywords`: without the
# look-through `do sleep 1` resolves to `do` and this passes silently, which is
# how it stood in the bash (CLOUD-1112).
test_a_foreground_wait_on_a_condition_is_refused if {
	some v in violation with input as {"call": {
		"command": "until [ -f /tmp/done ]; do sleep 1; done",
		"run-in-background": false,
		"segments": [
			seg(["until", "[", "-f", "/tmp/done", "]"], ";", false),
			seg(["do", "sleep", "1"], ";", false),
			seg(["done"], null, false),
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
		"segments": [
			seg(["for", "i", "in", "$(seq", "60)"], ";", false),
			seg(["do", "sleep", "10"], ";", false),
			seg(["done"], null, false),
		],
	}}
	v.rule == "background-timer"
}

# The exemption's other reachable shape: a bare sleep and a loop keyword in one
# backgrounded call, where the sleep resolves without any look-through at all.
test_a_bare_sleep_beside_a_condition_loop_is_exempt if {
	count(violation) == 0 with input as {"call": {
		"command": "sleep 5; until [ -f /tmp/done ]; do :; done",
		"run-in-background": true,
		"segments": [
			seg(["sleep", "5"], ";", false),
			seg(["until", "[", "-f", "/tmp/done", "]"], ";", false),
			seg(["do", ":"], ";", false),
			seg(["done"], null, false),
		],
	}}
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

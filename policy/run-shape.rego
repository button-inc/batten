# The `git commit` that cannot obtain a message, as a policy predicate.
#
# Migrated from `mise-tasks/run-shape-guard`'s no-message-source arm (CLOUD-843
# track 2). It is the ONE family of that guard's five whose predicate is a
# function of the command string alone, which is the only thing
# `hook::call_document` puts in front of a module on the mediated call. The
# other four, and the blocker each waits on, are in the guard's own header.
#
# WHY IT IS WORTH REFUSING: `githooks(5)` runs `pre-commit` BEFORE git asks for
# a message, so a commit that was always going to fail spends the whole gate
# first (~4 minutes measured, CLOUD-488) and then blocks on $EDITOR in a
# non-interactive call.
#
# THE SCRUBBING IS THE PREDICATE, not preamble. A `git commit` written inside a
# heredoc body or a quoted span is prose, not a call, and a module judging the
# raw string would refuse this repository's own commit messages. The engine does
# not scrub for us: `input.call.command` is the command exactly as written
# (`hook::segments` is computed for `shape`/`pipeline` rows and is not
# projected), and this build of regorus carries no `regex` builtins, so both
# passes are core-builtin string work.
package batten.run_shape

import rego.v1

rules contains "commit-names-no-message-source"

# THE FOUR MUTATIONS, and the last three are the ones worth having: they corrupt
# the SCRUBBING and the SPLITTING rather than the flag table, which is where a
# raw-string module goes quietly wrong. `@` delimits each sed script because the
# rows themselves are `|`-separated.
#MUTANT message-flag-unchecked|s@\[mFCc\]@[Z]@|every form that CAN obtain a message stays allowed
#MUTANT list-not-split|s@^elements :=.*@elements := [scrubbed]@|a compound list is judged per element
#MUTANT heredoc-body-judged|s@	j < i@	j < -1@|a git commit inside a heredoc body is prose
#MUTANT double-quoted-span-judged|s@^scrubbed := quoted_out(single_scrubbed.*@scrubbed := single_scrubbed@|a quoted span carrying a list separator is not a list
#MUTANT single-quoted-span-judged|s@^single_scrubbed := quoted_out(code_lines.*@single_scrubbed := code_lines@|a quoted span carrying a list separator is not a list

violation contains {
	"rule": "commit-names-no-message-source",
	"msg": "this `git commit` names no message source — no `-m`, `-F`, `-C`, `--no-edit`, `--fixup` or `--squash` — so git opens $EDITOR and blocks there, after `pre-commit` has already spent the whole gate (~4 minutes measured, CLOUD-488). Write the message to a file and use `git commit -F <path>`, the one form that cannot rebind",
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

# ---------------------------------------------------------------------------
# Scrubbing: heredoc bodies, then quoted spans. Same order as the bash.
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
	regex.match(`^-[A-Za-z]*[mFCc]`, t)
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

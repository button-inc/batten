#!/usr/bin/env bats
# subject: mise-tasks/awk-regex-check
# A pattern passed through `awk -v` goes through assignment escape processing
# before awk sees it as a regex, and what that does to a backslash is undefined
# across implementations. gawk strips `\(` to `(`; mawk keeps it.
#
# The failure this encodes: `ready-lint` matched its §8 label that way, worked on
# mawk locally, matched NOTHING on the gawk runner — so the clause that catches a
# blocker claimed without a relation went back to passing silently, taking three
# older tests with it. A gate that cannot match its own label does not fail.
#
# The predicate is the USE, not the value. A literal without a backslash is safe
# today and unsafe the moment someone adds one, and a variable's runtime content
# is invisible to any static check.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/awk-regex-check"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	mkdir -p "$REPO/mise-tasks"
	cd "$REPO" || return 1
	git init -q .
	git config user.email t@t
	git config user.name t
}

# Writes $1 as a task body and stages it, since the gate reads tracked files.
task() {
	printf '#!/usr/bin/env bash\n%s\n' "$1" >mise-tasks/subject
	git add -A
}

@test "this repo's own tasks pass today" {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the real bug: a -v name used with ~ is reported" {
	task 'x=$(awk -v re="$LABEL" '"'"'!f && $0 ~ re { f=1; print }'"'"' <<<"$b")'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"assigned with -v and used as a regex"* ]]
}

@test "the report names file and line, not the whole command" {
	task 'x=$(awk -v re="$L" '"'"'$0 ~ re'"'"')'
	run "$GATE"
	[[ "$output" == *"mise-tasks/subject:2"* ]]
}

@test "match() is regex position too" {
	task 'x=$(awk -v pat="$P" '"'"'{ if (match($0, pat)) print }'"'"')'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a -v value compared with == is fine — that is most of its use" {
	task 'x=$(awk -F"\t" -v t="$tool" '"'"'$1 == t { print $2 }'"'"')'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a -v value printed or counted is fine" {
	task 'x=$(awk -v n="$count" '"'"'END { print n + NR }'"'"')'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an inline regex in the awk program is the recommended form, not a finding" {
	# No assignment processing happens, so backslashes survive intact.
	task 'x=$(awk '"'"'/^[[:space:]]*Blockers \(/ { print }'"'"')'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a name that merely PREFIXES another is not confused for it" {
	# `re` assigned, `remainder` used with ~ — different names.
	task 'x=$(awk -v re="$L" '"'"'$0 ~ remainder { print re }'"'"')'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "several -v assignments on one line are each judged" {
	task 'x=$(awk -v a="$A" -v b="$B" '"'"'$1 == a && $0 ~ b { print }'"'"')'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'`b`'* ]]
	[[ "$output" != *'`a`'* ]]
}

@test "an untracked file is not judged — the gate reads what is committed" {
	printf '#!/usr/bin/env bash\nx=$(awk -v re="$L" '"'"'$0 ~ re'"'"')\n' >mise-tasks/untracked
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a tree with no awk at all passes rather than erroring" {
	task 'echo hello'
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no regex reaches awk"* ]]
}

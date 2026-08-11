#!/usr/bin/env bats
# The guard that keeps memory writes going through the tools that enforce their
# own limits.
#
# These tests were `context-budget.bats` until CLOUD-50 moved the budget gate
# into the engine (`batten policy budget`) and deleted the shell task. The budget
# half of that file went with its subject — the equivalent assertions are now
# `crates/batten/tests/cli.rs` and the estimator's in-module unit tests — and the
# guard half moved here, under the name of the task it actually covers.
#
# CLOUD-185 added the second half: the guard used to be wired to the
# `Write|Edit|MultiEdit|NotebookEdit` matcher only, so every Bash write shape
# reached the memories tree unjudged. The Bash cases below are the ones that
# were measured getting through.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/memory-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# The hook adapter, driven the way the harness drives it.
guard_path() {
	jq -nc --arg p "$1" '{tool_input: {file_path: $p}}' | "$GUARD"
}

guard_cmd() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

# --- the Write/Edit table (unchanged by CLOUD-185) --------------------------

@test "guard denies a direct write to a memory" {
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\"/x/.serena/memories/github-access.md\"}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	# Names the memory so the redirect is actionable, not just a refusal.
	[[ "$output" == *"github-access"* ]]
}

@test "guard ignores writes outside the memories directory" {
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\"/x/AGENTS.md\"}}' | '$GUARD'"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "guard fails open on unparseable input and honours the bypass" {
	run bash -c "printf '%s' 'not json' | '$GUARD'"
	[ -z "$output" ]
	run bash -c "printf '%s' '{\"tool_input\":{\"file_path\":\".serena/memories/x.md\"}}' | BATTEN_MEMORY_GUARD_BYPASS=1 '$GUARD'"
	[ -z "$output" ]
}

# --- the Bash table (CLOUD-185) ---------------------------------------------
#
# The measured bypass: memories were written by Bash heredoc and the guard, wired
# to the Write/Edit matcher, saw nothing at all.

@test "a heredoc into a memory is denied — the shape that actually happened" {
	run guard_cmd "cat > .serena/memories/github-access.md <<'MD'
some memory body
MD"
	denied "$output"
	[[ "$output" == *"write_memory"* ]]
	# Pointer, not payload: the memory name, never the body being written.
	[[ "$output" == *"github-access"* ]]
	[[ "$output" != *"some memory body"* ]]
}

@test "an append redirect is the same write" {
	run guard_cmd 'printf "x\n" >> .serena/memories/toolchain-and-hooks.md'
	denied "$output"
}

@test "tee into a memory is denied" {
	run guard_cmd 'printf "x\n" | tee .serena/memories/github-access.md'
	denied "$output"
}

@test "git mv of a memory is denied, and names the rename tool" {
	# The worst uncaught shape: rename_memory is the only thing that rewrites
	# `mem:` referrers, so a git mv silently orphans every reference.
	run guard_cmd 'git mv .serena/memories/github-access.md .serena/memories/gh-access.md'
	denied "$output"
	[[ "$output" == *"rename_memory"* ]]
}

@test "a plain mv of a memory is denied for the same reason" {
	run guard_cmd 'mv .serena/memories/a.md .serena/memories/b.md'
	denied "$output"
	[[ "$output" == *"rename_memory"* ]]
}

@test "git rm and rm of a memory are denied, naming the delete tool" {
	run guard_cmd 'git rm .serena/memories/stale.md'
	denied "$output"
	[[ "$output" == *"delete_memory"* ]]
	run guard_cmd 'rm -f .serena/memories/stale.md'
	denied "$output"
	[[ "$output" == *"delete_memory"* ]]
}

@test "sed -i over a memory is an edit and is denied" {
	run guard_cmd "sed -i 's/old/new/' .serena/memories/github-access.md"
	denied "$output"
	[[ "$output" == *"edit_memory"* ]]
}

@test "cp INTO the memories tree is denied; cp OUT of it is a read" {
	run guard_cmd 'cp /tmp/draft.md .serena/memories/new-note.md'
	denied "$output"
	run guard_cmd 'cp .serena/memories/github-access.md /tmp/copy.md'
	! denied "$output"
}

@test "reads over the memories tree stay allowed" {
	run guard_cmd 'cat .serena/memories/github-access.md'
	! denied "$output"
	run guard_cmd 'grep -r "mem:" .serena/memories/'
	! denied "$output"
	run guard_cmd 'ls -la .serena/memories/'
	! denied "$output"
	run guard_cmd 'wc -l .serena/memories/*.md'
	! denied "$output"
}

@test "a write elsewhere is untouched" {
	run guard_cmd 'cat > /tmp/scratch.md <<EOF
hello
EOF'
	! denied "$output"
	run guard_cmd 'sed -i s/a/b/ AGENTS.md'
	! denied "$output"
	run guard_cmd 'git mv src/a.rs src/b.rs'
	! denied "$output"
}

@test "the wrapper form is resolved, not stopped at" {
	# Same wrapper-skip as gh-guard-check (CLOUD-181): in the web sandbox the
	# wrapped form is often the only working one, so a guard that judges the
	# wrapper token sees none of the calls that matter.
	run guard_cmd 'mise exec -- sed -i s/a/b/ .serena/memories/github-access.md'
	denied "$output"
	run guard_cmd 'env FOO=1 tee .serena/memories/x.md'
	denied "$output"
}

@test "a pager over a memory is a read even though a redirect follows elsewhere" {
	# Per SEGMENT, like every other guard here: a write in one segment must not
	# condemn a read in another, and vice versa.
	run guard_cmd 'cat .serena/memories/a.md; echo done > /tmp/x'
	! denied "$output"
	run guard_cmd 'cat /tmp/x; echo done > .serena/memories/a.md'
	denied "$output"
}

@test "a commit message or heredoc body describing the shape is not the shape" {
	run guard_cmd 'git commit -m "explain why cat > .serena/memories/x.md bypasses the guard"'
	! denied "$output"
	run guard_cmd "cat > /tmp/notes.md <<'MD'
never run: sed -i s/a/b/ .serena/memories/x.md
MD"
	! denied "$output"
}

@test "the Bash table honours the bypass and fails open" {
	run bash -c "jq -nc '{tool_input:{command:\"echo x > .serena/memories/a.md\"}}' | BATTEN_MEMORY_GUARD_BYPASS=1 '$GUARD'"
	! denied "$output"
	run bash -c "printf 'not json' | '$GUARD'"
	! denied "$output"
	[ "$status" -eq 0 ]
	run bash -c "jq -nc '{tool_input:{}}' | '$GUARD'"
	! denied "$output"
}

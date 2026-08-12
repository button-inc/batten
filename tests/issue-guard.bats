#!/usr/bin/env bats
# The mechanism for the board rule, which was prose and therefore skipped.
#
# The failure it encodes: three PRs landed in one session with no issue moved,
# no issue created, and an existing CLOUD issue — carrying measurements that
# contradicted the fix — never read. Every OTHER discipline in that session was
# followed, and every one of those has a gate on a call the agent cannot avoid.
#
# Every case runs in a throwaway repo, never in this one. The first draft ran in
# the real checkout and passed; the commit that added this guard put `Refs:
# CLOUD-178` in its own message, the guard then correctly allowed, and every
# deny case flipped red. A guard whose verdict reads live git state must be
# tested against git state the test controls.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/issue-guard"
	# A repo with no issue reference anywhere: not in the branch, not in history.
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	# The developer's global git config must not reach a fixture repo
	# (CLOUD-282). `init.defaultBranch=main` is the leak this suite tripped on —
	# git refuses `branch -f` on the CHECKED-OUT branch, so a machine configured
	# the modern way failed every test in the file at setup, while CI passed only
	# because the runner's git still defaults to `master`. `commit.gpgsign` is
	# the same shape. crates/batten/tests/common/mod.rs:184-185 already does this.
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	# `-b work`, so the checked-out branch is NAMED rather than inherited. The
	# `main` created below is a second branch marking the trunk while HEAD stays
	# on the feature branch — that topology is what these cases exercise — and
	# the force-create this replaces could only ever build it by accident: it
	# works while git's default is `master`, and git REFUSES to force the branch
	# that is currently checked out, so the same line failed outright the moment
	# a developer's default was the trunk's own name. Naming the branch makes the
	# topology explicit instead of inheriting it, and `main` is then a fresh name
	# needing no force at all. `no-branch-f-main` in batten.toml keeps the old
	# form out; the literal is not spelled here, because that row is a substring
	# rule over this directory and would fire on its own explanation.
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
	git update-ref refs/remotes/origin/main main
	git checkout -q -b plain-branch

	# A stubbed `gh`, ahead of the real one on PATH, so the duplicate-claim
	# lookup (CLOUD-230) is exercised against state the test controls and the
	# suite never touches the network. It answers empty by default — no
	# competing PR — which leaves every case written before that check behaving
	# exactly as it did.
	STUB="$BATS_TEST_TMPDIR/bin-$BATS_TEST_NUMBER"
	mkdir -p "$STUB"
	# A competitor's title, body and commits are three separate reads since
	# CLOUD-378 — the guard asks `claimed-keys` which of them is a CLAIM, and a
	# stub that answered one blob for all three could not tell the cases apart.
	# `STUB_BODY` keeps its name and its meaning (the competitor's body), so
	# every case written before that split reads the same.
	cat >"$STUB/gh" <<-'EOF'
		#!/usr/bin/env bash
		case "$*" in
		*"pr view --json number"*) printf '{"number":%s,"title":"","body":"%s"}\n' "${STUB_SELF:-0}" "${STUB_SELF_BODY:-}" ;;
		*"pr list"*) printf '%s\n' "${STUB_PRS:-}" ;;
		*"pr view "*"--json title "*) printf '%s\n' "${STUB_TITLE:-}" ;;
		*"pr view "*"--json commits "*) printf '%s\n' "${STUB_COMMITS:-}" ;;
		*"pr view "*) printf '%s\n' "${STUB_BODY:-}" ;;
		*) exit 1 ;;
		esac
	EOF
	chmod +x "$STUB/gh"
	PATH="$STUB:$PATH"
	export PATH
	# `gh` lives only inside the mise environment here, so a PATH without the
	# stub and without mise's shims genuinely has no `gh` — which is what the
	# fail-open-on-absence case below relies on.
	BARE_PATH="/usr/bin:/bin"
}

# Feed a PreToolUse payload the way Claude Code does.
guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

@test "gh pr create with no issue anywhere is denied" {
	run guard 'gh pr create --draft --title x'
	denied "$output"
}

@test "the denial says what to do, not merely that it refused" {
	run guard 'gh pr create'
	[[ "$output" == *"Search the board"* ]]
	[[ "$output" == *"BATTEN_ISSUE_GUARD_BYPASS"* ]]
}

@test "gh pr ready is gated too — readying is what starts CI" {
	run guard 'gh pr ready 99'
	denied "$output"
}

@test "the wrapper form is judged, not the wrapper — mise exec is the sandbox's only form" {
	run guard 'mise exec -- gh pr create --draft'
	denied "$output"
}

@test "an issue named in the command body is enough" {
	run guard 'gh pr create --body Fixes CLOUD-178'
	! denied "$output"
}

@test "a branch naming the issue satisfies the guard without touching the command" {
	# The convention Linear's own gitBranchName produces.
	git checkout -q -b wenzowski/cloud-178-connector-names
	run guard 'gh pr create --draft'
	! denied "$output"
}

@test "a commit trailer naming the issue satisfies it, on a branch that does not" {
	git commit -q --allow-empty -m "fix: a thing

Refs: CLOUD-178"
	run guard 'gh pr create --draft'
	! denied "$output"
}

@test "an issue on main but not on this branch does not count" {
	# The reference has to be in work this branch adds, or the guard would pass
	# on any repo whose history has ever mentioned an issue.
	git checkout -q main
	git commit -q --allow-empty -m "chore: mentions CLOUD-999"
	git update-ref refs/remotes/origin/main main
	git checkout -q plain-branch
	run guard 'gh pr create --draft'
	denied "$output"
}

@test "an unrelated gh call is none of this guard's business" {
	run guard 'gh pr view 99 --json state'
	! denied "$output"
}

@test "a non-gh command is not touched" {
	run guard 'git push -u origin HEAD'
	! denied "$output"
}

@test "a commit message merely mentioning the command is not the command" {
	run guard 'git commit -m "explain gh pr create in the docs"'
	! denied "$output"
}

@test "the bypass is honoured, because a PR sometimes precedes its issue" {
	BATTEN_ISSUE_GUARD_BYPASS=1 run guard 'gh pr create'
	! denied "$output"
}

@test "unparseable input fails open rather than blocking every command" {
	run bash -c "printf 'not json' | $GUARD"
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "an empty command fails open" {
	run bash -c "jq -nc '{tool_input:{}}' | $GUARD"
	! denied "$output"
}

@test "outside a git repo it fails open rather than blocking every PR" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run guard 'gh pr create --draft'
	! denied "$output"
}

# --- the duplicate-claim refusal (CLOUD-230) ----------------------------------
#
# Replayed from the measurement that motivated it: CLOUD-49 was implemented
# twice in one cycle, and the competing PR (#145) named the issue only in its
# title and body — its branch, `claude/fail-on-warning-setting-wc1wdx`, carried
# no key at all. A check reading branch names alone would have missed it.
#
# What counts as a CLAIM is narrower than what counts as a mention, and these
# cases exist because conflating them made this guard refuse its own PR twice: a
# body cites related issues as evidence, and a bundle branch names issues that
# already landed. Only a closing keyword, an unambiguous single-issue branch, or
# a single `Refs:` trailer is a claim.

@test "an issue already claimed by another open PR is denied" {
	# The competitor's TITLE names the issue — this repo ends every PR title
	# with `(CLOUD-<n>)`, so a title is a self-declaration the way a branch is.
	STUB_SELF=144 STUB_PRS="145 claude/fail-on-warning-setting-wc1wdx" \
		STUB_TITLE="feat: promote warn findings (CLOUD-49)" \
		run guard 'gh pr create --draft --body Closes CLOUD-49'
	denied "$output"
	[[ "$output" == *"#145"* ]]
}

@test "the duplicate denial names the competing PR and the way out" {
	STUB_SELF=144 STUB_PRS="145 some-branch" STUB_TITLE="CLOUD-49" \
		run guard 'gh pr create --body Fixes CLOUD-49'
	[[ "$output" == *"claim-check"* ]]
	[[ "$output" == *"BATTEN_ISSUE_GUARD_BYPASS"* ]]
}

@test "a competitor whose branch alone names the issue is caught" {
	# The other direction: no mention in title or body, only the branch.
	STUB_SELF=144 STUB_PRS="150 wenzowski/cloud-49-add-fail-on-warning" STUB_BODY="" \
		run guard 'gh pr create --body Resolves CLOUD-49'
	denied "$output"
	[[ "$output" == *"#150"* ]]
}

@test "our own PR is not a competitor, or pr ready would deny every time" {
	STUB_SELF=145 STUB_PRS="145 claude/fail-on-warning-setting-wc1wdx" \
		STUB_BODY="CLOUD-49" \
		run guard 'gh pr ready --body Closes CLOUD-49'
	! denied "$output"
}

@test "a different issue's open PR is not a competitor" {
	STUB_SELF=144 STUB_PRS="145 some-branch" STUB_BODY="feat: something CLOUD-49" \
		run guard 'gh pr create --body Closes CLOUD-230'
	! denied "$output"
}

@test "a near-miss issue number does not collide" {
	# CLOUD-4 must not match a PR claiming CLOUD-49.
	STUB_SELF=144 STUB_PRS="145 some-branch" STUB_TITLE="CLOUD-49" \
		run guard 'gh pr create --body Closes CLOUD-4'
	! denied "$output"
}

# --- The competitor is asked the same question this branch is (CLOUD-378) -----
#
# The narrowing above was applied to THIS branch and not to the other one, so a
# PR citing the key as evidence read as racing it. Measured on #306, whose only
# mention of CLOUD-133 is a row of an evidence table, refusing CLOUD-133's own
# first PR.

@test "a competitor that merely CITES the issue in its body is not a claim" {
	# The measured case. The competitor claims CLOUD-268 by branch and title,
	# and names CLOUD-133 once as evidence.
	STUB_SELF=144 \
		STUB_PRS="306 wenzowski/cloud-268-design-agent-neutral-attribution" \
		STUB_TITLE="docs(agents): point at the attribution decision record (CLOUD-268)" \
		STUB_BODY="| Provenance records (CLOUD-133 fields, joined by SHA) | CLOUD-275 |" \
		run guard 'gh pr create --draft --body Closes CLOUD-133'
	! denied "$output"
}

@test "a competitor whose body CLOSES the issue is a claim, whatever its branch says" {
	# The escape hatch `claimed-keys` documents, applied to the other side: a
	# branch whose name no longer reflects the work says so in the body.
	STUB_SELF=144 STUB_PRS="150 some-bundle-branch" STUB_TITLE="chore: unrelated" \
		STUB_BODY="Closes CLOUD-49 — the fail-on-warning setting." \
		run guard 'gh pr create --body Closes CLOUD-49'
	denied "$output"
	[[ "$output" == *"#150"* ]]
}

@test "a competitor whose commits carry the Refs: trailer is a claim" {
	# Source 3, which the inline derivation could not reach at all: a PR whose
	# branch and title name nothing and whose body cites nothing.
	STUB_SELF=144 STUB_PRS="151 claude/some-branch" STUB_TITLE="chore: tidy" \
		STUB_COMMITS="chore: tidy the thing"$'\n'"Refs: CLOUD-49" \
		run guard 'gh pr create --body Closes CLOUD-49'
	denied "$output"
	[[ "$output" == *"#151"* ]]
}

@test "a competitor citing the key in a commit message is still not a claim" {
	# The same conflation one level down: a commit body may cite prior work.
	STUB_SELF=144 STUB_PRS="152 claude/some-branch" STUB_TITLE="chore: tidy" \
		STUB_COMMITS="chore: tidy"$'\n'"Measured against CLOUD-49 and CLOUD-37." \
		run guard 'gh pr create --body Closes CLOUD-49'
	! denied "$output"
}

@test "a merely CITED issue is not a claim" {
	# This PR's own body cites the issues it measured. Citing CLOUD-49 as
	# evidence while closing CLOUD-230 must not be read as racing CLOUD-49 —
	# the guard refused its own PR on exactly this before the split.
	STUB_SELF=144 STUB_PRS="145 some-branch" STUB_BODY="CLOUD-49" \
		run guard 'gh pr create --body Closes CLOUD-230. Measured on CLOUD-49 and CLOUD-37.'
	! denied "$output"
}

@test "a closing keyword overrides a branch whose name no longer fits the work" {
	# The escape hatch, and the case that produced this whole distinction. A
	# bundle branch (`claude/cloud-37-49-config-…`) reads as claiming CLOUD-37
	# forever, including long after CLOUD-37 landed. The body is how the PR says
	# which issue it is actually for.
	git checkout -q -b claude/cloud-37-49-config-7ssbsh
	STUB_SELF=999 STUB_PRS="150 claude/git-state-core-primitives" \
		STUB_TITLE="feat: git state primitives (CLOUD-37)" \
		run guard 'gh pr create --draft --body Closes CLOUD-230'
	! denied "$output"
}

@test "without that override, the branch is taken at its word" {
	# Same branch, no closing keyword: CLOUD-37 is the only claim evidence
	# available, so a live PR for it is a genuine collision to report.
	git checkout -q -b claude/cloud-37-49-config-7ssbsh
	STUB_SELF=999 STUB_PRS="150 claude/git-state-core-primitives" \
		STUB_TITLE="feat: git state primitives (CLOUD-37)" \
		run guard 'gh pr create --draft'
	denied "$output"
	[[ "$output" == *"#150"* ]]
}

@test "a single-issue branch is an unambiguous claim" {
	git checkout -q -b wenzowski/cloud-49-add-fail-on-warning
	STUB_SELF=999 STUB_PRS="145 other" STUB_TITLE="CLOUD-49" \
		run guard 'gh pr create --draft'
	denied "$output"
	[[ "$output" == *"#145"* ]]
}

@test "a Refs: trailer claims when nothing more explicit does" {
	git commit -q --allow-empty -m "fix: a thing

Refs: CLOUD-49"
	STUB_SELF=999 STUB_PRS="145 other" STUB_TITLE="CLOUD-49" \
		run guard 'gh pr create --draft'
	denied "$output"
}

@test "a failing gh fails open — a guard that cannot reach GitHub must not block" {
	# The stub exits non-zero for everything it is not told to answer; here it
	# is told nothing, so every call fails.
	STUB_FAIL=1 run guard 'gh pr create --body Closes CLOUD-230'
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "gh absent fails open too" {
	PATH="$BARE_PATH" run guard 'gh pr create --body Closes CLOUD-230'
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "the bypass skips the duplicate check as well as the naming check" {
	BATTEN_ISSUE_GUARD_BYPASS=1 STUB_SELF=144 STUB_PRS="145 b" STUB_BODY="CLOUD-49" \
		run guard 'gh pr create --body Closes CLOUD-49'
	! denied "$output"
}

@test "gh pr ready reads the claim from the PR it is readying" {
	# `gh pr ready <n>` carries no body, so without this the branch is the only
	# evidence — and a leftover bundle branch then contradicts the PR's own
	# `Closes:` line. The guard allowed `pr create` and denied `pr ready` on one
	# unchanged PR before this was added.
	git checkout -q -b claude/cloud-37-49-config-7ssbsh
	STUB_SELF=159 STUB_SELF_BODY="Closes CLOUD-230" \
		STUB_PRS="150 claude/git-state-core-primitives" \
		STUB_TITLE="feat: git state primitives (CLOUD-37)" \
		run guard 'gh pr ready 159'
	! denied "$output"
}

@test "a competitor is still caught when the claim comes from our own PR body" {
	git checkout -q -b some-branch
	STUB_SELF=160 STUB_SELF_BODY="Closes CLOUD-49" \
		STUB_PRS="145 other" STUB_TITLE="CLOUD-49" \
		run guard 'gh pr ready 160'
	denied "$output"
	[[ "$output" == *"#145"* ]]
}

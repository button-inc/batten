#!/usr/bin/env bats
# subject: mise-tasks/coderabbit-config-check
# The mechanism CLOUD-847 shipped without (CLOUD-860).
#
# That row landed `.coderabbit.yaml` and measured what each key buys; nothing then
# held the file to those readings. These cases pin both directions per CLOUD-418 —
# each of the three keys refused when flipped, the real file passing — plus the
# vacuity case a key-absence check needs, where a file carrying no keys satisfies
# every per-key assertion by having none to judge.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/coderabbit-config-check.sh"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# The same shape as the real file, so a fixture exercises the parser rather than a
# simplified stand-in — including the sibling tools whose `enabled:` keys are what
# make the gitleaks arm need scoping.
write_config() {
	# $1 = destination, $2 = request_changes_workflow, $3 = drafts, $4 = gitleaks enabled
	cat >"$1" <<EOF
# a leading comment, which the parser must skip
reviews:
  request_changes_workflow: $2

  auto_review:
    drafts: $3
    auto_pause_after_reviewed_commits: 50

  high_level_summary: false

  tools:
    clippy:
      enabled: false
    shellcheck:
      enabled: false
    gitleaks:
      enabled: $4
EOF
}

@test "the repo as it stands passes" {
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "the gate is wired: hk.pkl declares a step that runs this task" {
	# Asserted on the step block, not a bare grep: the surrounding comment names
	# the task too, and a comment is not a call site. A suite that passes while
	# nothing invokes the task measures only itself.
	run awk '/^  \["coderabbit-config-check"\] \{$/ { found = 1; next }
	         found && /mise run coderabbit-config-check/ { print "wired"; exit }
	         found && /^  \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "a compliant fixture passes" {
	write_config "$BATS_TEST_TMPDIR/c.yaml" true true true
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 0 ]
}

@test "request_changes_workflow flipped off fails, and names the key" {
	# Off, the bot only COMMENTS: `reviewDecision` stays null and no verdict exists.
	write_config "$BATS_TEST_TMPDIR/c.yaml" false true true
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"request_changes_workflow=false"* ]]
}

@test "drafts flipped off fails, and names the key" {
	# Off, the free phase goes back to being the unreviewed phase.
	write_config "$BATS_TEST_TMPDIR/c.yaml" true false true
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"drafts=false"* ]]
}

@test "gitleaks disabled fails: drafts would have no secret scanning at all" {
	write_config "$BATS_TEST_TMPDIR/c.yaml" true true false
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"gitleaks"* ]]
}

@test "the gitleaks arm is SCOPED to gitleaks, not to the first tool in the file" {
	# clippy and shellcheck are `enabled: false` by design. An unscoped read of
	# `enabled:` would answer about whichever tool came first and fail a compliant
	# file — the false refusal that would get this gate bypassed.
	write_config "$BATS_TEST_TMPDIR/c.yaml" true true true
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 0 ]
}

@test "gitleaks absent passes: its default is enabled, so only an explicit false is a violation" {
	cat >"$BATS_TEST_TMPDIR/c.yaml" <<'EOF'
reviews:
  request_changes_workflow: true
  auto_review:
    drafts: true
EOF
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 0 ]
}

@test "a key deleted rather than flipped fails: absence leaves the default in force" {
	# The two ways a key stops holding are the same file to CodeRabbit, so they
	# must be the same verdict here.
	cat >"$BATS_TEST_TMPDIR/c.yaml" <<'EOF'
reviews:
  auto_review:
    drafts: true
EOF
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"request_changes_workflow absent"* ]]
}

@test "a comment-only file is a failure, not a vacuous pass" {
	# The case the whole gate is shaped around: every check is an assertion ABOUT
	# a key, so a file with none satisfies all of them by having nothing to judge.
	printf '# every key deleted\n# but the file still exists\n' >"$BATS_TEST_TMPDIR/c.yaml"
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no keys at all"* ]]
}

@test "a commented-out key does not satisfy the assertion" {
	# `# drafts: true` is the shape of a key someone disabled while leaving a note.
	cat >"$BATS_TEST_TMPDIR/c.yaml" <<'EOF'
reviews:
  request_changes_workflow: true
  auto_review:
    # drafts: true
    auto_pause_after_reviewed_commits: 50
EOF
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"drafts absent"* ]]
}

@test "an absent file fails rather than passing for want of anything to read" {
	run "$CHECK" "$BATS_TEST_TMPDIR/does-not-exist.yaml"
	[ "$status" -eq 2 ]
	[[ "$output" == *"absent"* ]]
}

@test "output is pointer-only: it names keys and lines, never the file's contents" {
	# Non-negotiable rule 4. A config carries paths and instructions, and a gate
	# that echoed them would put them in every CI log.
	write_config "$BATS_TEST_TMPDIR/c.yaml" false true true
	run "$CHECK" "$BATS_TEST_TMPDIR/c.yaml"
	[[ "$output" != *"auto_pause_after_reviewed_commits"* ]]
	[[ "$output" != *"high_level_summary"* ]]
}

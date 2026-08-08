#!/usr/bin/env bats
# The one output-posture tell AGENTS.md names literally, as an exit code. The
# cases that matter are the negative ones: a message QUOTING the tell must not be
# judged as making it, which is the exact trap `run-shape-guard` fell into twice
# before its scrubber covered line-wrapped spans.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/stop-posture-check"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

check() {
	printf '%s' "$1" | "$CHECK"
}

# --- it fires, on the literals AGENTS.md itself writes down -------------------

@test "the first tell AGENTS.md names fires" {
	run check 'The land task is green. One thing I would flag is that the receipt is keyed to the old SHA.'
	[ "$status" -eq 1 ]
	[[ "$output" == *"hedged-flag-framing"* ]]
}

@test "the second tell AGENTS.md names fires" {
	run check 'Landed on main. Worth noting that config-lint still has no caller.'
	[ "$status" -eq 1 ]
	[[ "$output" == *"hedged-flag-framing"* ]]
}

@test "the inflection that a closed two-item list would have missed fires" {
	run check 'All seven pass. I should flag that the epic frontier is still empty.'
	[ "$status" -eq 1 ]
}

@test "the report carries a count" {
	run check 'Worth noting one thing. Also worth flagging another.'
	[ "$status" -eq 1 ]
	[[ "$output" == *"hedged-flag-framing 2"* ]]
}

# --- pointer-only ------------------------------------------------------------

@test "the report never echoes the sentence it judged" {
	run check 'Worth noting that account 90210 in the entity path is unredacted.'
	[ "$status" -eq 1 ]
	[[ "$output" != *"90210"* ]]
	[[ "$output" != *"entity path"* ]]
}

# --- quoting the rule is not breaking it -------------------------------------

@test "a code span carrying the tell does not fire" {
	run check 'The guard matches `worth noting` and its inflections.'
	[ "$status" -eq 0 ]
}

@test "a double-quoted span carrying the tell does not fire" {
	run check 'AGENTS.md names the tell as "one thing I would flag", which the gate now reads.'
	[ "$status" -eq 0 ]
}

@test "a block quote carrying the tell does not fire" {
	run check 'CLOUD-200 recorded it:

> its tell is hedged flag-framing, worth noting being the commonest form

That is the sentence this gate makes computable.'
	[ "$status" -eq 0 ]
}

@test "a fenced block carrying the tell does not fire" {
	run check 'The literal set is:

```
worth noting|worth flagging
```

and nothing else.'
	[ "$status" -eq 0 ]
}

@test "a LINE-WRAPPED quoted span carrying the tell does not fire" {
	# The defect this asserts against is sed being line-based by default: a
	# line-based scrub leaves the interior of a wrapped quotation exposed, so the
	# gate denies the very message documenting it. `-z` is why this passes.
	run check 'The posture section says "the failure this kills is writing findings
twice, and its tell is hedged flag-framing — worth noting being the
commonest form" and that is what the gate now reads.'
	[ "$status" -eq 0 ]
}

# --- narrowness: it judges an act of flagging, not any use of the words ------

@test "reporting a measured value is not hedged framing" {
	run check 'I noted the exit code was 2 and the receipt was absent.'
	[ "$status" -eq 0 ]
}

@test "a command flag is not hedged framing" {
	run check 'The --flag argument is passed through to the child process.'
	[ "$status" -eq 0 ]
}

@test "a plainly stated finding with a durable home does not fire" {
	run check 'config-lint claimed a --config-from caller that does not exist. Filed as CLOUD-236 and the false claim is removed in this commit.'
	[ "$status" -eq 0 ]
}

# --- failure posture ---------------------------------------------------------

@test "empty stdin is clean rather than an error" {
	run bash -c "printf '' | $CHECK"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "a clean message produces no output at all" {
	# The overload this asserts against: a predicate whose fail-open path and whose
	# fired path both exit 0 fires on every turn. Silence on the clean path is what
	# makes the caller's `&& exit 0` meaningful.
	run check 'Landed on main by fast-forward, CI green. CLOUD-233 is Done.'
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

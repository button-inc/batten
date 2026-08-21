#!/usr/bin/env bats
# subject: mise-tasks/spec-ref-check
# CLOUD-809. Every case runs against a throwaway tree via `SPEC_REF_ROOT`, never
# this checkout: the gate scans `git ls-files`, so a suite running here would be
# judging the repository's own live citations and would go red or green for
# reasons that have nothing to do with the code under test.
#
# The payloads are fixtures rather than live `get_issue` output for the same
# reason `ready-lint`'s suite uses fixtures — a test that needs a tracker
# credential is a test CI cannot run.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/spec-ref-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/mise-tasks"
	git -C "$REPO" init --quiet
	# The identity is set PER FIXTURE, never inherited: a CI runner carries no
	# global one, so a bare commit here is `fatal: empty ident name` and fails
	# only there. Every fixture suite in this tree spells it the same way.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t

	# CLOUD-420's real clause set, which is the whole point of the witness below:
	# §1, §2, §3, §6, §8 and no §4. `Engine gap, per §2 (§3)` is kept verbatim
	# because it is the label that names two numbers, and the over-declaring
	# branch has to survive it.
	PAYLOAD="$BATS_TEST_TMPDIR/payload.json"
	cat >"$PAYLOAD" <<'JSON'
[{"id":"CLOUD-420","description":"**Refinement — Ready**\n\n* **Source of truth (§1).** The lease ref.\n* **Mechanism (§3).** land-lock gains a read-only verb.\n* **THE HAZARD — a stop is a third answer (§2).** Cancelled is the one that works.\n* **Below it, for free (§3).** Extend ready-guard.\n* **Engine gap, per §2 (§3).** Extends ci-local-parity.\n* **Commit / bump (§6):** `feat(ci)`.\n* **Blockers (§8):** blockedBy CLOUD-363.\n"},
 {"id":"CLOUD-326","description":"**Refinement — Ready**\n\n* **Source of truth (§1).** The transcript corpus.\n* **Blockers (§8).** N independent sessions.\n"}]
JSON
}

# Stage a tracked file carrying the given lines, and run the gate over it.
scan() {
	printf '%s\n' "$@" >"$REPO/mise-tasks/subject"
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m fixture
	run env SPEC_REF_ROOT="$REPO" bash -c "'$CHECK' < '$PAYLOAD'"
}

# THE REGRESSION WITNESS, and it is a real defect rather than an invented one:
# `CLOUD-420 §4` was cited at mise-tasks/land-lock:459, tests/land-lock.bats:1172
# and tests/ready-guard.bats:46 on `main`, and CLOUD-420 has no §4. The content
# meant is under its §3. This case is why the gate exists; it must never pass.
@test "a citation naming a clause the issue does not carry is reported with its pointer" {
	scan "# the offline half (CLOUD-420 §4)"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/subject:1 CLOUD-420 §4 absent-issue-clause"* ]]
}

@test "a citation naming a clause the issue does carry passes" {
	scan "# the receipt ready-guard reads (CLOUD-420 §3)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every CLOUD-<n> §N citation resolves"* ]]
}

# CLOUD-326 §8.1 is on `main`. §8.1 is a nested point under the §8 label the
# block actually carries, so resolving to the parent is the only reading that
# does not report a correct citation.
@test "a sub-numbered citation resolves to its parent clause" {
	scan "# the unblock condition (CLOUD-326 §8.1)"
	[ "$status" -eq 0 ]
}

@test "the possessive form is read as a citation" {
	scan "# CLOUD-420's §4 says so"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-420 §4 absent-issue-clause"* ]]
}

# A label carrying two numbers must declare both, or the gate reports a correct
# citation of the tag it failed to read. `Engine gap, per §2 (§3)` is that label.
@test "a clause label naming two numbers declares both" {
	scan "# per the engine gap (CLOUD-420 §2)"
	[ "$status" -eq 0 ]
}

# CLOUD-189's shape: an issue nobody fetched looks exactly like an issue with no
# defects. Exit 2 is the only honest answer, and a silent 0 is the false green
# this repository keeps meeting in new disguises.
@test "a cited issue absent from the payload set is exit 2, never a silent pass" {
	scan "# see CLOUD-999 §1"
	[ "$status" -eq 2 ]
	[[ "$output" == *"CLOUD-999 unjudgeable-issue"* ]]
}

# A finding this gate PROVED is wrong stays wrong whatever else it could not see.
# Reporting exit 2 here would let a real defect hide behind an unfetched sibling.
@test "a proven finding outranks an unfetched issue" {
	scan "# the offline half (CLOUD-420 §4)" "# see CLOUD-999 §1"
	[ "$status" -eq 1 ]
}

@test "empty stdin is exit 2" {
	printf '# nothing to see\n' >"$REPO/mise-tasks/subject"
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m fixture
	run env SPEC_REF_ROOT="$REPO" bash -c "'$CHECK' < /dev/null"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
}

@test "stdin that is not a get_issue payload set is exit 2" {
	printf '# nothing to see\n' >"$REPO/mise-tasks/subject"
	git -C "$REPO" add -A
	git -C "$REPO" commit -q -m fixture
	run env SPEC_REF_ROOT="$REPO" bash -c "printf '[{\"id\":\"CLOUD-1\"}]' | '$CHECK'"
	[ "$status" -eq 2 ]
	[[ "$output" == *"need id and description"* ]]
}

@test "a tree with no citations at all passes" {
	scan "# no section references here"
	[ "$status" -eq 0 ]
}

# Non-negotiable rule 4, asserted rather than assumed: issue bodies carry decision
# history, and a gate that echoed them republishes it into every CI log that runs
# it. The finding must be a pointer and nothing more.
@test "the emitted bytes carry no substring of any issue body" {
	scan "# the offline half (CLOUD-420 §4)"
	[ "$status" -eq 1 ]
	[[ "$output" != *"lease ref"* ]]
	[[ "$output" != *"read-only verb"* ]]
	[[ "$output" != *"Cancelled is the one"* ]]
	[[ "$output" != *"blockedBy"* ]]
}

# The gate documents the CLOUD-420 §4 pair in its header and this suite carries it
# as a fixture. Scanning either would report the witness as a live defect, which
# is unfixable — the finding would survive every correction.
@test "the gate does not report its own header or suite" {
	mkdir -p "$REPO/tests"
	cp "$CHECK" "$REPO/mise-tasks/spec-ref-check"
	cp "$BATS_TEST_DIRNAME/spec-ref-check.bats" "$REPO/tests/spec-ref-check.bats"
	scan "# no section references here"
	[ "$status" -eq 0 ]
}

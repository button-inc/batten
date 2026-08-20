#!/usr/bin/env bats
# CLOUD-508. The half that records how fresh a read of an issue was.
#
# Split from `issue-read-guard.bats` for the reason `claim-check` is split from
# the claim gate: `mutant` derives a suite from the gate's own name, so a decision
# and its adapter each need their own file to be coverable at all.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir — the receipt is stored under `$GIT_DIR`, and a suite running in this
# repo's checkout would mint receipts that authorise a real session's writes.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/issue-read-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# Per fixture, never inherited: a CI runner carries no global identity, so a
	# bare `git commit` here fails only there.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
	RECEIPTS="$REPO/.git/batten-receipts"
}

payload() {
	jq -nc --arg id "${1:-CLOUD-1}" --arg u "${2:-2026-08-13T04:00:00.000Z}" \
		'{id: $id, updatedAt: $u, status: "Todo"}'
}

@test "a get_issue payload mints a receipt keyed by the issue" {
	# Piped directly, never through `bash -c "$(payload) | …"`: that embeds the
	# JSON into a shell string, which reinterprets its braces and quotes before
	# the gate sees them. `issue-search-guard.bats` records the same trap costing
	# it nine of fifteen rows.
	run bash -c "'$CHECK'" <<<"$(payload)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/issue-read.CLOUD-1" ]
	[[ "$output" == *"CLOUD-1"* ]]
}

# The receipt must carry WHEN, not only THAT. Existence alone is the gate this
# replaces — the claim gate's shape — and it cannot express a bound.
@test "the receipt records the revision seen and the time it was seen" {
	payload CLOUD-7 "2026-08-13T03:00:00.000Z" | "$CHECK" >/dev/null
	local line
	line=$(cat "$RECEIPTS/issue-read.CLOUD-7")
	[[ "$line" == "CLOUD-7 2026-08-13T03:00:00.000Z "* ]]
	# Field 3 is an epoch the guard subtracts from `now`; a non-numeric one makes
	# the guard fail open, so its shape is part of the contract between them.
	local stamp
	stamp=$(awk '{print $3}' <<<"$line")
	[[ "$stamp" =~ ^[0-9]+$ ]]
}

# The row the `receipt-carries-no-time` mutation is written against, and which did
# not exist: that mutation pins `read_at` to 0, and 0 is numeric, so the shape
# assertion above passes under it unchanged. A receipt frozen at the epoch reads
# as ~56 years old to `issue-read-guard`, which denies every write — so the
# mutation's damage is invisible in this suite and loud in production. The value
# has to be tied to NOW, not merely to a digit class.
@test "the recorded time is when the read happened, so a receipt can actually age" {
	local before after stamp
	before=$(date -u +%s)
	payload CLOUD-71 | "$CHECK" >/dev/null
	after=$(date -u +%s)
	stamp=$(awk 'NR==1{print $3}' "$RECEIPTS/issue-read.CLOUD-71")
	[ "$stamp" -ge "$before" ]
	[ "$stamp" -le "$after" ]
}

# Field 4 is the BODY BASELINE `claim-check` compares against (CLOUD-597,
# CLOUD-615). The contract between the two files is that it moves when the body
# moves and holds still when anything else about the row changes — which is the
# whole reason it exists, since `updatedAt` cannot tell those apart.
@test "the receipt records a body hash that tracks the body and nothing else" {
	local with_body
	with_body() { # with_body <key> <updatedAt> <description>
		jq -nc --arg id "$1" --arg u "$2" --arg d "$3" \
			'{id: $id, updatedAt: $u, status: "Todo", description: $d}'
	}
	field4() { awk 'NR==1{print $4}' "$RECEIPTS/issue-read.$1"; }

	with_body CLOUD-597 "2026-08-13T03:00:00.000Z" "the body" | "$CHECK" >/dev/null
	local first
	first=$(field4 CLOUD-597)
	[[ "$first" =~ ^[0-9a-f]{40}$ ]]

	# The CLOUD-597 shape: the row was touched, the body was not.
	with_body CLOUD-597 "2026-08-14T09:99:00.000Z" "the body" | "$CHECK" >/dev/null
	[ "$(field4 CLOUD-597)" = "$first" ]

	# And the shape the rule must still catch: the body itself changed.
	with_body CLOUD-597 "2026-08-13T03:00:00.000Z" "the body, refined" | "$CHECK" >/dev/null
	[ "$(field4 CLOUD-597)" != "$first" ]
}

# CLOUD-526 / CLOUD-691. This row previously asserted the opposite — that an
# absent body hashes the empty string "so the baseline is never a lie" — and the
# behaviour it pinned was the lie. `jq -r '.description // ""'` emitted a lone
# newline, which hashed to 8b137891791fe96927ad78e64b0aad7bded08bdc: a 40-hex
# digest indistinguishable from a real one, identical for every bodyless payload,
# and treated by `claim-check` as a baseline to compare against. It was minted
# seven times on 2026-08-18 and twice more on 2026-08-19 before anyone looked.
@test "a payload with no description records no baseline, rather than a digest of nothing" {
	payload CLOUD-3 | "$CHECK" >/dev/null
	[ "$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-3")" = "-" ]
}

# The specific constant, named, because "not a digest" is satisfied by any bug
# that writes a different wrong thing. This is the value that actually shipped.
@test "the empty-body digest 8b13789 is never written for an absent description" {
	payload CLOUD-31 | "$CHECK" >/dev/null
	local field4
	field4=$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-31")
	[ "$field4" != "8b137891791fe96927ad78e64b0aad7bded08bdc" ]
	# And derived rather than trusted: recompute it the way the minting side used
	# to, so the constant above cannot drift away from what it names.
	[ "$field4" != "$(jq -rn 'null // ""' | git hash-object --stdin)" ]
}

# An explicitly null body is the same fact as an absent one, and a `has()` test
# alone would let it through to `jq -r`, which renders it as the string "null".
@test "an explicitly null description records no baseline either" {
	jq -nc '{id: "CLOUD-32", updatedAt: "2026-08-13T04:00:00.000Z", description: null}' | "$CHECK" >/dev/null
	[ "$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-32")" = "-" ]
}

# Field 5 is the COLUMN the read saw (CLOUD-775), and `finding-sink-check` reads
# it to tell an annotation on a terminal row from an amendment to an open one.
@test "the receipt records the column the read saw" {
	jq -nc '{id: "CLOUD-775", updatedAt: "2026-08-20T04:00:00.000Z", status: "Done"}' | "$CHECK" >/dev/null
	[ "$(awk 'NR==1{print $5}' "$RECEIPTS/issue-read.CLOUD-775")" = "done" ]
}

# The delimiter, which is the whole reason the value is normalised rather than
# written through: half the board's columns carry a space, and `In Progress`
# verbatim makes field 5 `In` and field 6 `Progress`. Field 6 is asserted empty,
# because "field 5 is in-progress" alone passes against a receipt that also
# spilled a sixth field.
@test "a column with a space is one field, not two" {
	jq -nc '{id: "CLOUD-776", updatedAt: "2026-08-20T04:00:00.000Z", status: "In Progress"}' | "$CHECK" >/dev/null
	local line
	line=$(cat "$RECEIPTS/issue-read.CLOUD-776")
	[ "$(awk 'NR==1{print $5}' <<<"$line")" = "in-progress" ]
	[ -z "$(awk 'NR==1{print $6}' <<<"$line")" ]
}

# The row the `absent-status-reads-open` mutation is written against, and the
# direction the whole arm rests on. An omitted status must record `-`, which
# `finding-sink-check` reads as "could not look" and still reports on — so
# sending less makes that gate louder. A plausible open column recorded here
# instead is the forgery: a receipt asserting a row is open when nothing was ever
# read about it, minted by sending LESS. It is the hollow digest one field over
# (CLOUD-691) in a second spelling.
@test "a payload with no status records no column, rather than one that reads as open" {
	run bash -c "'$CHECK'" <<<"$(jq -nc '{id: "CLOUD-777", updatedAt: "2026-08-20T04:00:00.000Z"}')"
	[ "$status" -eq 0 ]
	[ "$(awk 'NR==1{print $5}' "$RECEIPTS/issue-read.CLOUD-777")" = "-" ]
}

# An explicitly null column is the same fact as an absent one, and a `has()` test
# alone would let it through to `jq -r`, which renders it as the string "null" —
# a column name no board carries and no reader recognises.
@test "an explicitly null status records no column either" {
	jq -nc '{id: "CLOUD-778", updatedAt: "2026-08-20T04:00:00.000Z", status: null}' | "$CHECK" >/dev/null
	[ "$(awk 'NR==1{print $5}' "$RECEIPTS/issue-read.CLOUD-778")" = "-" ]
}

# The arms are independent. A payload carrying a body and no status, or a status
# and no body, must record the one it has and `-` for the one it does not —
# otherwise the projection CLOUD-526 bought is silently re-coupled.
@test "the body baseline and the column arm do not depend on each other" {
	jq -nc '{id: "CLOUD-779", updatedAt: "x", description: "a body"}' | "$CHECK" >/dev/null
	[[ "$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-779")" =~ ^[0-9a-f]{40}$ ]]
	[ "$(awk 'NR==1{print $5}' "$RECEIPTS/issue-read.CLOUD-779")" = "-" ]

	jq -nc '{id: "CLOUD-780", updatedAt: "x", status: "Todo"}' | "$CHECK" >/dev/null
	[ "$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-780")" = "-" ]
	[ "$(awk 'NR==1{print $5}' "$RECEIPTS/issue-read.CLOUD-780")" = "todo" ]
}

# CLOUD-526's accept row: the declared field set is `id` and `updatedAt`, and a
# payload carrying exactly those is accepted. This is the row that buys the
# projection — without it, "the gate no longer demands the body" is a claim
# nothing holds to.
@test "a payload carrying only the declared field set is accepted" {
	run bash -c "'$CHECK'" <<<"$(jq -nc '{id: "CLOUD-33", updatedAt: "2026-08-13T04:00:00.000Z"}')"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/issue-read.CLOUD-33" ]
}

# Pointer-only, non-negotiable 4. A receipt is read by a human debugging a
# refusal, and an issue body can carry anything.
@test "the receipt carries no title and no body" {
	jq -nc '{id: "CLOUD-2", updatedAt: "2026-08-13T04:00:00.000Z", title: "a secret name", description: "a secret body"}' | "$CHECK" >/dev/null
	run cat "$RECEIPTS/issue-read.CLOUD-2"
	[[ "$output" != *"secret"* ]]
}

# A FRESH READ MUST OVERWRITE A STALE ONE. `issue-search-check` appends, because
# its receipt accumulates what the author has seen; this one answers "how old is
# the newest read", and an append would leave the guard parsing whichever line
# came first — the stalest.
@test "a second read replaces the first rather than appending" {
	payload CLOUD-3 | "$CHECK" >/dev/null
	payload CLOUD-3 | "$CHECK" >/dev/null
	run wc -l <"$RECEIPTS/issue-read.CLOUD-3"
	[ "${output// /}" = 1 ]
}

@test "reads of different issues do not authorise each other" {
	payload CLOUD-4 | "$CHECK" >/dev/null
	[ -f "$RECEIPTS/issue-read.CLOUD-4" ]
	[ ! -f "$RECEIPTS/issue-read.CLOUD-5" ]
}

# CLOUD-526's refuse row, and the inversion of what stood here. Recording `-` for
# an absent `updatedAt` mints a receipt that cannot name the revision it read,
# which is the same defect as the hollow body digest one field over: a real file
# on disk, satisfying `issue-read-guard`, attesting to nothing. `updatedAt` is in
# the declared field set, so its absence is refused by name.
@test "a payload missing updatedAt is refused rather than minting a receipt that names no revision" {
	run bash -c "'$CHECK'" <<<"$(jq -nc '{id: "CLOUD-6", status: "Todo"}')"
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPTS/issue-read.CLOUD-6" ]
	[[ "$output" == *"updatedAt"* ]]
	# Pointer-only: the refusal names the field, never a byte of the payload.
	[[ "$output" != *"Todo"* ]]
}

@test "a single-element array is accepted, so a list payload of one composes" {
	run bash -c "jq -nc '[{id: \"CLOUD-8\", updatedAt: \"x\"}]' | '$CHECK'"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/issue-read.CLOUD-8" ]
}

# Exit 2 is "I could not read the input", distinct from exit 1 "this is not a
# usable read" — a caller piping the wrong thing must not look like one who
# skipped the step. Same split as `claim-check` and `issue-search-check`.
@test "stdin that is not a get_issue payload is exit 2, not a silent mint" {
	local bad
	for bad in 'not json' '{}' '{"title":"no id"}' '[]'; do
		run bash -c "printf '%s' '$bad' | '$CHECK'"
		[ "$status" -eq 2 ]
	done
	run bash -c "ls '$RECEIPTS' 2>/dev/null"
	[ -z "$output" ]
}

# The receipt namespace is issue KEYS. A payload naming the row some other way
# cannot be filed against one, and inventing a name would mint a receipt the
# guard can never match — a hole rather than a refusal.
@test "an id that is not an issue key is refused rather than filed under a made-up name" {
	run bash -c "jq -nc '{id: \"7f3a-not-a-key\", updatedAt: \"x\"}' | '$CHECK'"
	[ "$status" -eq 1 ]
	run bash -c "ls '$RECEIPTS' 2>/dev/null"
	[ -z "$output" ]
}

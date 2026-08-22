#!/usr/bin/env bash
#MISE description="Gate: record how fresh your read of an issue was (reads a get_issue payload on stdin, mints the receipt issue-read-guard demands)"
#
# CLOUD-508. CLOUD-505 gated the path that CREATES rows and said, correctly, that
# "an update must never be denied, or every edit to an issue needs a search
# first". That leaves the update path with a different hazard it does not claim
# to cover: an update is written against a snapshot the agent read at some
# earlier, unbounded time, and nothing anywhere bounds that gap.
#
# Measured 2026-08-13. A session read CLOUD-504 at 01:16:08, planned against it,
# and wrote at 02:07:36 — appending a Ready block and moving it Backlog -> Todo.
# In between, another session marked it a duplicate. ~51 minutes between the read
# the plan was built on and the write it authorised, and a known duplicate landed
# in the ready queue where `graph-check`'s frontier offers pullable work. It was
# caught by reading the response, which is not a gate.
#
# A RECENCY BOUND, NOT A FRESHNESS PROOF — and the difference is the whole
# design, so it is stated here rather than discovered later. A true
# compare-and-swap is NOT available: `save_issue` takes no if-match parameter, so
# nothing can make the write itself conditional, and an update always wins over
# whatever landed since the read. What IS computable locally is how old the read
# was: two clock readings, no network. That bounds the window a concurrent edit
# can hide in; it does not close it. Anything stronger needs the tracker to offer
# a precondition on write, which is a capability gap (CLOUD-312's line), not
# something to simulate here.
#
# This is `claim-check`'s inversion, borrowed wholesale for the reason that file
# gives: no tracker credential exists in a hook, so the read cannot happen there.
# The agent already did it. This records that it happened AND WHEN, and the guard
# demands the record be recent.
#
# KEYED BY ISSUE, not by branch — the one place this departs from
# `claim-check` and `issue-search-check`, and it departs deliberately. A claim and
# a search each attest to a decision about what to WORK ON, which every commit on
# that branch continues to serve. This attests to a fact about one ROW at one
# moment, and a single branch legitimately updates several issues; a branch key
# would let a fresh read of one issue authorise a stale write to another.
#
# Usage: mise run issue-read-check   (a get_issue payload on stdin)
#
# DECLARED FIELD SET (CLOUD-526): `id` and `updatedAt`, both required, plus
# `description` on the optional baseline arm and `status` on the optional column
# arm (CLOUD-775). Sending fields it does not read is harmless; sending a body it
# does not need is the cost this gate stopped charging. Both arms record `-` when
# absent, and `-` is read downstream as "could not look" — so an omission always
# makes a later gate louder, never quieter.
#
# Exit 0 receipt minted / 1 the payload is not a usable read / 2 unreadable
# stdin — matching `claim-check` and `issue-search-check` so all three compose.
#
# The mutation drops the timestamp from the receipt, so every receipt reads as
# age zero and the guard can only ever test existence — which is the gate this
# replaces, and every DENY row for a missing receipt still passes.
#MUTANT receipt-carries-no-time|s/read_at=\$(date -u +%s)/read_at=0/|so a receipt can actually age
set -uo pipefail

if ! payload=$(jq -sc 'if length == 1 and (.[0] | type == "array") and (.[0] | length == 1) then .[0][0] elif length == 1 then .[0] else . end' 2>/dev/null); then
	echo "::error:: issue-read-check: stdin is not JSON — pipe a get_issue payload" >&2
	exit 2
fi

# One issue, not a set. `claim-check` and `graph-check` take a set because they
# decide over a frontier; this records a single read, and accepting an array
# would make "which row did you actually look at" ambiguous at the receipt.
if ! jq -e 'type == "object" and has("id")' <<<"$payload" >/dev/null 2>&1; then
	echo "::error:: issue-read-check: stdin is not a get_issue payload (want one object carrying an id)" >&2
	exit 2
fi

# THE DECLARED FIELD SET (CLOUD-526). This gate decides two things — which row
# was read, and at which revision — so `id` and `updatedAt` are what it is
# entitled to demand, and it demands both. `description` is NOT in the set: it is
# read by exactly one arm below, and that arm is optional by construction.
#
# The rule the projection must not break is `claim-check`'s: "a rule that
# silently disappears when a field is absent is a rule an agent turns off by
# sending less." It survives because narrowing here is a REFUSAL, never a skip —
# a payload missing `updatedAt` is turned away by name rather than recorded with
# an invented value.
if ! jq -e 'has("updatedAt") and (.updatedAt != null)' <<<"$payload" >/dev/null 2>&1; then
	echo "::error:: issue-read-check: payload carries no updatedAt — the receipt cannot say which revision was read. Re-fetch with get_issue." >&2
	exit 1
fi

key=$(jq -r '.id' <<<"$payload")

# The receipt namespace is issue KEYS. A payload identifying the row some other
# way cannot be filed against one, and inventing a name for it would mint a
# receipt the guard can never match — a silent hole rather than a refusal.
case "$key" in
[A-Z]*-[0-9]*) ;;
*)
	echo "::error:: issue-read-check: \"$key\" is not an issue key (want CLOUD-123) — nothing to key a receipt to" >&2
	exit 1
	;;
esac

# `updatedAt` is what the read SAW; `read_at` is when it saw it. Both are
# recorded because they answer different questions: the guard compares `read_at`
# against now, and a human debugging a refusal wants to know which revision the
# author had in front of them. Its presence is asserted above rather than
# defaulted here (CLOUD-526): a receipt that cannot name a revision is a receipt
# that attests to nothing, which is the same defect as a hollow body digest.
seen=$(jq -r '.updatedAt' <<<"$payload")
read_at=$(date -u +%s)

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: issue-read-check: not a git repository — cannot record the read" >&2
	exit 2
}

mkdir -p "$git_dir/batten-receipts" 2>/dev/null || {
	echo "::error:: issue-read-check: cannot create the receipt store" >&2
	exit 2
}

# No branch in the key, and no slashes possible in an issue key, so no
# substitution is needed here — but the spelling must match `issue-read-guard`'s
# exactly, which is why both files name it in one place each and nowhere else.
receipt="$git_dir/batten-receipts/issue-read.$key"

# THE BODY BASELINE, a fourth field (CLOUD-597, CLOUD-615). `claim-check`'s
# `refined-this-session` rule used to compare two clocks — the row's `updatedAt`
# against the container's session stamp — and NEITHER measures "did this agent
# refine this story". Every write to the row moves the first (a label, an
# assignee, a reciprocal relation written by another issue's creation), and every
# container restart resets the second. So the rule refused claims nobody had
# refined and passed self-refinements laundered by a restart, in the same hour.
#
# Recording what the body WAS when this clone read it turns the question into
# content against content: "did the body change under this clone". A relation
# write does not move it; writing a Ready block does. It survives a restart
# because it lives in the clone, not in the container.
#
# This is the natural place for it and not an extra step: `issue-read-guard`
# already denies `save_issue` without a fresh receipt from here, so refining an
# issue REQUIRES first recording what it looked like beforehand.
#
# `git hash-object` rather than `sha256sum`: git is already required in this
# file, and `sha256sum` does not exist on macOS, which `cross-check` covers.
#
# THE BASELINE IS AN ARM, NOT THE CONTRACT (CLOUD-526). `description` is the
# largest field on the row and the model transports it by re-typing it, so
# demanding it on every read prices this gate — the pre-condition of every
# `save_issue` — at the size of the artifact rather than the size of the
# question. A caller that only needs to date its read sends no body and gets a
# receipt that says so.
#
# `// ""` USED TO STAND WHERE THE `has` TEST NOW DOES, and it is the single
# operator that made the forgery indistinguishable from the honest read
# (CLOUD-691). An absent `description` fell through it to the empty string, which
# `jq -r` emitted as a lone newline, which hashed to
# 8b137891791fe96927ad78e64b0aad7bded08bdc — a real-looking 40-hex digest that
# `claim-check` then compared against as though it were a baseline. Two payloads
# with no body matched each other. Measured seven times on 2026-08-18 and twice
# more on 2026-08-19.
#
# `-` is the honest answer and it is not a weakening: `claim-check` already reads
# `-` as "no baseline" and falls back to the clock pair, which refuses on any
# write to the row. Sending less therefore makes a claim HARDER, never easier,
# which is the direction the incentive has to point.
#
# The mutation widens the arm's guard back to something every payload satisfies,
# so a bodyless read takes the hashing branch again and records a 40-hex digest
# where `-` belongs — the hollow receipt, by the route it actually shipped.
# (No `|` may appear in a mutation script: `mutant` splits these rows on it.)
#MUTANT hollow-digest-restored|s@has("description") and (.description != null)@has("id")@|records no baseline
if jq -e 'has("description") and (.description != null)' <<<"$payload" >/dev/null 2>&1; then
	body_hash=$(jq -r '.description' <<<"$payload" | git hash-object --stdin 2>/dev/null) || body_hash="-"
	[[ -n "$body_hash" ]] || body_hash="-"
else
	body_hash="-"
fi

# THE STATUS ARM, a fifth field (CLOUD-775). `finding-sink-check` decides whether
# a turn that cited evidence gave the finding a HOME, and since CLOUD-475 it has
# split tracker writes on a proxy: a `save_issue` with no `id` opens a row, one
# WITH an id annotates a row that may be terminal. The proxy is right about a
# comment onto the Done issue that shipped the defect and wrong about the
# symmetric case — amending a row that is still open schedules the work, and was
# reported as a stranding. The target's state is not lookupable in a hook (no
# tracker credential, `claim-check`'s constraint), but this receipt already
# exists for every row by the time anything annotates it: `issue-read-guard`
# denies `save_issue` without one. So the column the read SAW is recorded here
# and read there, and an uncomputable question becomes a local file read.
#
# AN ARM, NOT A FIELD OF THE DECLARED SET, exactly like `description` above and
# for the same CLOUD-526 reason: the declared set is what this gate DECIDES over
# — which row, at which revision — and `status` decides nothing here. Demanding
# it would price every read on behalf of a different gate's question.
#
# WHICH MEANS THE DIRECTION IS THE SAFETY ARGUMENT. Absent records `-`, which
# `finding-sink-check` reads as "could not look" and STILL REPORTS. Sending less
# makes that gate LOUDER, so there is no payload an author can send, and no
# payload they can withhold, that buys silence. `-` already points this way one
# field over (CLOUD-691), where the opposite — a plausible value invented for an
# absent field — is the hollow digest that shipped.
#
# NORMALISED, because the receipt is space-delimited and half the board's columns
# carry a space. `In Progress` written through would make field 5 `In` and field 6
# `Progress`, and every positional reader downstream would be reading a fragment.
# Lowercase with non-alphanumerics folded to `-`: `todo`, `in-progress`, `done`.
# Appending is safe for the readers that exist — `issue-read-guard` reads field 3,
# `claim-check` field 4, and neither moves.
#
# The mutation gives the absent arm a plausible open column instead of `-`, which
# is the forgery this shape exists to refuse: a receipt asserting a row is open
# when nothing was ever read about it, minted by sending LESS.
#MUTANT absent-status-reads-open|s@seen_status="-"@seen_status="todo"@|a payload with no status records no column
if jq -e 'has("status") and (.status != null)' <<<"$payload" >/dev/null 2>&1; then
	seen_status=$(jq -r '.status | ascii_downcase | gsub("[^a-z0-9]+"; "-")' <<<"$payload" 2>/dev/null) || seen_status="-"
	[[ -n "$seen_status" ]] || seen_status="-"
else
	seen_status="-"
fi

# TRUNCATED, never appended, unlike `issue-search-check`'s. A search receipt
# accumulates what the author has seen; this one answers "how old is the newest
# read", and an append would leave the guard reading whichever line it happened
# to parse first — the freshest read must overwrite the stalest.
printf '%s %s %s %s %s\n' "$key" "$seen" "$read_at" "$body_hash" "$seen_status" >"$receipt" 2>/dev/null || {
	echo "::error:: issue-read-check: cannot write $receipt" >&2
	exit 2
}

# Pointer-only (non-negotiable 4): the key and the revision it was read at, never
# a title and never a line of the body.
echo "issue-read-check: $key read at $seen — an update is authorised for the next ${BATTEN_ISSUE_READ_MAX_AGE:-300}s"

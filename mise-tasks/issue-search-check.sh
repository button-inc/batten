#!/usr/bin/env bash
#MISE description="Gate: you searched the board before filing (reads a list_issues payload on stdin, mints the receipt issue-search-guard demands)"
#
# CLOUD-505. Every path ONTO the board is gated except the one that creates rows.
# `claim-check` refuses an issue already claimed, the engine's claim receipt an
# edit with no
# claim receipt, `issue-guard` a PR naming no issue, `ready-lint` an unrefined
# block, `graph-check` an incoherent frontier. Filing has none, and the cost is
# not a redundant row: measured 2026-08-13, a session blocked behind a starved
# landing lease spent ~45 minutes re-deriving a cause that was already filed and
# searchable, reported twice to a human that no answer was available, and filed a
# duplicate of an issue two searches return in seconds.
#
# THE OBVIOUS GATE IS FORBIDDEN. Scoring a candidate against open issues and
# refusing above a threshold is a model verdict, and non-negotiable 3 says a gate
# resolves to a command and an exit code over an object it decides. So this does
# not judge similarity, does not read the candidate at all, and cannot tell you
# whether what you are about to file is a duplicate.
#
# WHAT IT DOES INSTEAD is `claim-check`'s inversion, and the reasoning is that
# file's, borrowed wholesale: no tracker credential exists in a hook, so the
# lookup cannot happen there. The agent already has one. So the agent searches,
# this records that the search happened, and the guard demands the record. The
# receipt is the search's local durable trace, which is what makes the guard a
# pure function of the filesystem.
#
# THE HONEST LIMIT, stated because it will occur to every reader: nothing stops a
# nonsense search satisfying this. It does not have to. The claim receipt has the
# identical property — its receipt attests that a read happened, not that it was
# understood — and that was accepted there deliberately. The gate forces the
# ACTION; an agent that runs the search sees the results, and seeing them is the
# whole failure mode. Anything stronger judges the query.
#
# Keyed by BRANCH, like `claim-check`'s receipt and for the same reason: a search
# attests to a decision about what to file, and every filing on that branch
# continues to serve it. A SHA key would demand a re-search per commit.
#
# Usage: mise run issue-search-check   (a list_issues payload on stdin)
#
# Exit 0 receipt minted / 1 the payload is not a usable search / 2 unreadable
# stdin — matching `claim-check` so the two compose in one pipeline.
#
# The mutation removes the shape check, so anything piped in mints a receipt —
# which turns the gate into a rubber stamp while every row that asserts a DENY
# still passes. Only the cannot-look rows can catch it.
#MUTANT any-payload-is-a-search|s/all(\.\[\]; type == "object" and has("id"))/true/|a payload that is not a search cannot look
set -uo pipefail

# Exit 2 is "I could not read the input", distinct from exit 1 "you did not
# search" — a caller piping the wrong thing must not look like a caller who
# skipped the step.
if ! payload=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] elif length == 1 and (.[0] | type == "object") and (.[0] | has("issues")) then .[0].issues else . end' 2>/dev/null); then
	echo "::error:: issue-search-check: stdin is not JSON — pipe a list_issues payload" >&2
	exit 2
fi

if ! jq -e 'type == "array"' <<<"$payload" >/dev/null 2>&1; then
	echo "::error:: issue-search-check: stdin is not a list_issues payload (want an array of issues, or {issues: [...]})" >&2
	exit 2
fi

# An array of things that are not issues is a caller piping the wrong shape, not
# a search. Every element must carry an id, the one field every list_issues
# result has whatever `fields` was requested.
if ! jq -e 'all(.[]; type == "object" and has("id"))' <<<"$payload" >/dev/null 2>&1; then
	echo "::error:: issue-search-check: stdin is not a list_issues payload (an element carries no id)" >&2
	exit 2
fi

# A SEARCH THAT RETURNED NOTHING IS STILL A SEARCH, and this is the load-bearing
# case rather than an edge one. The commonest honest outcome of searching before
# filing a genuinely new finding is zero hits — refusing it would make the gate
# punish exactly the behaviour it exists to produce, and teach the bypass.
count=$(jq 'length' <<<"$payload")

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: issue-search-check: not a git repository — cannot record the search" >&2
	exit 2
}
branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || branch=""
[[ -n "$branch" ]] || {
	echo "::error:: issue-search-check: detached HEAD — no branch to key the receipt to" >&2
	exit 2
}

mkdir -p "$git_dir/batten-receipts" 2>/dev/null || {
	echo "::error:: issue-search-check: cannot create the receipt store" >&2
	exit 2
}

# Slashes are the one character a filename cannot carry; the substitution must
# match `issue-search-guard`'s spelling exactly.
receipt="$git_dir/batten-receipts/issue-search.${branch//\//-}"

# The ids seen, so the receipt is a record of WHAT was in front of the author
# rather than merely that a command ran. Pointer-only (non-negotiable 4): ids,
# never titles or bodies — a receipt is read by humans debugging a refusal.
jq -r '[.[].id] | join(" ")' <<<"$payload" >>"$receipt" 2>/dev/null || {
	echo "::error:: issue-search-check: cannot write $receipt" >&2
	exit 2
}

# THE `origin/main` THIS SEARCH WAS MADE AGAINST, and the engine will not accept a
# branch-keyed receipt without it (CLOUD-312 row 1, CLOUD-516). A branch NAME
# outlives the branch it described: `git checkout -B <name> origin/main` recycles
# one, so a receipt keyed on the name alone lets a previous occupant's search
# authorise this occupant's filing. `receipt::branch_validity` refuses a body that
# cannot say what it was taken against, which made the existence-only receipt this
# task used to write unsatisfiable by the row that replaced the guard — the gate
# would have been silently un-passable rather than merely weak.
#
# `-` when the ref cannot be read, which the reader treats as unproven: a search
# whose base could not be established is exactly as unproven as one made against
# something that has since moved. Same spelling and same reason as `claim-check`.
echo "base $(git rev-parse --verify --quiet origin/main || echo -)" >>"$receipt" 2>/dev/null || {
	echo "::error:: issue-search-check: cannot record the base in $receipt" >&2
	exit 2
}

echo "issue-search-check: search recorded for branch \"$branch\" ($count issue(s) seen)"

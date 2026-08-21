#!/usr/bin/env bash
#MISE description="Effect: how many paths an issue body names that this branch is also changing (body on stdin; prints the count and the paths)"
#
# CLOUD-514's missing half. `filed-here-check` charges a new row a complete Ready
# block, on the theory that filing is cheap and fixing is expensive so the toll
# reverses the arithmetic. Its own header stated the bound honestly: it prices
# "without anything judging whether a given spin-off was lazy", and "it does not
# compare the row to the diff".
#
# WHY THE TOLL DID NOT BITE. Measured 2026-08-20: four rows filed in three and a
# half minutes, then twelve spent writing four Ready blocks to pay for them, and
# `board-write-record` recorded every one `ready`. A toll denominated in PROSE is
# denominated in the one currency an agent has without limit, so it reversed
# nothing — it certified the punts. CLOUD-514 wrote the re-open predicate this
# satisfies ("a Ready block written to satisfy `ready-lint` rather than to be
# worked"), and its acceptance — "the cheapest path through the gate for a defect
# in the branch's own diff is to fix it" — was unmet.
#
# WHAT THIS DECIDES, AND WHY IT IS NOT A JUDGEMENT. One fact: how many paths the
# body names that this branch is also changing. A set intersection over two file
# lists, the shape the protected-path gate already uses ({verb} x {protected}).
# It scores no prose, compares no semantics and infers no intent, so
# non-negotiable 3 holds. Whether a given spin-off was lazy stays exactly as
# unjudged as `filed-here-check` leaves it.
#
# BASENAMES RESOLVE, AND THAT IS MEASURED RATHER THAN ASSUMED. Bodies here write
# `git.rs:107`, not `crates/batten/src/git.rs`. Against the three rows this was
# built from, exact path matching finds ZERO and basename resolution finds all
# three — so exact matching would have shipped a sensor blind to its own corpus.
# An AMBIGUOUS basename resolves to NOTHING rather than to a guess, which is the
# "could not look" reading this repo draws everywhere; 28 of 530 tracked
# basenames are ambiguous in this tree.
#
# POINTER-ONLY IS STRUCTURAL, not careful: only paths TRACKED IN THIS REPOSITORY
# can reach the output, so a body's prose, a customer name or a pasted credential
# cannot (non-negotiable 4).
#
# The Python is inline for `macos-link-check`'s reason — one file, so the code
# and the mutations that corrupt it cannot drift into two authorities — but fed
# through a QUOTED heredoc rather than `-c "…"`, so nothing inside it is subject
# to a second round of shell expansion. Both inputs arrive as env vars, which
# leaves stdin free for the script itself.
#
# Usage: board-diff-overlap   (an issue body on stdin)
# Prints: `<count> <path>...` on success, or `-` when it could not look.
# Exit 0 always — this is a sensor; `filed-here-check` is the gate.
#
# The mutation drops the basename arm, which is the whole reason it sees
# anything: every body in the corpus names `git.rs`, not the tracked path.
#MUTANT overlap-exact-only|s/^    cands = by_base.get(.*)$/    cands = []/|a short form resolves to the tracked path
# And an ambiguous basename must stay unresolved: guessing one of several is a
# wrong answer wearing a right answer's shape.
#MUTANT overlap-guesses-ambiguous|s/if len(cands) == 1:/if len(cands) >= 1:/|an ambiguous basename resolves to nothing
# The intersection is with what this branch CHANGES, not with what it tracks. Drop
# that term and every row naming any file in the repository is refused, which is a
# gate nobody can work under and therefore a gate that gets switched off.
#
# RE-AIMED AT THE DEFAULT BRANCH (CLOUD-774). This row used to mutate the line to
# `sorted(named)`, which is now a legitimate MODE rather than a defect — the
# mutation and the feature had become the same bytes, so the row would have
# demanded a test that `--named` fails. It now forces the named set in the
# DEFAULT path, which is the thing that must never happen and which `--named`
# does not do.
#MUTANT overlap-ignores-the-diff|s/^named_only = .*$/named_only = True/|the default mode still intersects, so the same body reports nothing
set -uo pipefail

# `--named` reports what the body NAMES, with no diff term (CLOUD-774). The
# recorder wants that rather than the intersection, because an intersection is a
# fact about the diff AT WRITE TIME and a row is routinely filed before the file
# is touched — the order AGENTS.md prescribes. What a row is about does not decay;
# the diff it is measured against does.
named_only=
case "${1:-}" in
--named) named_only=1 ;;
"") ;;
*)
	echo "usage: board-diff-overlap [--named]  (issue body on stdin)" >&2
	exit 2
	;;
esac

body=$(cat) || {
	echo -
	exit 0
}
[ -n "$body" ] || {
	echo -
	exit 0
}

# Both halves come from git, and either being unavailable is "could not look" —
# EXCEPT under `--named`, which needs no diff at all. That asymmetry is the point
# rather than an oversight: a container with no `origin/main` (a fresh clone, a
# detached checkout) would otherwise record `-` for every row it files, losing the
# entry the later intersection depends on.
changed=$(git diff --name-only origin/main...HEAD 2>/dev/null) || {
	if [ -z "$named_only" ]; then
		echo -
		exit 0
	fi
	changed=""
}
tracked=$(git ls-files 2>/dev/null) || {
	echo -
	exit 0
}
[ -n "$tracked" ] || {
	echo -
	exit 0
}

BODY="$body" CHANGED="$changed" TRACKED="$tracked" NAMED_ONLY="$named_only" python3 - <<'PY' 2>/dev/null || echo -
import collections
import os
import re

tracked = [line for line in os.environ["TRACKED"].splitlines() if line]
changed = {line for line in os.environ["CHANGED"].splitlines() if line}
body = os.environ["BODY"]

by_base = collections.defaultdict(list)
for path in tracked:
    by_base[path.rsplit("/", 1)[-1]].append(path)
exact = set(tracked)

# Three shapes, because bodies here use all three: a dotted path or filename, a
# backticked `mise-tasks/<task>`, and a bare backticked task name with no
# extension at all.
tokens = set(re.findall(r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]+", body))
tokens |= set(re.findall(r"`(mise-tasks/[A-Za-z0-9_.-]+)`", body))
tokens |= {m for m in re.findall(r"`([a-z0-9][a-z0-9-]{3,})`", body) if m in by_base}

named = set()
for token in tokens:
    token = token.rstrip(".,;:")
    if token in exact:
        named.add(token)
        continue
    cands = by_base.get(token.rsplit("/", 1)[-1], [])
    # Exactly one candidate resolves. Several is ambiguous and resolves to none:
    # guessing which file was meant is a wrong answer wearing a right one's shape.
    if len(cands) == 1:
        named.add(cands[0])

named_only = bool(os.environ.get("NAMED_ONLY"))
overlap = sorted(named) if named_only else sorted(named & changed)
print(f"{len(overlap)} {' '.join(overlap)}".strip() if overlap else "0")
PY

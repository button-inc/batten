#!/usr/bin/env bash
#MISE description="Gate: batten is registered exactly once on every hook surface of every harness, matching what `generate hooks` derives (CLOUD-777)"
#
# House style §11: the hook wiring is a derivation of the spec, the same way
# completions and man pages are. `derived-check` gates those. This gates the
# wiring, and it is a separate program rather than another `derived-check` row
# for the reason `schema-check` is also separate: that gate's rows are <whole
# committed artifact> x <generate argv>, compared with `cmp`. This compares
# SELECTED ENTRIES INSIDE A SHARED FILE, canonicalized — not that shape.
#
# WHY A FILE MAY BE SHARED, AND WHY THAT IS NOT A WORKAROUND. Claude Code merges
# hooks across its settings files and defines no hooks-only project file, so
# `.claude/settings.json` carries configuration the engine does not own —
# `enabledMcpjsonServers`, permissions, everything a consumer puts there. Gemini
# is the same shape. The derivation target is batten's registrations inside the
# file, never the file. The other three hosts do define a hooks-only file, and
# `WiringFile` is what records which is which.
#
# THE LAUNCHER INDIRECTION IS GONE, AND THE COLUMN THAT RESOLVED IT STAYS
# (CLOUD-824). This paragraph used to argue for the indirection, and the argument
# was sound about the two jobs it named:
#
#   *"Claude Code's committed wiring does not run `batten hook` directly; it runs
#   `.claude/hooks/batten-hook.sh`, a launcher that `cd`s so `load_policy` finds
#   the authority (there is no upward walk), resolves a binary that is not on
#   PATH, and fails open — none of which `settings.json` can express."*
#
# Both jobs were binary defects paid for in shell. The `cd` asked
# `--show-toplevel`, the WORKTREE's root, where `git::repo_root` answers the
# repository's — so from a linked worktree the launcher read the wrong
# `batten.toml`, or none, and allowed every mediated call silently. That is now
# `lib.rs`'s `hook_authority_root`, inside CLOUD-34's single-implementation gate.
# The binary search is `mise run install:local`, an install concern rather than a
# hook one. So all five harnesses are held to the derived command exactly, and
# claude-code stops being the one host running a different, less-tested entry
# path than every other.
#
# THE COLUMN SURVIVES WITH NOTHING IN IT, and that is deliberate rather than
# leftover. What made the emitter's neutrality necessary has not changed: naming
# a consumer's file layout from `crates/batten` is what non-negotiable rule 1
# forbids ("a grep for a specific consumer's names must return zero hits"), so a
# consumer that DOES need an indirection resolves it here, in its own gate. The
# column being all `-` today is a measurement, not a reason to delete the
# affordance — and `HOOKS_WIRING_HARNESSES` is what lets the suite point it at a
# fixture that uses one.
#
# ---------------------------------------------------------------------------
# WHAT CLOUD-777 CHANGED, and why each note it reverses is quoted rather than
# deleted. The decision it records is one sentence: **batten is hooked exactly
# once on every available hook surface in every harness we support, and nothing
# else registers a hook.** Three things this gate used to say are consequences
# of that decision being unmade, so they are corrected here rather than left to
# be rediscovered:
#
#   1. *"WHAT IS NOT A FAILURE: an event the derivation emits that the wiring
#      does not yet register. Installing the full set is CLOUD-312's cutover
#      obligation, not this gate's."* — This IS the cutover. A derived event with
#      no registration is now `wiring-event-unregistered`. The reasoning stands
#      for what it was: a gate red for another issue's reason gets bypassed. The
#      issue has landed, so the exemption expires with it.
#
#   2. *"THE MATCHER IS NOT COMPARED, and that is a decision rather than an
#      omission… a matcher derived from [the `Harness` enum] would be the core
#      asserting something it cannot know."* — Still exactly right, and NOT what
#      is asserted now. The derivation emits NO matcher, deliberately: "the
#      host's absent-matcher default is 'every tool', which lets the engine's own
#      filter be the only narrowing." So this compares the matcher's ABSENCE, not
#      its content. Asserting that the core declines to narrow is the opposite of
#      the core asserting a vocabulary. `hook-matcher-check` (CLOUD-471) still
#      owns matchers that DO name tools; a matcher on batten's own entry is now
#      `wiring-matcher-narrows`.
#
#   3. *"`PreToolUse` ONLY, and that is a scope choice rather than an oversight…
#      Sweeping [the other events] in would widen this gate past what CLOUD-312
#      argued."* — CLOUD-777 widened it: "CLOUD-312 is titled 'the engine is the
#      pre-tool entry point'. The entry point is every point." Every event is
#      counted now, and the declared list grew from six rows to twelve.
# ---------------------------------------------------------------------------
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT undeclared-launcher-passes|s/^\texit 1$/\texit 0/|an UNDECLARED launcher is drift

set -euo pipefail

# The CRATE is where the engine is built from; the ROOT is what gets judged, and
# since this gate grew a suite the two are not always the same directory. Both
# are captured before the `cd` so `--manifest-path` below can reach the manifest
# from a fixture root that has none.
crate_root=$(git rev-parse --show-toplevel)
cd "${HOOKS_WIRING_ROOT:-$crate_root}"
root=$(pwd)

# The surface, as data: `<harness> <committed wiring file> <launcher substring>`.
#
# One row per harness in `Harness::ALL` that has a hook-config surface.
# `exit-code` has none and is absent on purpose — it is the neutral contract,
# envelope in and decision as exit status out, and `generate hooks
# --harness exit-code` refuses with a message saying so. `census` below asserts
# this table and `Harness::ALL` agree, so a seventh adapter cannot land unwired
# by simply not being listed here.
#
# A launcher of `-` means the host is held to the derived command exactly.
# AN ARGUMENT, for the reason `HOOKS_WIRING_DECLARED` is one: the decision is the
# part worth testing, and it only tests if the suite can point it at a table that
# disagrees with the fixtures in front of it.
HARNESSES="${HOOKS_WIRING_HARNESSES-claude-code .claude/settings.json -
cursor .cursor/hooks.json -
copilot-cli .github/hooks/batten.json -
gemini-cli .gemini/settings.json -
codex-cli .codex/hooks.json -}"

# The surfaces a host MERGES its hook config from beyond the committed one
# (CLOUD-525), as `<harness> <home-relative path>`.
#
# HOME-RELATIVE, and joined at the read. An absolute path differs per machine
# and per user, so it could not be a table entry and must never be reported —
# every finding below names the harness, the event and the DECLARED pattern,
# which are stable strings, and never the resolved path.
#
# This is the same set `Harness::merge_surfaces` states in the core, and the
# duplication is deliberate rather than a second authority: `doctor hooks`
# reports a merged COUNT and never a name (rule 4), which makes an undeclared
# registration visible without saying what it is. Turning that count into a named
# verdict needs this consumer's `DECLARED` table, so the names live here — and
# `merged-surface-census` in the suite asserts the two lists agree.
MERGED="${HOOKS_WIRING_MERGED-claude-code .claude/settings.json
claude-code .claude/settings.local.json
claude-code .claude/launcher-settings.json
gemini-cli .gemini/settings.json}"

# What is wired today that should not be, each naming the issue that owns its
# retirement. This is the gate going red on the state it exists to refuse — a
# gate that shipped already-green over it would be one nothing can fail — with
# the current violations recorded rather than tolerated silently.
#
# A row is `<command substring> <CLOUD-key>`. Two rules keep the list from
# becoming a permanent exemption: a row naming no key is itself a violation, so
# the hatch cannot be used without saying who owns the fix; and a row matching
# nothing wired is a violation too, so a retirement that lands must delete its
# row rather than leaving a licence behind for the next command with a similar
# path.
#
# THE LAST TWO ROWS ARE ON A MERGED SURFACE, NOT A COMMITTED ONE (CLOUD-525).
# They are launcher-provisioned files under `$HOME` that this repository cannot
# delete and that no committed file declares — measured in one container
# 2026-08-21, they made `Stop` run three handlers and `SessionStart` four while
# every gate read two and three. Declaring them is the difference between a
# census and a demand: an added launcher hook becomes VISIBLE instead of silent,
# and no run goes red on state this repo cannot fix.
#
# Named by BASENAME, unlike the committed rows: a merged command is reported
# without its directory (§5), so the pattern it is matched against must be the
# same shape. The basenames are distinctive enough to be unambiguous.
#
# BOTH are owned by CLOUD-605, and the second owner is a correction. CLOUD-525's
# §2 named CLOUD-669 for the `SessionStart` one; read the script and it sets
# `user.email`/`user.name`, which is identity — CLOUD-605's subject — where
# CLOUD-669 is about `commit.gpgsign` and is DONE. A declared row naming a closed
# issue as the owner of an open retirement is exactly what
# `wiring-declaration-closed-owner` below refuses, reproduced while specifying
# the mechanism against it.
#
# THE COUNT IS THE LIST BELOW, and this paragraph no longer states one. It said
# "THIRTEEN ROWS" over twelve and then over eleven, because it is a tally of a
# thing directly under it and every retirement makes it wrong — the drift
# `.claude/rules/toolchain.md` records as "don't restate a count here", met on the
# second retirement rather than the first.
#
# What matters is the DIRECTION, which no count carries: a row is DELETED when its
# retirement lands, never left behind, and `wiring-declaration-stale` below
# enforces exactly that — otherwise the next command with a similar path inherits
# a licence nobody granted. CLOUD-461 removed `contract-drift`'s row when the
# advisory channel landed; CLOUD-312's rows 1 and 2 removed theirs the same way.
#
# The rest were six until CLOUD-777, whose widened scope could finally see them.
# Their owners are not invented: CLOUD-312 is "the shell guards retire behind
# it", whose scope CLOUD-777 widened from pre-tool to every point.
# THE TABLE IS NOW EMPTY, WHICH IS THE CAMPAIGN FINISHING RATHER THAN THE GATE
# RELAXING (CLOUD-312 row 10, CLOUD-605).
#
# Two removals, in one change, for two different reasons:
#
# `.claude/hooks/session-start.sh` was the last native registration this
# repository owned. It is a `[[hook.handler]]` row now, so its declaration would
# be stale by the rule directly below — the DIRECTION that paragraph names,
# applied to itself.
#
# The two CLOUD-605 basenames went because **`batten wiring reclaim` gives them a
# remedy a row could not.** Read what they were for: they existed because these are
# launcher-provisioned files under `$HOME` "that this repository cannot delete",
# so the most a row could do was make an invisible registration visible and name
# who would eventually remove it. The verb removes them: measured on this
# container, two registrations found, two removed, the surface left carrying
# `"hooks": {}` and every other key untouched.
#
# BUT THE REPAIR DOES NOT SURVIVE A SESSION BOUNDARY, and saying so is the point
# of this paragraph rather than a caveat on it. Measured across a real restart:
# the reclaim removed both, and the next session read them BACK with the at-load
# record already cleared — because the launcher re-provisions its settings at
# session start and `batten hook`'s own `SessionStart` expires the record at the
# same instant. The repair and its erasure are one event, so there is no
# in-session route to green and reclaiming again only exchanges one honest red
# (`wiring-sibling-command` twice) for another (`wiring-repair-unloaded`).
#
# So the remedy is NOT "one command", which an earlier draft of this comment
# claimed. It is one command plus an owner action on whatever generates those
# `$HOME` settings — CLOUD-605's, outside this repository. What the verb buys is
# that the violation is now repairable and reported rather than merely declared;
# what it does not buy is that it stays repaired.
#
# THIS IS NOT A GATE BEING WEAKENED TO SUIT A CHANGE, and the distinction is worth
# stating because it is exactly the move that would be. A row here has excused
# nothing since CLOUD-893 flipped it — "a DECLARED row records who retires it and
# no longer excuses it" — so deleting one cannot make any sibling pass. What is
# lost is a pointer: on a fresh container the launcher provisions those two again
# and the gate reports them with no owner named. That is a real cost and a small
# one, because the remedy is no longer "wait for CLOUD-605", it is one command.
#
# The affordance stays for the next consumer that needs it, and every case in
# `tests/hooks-wiring-check.bats` sets `DECLARED` itself, so the rules over this
# column are exercised exactly as before an empty default.
DECLARED="${HOOKS_WIRING_DECLARED-}"

violations=0
report() { # pointer-only (rule 4): the file, the event, the rule id
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

# --- the derivation half: ONE call into the binary (CLOUD-777) ---------------
#
# This was ~200 lines of bash: `cargo run … generate hooks` once per harness, a
# `jq` re-parse of each result, a second copy of `WiringFile`'s Key/Whole split
# written as `(.hooks // .)`, and a harness census read out of clap's
# `possible values`. All of it now happens in-process, where the types it is
# reasoning about actually live. Deleting the second copy of the Key/Whole split
# is the point rather than a side effect.
#
# It also means the check SHIPS. A repository adopting Batten had no way to ask
# *am I wired?* — which is why CLOUD-777 could observe that "the other five
# harnesses have no committed wiring in this repo to measure." `batten doctor
# hooks` is that question, and this file is now one consumer of it.
#
# `-J`, not the pointer lines: the suppression below is per finding, and parsing
# a rendering back into fields is the shape that drifts.
#PIN-OK: jq
if ! command -v jq >/dev/null 2>&1; then
	echo "::error:: hooks-wiring-check: no jq on PATH. Run: mise install" >&2
	exit 2
fi
# `cargo run`, not an installed binary, for the reason `batten-check` states: a
# gate judges the WORKING TREE's engine and config together, which is the pair
# that ships. `--manifest-path` is what lets it do that while the child's cwd is
# the root under test rather than the crate.
#
# INJECTABLE, for the reason `HOOKS_WIRING_DECLARED` is: the "could not look" arm
# below is a decision, and it only tests if a case can produce a diagnosis that
# does not come back. Same seam `linear-check` and `unlanded-check` open with
# `BATTEN_BIN`, and used the same way — a suite points it at a stub.
diagnose="${HOOKS_WIRING_DIAGNOSIS-cargo run --quiet --manifest-path $crate_root/Cargo.toml -p batten -- doctor hooks -J}"
if ! diagnosis=$(cd "$root" && $diagnose 2>/dev/null); then
	# `doctor` exits 1 on an unhealthy diagnosis, which is an ANSWER; only an
	# unparseable one is "could not look". So the status is not the test — the
	# document is.
	:
fi
if ! jq -e 'has("harnesses")' >/dev/null 2>&1 <<<"$diagnosis"; then
	echo "::error:: hooks-wiring-check: \`batten doctor hooks -J\` did not answer, so the wiring cannot be judged. That is 'could not look', not 'the wiring is fine'." >&2
	exit 2
fi

registrations=$(jq -r '[.harnesses[].registrations] | add // 0' <<<"$diagnosis")
diagnosed=$(jq -r '.harnesses[].harness' <<<"$diagnosis")

# THE SUBJECT OF THIS GATE IS THE RECORD, NOT ONLY THE DISK (CLOUD-893).
#
# A harness reads its hook wiring once, when a session starts. So `batten wiring
# reclaim` changes what is on disk and cannot change what the running host has
# already loaded — and a gate that read only the disk would go green one moment
# after the repair, over a runtime still dispatching every sibling that was just
# deleted. That is a manufactured false green, and strictly worse than the
# expiring waiver table CLOUD-893 removed: a waiver at least says what it excuses.
#
# So the reclaim writes an AT-LOAD record before it edits a byte, `doctor hooks`
# reports its total as `at_load_siblings`, and this reads that number FIRST. Two
# states the disk cannot tell apart:
#
#   * `null`  — no repair recorded. Read the disk; the loops below do exactly that.
#   * `0`     — a repair ran and found nothing. The disk is also the answer.
#   * `n > 0` — this session loaded `n` siblings that are no longer on disk. RED,
#               naming the restart, because nothing else can distinguish it from
#               a clean tree.
#
# `batten hook` on `SessionStart` expires the record, which is the one moment the
# two are the same by definition — so the next session's run of this gate reads
# the disk again and goes green if the repair held.
at_load=$(jq -r '.at_load_siblings // 0' <<<"$diagnosis")
if [[ "$at_load" =~ ^[0-9]+$ ]] && [[ "$at_load" -gt 0 ]]; then
	report "hooks-wiring-check:at-load:$at_load" "wiring-repair-unloaded"
fi

# THE LAUNCHER INDIRECTION IS RESOLVED HERE, WHICH IS THE WHOLE REASON THIS FILE
# STILL EXISTS AS A GATE. The core compares a committed command against the
# neutral `batten hook --harness <h>` it emits, and it cannot do otherwise:
# naming a consumer's file layout from `crates/batten` is what non-negotiable
# rule 1 forbids. So a consumer that fronts the engine with its own launcher gets
# `hook-wiring-command-drift` from the core and answers for it here, against the
# table above. Every row of this repository's table is `-` since CLOUD-824, and
# the affordance is kept because the reason for it did not change with it.
while read -r harness event reason; do
	[[ -n "$harness" ]] || continue
	wiring=$(awk -v h="$harness" '$1 == h {print $2}' <<<"$HARNESSES")
	launcher=$(awk -v h="$harness" '$1 == h {print $3}' <<<"$HARNESSES")
	if [[ -z "$wiring" ]]; then
		report "hooks-wiring-check:$harness" "wiring-harness-unlisted"
		continue
	fi
	if [[ "$reason" = "hook-wiring-command-drift" ]] && [[ -n "$launcher" ]] && [[ "$launcher" != "-" ]]; then
		# A declared launcher stands in for the derived command, and only for
		# THIS harness's own file: the substring is matched against what is
		# actually registered, so a typo is still drift rather than a licence.
		if jq -e --arg e "$event" --arg l "$launcher" '
		      (.hooks // {}) | .[$e][]? | .hooks[]?
		      | select(.command // "" | contains($l))
		    ' "$wiring" >/dev/null 2>&1; then
			continue
		fi
	fi
	# THE ENGINE'S SIBLING FINDINGS ARE NOT RELAYED, because this file reports
	# the same fact better (CLOUD-893). Under `[hook] exclusive` the engine emits
	# `hook-wiring-sibling-registered` and `hook-wiring-merged-sibling`, and it
	# must stay pointer-only: a sibling's command line carries a path, and rule 4
	# forbids the ENGINE from emitting one. A consumer's own gate is under no such
	# constraint over its own repository, so the loop below names the command and
	# the issue that retires it — strictly more than the relay could say.
	#
	# Measured before this arm existed: 20 violations for 10 registrations, each
	# reported once bare and once with its command. A doubled count is not a
	# louder gate, it is a gate whose arithmetic a reader has to correct.
	case "$reason" in
	hook-wiring-sibling-registered | hook-wiring-merged-sibling) continue ;;
	hook-wiring-merged-*) report "$harness:merged:$event" "${reason#hook-}" ;;
	*) report "$wiring:$event" "${reason#hook-}" ;;
	esac
done < <(jq -r '.harnesses[] as $h | $h.findings[]? | "\($h.harness) \(.event) \(.reason)"' <<<"$diagnosis")

# The census, inverted. The core ranges over `Harness::ALL`, so what needs
# checking is no longer "does the table cover every harness" but "does the table
# name one the core does not diagnose" — a row for a host that no longer exists,
# which would make its launcher and its file path read as live.
while read -r harness wiring launcher; do
	[[ -n "$harness" ]] || continue
	: "$wiring" "$launcher"
	grep -qxF "$harness" <<<"$diagnosed" ||
		report "hooks-wiring-check:$harness" "wiring-harness-unknown"
done <<<"$HARNESSES"

# --- whose owners are already closed (CLOUD-525 §7(e)) -----------------------
#
# A declared row whose owner is a CLOSED issue is the permanent-exemption shape
# the `DECLARED` pattern exists to refuse: the retirement's licence outlives the
# row that was supposed to deliver it. `wiring-declaration-stale` already catches
# the other half — a row matching nothing wired — and this is its sibling.
#
# AGENTS FETCH, GATES DECIDE, for the reason every board gate here gives: no
# tracker credential exists on any gate path, so the caller pipes
# `get_issue` payloads in and the verdict is this program's alone. Nothing here
# makes a network call, so nothing here can hang, rate-limit, or answer
# differently in the sandbox than in CI.
#
# ABSENT STDIN IS COULD-NOT-LOOK, NEVER A PASS AND NEVER A FAILURE. The rule is
# unenforced when nobody supplies the board, which is the ordinary pre-commit
# case — a gate that demanded a payload would be red on every commit, and one
# that read "no payload" as "every owner is open" would be a check that cannot
# discriminate. It reports what it did.
closed_owners=""
if [[ ! -t 0 ]]; then
	payloads=$(cat 2>/dev/null || true)
	if [[ -n "$payloads" ]]; then
		closed_owners=$(jq -rs '
		    [ .. | objects | select(has("id") and has("statusType"))
		      | select(.statusType == "completed" or .statusType == "canceled")
		      | .id ] | unique | .[]
		  ' <<<"$payloads" 2>/dev/null || true)
	fi
fi

if [[ -n "$closed_owners" ]]; then
	while read -r pattern key; do
		[[ -n "$pattern" ]] || continue
		grep -qxF "$key" <<<"$closed_owners" &&
			report "hooks-wiring-check:$pattern:$key" "wiring-declaration-closed-owner"
	done <<<"$DECLARED"
fi

# --- the commands that are not batten's (CLOUD-713, widened by CLOUD-777) -----
#
# THIS HALF STAYS IN BASH, and not for want of somewhere to put it. `doctor
# hooks` reports a sibling COUNT and never a name, twice over: rule 4 forbids a
# diagnostic from emitting a command line, which carries a path, and whether a
# hook beside batten's is legitimate is a CONSUMER's judgement. This repository
# refuses them and records who retires each — a fact about this repository, which
# is exactly why it cannot move into `crates/batten`.
while read -r harness wiring launcher; do
	[[ -n "$harness" ]] || continue
	: "$launcher"
	if [[ ! -f "$wiring" ]]; then
		# The core already reported `hook-wiring-file-missing` for this harness,
		# so there is nothing to add and nothing to scan.
		continue
	fi
	# And likewise for one it could not parse: the core reported
	# `hook-wiring-file-unreadable`, which is the answer. Re-deriving it here as an
	# exit 2 would replace a verdict somebody made with "could not look".
	if ! jq -e . "$wiring" >/dev/null 2>&1; then
		continue
	fi
	if ! siblings=$(jq -r --arg where "$wiring" '
	    (.hooks // {}) | to_entries[] as $event
	    | $event.value[]? | .hooks[]?
	    | select(.command // "" | contains("batten") | not)
	    | "\($where)\t\($event.key)\t\(.command)"
	  ' "$wiring" 2>/dev/null); then
		echo "::error:: hooks-wiring-check: could not read $wiring's non-batten entries" >&2
		exit 2
	fi

	# The MERGED surfaces for this harness, appended to the committed file's
	# siblings so both go through one DECLARED matching (CLOUD-525). A merged
	# entry that is absent is the ordinary case and contributes nothing: most
	# machines carry no launcher file, and a gate red for its absence would be red
	# on every developer's box for a state nobody can fix.
	#
	# COUNTED, because the stale rule below needs to tell "this row names a merged
	# command nobody registers any more" from "no merged surface was READ AT ALL".
	# Zero here is could-not-look, exactly as an absent stdin is for the
	# closed-owner rule above, and it is the permanent state of a CI runner and of
	# any box whose launcher has not provisioned one.
	merged_read=0
	while read -r merged_harness merged_rel; do
		[[ -n "$merged_harness" ]] || continue
		[[ "$merged_harness" == "$harness" ]] || continue
		merged_file="$HOME/$merged_rel"
		[[ -f "$merged_file" ]] || continue
		# THE SAME FILE IS NOT A SECOND SURFACE, and `doctor.rs` already
		# refuses this in the half it owns — this is the same exclusion on the
		# consumer side, which was missing. A host's user-level surface and its
		# project-level one share a spelling, so a checkout sitting AT the home
		# directory resolves both to one file: the loop would then scan one
		# command twice, once with its full path from the committed surface and
		# once as a basename from the merged one, and report a merged finding
		# for a registration that is only committed. `-ef` compares by device
		# and inode, so a symlinked checkout is caught too.
		[[ "$merged_file" -ef "$wiring" ]] && continue
		jq -e . "$merged_file" >/dev/null 2>&1 || continue
		# NEVER THE PATH, on either field (CLOUD-525 §5). The `where` is the
		# harness plus the word `merged` — a stable string that says which
		# SURFACE CLASS this came from — and the command is reduced to its
		# basename, so a reader knows what to look at without the report
		# carrying the layout of somebody's home directory. Reporting
		# `$merged_file` would differ per machine and defeat §6 byte-stability
		# as well as rule 4.
		merged_siblings=$(jq -r --arg where "$harness:merged" '
		    (.hooks // {}) | to_entries[] as $event
		    | $event.value[]? | .hooks[]?
		    | select(.command // "" | contains("batten") | not)
		    | "\($where)\t\($event.key)\t\(.command | split("/") | last)"
		  ' "$merged_file" 2>/dev/null) || continue
		merged_read=$((merged_read + 1))
		[[ -n "$merged_siblings" ]] || continue
		siblings="${siblings:+$siblings$'\n'}$merged_siblings"
	done <<<"$MERGED"

	# A DECLARED ROW ANNOTATES THE FAILURE AND NO LONGER SUPPRESSES IT (CLOUD-893).
	#
	# This loop used to skip `wiring-sibling-command` for any command a `DECLARED`
	# row matched. The table was written as diligence — every sibling named beside
	# the issue that would retire it — and functioned as a permanent exemption:
	# measured 2026-08-25, ten registrations, ten rows, this gate exit 0 and
	# `batten doctor hooks` `ok: true` over the exact state the one-registration
	# decision refuses.
	#
	# The direction is what makes it inadmissible rather than merely lenient. A
	# declaration that ADDS a refusal is raise-only (house-style §8) and cannot
	# weaken policy; one that REMOVES a refusal reads identically in the file and
	# does the opposite. `[hook] exclusive` in `batten.toml` is the first kind and
	# is where the decision now lives; this table keeps only the half that was
	# always honest, which is WHO retires each entry.
	#
	# So the ownership rules below are not vestigial — they are the whole point of
	# keeping the table. `-unowned` refuses a row naming nobody, `-stale` refuses
	# one naming a command nothing registers, and `-closed-owner` refuses one whose
	# issue is already closed. Each says something about the retirement; none of
	# them says the registration is allowed.
	while IFS=$'\t' read -r where event command; do
		[[ -n "$command" ]] || continue
		# Substring rather than equality: the committed commands carry the host's
		# `$CLAUDE_PROJECT_DIR` prefix unexpanded, and a declaration should name
		# the task rather than restate a path the host owns.
		owner=""
		while read -r pattern key; do
			[[ -n "$pattern" ]] || continue
			case "$command" in
			*"$pattern"*)
				owner="$key"
				# A declaration with no owner is worse than none: it reads as a
				# decision someone made and records nobody to ask.
				case "$key" in
				CLOUD-[0-9]*) ;;
				*) report "$where:$event:$pattern" "wiring-declaration-unowned" ;;
				esac
				;;
			esac
		done <<<"$DECLARED"
		# Reported either way. The owner rides along when one is declared, so the
		# pointer still answers "who retires this" without answering "may it stay".
		report "$where:$event:$command${owner:+ (retires with $owner)}" "wiring-sibling-command"
	done <<<"$siblings"

	# The other direction: a declared row that matches nothing wired IN THIS FILE.
	# Without it the list only ever grows, and a retirement leaves behind a
	# licence that the next command with a similar path inherits silently.
	#
	# Scoped per harness rather than across the set, because a row naming a
	# `mise-tasks/*` command describes THIS consumer's Claude wiring and would
	# read as stale against every other host's file, which never had it.
	#
	# A MERGED-SURFACE ROW IS UNENFORCED WHEN NO MERGED SURFACE WAS READ, which is
	# the same could-not-look posture the closed-owner rule takes on absent stdin.
	# Those rows name a launcher-provisioned command under `$HOME`; a CI runner has
	# no such file, so judging them against `siblings` there asks whether a surface
	# nobody opened still registers them, and answers "stale" to a question that was
	# never looked at. Measured: green on a box whose launcher provisioned one, red
	# on every CI run — the verify/CI disagreement `land` stops on, and it made two
	# rows permanently unlandable rather than occasionally noisy. The paragraph that
	# added those rows says a run must not go red on state this repo cannot fix.
	#
	# The two classes are told apart by the shape the DECLARED table already uses: a
	# committed row is a PATH (`mise-tasks/…`), a merged row is a BASENAME, because
	# a merged command is reported without its directory (§5). So the discriminator
	# is one already load-bearing above, not a second list to keep in step. Where a
	# merged surface WAS read these rows are judged exactly like the rest — a
	# launcher hook that goes away still has to take its licence with it.
	if [[ "$harness" = "${HOOKS_WIRING_DECLARED_FOR-claude-code}" ]]; then
		while read -r pattern key; do
			[[ -n "$pattern" ]] || continue
			: "$key"
			[[ "$pattern" != */* && "$merged_read" -eq 0 ]] && continue
			grep -qF -- "$pattern" <<<"$siblings" ||
				report "$wiring:$pattern" "wiring-declaration-stale"
		done <<<"$DECLARED"
	fi
done <<<"$HARNESSES"

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: hooks-wiring-check: $violations wiring violation(s) above. For an entry that IS batten's, the derivation is the authority: edit the wiring, or the rows in crates/batten/src/hook.rs if the derivation is what is wrong — \`batten doctor hooks\` is the same read without this file's consumer-side table. For a \`wiring-sibling-command\`, \`batten hook\` is the only command this repository registers natively: move the program BEHIND the engine — a \`[[hook.handler]]\` row in batten.toml if it must keep running, a policy row if its decision can be expressed as one — and delete the registration. A DECLARED row records who retires it and no longer excuses it; adding one changes the pointer and not the verdict. A \`wiring-repair-unloaded\` is not a wiring defect at all: \`batten wiring reclaim\` has already removed that many registrations from a merged surface and this session is still running them, so restart the harness — the record expires at the next SessionStart and this gate reads the disk again." >&2
	exit 1
fi

echo "hooks-wiring-check: $registrations \`batten hook\` registration(s) across $(grep -c . <<<"$diagnosed") harness(es) agree with the derivation — one per emitted event, no matcher — and nothing else is registered natively"

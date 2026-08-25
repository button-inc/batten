#!/usr/bin/env bash
#MISE description="What batten tasks are running right now, and what phase each is in — one call, no log reading"
#
# CLOUD-425. The reader half of `task-registry`. One call, one line per task:
#
#   land verify 31337 214s
#   land crashed(ci-wait) 31201 869s
#
# **Pointer-only** (non-negotiable 4): a task name, a phase word, a pid and a
# number of seconds. Never a line of any log — being forced to read logs is the
# defect this exists to remove, so emitting log content here would reintroduce it
# through the front door. `tests/alive.bats` pins that as a property.
#
# **A gone pid is `crashed`, not absent.** That distinction is the entire point.
# An absent entry means "never registered"; a registered entry whose process is
# gone means "started and died", which is the state a human actually needs and
# the one that cost seventeen minutes of guessing on 2026-08-12. It is the same
# distinction `target-ensure` already draws between a free lock and one held by a
# corpse. Reporting it also reaps it, so the registry is self-healing rather than
# an ever-growing pile of headstones.
#
# **This task never sends a signal.** CLOUD-425 demotes SIGUSR1 to an
# enhancement, and its safety property — no signal is ever delivered to a process
# that did not declare it handles it — holds here structurally rather than by
# check, because there is no `kill` in this file that sends anything. SIGUSR1's
# default disposition is Term: a reader that signalled would kill what it came to
# inspect. `tests/alive.bats` pins the absence.
#
# **Composition, not re-derivation** (house-style §2): this says what is running.
# "Is this SHA green" stays `checks-green`'s question; "is the lease held" stays
# `land-lock-check`'s. A landing summary composing all three is a separate, later
# question and is deliberately not smuggled in here.
#
# Exit codes follow the one contract: 0 the registry was read (whether or not
# anything is running), 2 could not look. There is no exit 1 — this is a reader,
# not a gate, and it has no verdict to refuse.
#
# CLOUD-901's three mutations. Each names a DIFFERENT wrong implementation, and
# all three were verified by hand before being declared — the suffix arm removed
# reds 17, the naive glob reds 18, and an unguarded reap reds 19. Declaring them
# is what makes that repeatable instead of something one session did once.
#
# The character classes are load-bearing, not typos: without them each pattern
# matches THIS DECLARATION LINE before the code and mutates its own row, which is
# the `self-mutating-row` shape CLOUD-480 refuses. Field 3 is a bats --filter,
# never a description — a title matching no case reports `names-no-case`.
#MUTANT alive-ignores-the-sh-suffix|s@\*"/mise-tasks/\$tas[k].sh "\*) return 0 ;;@;;@|a task whose FILE carries .sh
#MUTANT alive-corroborates-by-prefix|s@\*"/mise-tasks/\$tas[k].sh "\*)@*"/mise-tasks/$task"*)@|a sibling task whose name EXTENDS
#MUTANT alive-reaps-a-live-task|s@i[f] ! kill -0 "\$pid" 2>/dev/null; then@if true; then@|is reported, never reaped
set -euo pipefail

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: alive: not a git repository" >&2
	exit 2
}

state_dir="$git_dir/batten-tasks"

now() { date -u +%s; }

field() { # <file> <name>
	sed -n "s/^$2: //p" "$1" 2>/dev/null | head -n 1
}

# Nothing has ever registered in this clone. That is a real answer — "nothing is
# running" — and is NOT the same as being unable to read the registry, which is
# exit 2 below. Conflating the two is precisely the failure this issue names, so
# only genuine ABSENCE may take this branch.
[[ -e "$state_dir" ]] || {
	echo "alive: nothing registered"
	exit 0
}

# Present but not a directory, or present and unreadable: both are "could not
# look", never "nothing runs". Testing the first is also the only way to drive
# this branch as root, for whom the permission bits below are not a constraint.
[[ -d "$state_dir" ]] && [[ -r "$state_dir" ]] && [[ -x "$state_dir" ]] || {
	echo "::error:: alive: registry at $state_dir is unreadable — cannot say what is running" >&2
	exit 2
}

# Is the process behind this entry still the task that registered it?
#
# Two parts, because existence alone is not enough: pids recycle, and this clone
# measurably wrapped its pid space inside 20 minutes (CLOUD-432). But the
# asymmetry runs the OTHER way here than it does in `land-lock`'s heartbeat.
# There, an unevaluable probe reads as gone, because a wrongly renewed lease
# wedges the fleet. Here, a wrongly CRASHED verdict is the expensive direction:
# CLOUD-428 consumes this to refuse a second `land`, so a live task misreported
# as dead licenses exactly the duplicate-landing incident the registry exists to
# prevent. So an unevaluable corroboration reads as ALIVE.
#
# That also keeps the reader honest off Linux. `/proc/<pid>/cmdline` does not
# exist on macOS (CLOUD-286 is the standing lesson about assuming otherwise), so
# there the probe is `kill -0` alone rather than a machine that calls every live
# task dead.
task_alive() { # <pid> <task>
	local pid="$1" task="$2" cmd
	kill -0 "$pid" 2>/dev/null || return 1
	cmd=$(tr '\0' ' ' </proc/"$pid"/cmdline 2>/dev/null) || return 0
	[[ -n "$cmd" ]] || return 0
	# The trailing space matters: `tr` turns argv's NUL terminator into one, and
	# without it `land` would match a `land-lock` process by prefix.
	#
	# TWO SPELLINGS, BOTH SPELLED OUT — never `$task*` (CLOUD-901). The task NAME
	# kept its old form and the task FILE gained `.sh` (CLOUD-865), so `mise`
	# registers `land` and execs `mise-tasks/land.sh`: the cmdline reads `land.sh `
	# where this arm demanded `land` followed by a space. `land` is followed by
	# `.`, nothing matched, and every live file task fell through to `return 1` —
	# a total failure dated to the rename, not an intermittent race.
	#
	# The glob `*"/mise-tasks/$task"*` would fix that case and destroy the
	# defence this function exists for: it matches `land-lock.sh` too, so a
	# recycled pid running a DIFFERENT task would corroborate as `land`. That is
	# CLOUD-432's measurement — this clone wrapped its pid space inside 20
	# minutes. Each accepted suffix is therefore written out, and
	# `tests/alive.bats` carries the `land-lock.sh` case that refuses the glob.
	case "$cmd" in
	*"/mise-tasks/$task "*) return 0 ;;
	*"/mise-tasks/$task.sh "*) return 0 ;;
	esac
	return 1
}

# Bash expands a glob in lexical order, so the output is byte-stable across runs
# for the same registry state (non-negotiable 5) rather than dependent on
# readdir order. Quoted throughout: a path is one word however it is spelled.
found=0
for file in "$state_dir"/*; do
	[[ -f "$file" ]] || continue
	task=$(field "$file" task)
	pid=$(field "$file" pid)
	phase=$(field "$file" phase)
	started=$(field "$file" started_at)
	phase_since=$(field "$file" phase_since)
	# A malformed entry is skipped rather than rendered as a line of blanks: a
	# half-written record is not a task, and inventing one would be a claim.
	[[ -n "$task" ]] && [[ -n "$pid" ]] || continue
	found=$((found + 1))

	age="?"
	[[ -n "$started" ]] && age=$(($(now) - started))
	# HOW LONG IT HAS BEEN WHERE IT IS (CLOUD-499), which is the number that
	# separates a task working from a task stuck — the total age says only how
	# long it has been running, and a wedged land looks identical to a busy one
	# under it. Appended rather than substituted, and omitted entirely on an
	# entry written before this field existed, so the line stays byte-stable for
	# every reader that predates it. Still pointer-only: two counts and a phase
	# word, never a line of any log.
	in_phase=""
	[[ -n "$phase_since" ]] && in_phase=" in-phase $(($(now) - phase_since))s"

	if task_alive "$pid" "$task"; then
		printf '%s %s %s %ss%s\n' "$task" "${phase:-unknown}" "$pid" "$age" "$in_phase"
	else
		printf '%s crashed(%s) %s %ss%s\n' "$task" "${phase:-unknown}" "$pid" "$age" "$in_phase"
		# REAP ONLY A GENUINELY DEAD PID (CLOUD-901). Reaping a corpse is right —
		# a headstone read once is a diagnosis, read forever it is a registry that
		# fills up and stops being read. Reaping on an UNMATCHED CORROBORATION is
		# not, and this line used to do both, because `task_alive` collapses "the
		# process is gone" and "the process is not this task" into one `false`.
		#
		# That made a read verb destroy the state it reads, and the anchor bug
		# above pointed it at healthy tasks: measured, one call reported a live
		# `land` as crashed AND erased its entry, so the follow-up call reported
		# `nothing registered` — a different lie, caused by the first. The registry
		# is what a SUCCESSOR session reads after a container reclaim to learn what
		# was in flight, and CLOUD-428 consumes this verdict to refuse a duplicate
		# `land`; both were being handed the one answer that disables them.
		#
		# So the asymmetry this file already argues for — "a wrongly CRASHED
		# verdict is the expensive direction … an unevaluable corroboration reads
		# as ALIVE" — is extended to the destructive action. `kill -0` is the only
		# fact that licenses deletion. A future corroboration bug then costs a
		# wrong word, never the evidence, which is what would have contained this
		# one.
		if ! kill -0 "$pid" 2>/dev/null; then
			rm -f "$file" 2>/dev/null || true
		fi
	fi
done

[[ "$found" -ne 0 ]] || echo "alive: nothing registered"

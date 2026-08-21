#!/usr/bin/env bash
#MISE description="Record what a long-running task is doing, so its liveness and phase can be read without a log"
#
# CLOUD-425. AGENTS.md forces anything over ~2 minutes into the background, and
# nothing was ever built to observe the result. A backgrounded task's death
# surfaces only as a harness notification, which does not survive a container
# restart and cannot be asked again. So "is it alive?" and "what is it doing?"
# had exactly one available answer: read the log and `pgrep`. That is the
# payload-reading non-negotiable 4 forbids everywhere else, and it is unreliable
# — measured 2026-08-12, a dead `land` was reported to a human as "still in
# verify" twice, seventeen minutes apart, because `pgrep -f` matched the asking
# subshell and nothing checked whether the work processes existed.
#
# **State is pushed, not polled.** Each task writes its phase here at transitions
# it already has; reading it requires no cooperation from a blocked process and
# no signal at all. That is not a stylistic preference, it is forced by three
# facts from signal(7) and kill(2):
#
#   * `kill -0` sends no signal — existence and permission checks only. Free and
#     safe against any process, whatever it is doing. This is the reliable half,
#     and it works while the target is blocked in a 200s `cargo test`.
#   * SIGUSR1/SIGUSR2's default disposition is **Term**. Signalling a task that
#     never installed a handler KILLS it, so a broadcast to "all batten
#     processes" is a footgun that terminates the work it meant to inspect.
#   * A bash trap does not run while a foreground child runs. Handlers fire
#     between commands, so a task blocked in `cargo test` cannot answer a signal
#     until that child exits — precisely when the answer is wanted.
#
# So on-demand signalling cannot be the primary mechanism for shell tasks, and
# this file never sends a signal. `mise run alive` is the reader.
#
# **Shape.** CLOUD-425's refinement says "a shared preamble every long task
# sources". There is no sourced library anywhere in `mise-tasks/` — all 70 tasks
# are standalone — and the directory is auto-scanned by mise, so a library file
# here would also surface as a runnable task. This follows the established
# precedent instead: a verb-dispatching task that siblings shell out to, exactly
# as `land-lock` and `step-receipt` already are. Phase transitions are per-lap,
# not per-second, so a subprocess per transition costs nothing.
#
# **Composition, not re-derivation** (non-negotiable, house-style §2): this says
# what is RUNNING. It does not re-answer any verdict — "is this SHA green" stays
# `checks-green`'s, "is the lease held" stays `land-lock-check`'s.
#
# Exit codes follow the one contract: 0 recorded, 2 could not look.
set -euo pipefail

verb="${1:-}"
case "$verb" in
register | phase | tick | sig | read | unregister) ;;
*)
	echo "::error:: usage: task-registry <register <task> <pid> [phase]|phase <pid> <phase>|tick <pid> <token>|sig <pid> <token>|read <pid> <field>|unregister <pid>>" >&2
	exit 2
	;;
esac

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: task-registry: not a git repository" >&2
	exit 2
}

# One entry per running task, keyed by pid, under the `batten-<noun>` convention
# `batten-receipts/` and `batten-land-lock/` already use.
state_dir="$git_dir/batten-tasks"

now() { date -u +%s; }

# A registry that cannot be written is not an error the CALLER should die on: a
# `land` must not fail because its bookkeeping is unwritable. Registration
# degrades to a no-op, and the reader reports "could not look" rather than
# "nothing runs" — those two are different answers and conflating them is the
# defect this issue exists to fix.
mkdir -p "$state_dir" 2>/dev/null || exit 0

entry() { printf '%s/%s\n' "$state_dir" "$1"; }

# CLOUD-499 doubled the record's job: it must answer "is it MOVING", not only
# "what is it doing", and there are TWO independent ways to move — see the verbs
# below. That put the field list past what positional parameters carry legibly,
# so the entry is loaded into globals, edited, and written back whole. Each
# writer touches one pair and preserves the rest, which is what stops a `tick`
# from silently erasing a `phase`.
e_task=''
e_pgid=''
e_phase=''
e_started_at=''
e_phase_since=''
e_tick=''
e_tick_at=''
e_sig=''
e_sig_at=''

field() { # <file> <name>
	sed -n "s/^$2: //p" "$1" 2>/dev/null | head -n 1
}

load_entry() { # <file>
	e_task=$(field "$1" task)
	e_pgid=$(field "$1" pgid)
	e_phase=$(field "$1" phase)
	e_started_at=$(field "$1" started_at)
	e_phase_since=$(field "$1" phase_since)
	e_tick=$(field "$1" tick)
	e_tick_at=$(field "$1" tick_at)
	e_sig=$(field "$1" sig)
	e_sig_at=$(field "$1" sig_at)
}

# The whole entry is rewritten on every update. It is a few short lines, and a
# rewrite via a temp file plus `mv` is atomic, so a reader never sees a half
# written record — which a line-edit in place could not promise.
write_entry() { # <pid>
	local file tmp
	file=$(entry "$1")
	tmp="$file.$$"
	printf 'task: %s\npid: %s\npgid: %s\nphase: %s\nstarted_at: %s\nphase_since: %s\ntick: %s\ntick_at: %s\nsig: %s\nsig_at: %s\n' \
		"$e_task" "$1" "$e_pgid" "$e_phase" "$e_started_at" "$e_phase_since" \
		"$e_tick" "$e_tick_at" "$e_sig" "$e_sig_at" >"$tmp" 2>/dev/null || return 0
	mv -f "$tmp" "$file" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

# A stamp moves only when its value CHANGES. That one rule is the whole
# mechanism: a writer re-announcing what it already said — a lap repeating a
# step, a poll that learned nothing — must not thereby report progress it did
# not make, because the stall bail's entire job is to disbelieve exactly that.
# Prints the timestamp to use; `$3` is the stamp currently recorded.
stamp_for() { # <new> <old> <old_stamp>
	if [ "$1" = "$2" ] && [ -n "$3" ]; then
		printf '%s\n' "$3"
	else
		now
	fi
}

case "$verb" in
register)
	task="${2:-}"
	pid="${3:-}"
	[ -n "$task" ] && [ -n "$pid" ] || {
		echo "::error:: task-registry register: need <task> <pid>" >&2
		exit 2
	}
	# `set -m` already puts each task's tree in its own process group, so
	# recording the pgid lets a prober reason about the TREE rather than the one
	# shell — which is what `land`'s own group kills already depend on. An
	# unreadable pgid is recorded as the pid: a group of one is the truth for a
	# task that was not started under job control.
	pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') || pgid=
	[ -n "$pgid" ] || pgid="$pid"
	e_task="$task"
	e_pgid="$pgid"
	e_phase="${4:-starting}"
	e_started_at=$(now)
	e_phase_since="$e_started_at"
	e_tick=''
	e_tick_at=''
	e_sig=''
	e_sig_at=''
	write_entry "$pid"
	;;
phase)
	# THE SLOW SIGNAL: what the task is doing, and since when. `land` pushes one
	# per lap step; nested gates refine it through `BATTEN_TASK_PID`.
	pid="${2:-}"
	new="${3:-}"
	[ -n "$pid" ] && [ -n "$new" ] || {
		echo "::error:: task-registry phase: need <pid> <phase>" >&2
		exit 2
	}
	file=$(entry "$pid")
	# A phase update for a task that never registered is a no-op rather than a
	# fabricated entry: the registry records what registered, and inventing a
	# record here would let a half-wired task look fully wired.
	[ -f "$file" ] || exit 0
	load_entry "$file"
	e_phase_since=$(stamp_for "$new" "$e_phase" "$e_phase_since")
	e_phase="$new"
	write_entry "$pid"
	;;
tick | sig)
	# THE TWO SIGNALS A LOOP PUSHES, and they answer different questions
	# (CLOUD-499). Both exist because one cannot cover both failures:
	#
	#   tick — the loop went ROUND. `ci-wait` pushes one per poll, counter and
	#          all, so it moves on every iteration including the ones that learn
	#          nothing. Frozen ⇒ the loop is blocked, not waiting.
	#   sig  — the WORLD moved. `ci-wait` pushes the check-run reading, so it
	#          moves only when a check does. Frozen while the tick keeps moving
	#          ⇒ a poll that will never resolve, which is the livelock a hang
	#          detector cannot see.
	#
	# Neither replaces `phase`: a task with no loop at all still advances its
	# phase, which is why the heartbeat reads the LATEST of the stamps rather
	# than any one of them.
	pid="${2:-}"
	token="${3:-}"
	[ -n "$pid" ] && [ -n "$token" ] || {
		echo "::error:: task-registry $verb: need <pid> <token>" >&2
		exit 2
	}
	file=$(entry "$pid")
	[ -f "$file" ] || exit 0
	load_entry "$file"
	if [ "$verb" = tick ]; then
		e_tick_at=$(stamp_for "$token" "$e_tick" "$e_tick_at")
		e_tick="$token"
	else
		e_sig_at=$(stamp_for "$token" "$e_sig" "$e_sig_at")
		e_sig="$token"
	fi
	write_entry "$pid"
	;;
read)
	# The single-field reader, so a prober composes rather than becoming a second
	# parser of this layout (house-style §2). `land-lock`'s heartbeat is the
	# caller; `alive` predates it and reads the directory as a whole.
	#
	# Exit 1 is "no such entry", which is a READING and not an error: a task that
	# never registered is invisible, exactly as `alive` reports it. Exit 2 stays
	# reserved for "could not look", which is the missing-argument case only.
	pid="${2:-}"
	name="${3:-}"
	[ -n "$pid" ] && [ -n "$name" ] || {
		echo "::error:: task-registry read: need <pid> <field>" >&2
		exit 2
	}
	file=$(entry "$pid")
	[ -f "$file" ] || exit 1
	field "$file" "$name"
	;;
unregister)
	pid="${2:-}"
	[ -n "$pid" ] || {
		echo "::error:: task-registry unregister: need <pid>" >&2
		exit 2
	}
	# Called from the task's EXIT trap, which also runs on INT/TERM given the
	# `trap 'exit 1' INT TERM` pairing every long task in this repo already has.
	# A task that is SIGKILLed cannot run it — that is exactly the case `alive`
	# reports as crashed rather than as absent.
	rm -f "$(entry "$pid")" 2>/dev/null || true
	;;
esac

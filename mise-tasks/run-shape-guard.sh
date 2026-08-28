#!/usr/bin/env bash
#MISE description="PreToolUse hook body: deny a foreground sleep, which spends the session's turn, a git commit that cannot obtain a message, which spends the whole gate first, and a mediated cargo that is a weaker form of a task's own argv"
#
# THREE FAMILIES, and what is NOT here is the point. This guard used to carry
# five predicates; the three that discard a verdict — a pager or filter pipe, a
# trailing list element, `nohup`/`&` — moved into the engine with CLOUD-443 as
# `batten.toml`'s `verdict-not-discarded` row, and the corpus that proved them is
# `crates/batten/tests/pipeline_shapes.rs`. They are gone from here rather than
# duplicated, because a predicate enforced in two places is two authorities that
# drift.
#
# These remain because the engine cannot express them, each for its own reason
# rather than for want of a rule kind:
#
#   foreground-sleep `cd repo; sleep 90; git log --oneline -1` waits inside the
#                   call. It fails GREEN only up to ~2 minutes; past that the
#                   harness kills the call, so the poll that was meant to be
#                   patient FAILS instead (measured at exit 143 and 144).
#                   `sleep 590; tail -6 land.log` BACKGROUNDED is the same shape
#                   with the clock moved off the turn: a timer where an exit
#                   condition belongs, written 490 times in one session while
#                   the completion notification it duplicated fired 523 times.
#                   The predicate is over `run_in_background` — a fact about the
#                   CALL rather than about the command string — and the mediated
#                   envelope carries it only inside the raw tool input.
#   unsatisfiable-commit  `git add -A && git commit -F - && mise run land <<'EOF'`
#                   is doomed at the instant it starts: the heredoc binds to the
#                   LAST element, so git's stdin is the harness's /dev/null. It
#                   fails RED, eventually — but `githooks(5)` runs `pre-commit`
#                   before git asks for the message, so the whole gate is spent
#                   first. Measured at ~4 minutes on a commit git was always
#                   going to refuse. The predicate is over heredoc BINDING, which
#                   no shape or operator table describes.
#
#   cargo-substitutes-for-a-task  `mise exec -- cargo clippy -p batten
#                   --all-targets` is the escape `no-bare-cargo`'s own refusal
#                   text recommends, and it is WEAKER than the task it stands in
#                   for — measured clean over 10 `expect_used` errors, then
#                   quoted as verification. Its predicate is over `mise.toml`'s
#                   task bodies, a FILE the rule reads; a `mediated_call` kind
#                   cannot spawn (`no_mediated_call_kind_spawns_a_process`) and a
#                   `shape` row's pattern is a literal, so neither can derive a
#                   mapping that must not be restated. CLOUD-822.
#
# One root cause, shared with the three that left: treating a Bash call as a
# terminal that should print something short, when it is a supervised process
# whose exit status and lifetime are the interface. A foreground `sleep` sits at
# the terminal waiting, which is the one thing a supervised process must never
# do; a commit that can never obtain a message spends the gate before saying so;
# a weaker `cargo` prints an exit 0 that means nothing and gets quoted anyway.
#
# WHAT HAS MIGRATED, AND WHAT HAS NOT (CLOUD-843 track 2, measured 2026-08-21).
# This table is the record the campaign's census reads against, and it is here
# rather than on the board because the board cannot say which arm of a file is
# gone. A family moves when its predicate is a function of something
# `hook::call_document` actually puts in front of a module.
#
#   family                          state    blocked on
#   ------------------------------  -------  --------------------------------
#   foreground-sleep                BASH     `run_in_background` is not in
#                                            `call_document`; reachable only
#                                            through `hook::Field`. CLOUD-613.
#   background-timer (CLOUD-821)    BASH     same fact, same row.
#   unsatisfiable-commit            BASH     heredoc BINDING, which nothing in
#     (`-F -`, nothing redirected)           the engine models. CLOUD-613, and
#                                            CLOUD-723 is the open row showing
#                                            the parser reading a heredoc body
#                                            as shell in the other direction.
#   commit-names-no-message-source  MIGRATED `policy/run-shape.rego`, negative
#                                            controls in `tests/run-shape.bats`.
#   cargo-substitutes-for-a-task    BASH     needs `mise.toml`, and
#     (CLOUD-822)                            `call_document` projects
#                                            `Fact::Document` as `None` on the
#                                            mediated call — its cost is
#                                            unbounded there. NOT CLOUD-613,
#                                            which names only the two facts
#                                            above; this blocker is CLOUD-856.
#
# So four of five stay, and this file is NOT deletable: it still owns them.
# Retiring the two CLOUD-613 names is that row; the cargo family is CLOUD-856.
#
# Fails OPEN on anything it cannot parse, and honours BATTEN_RUN_SHAPE_BYPASS=1.
#
# REGISTERED BY PATH on `PreToolUse`/`Bash` in `.claude/settings.json`, with its
# owning row in `hooks-wiring-check`'s `DECLARED` table. It was not registered
# anywhere for the first 267 lines of its life — `git log -S` over that file
# returns nothing before CLOUD-821 — so every rule below, and AGENTS.md's claim
# to be gated by them, was prose. That is non-negotiable rule 2 failing one
# level up: the mechanism landed and the wiring did not.
#
#MUTANT commit-stdin-unchecked|s@^COMMIT_STDIN=.*@COMMIT_STDIN="ZZZNEVERMATCHES"@|THE MEASURED SHAPE: the heredoc binds to a later element
#
# The third mutation restores the exemption CLOUD-821 narrowed: every background
# call reads as waiting on a condition again, so a bare backgrounded `sleep`
# takes the skip and the timer rows go green. It is the rule as it shipped
# before that issue, by the route it actually let through.
#MUTANT background-timer-exempt|s@waits_on_condition=0@waits_on_condition=1@|THE MEASURED SHAPE: a backgrounded sleep-then-read is a timer, not a wait
set -uo pipefail

[[ -n "${BATTEN_RUN_SHAPE_BYPASS:-}" ]] && exit 0

raw=$(cat) || exit 0

# PAYLOAD READS GO THROUGH `payload-field`, never `jq` (CLOUD-479, CLOUD-821):
# this is registered BY PATH, so it does not get mise's env, and a `jq` that
# resolved to nothing would make every read below fail OPEN and silently — the
# whole guard reporting clean while judging nothing. `hook-pin-check` refuses
# the pairing, and refused this file while it was being wired.
here="$(dirname -- "${BASH_SOURCE[0]}")"
field="$here/payload-field.sh"
# `mise.toml` is the one authority for what a task actually runs (CLOUD-822),
# resolved beside this file rather than from cwd: a `PreToolUse` hook is invoked
# from wherever the call was made.
MISE_TOML="$here/../mise.toml"
[[ -x "$field" ]] || exit 0

cmd=$(printf '%s' "$raw" | "$field" command) || exit 0
[[ -n "$cmd" ]] || exit 0

# THE ONE FACT ABOUT THE CALL rather than about the command string, and the one
# CLOUD-613 named as hidden by the mediated envelope. `Field::RunInBackground`
# is the deliberate allowlist edit that unhid it. Empty means the host did not
# say, which is judged as foreground: the shape this guard refuses is a wait,
# and a wait whose posture is unknown is the one to be strict about.
background=$(printf '%s' "$raw" | "$field" run-in-background) || background=""

# Heredoc BODIES are dropped first, then quoted spans neutralised, so a commit
# message, issue body or documentation paragraph *describing* these shapes is not
# judged as one. Quote-scrubbing alone is not enough: a heredoc writing prose that
# names `nohup`/`&` is unquoted text, and this guard denied exactly that on the
# command that documented it.
# A heredoc opener can appear anywhere on the line (`cat >> f <<EOF`), so this is
# not anchored — an anchored version missed `cat >> tests/x.bats <<BATS` and the
# guard denied the command writing its own test fixture. `<<<` is a here-STRING,
# not a heredoc, and must not start a skip that never terminates.
body=$(awk '
	!inheredoc && /<<-?[[:space:]]*['"'"'"]?[A-Za-z_][A-Za-z0-9_]*['"'"'"]?/ && !/<<</ {
		line = $0
		sub(/^.*<<-?[[:space:]]*/, "", line)
		sub(/[^A-Za-z0-9_'"'"'"].*$/, "", line)
		gsub(/['"'"'"]/, "", line)
		if (line != "") { term = line; inheredoc = 1 }
		print; next
	}
	inheredoc { if ($0 ~ "^[[:space:]]*" term "[[:space:]]*$") inheredoc = 0; next }
	{ print }
' <<<"$cmd")
# Slurped whole, so a quoted span is neutralised across NEWLINES. A line-at-a-
# time reader left the interior of every multi-line `git commit -m "…"` exposed
# — and a commit message documenting these shapes is the single most likely
# place to write them down. The guard denied exactly that.
#
# `perl -0777` and not sed's NUL-separated mode (CLOUD-282): `-z` is a GNU
# extension, BSD sed exits `illegal option -- z`, so a macOS checkout could not
# run this guard at all. Byte-identical for both substitutions, differentially
# verified against the real fixtures. The banned literal is deliberately not
# spelled here — `no-gnu-sed-z` in batten.toml is a substring rule over this
# directory, so quoting it would make the row fire on its own rationale.
scrubbed=$(printf '%s' "$body" | perl -0777 -pe "s/'[^']*'/QUOTED/g; s/\"[^\"]*\"/QUOTED/g")

# --- resolve a pipeline stage to its EFFECTIVE program ------------------------
#
# Prints "<program> <first non-flag word> <second non-flag word>". The wrapper
# skip is `gh-guard-check`'s: in the web sandbox `mise exec -- …` is often the
# only working form, so a guard that stops at the wrapper token sees none of the
# calls that matter.
# RESOLVED_VIA and RESOLVED_ARGV are set as a side effect, for the CLOUD-822 rule
# below, which needs two things this signature cannot carry: whether the call was
# MEDIATED through `mise exec` (a bare one belongs to the engine's
# `no-bare-cargo`, and two rules reporting one command is the drift this file's
# header refuses), and the flags — which `words` deliberately drops. Set here
# rather than re-derived by a second wrapper-skipping loop, because two loops
# agreeing about what `env -i timeout 5 mise exec -- cargo` resolves to is a
# coincidence waiting to end. Existing callers read three words and are
# unaffected; they call this in a subshell, where the globals simply do not
# escape.
RESOLVED_VIA=direct
RESOLVED_ARGV=()
resolve() {
	local seg=$1
	local -a toks words
	read -r -a toks <<<"$seg"
	local count=${#toks[@]} i=0
	RESOLVED_VIA=direct
	RESOLVED_ARGV=()
	while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do i=$((i + 1)); done
	while :; do
		case "${toks[$i]:-}" in
		env | command | nice | stdbuf | timeout | xargs | sudo | doas | nohup)
			i=$((i + 1))
			while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^(-|[A-Za-z_][A-Za-z0-9_]*=|[0-9]) ]]; do i=$((i + 1)); done
			;;
		mise)
			# Only `mise exec`/`mise x` run another program; `mise run` names a
			# task and IS the thing being judged.
			case "${toks[$((i + 1))]:-}" in
			exec | x)
				RESOLVED_VIA=mise
				i=$((i + 2))
				while [[ "$i" -lt "$count" ]] && [[ ${toks[$i]} =~ ^(-|[^ ]*@) ]]; do i=$((i + 1)); done
				;;
			*) break ;;
			esac
			;;
		*) break ;;
		esac
	done
	local prog=${toks[$i]:-}
	prog=${prog##*/}
	RESOLVED_ARGV=("${toks[@]:$i}")
	words=()
	local t
	for t in "${toks[@]:$((i + 1))}"; do
		case "$t" in -* | *'>'* | *'<'*) ;; *) words+=("$t") ;; esac
	done
	printf '%s %s %s' "$prog" "${words[0]:-}" "${words[1]:-}"
}

# A deny document on stdout with exit 0 — the in-band channel this host reads.
# Hand-escaped rather than built with `jq -n` for the reason above: a by-path
# registration cannot depend on a pinned tool. `fanout-guard`'s `decide()` is
# the same three substitutions in the same order, and the order matters —
# backslashes first, or the escapes this adds get escaped again.
deny() {
	local reason="$1" escaped
	escaped=${reason//\\/\\\\}
	escaped=${escaped//\"/\\\"}
	escaped=${escaped//$'\n'/\\n}
	printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$escaped"
	exit 0
}

# --- split into LIST elements, remembering the separator ----------------------
#
# `&&` and `||` are replaced before `;` so the two-character operators are never
# read as a bare `|` or `&`. What remains inside an element is a real pipe or a
# real background operator, which the two checks below judge.
list=$(printf '%s' "$scrubbed" | sed -E 's/\|\|/\n@OR@/g; s/\&\&/\n@AND@/g; s/;/\n@SEMI@/g')

elements=()
seps=()
while IFS= read -r line; do
	case "$line" in
	@OR@*)
		seps+=(OR)
		elements+=("${line#@OR@}")
		;;
	@AND@*)
		seps+=(AND)
		elements+=("${line#@AND@}")
		;;
	@SEMI@*)
		seps+=(SEMI)
		elements+=("${line#@SEMI@}")
		;;
	*)
		seps+=(FIRST)
		elements+=("$line")
		;;
	esac
done < <(printf '%s\n' "$list")

# --- foreground-sleep ---------------------------------------------------------
#
# A DIFFERENT FAMILY FROM THE THREE ABOVE, and it is here because it is the same
# root cause: treating a Bash call as a terminal you can wait at, when it is a
# supervised process whose lifetime is the interface. The other three destroy a
# verdict; this one destroys the SESSION.
#
# Measured 2026-08-12. A `git commit` hung inside a gate that had begun calling
# itself, and the session polled it with `sleep 90`, `sleep 100`, `sleep 180` in
# the foreground. A foreground call is killed at ~2 minutes, so the last two did
# not run slower — they FAILED, at exit 143 and 144 — and every turn in between
# bought nothing. The container was reclaimed with the fix uncommitted, and the
# branch it was landing is still a draft.
#
# AGENTS.md has stated "never use a foreground sleep" for as long as it has
# stated the other three, and nothing enforced it: this guard mentioned `sleep`
# only inside one comment's example. Prose is feedforward only (non-negotiable
# rule 2), and the session that hit this had read the prose.
#
# THE PREDICATE IS THE CALL'S OWN SHAPE, not the sleep's duration. A short sleep
# is not safer, it is the same shape spending less. Judged per stage, so a sleep
# anywhere in a compound (`cd x; sleep 90; git log`, the exact measured shape)
# is caught rather than only a leading one.
#
# WHAT `run_in_background` DECIDES, AND WHAT IT DOES NOT (CLOUD-821). Until that
# issue the flag skipped this family outright, on the reasoning that a
# background `until … sleep 0.5 … done` is the CORRECT form the tool
# documentation recommends and denying it would be the pure false positive
# CLOUD-199 measured. The carve-out is right; the flag is the wrong proxy for
# it, and the sentence this file already emits says so: what makes a wait
# correct is a command that **EXITS when the condition holds**.
#
# Measured 2026-08-21, one session landing CLOUD-776: 490 calls of
#
#   sleep 590; tail -6 /tmp/land.log
#
# backgrounded, against 5 that did any work, and 2 of the 490 changed a
# decision. That is not a wait, it is a wall clock standing in for an event —
# and the event already existed: 523 of that session's 524 backgrounded tasks
# re-invoked it on exit. The flag had moved the poll out of this guard's view
# rather than making it correct.
#
# So the exemption now asks for the exit condition itself. A background call
# whose command carries an `until`/`while` construct is exempt as before; a
# background call with a bare `sleep` and no loop is a timer, and is refused
# with the remedy the foreground case already names.
#
# THE LOOP TEST IS OVER THE WHOLE SCRUBBED COMMAND, never the element. The list
# split below turns `until <test>; do sleep 5; done` into three elements and the
# one carrying the sleep has no keyword in it — an element-scoped test would deny
# every correct wait, which is precisely the false positive that gets a guard
# bypassed. Coarse in the allowing direction on purpose: `for i in $(seq 60); do
# sleep 10; done` is a timer too and is NOT caught, because narrowing that costs
# a real parser and CLOUD-199's bar is that a guard be 100% right on a narrow
# shape rather than 80% right on a broad one.
#
# Matched with `<<<` and never a pipe: `grep -q` exits on its first match, which
# SIGPIPEs the producer, and under `pipefail` that makes the pipeline report
# failure — so a MATCH would read as "no keyword" and every correct wait would be
# denied. `pipefail-grep-check` refuses that shape and refused this one while it
# was being written.
if grep -Eq '(^|[[:space:]])(until|while)([[:space:]]|$)' <<<"$scrubbed"; then
	waits_on_condition=1
else
	waits_on_condition=0
fi

if [[ "$background" != true ]] || [[ "$waits_on_condition" = 0 ]]; then
	for element in "${elements[@]}"; do
		# A `read` loop, with the producer terminating its last line (CLOUD-282):
		# bash 4's array-read builtin is unavailable on macOS's 3.2. The trailing
		# newline is what makes the two equivalent — `read` returns false on an
		# unterminated final segment, and for a one-stage element that segment is
		# every stage, so `printf '%s'` here would empty the loop entirely.
		sleep_stages=()
		while IFS= read -r sleep_stage_line; do
			sleep_stages+=("$sleep_stage_line")
		done < <(printf '%s\n' "$element" | tr '|' '\n')
		for stage in "${sleep_stages[@]}"; do
			read -r prog _ _ <<<"$(resolve "$stage")"
			[[ "$prog" = sleep ]] || continue
			if [[ "$background" = true ]]; then
				deny "Refused: a backgrounded \`sleep\` with no loop around it is a TIMER, not a wait. It exits when the clock says so, never when the thing you are waiting for happens, so it reports the same whether that thing finished, failed, or never started.

You do not need it. A backgrounded task's exit notification IS the wake-up, and it is delivered: measured 523 of 524 backgrounded tasks in one session, including every failure. Idling until it arrives is the designed state, not a turn wasted — launch the work with run_in_background and act on the notification.

If the question is \"is it still going\" rather than \"has it finished\", ask once:

  mise run alive

which reports every running task and its phase, pushed rather than polled. If you must wait on state nothing notifies you about — a remote queue, a file another process writes — background a command that EXITS when the condition holds (\`until <test>; do sleep 5; done\`), which is allowed and is what this rule asks for.

Measured 2026-08-21: 490 of these in one session, 2 of which changed a decision.

Bypass with BATTEN_RUN_SHAPE_BYPASS=1."
			fi
			deny "Refused: a foreground \`sleep\` spends the session's own turn waiting, and the call is killed at ~2 minutes — so a wait longer than that does not run slowly, it FAILS (measured: exit 143 and 144 over a hung commit, then the container was reclaimed with the work uncommitted).

Waiting is the harness's job, not the command's. Put the thing you are waiting for in the background — pass run_in_background on the tool call itself — and act on its exit; the harness re-invokes you. That notification is delivered (measured 523 of 524 in one session), so the wait costs you nothing to skip. For a condition rather than a process, background a command that EXITS when the condition holds (\`until <test>; do sleep 1; done\`), which is a background wait and is allowed.

To ask what a running task is doing rather than wait for it, \`mise run alive\` answers in one call.

Never end a turn idle to watch something, and never poll in the foreground.

Bypass with BATTEN_RUN_SHAPE_BYPASS=1."
		done
	done
fi

# --- unsatisfiable-commit -----------------------------------------------------
#
# A THIRD FAMILY, and the waste lands somewhere new: not on a verdict and not on
# the session, but on the GATE. `githooks(5)` runs `pre-commit` BEFORE git obtains
# the proposed message, so a `git commit` that can never get one still runs the
# entire gate — here a full `test:bats` plus the cargo chain — and only then exits
# with "Aborting commit due to empty commit message".
#
# Measured 2026-08-12, landing PR #375:
#
#   git add -A && git commit -F - >log 2>&1 && mise run land >log2 2>&1 <<'EOF'
#
# The heredoc binds to the LAST command in the `&&` list, so `mise run land` got
# the message and `git commit -F -` got the harness's /dev/null. ~4 minutes of
# gate, and killing it took `kill -9` on the process GROUP, because hk's children
# carry its command line and `pkill -f` did not reach them.
#
# JUDGED PER ELEMENT, which is exactly what makes the measured shape decidable:
# the opener is present in the command STRING and absent from the element that
# needed it. A heredoc that genuinely binds here — `git commit -F - <<'EOF'` — has
# it in the same element and is allowed, as is `< msg.txt` and `<<< "$msg"`.
#
# ONE shape now. The other — no message flag at all, which opens $EDITOR in a
# non-interactive call — MIGRATED to `policy/run-shape.rego` and is gone from
# here rather than duplicated. See the census table in this file's header.
#
# `git -C <path> commit` resolves to `sub1=<path>` and is NOT caught. That is a
# deliberate false NEGATIVE: CLOUD-199 measured that a guard with false positives
# gets bypassed, this repo commits from its own root, and the direction to be
# wrong in is the one that lets real work through.
COMMIT_STDIN='(^|[[:space:]])(-[A-Za-z]*F[[:space:]]*-([[:space:]]|$)|--file[=[:space:]]-([[:space:]]|$))'
# shellcheck disable=SC2016  # the backticks are literal markdown and `$msg` is a literal example, not a subshell or an expansion
COMMIT_REMEDY='Write the message to a file and pass `-F <path>`. It is heredoc-free, so it cannot bind to a different element, and the file is inspectable after the fact:

  printf %s "$msg" >/tmp/msg.txt   # or the Write tool
  git commit -F /tmp/msg.txt

Bypass with BATTEN_RUN_SHAPE_BYPASS=1.'
for element in "${elements[@]}"; do
	# Per stage, like the sleep rule: `git commit` is not verdict-bearing, so the
	# `last_verdict` early exit below would never reach it.
	# Same read-loop-with-terminated-producer as the sleep rule above (CLOUD-282).
	commit_stages=()
	while IFS= read -r commit_stage_line; do
		commit_stages+=("$commit_stage_line")
	done < <(printf '%s\n' "$element" | tr '|' '\n')
	for stage in "${commit_stages[@]}"; do
		read -r prog sub1 _ <<<"$(resolve "$stage")"
		if [[ "$prog" != git ]] || [[ "$sub1" != commit ]]; then continue; fi
		# ANY redirect into this stage is a message source — `<` a file, `<<` a
		# heredoc, `<<<` a here-string — so one test covers all three and cannot
		# be wrong about which. Quoted spans and heredoc BODIES are already gone
		# by here, so a `<` written inside a commit message cannot reach this.
		if grep -qE "$COMMIT_STDIN" <<<"$stage" && ! grep -q '<' <<<"$stage"; then
			deny "Refused: \`git commit -F -\` with nothing redirected into it reads the harness's /dev/null, so the commit is doomed at the instant it starts — but \`pre-commit\` runs BEFORE git asks for the message, so the whole gate is spent first and only then does git say \"Aborting commit due to empty commit message\".

Measured 2026-08-12: ~4 minutes of gate on a doomed commit, in a chain whose heredoc bound to a LATER element (\`git commit -F - && mise run land <<EOF\` hands the message to \`land\`). Killing it took \`kill -9\` on the process group.

$COMMIT_REMEDY"
		fi
	done
done

# --- cargo-substitutes-for-a-task (CLOUD-822) --------------------------------
#
# `no-bare-cargo` gates the TOOLCHAIN and not the STRICTNESS, and its own refusal
# text hands out the gap: "or `mise exec -- cargo ...` for a one-off." That
# escape fixes which compiler runs and says nothing about which lint set does.
# `mise run lint:clippy` adds `-D warnings`, which promotes the workspace's
# warn-level `unwrap_used`/`expect_used` to errors; the escape omits it.
#
# Measured 2026-08-21, three times in one session. `mise exec -- cargo check -p
# batten` missed 15 `Policy` literals short a field — the lib test target did not
# compile, on two PUSHED commits. `mise exec -- cargo clippy -p batten
# --all-targets` missed 10 `expect_used` errors and a `needless_raw_string_hashes`.
# `--all-targets` is MORE thorough than the default and still weaker than the
# task, because thoroughness and strictness are different axes, and adding flags
# does not converge on the task.
#
# WORSE THAN AN ORDINARY MISS: the exit 0 was then quoted as verification, into a
# commit message and a summary. The wrong answer did not merely fail to help.
#
# THE MAPPING IS DERIVED, NEVER RESTATED (§1). `mise.toml` already holds the real
# command lines, so this reads them — the discipline `hooks-wiring-check` uses
# against `render_wiring`, and what keeps this off CLOUD-691's shape, where a
# predicate enumerating spellings lags the thing it guards.
#
# ONLY THE MEDIATED FORM, so the two rules never report one command. A bare
# `cargo clippy` is the engine's `no-bare-cargo`, and `RESOLVED_VIA` is what
# tells them apart.
#
# The mutation makes the flag comparison unfalsifiable, so no invocation is ever
# weaker than a task and the escape is allowed again — the state this row found,
# where the false green was reportable and every case below still passed.
#MUTANT cargo-substitution-allowed|s@missing="\$flag"@missing=""@|THE MEASURED SHAPE: a weaker clippy through the sanctioned escape is refused

# The cargo argv of one command line, split into the three things "weaker" is
# decided over. Sets CARGO_SUB, CARGO_FLAGS and CARGO_TAIL.
#
# THE `--` SEPARATOR MEANS TWO DIFFERENT THINGS, and the discriminator is derived
# rather than listed: after `cargo clippy --` come more LINT FLAGS (`-D
# warnings`), and after `cargo run --` comes a different program's ARGV
# (`provision apply`). Which one it is, is whether the first token past `--`
# starts with a dash. That distinction is load-bearing — without it `cargo run -p
# batten -- check` reads as a weaker `cargo run --quiet -p batten -- provision
# apply`, which is not a substitution at all but a different command, and a guard
# that denies those is one CLOUD-199 measured getting switched off.
cargo_shape() { # cargo_shape <tokens from `cargo` onward>
	local -a toks=("$@")
	local count=${#toks[@]} i=1 t
	CARGO_SUB=""
	CARGO_FLAGS=""
	CARGO_TAIL=""
	# `+nightly` selects a toolchain, not a subcommand.
	while [[ "$i" -lt "$count" ]] && [[ "${toks[$i]#+}" != "${toks[$i]}" ]]; do i=$((i + 1)); done
	while [[ "$i" -lt "$count" ]]; do
		t=${toks[$i]}
		[[ "$t" = "--" ]] && break
		case "$t" in
		-*) CARGO_FLAGS="$CARGO_FLAGS $t" ;;
		*) if [[ -z "$CARGO_SUB" ]]; then CARGO_SUB=$t; else CARGO_FLAGS="$CARGO_FLAGS $t"; fi ;;
		esac
		i=$((i + 1))
	done
	[[ "$i" -lt "$count" ]] || return 0
	i=$((i + 1)) # step over the `--`
	case "${toks[$i]:-}" in
	-*)
		# More flags for the same subcommand. `-D warnings` IS the strictness
		# this rule exists to notice, so it belongs on the flag side.
		while [[ "$i" -lt "$count" ]]; do
			CARGO_FLAGS="$CARGO_FLAGS ${toks[$i]}"
			i=$((i + 1))
		done
		;;
	?*)
		# A program argv: identity, not strictness, so it is compared whole.
		while [[ "$i" -lt "$count" ]]; do
			CARGO_TAIL="$CARGO_TAIL ${toks[$i]}"
			i=$((i + 1))
		done
		;;
	esac
}

# Every `cargo` command line `mise.toml`'s task bodies declare, as
# `<task><TAB><line>`.
#
# ONLY `run` BODIES ARE READ. A `description` naming a command is prose, and
# reading it registered `test:bats` as wrapping `cargo test` while this was being
# written — a task whose body runs no cargo at all.
#
# `awk`, not a pinned `taplo` or `jq`: this guard is registered BY PATH and does
# not get mise's env, which is the whole reason `payload-field` exists and what
# `hook-pin-check` refuses. The triple-quote delimiters are built from character
# codes rather than written as literals, so this stays quotable inside the single
# quotes the shell puts around it.
declared_cargo_lines() {
	awk '
		BEGIN {
			sq = sprintf("%c", 39)
			dq = sprintf("%c", 34)
			tq_s = sq sq sq
			tq_d = dq dq dq
		}
		/^\[/ {
			inrun = 0
			name = ""
			if ($0 ~ /^\[tasks[.]/) {
				name = $0
				sub(/^\[tasks[.]/, "", name)
				sub(/\]$/, "", name)
				gsub(dq, "", name)
			}
			next
		}
		name == "" { next }
		{
			trimmed = $0
			sub(/^[[:space:]]+/, "", trimmed)
			sub(/[[:space:]]+$/, "", trimmed)
		}
		inrun {
			if (trimmed == tq_s || trimmed == tq_d) { inrun = 0; next }
			print name "\t" $0
			next
		}
		trimmed ~ /^run[[:space:]]*=/ {
			rest = trimmed
			sub(/^run[[:space:]]*=[[:space:]]*/, "", rest)
			if (rest == tq_s || rest == tq_d) { inrun = 1; next }
			first = substr(rest, 1, 1)
			if (first == sq || first == dq) { rest = substr(rest, 2, length(rest) - 2) }
			print name "\t" rest
			next
		}
	' "$1"
}

for element in "${elements[@]}"; do
	cargo_stages=()
	while IFS= read -r cargo_stage_line; do
		cargo_stages+=("$cargo_stage_line")
	done < <(printf '%s\n' "$element" | tr '|' '\n')
	for stage in "${cargo_stages[@]}"; do
		# Called OUTSIDE a subshell, unlike the two rules above: the argv and the
		# wrapper this rule needs are side-effect globals, and `$(…)` would eat
		# them. The alternative is a second copy of the wrapper-skipping loop,
		# which is the drift this file's header refuses.
		resolve "$stage" >/dev/null
		prog=${RESOLVED_ARGV[0]:-}
		prog=${prog##*/}
		[[ "$prog" = cargo ]] || continue
		[[ "$RESOLVED_VIA" = mise ]] || continue
		[[ -f "$MISE_TOML" ]] || continue
		cargo_shape "${RESOLVED_ARGV[@]}"
		[[ -n "$CARGO_SUB" ]] || continue
		want_sub=$CARGO_SUB
		want_flags=$CARGO_FLAGS
		want_tail=$CARGO_TAIL
		wrapped=""
		while IFS=$'\t' read -r task line; do
			[[ -n "$task" ]] || continue
			# Cut at the first shell operator, so `if ! cargo test --workspace;
			# then exit 1; fi` yields the argv and not the words around it.
			line=${line%%;*}
			read -r -a line_toks <<<"$(sed -E 's/[|&<>]/ /g' <<<"$line")"
			start=-1
			for idx in "${!line_toks[@]}"; do
				if [[ "${line_toks[$idx]##*/}" = cargo ]]; then
					start=$idx
					break
				fi
			done
			[[ "$start" -ge 0 ]] || continue
			cargo_shape "${line_toks[@]:$start}"
			[[ "$CARGO_SUB" = "$want_sub" ]] || continue
			# A different program argv is a different command, not a weaker one.
			[[ "$CARGO_TAIL" = "$want_tail" ]] || continue
			# WEAKER IS DECIDABLE, never judged: the task carries at least one
			# flag token this invocation omits. An EQUAL argv is not weaker, so
			# spelling a task's own line out by hand stays allowed.
			missing=""
			# shellcheck disable=SC2086  # word splitting is the comparison
			for flag in $CARGO_FLAGS; do
				case " $want_flags " in
				*" $flag "*) ;;
				*) missing="$flag" ;;
				esac
			done
			[[ -n "$missing" ]] || continue
			case " $wrapped " in
			*" $task "*) ;;
			*) wrapped="$wrapped $task" ;;
			esac
		done < <(declared_cargo_lines "$MISE_TOML")
		# A subcommand no task wraps is a genuine one-off and is UNTOUCHED: the
		# refusal is about SUBSTITUTION, not about the escape existing.
		[[ -n "$wrapped" ]] || continue
		# EVERY task it is weaker than, sorted, because which one "should have
		# run" is not derivable — several tasks legitimately wrap one subcommand,
		# and picking between them needs a judgement a gate must not make. Sorted
		# so the output is byte-stable. Pointer-only: the subcommand and task
		# names, never the tree or the diff.
		# shellcheck disable=SC2086  # word splitting is how the list is re-read
		named=$(printf '%s\n' $wrapped | sort | tr '\n' ' ')
		named=${named% }
		deny "Refused: this is a WEAKER form of a task that already declares \`cargo $want_sub\` — ${named// /, }. Each of those carries flags this invocation omits.

\`mise exec -- cargo ...\` fixes the TOOLCHAIN and says nothing about the STRICTNESS: \`mise run lint:clippy\` adds \`-D warnings\`, which promotes the workspace's warn-level lints to errors, and the escape does not. Measured 2026-08-21, \`mise exec -- cargo clippy -p batten --all-targets\` reported clean over 10 \`expect_used\` errors — and \`--all-targets\` is MORE thorough than the default, because thoroughness and strictness are different axes. That exit 0 was then quoted as verification.

Run the task instead: \`mise run <task>\`. A subcommand no task wraps is untouched, so a genuine one-off still works. Bypass with BATTEN_RUN_SHAPE_BYPASS=1."
	done
done

exit 0

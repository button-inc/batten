#!/usr/bin/env bash
#MISE description="Gate: a shipped tag reaches Linear — both release-tracking invocations present, pinned, and bound to the tag, on the release path and the backfill path alike"
#
# CLOUD-618. `release-plz.yml` publishes a tag and a GitHub release; until this
# landed, nothing in the repository ever told Linear that the tag existed. The
# `batten` pipeline's `releaseCount` was 0 with 77 tags on `main`, and the only
# release->board signal was a summary step that prints a list and moves nothing.
#
# AND THEN THE WIRING RAN ZERO TIMES, which is the second half of the same issue
# and the reason this file grew a subject and an ordering assertion. Every shape
# below was held, the workflow was correct by every one of them, and the tracking
# still never fired: `release-plz release` creates and pushes the tag from its own
# temporary clone, so `git tag --points-at HEAD` in the outer checkout answered
# empty and every tracking step skipped. Measured at `v0.0.110`, run
# 32665754952 — tag created 20:53:13Z inside `mise run release`, pointing at that
# checkout's own HEAD; resolver at 20:54:21Z found nothing; pipeline still at 0
# releases across 32 tagged releases. A gate that holds every node and misses the
# ORDER of two of them is a gate that certifies a broken path.
#
# WHY THIS IS A `command` ROW AND NOT A DECLARATIVE ONE. The property is
# PRESENCE — a node that must exist in a workflow document — and no rule kind in
# `batten.toml` can address a document node. That is CLOUD-452, `relatedTo` on
# the issue and now superseded (CLOUD-772 landed the fact, CLOUD-833 owns
# evaluating a predicate over it), and `command` is the sanctioned form until that
# lands; the day a kind exists that can express "this document contains this
# node", this row collapses into it and this file goes away.
#
# TWO SUBJECTS, ONE SET OF SHAPES. The release path records a tag as it ships; the
# backfill path (`linear-release-backfill.yml`, CLOUD-618's second half) records
# one that shipped before the recording worked. They differ in exactly one thing —
# where the version comes from — so they are judged by one program under a
# per-subject PROFILE rather than by two programs that would drift apart. A second
# script would have duplicated the step-block walk, which is the part with the
# subtlety in it.
#
# THE SHAPES, and each is here because it fails SILENTLY rather than loudly:
#
#   * a DROPPED INVOCATION. `sync` records the release and attaches the issues in
#     the tag's commit range; `complete` marks it done. The pipeline is
#     `type: scheduled`, so `sync` alone leaves the release started and it never
#     reaches Released — and a job that ran `sync` and skipped `complete` is
#     green, with a release sitting in the wrong stage and nothing saying so.
#   * an UNPINNED REF. Upstream publishes a floating `@v0`. zizmor's
#     `unpinned-uses` reds on it, but only while the workflow is in zizmor's
#     path filter; the pin also carries the trailing `# vX.Y.Z` comment every
#     other `uses:` here carries, because the bot's `github-actions`
#     ecosystem tracks the pin through that comment and not through the SHA.
#   * a VERSION NOT BOUND TO THE TAG. §1 of the refinement is that "which tag did
#     this push ship" is computed in exactly ONE place. A literal version, or a
#     second inline `git tag --points-at`, is how Linear's record and the run
#     summary come to disagree about what shipped — a disagreement nothing would
#     report, since each half is internally consistent. What counts as bound
#     depends on the profile: a declared step output on the release path, a
#     declared `workflow_dispatch` input on the backfill path.
#   * a SHALLOW CHECKOUT. The action reads commit history to find the `CLOUD-*`
#     identifiers in the tag's range. Under a default `actions/checkout` there is
#     no range to read, so it attaches NOTHING and says so nowhere: the release
#     is created, the job is green, and every issue is missing from it.
#   * a TAG RESOLVED FROM A STALE REF SET (the release path only). The measurement
#     at the top of this file. `fetch-depth: 0` is not enough, because the tag
#     does not exist at checkout time — it is created several steps later, in a
#     clone this one cannot see. So the refresh must be PRESENT and it must come
#     BEFORE the resolver; a `git fetch --tags` after it is decoration.
#
# Plus the credential precondition, which is the same class one layer out: a
# tagged push whose `LINEAR_ACCESS_KEY` is empty must FAIL, not skip tracking
# quietly. Nothing in this tree can confirm the secret exists, so the guard's
# presence is the only part of that a gate can hold. The backfill path adds a
# TAG-EXISTS probe for the same reason one layer further out: its version is typed
# by a human, so `sync` would create a release for a version that never shipped.
#
# Pointer-only (non-negotiable rule 4): `path:line` plus a rule id, never a line
# of a workflow and never a secret's value. Output is sorted, so the byte
# sequence is stable across runs and across both subjects. Exit 0 clean / 1
# violation / 2 could-not-look, the house-style §7 table the sibling `*-check`
# programs share — and EITHER subject being unreadable is 2, never a pass earned
# on the strength of the other one.
#
# grep AND awk RATHER THAN A YAML PARSER, and it was a measurement rather than a
# preference: no YAML parser is pinned in `mise.toml` (`jq` is JSON), and adding
# one for a single gate has to clear `no-source-built-tool` plus `lock-complete`,
# which needs prebuilt linux-arm64/x64 and macOS assets — the same wall
# `cargo-msrv` and `cargo-fuzz` are on. `publish-credential-check` is the shipped
# model: a shape gate over THIS SAME workflow, matching with `grep -n` precisely
# because `grep -n` is what yields the `path:line` a finding has to be. The
# step-block walk below is what keeps that honest — `command: sync` is read
# inside the invocation it belongs to, never anywhere in the file.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT unpinned-sha-passes|s/^\texit 1$/\texit 0/|a SHA pin without its version comment is a violation
# The ORDER is the whole of the second defect. Drop the comparison and a refresh
# placed AFTER the resolver satisfies the rule — which is the workflow that ran 32
# times and recorded nothing, wearing a passing gate.
#MUTANT refresh-order-ignored|s/\[\[ "\$refresh_line" -lt "\$resolver_line" \]\]/true/|a tag refresh AFTER the resolver does not satisfy the rule

set -euo pipefail

# THE ROW IS `deny` + `scope = "tree"`, SO THIS RUNS ON EVERY GATE INVOCATION —
# including a `batten hook` mediated call, whose working directory is whatever
# the caller happened to be in rather than this tree's root. Reading the workflow
# relative to that CWD is a gate that answers "could not look" wherever it is not
# launched from the top, and a `deny` row that cannot look denies: measured in CI
# on `the_committed_policy_gates_ready_on_receipts_rather_than_banning_it`, where
# an unrelated `gh pr ready` was refused under THIS rule's name instead of the
# receipt row's — the exact confusion that case exists to catch.
#
# `attestation-check` opens with the same line for the same reason; it is the
# half of that model that is invisible until a caller runs from elsewhere. The
# override is the `BATTEN_BIN` idiom, so the suite can drive a fixture root.
if root="${RELEASE_TRACKING_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null)}" && [[ -n "$root" ]]; then
	cd "$root"
fi

RELEASE_WORKFLOW="${BATTEN_RELEASE_WORKFLOW:-.github/workflows/release-plz.yml}"
BACKFILL_WORKFLOW="${BATTEN_BACKFILL_WORKFLOW:-.github/workflows/linear-release-backfill.yml}"

findings=()
# The comment-stripped copies, removed on every exit path including a refusal.
scratch=()
cleanup() { [[ "${#scratch[@]}" -eq 0 ]] || rm -f "${scratch[@]}"; }
trap cleanup EXIT
# The per-subject summary lines, held until the verdict is known. Printed by
# `judge` directly, they would announce that a workflow "records and completes a
# Linear release" on the same run that reported it does not — the false-green
# sentence a reader quotes back.
summaries=()
# Pointer-only per rule 4: the path, the line, and the rule id. Nothing else from
# either file reaches this function, so nothing else can reach a log.
report() {
	findings+=("$1:${2:-0} $3")
}

# --- COMMENTS ARE NOT CODE, and this gate learned that the hard way -----------
#
# Every probe below asks "does this document contain this node", and a document's
# comments are full of prose ABOUT those nodes — including the comments this same
# change added to `release-plz.yml`, which explain the measurement by quoting
# `git tag --points-at HEAD`. Measured on the first run of this file: the resolver
# probe matched a comment 29 lines above the real resolver, the ordering
# comparison was made against that line, and a correctly ordered workflow was
# reported as `release-tracking-tag-refresh-missing`.
#
# That is CLOUD-843's substring-versus-command-position finding, which
# `.claude/rules/scanning.md` carries as a standing rule, arriving inside the gate
# that quotes it. So every probe reads a comment-stripped copy of the subject.
#
# LINE NUMBERS SURVIVE, which is why this is a rewrite rather than a filter: a
# comment becomes an empty line rather than disappearing, so `grep -n` over the
# copy yields the line number in the ORIGINAL and every pointer stays true.
#
# YAML's own comment rule, applied literally: `#` starts a comment at the start of
# a line or after whitespace. Inside a quoted scalar it does not, so this can
# strip a `#` that was really data — which loses a match and reports a node
# MISSING. That direction is loud; the other one certifies a broken workflow, and
# is the one that just happened.
strip_comments() {
	awk '{ line = $0; sub(/(^|[[:space:]])#.*$/, "", line); print line }' "$1"
}

# --- one subject, one profile --------------------------------------------------
#
# `profile` is `push` (the tag is resolved from git, in this workflow) or
# `dispatch` (the tag is named by an operator through a `workflow_dispatch`
# input). Everything the two share is asserted unconditionally; the three
# profile-specific arms say which they are for.
#
# `workflow` is the path a finding names; `code` is the comment-stripped copy
# every probe actually reads. They are line-for-line aligned.
judge() {
	local workflow="$1" profile="$2" code

	if [[ ! -f "$workflow" ]] || [[ ! -r "$workflow" ]]; then
		echo "::error:: release-tracking-check: cannot read $workflow, so whether a shipped tag reaches Linear is unknown — and a gate that cannot answer its own question must not report green." >&2
		exit 2
	fi

	code=$(mktemp) || {
		echo "::error:: release-tracking-check: cannot create a scratch file to read $workflow without its comments" >&2
		exit 2
	}
	scratch+=("$code")
	strip_comments "$workflow" >"$code"

	# --- the invocations, read per step block -----------------------------------
	#
	# One record per `uses: linear/linear-release-action@...` step, carrying the
	# ref text as written, the `command:`/`version:` values from THAT step only,
	# and the JOB the step belongs to. A bare `grep 'command: sync'` would be
	# satisfied by the word appearing anywhere in the file — including in a comment
	# explaining this gate — which is exactly the drift a shape gate written as a
	# flat grep acquires.
	#
	# The job name travels with the record so the checkout assertion below can ask
	# about the checkout of the job that actually invokes the action, rather than
	# about any `fetch-depth: 0` anywhere in the document. That distinction is not
	# hypothetical here: `release-plz.yml`'s FIRST checkout belongs to
	# `cache-warm-linux` and carries no `fetch-depth` at all, so the file-global
	# form both passed for the wrong reason and pointed at the wrong line.
	#
	# THIS ONE WALK READS THE ORIGINAL, not the comment-stripped copy, and it is the
	# single exception: the pin assertion needs the trailing `# vX.Y.Z` comment,
	# which is the half the bot's `github-actions` ecosystem tracks. Stripping
	# comments here would delete the very thing being asserted, so a valid pin would
	# read as unpinned. A comment-ONLY line is skipped instead, which is the shape
	# that could otherwise mint a phantom invocation out of prose.
	#
	# The pattern is embedded in the program rather than passed through `awk -v`:
	# assignment escape processing is undefined across implementations for a
	# backslash, which is what `awk-regex-check` gates (ready-lint matched its own
	# §8 label that way and silently matched nothing on the runner's gawk).
	local records
	records=$(awk '
		/^[[:space:]]*#/ { next }
		function trim(s) {
			sub(/^[[:space:]]+/, "", s)
			sub(/[[:space:]]+$/, "", s)
			return s
		}
		# Emit the step just closed, if it invoked the action.
		function flush() {
			if (uses_line != 0)
				printf "%s\t%s\t%s\t%s\t%s\t%s\n", uses_line, ref, cmd, version_line, version, job
			uses_line = 0; ref = ""; cmd = ""; version_line = 0; version = ""
		}
		# A job header: exactly two spaces of indent, a bare key, nothing after the
		# colon. Tracked so a step can name its enclosing job; the walk never has to
		# understand the document beyond that.
		/^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$/ {
			flush()
			job = $0
			sub(/^[[:space:]]*/, "", job)
			sub(/:.*$/, "", job)
		}
		/^[[:space:]]*-[[:space:]]/ { flush() }
		/uses:[[:space:]]*linear\/linear-release-action@/ {
			uses_line = NR
			ref = $0
			sub(/^.*linear\/linear-release-action@/, "", ref)
			ref = trim(ref)
		}
		/^[[:space:]]*command:[[:space:]]*/ {
			cmd = $0
			sub(/^[[:space:]]*command:[[:space:]]*/, "", cmd)
			cmd = trim(cmd)
		}
		/^[[:space:]]*version:[[:space:]]*/ {
			version_line = NR
			version = $0
			sub(/^[[:space:]]*version:[[:space:]]*/, "", version)
			version = trim(version)
		}
		END { flush() }
	' "$workflow")

	local have_sync=0 have_complete=0
	# The jobs that invoke the action, deduped, so the checkout assertion below runs
	# once per job rather than once per invocation.
	local invoking_jobs=""

	if [[ -n "$records" ]]; then
		local uses_line ref cmd version_line version job
		while IFS=$'\t' read -r uses_line ref cmd version_line version job; do
			[[ -n "$uses_line" ]] || continue

			case "$cmd" in
			sync) have_sync=1 ;;
			complete) have_complete=1 ;;
			# Any other subcommand of the same action is not one of the two this
			# gate requires, and is neither an error nor evidence.
			*) ;;
			esac

			if [[ -n "$job" ]] && [[ " $invoking_jobs " != *" $job "* ]]; then
				invoking_jobs="${invoking_jobs}${invoking_jobs:+ }$job"
			fi

			# A 40-hex SHA **and** the trailing `# vX.Y.Z` comment. Either half alone
			# is a pin nothing can track: the SHA without the comment is invisible to
			# the bot, and a comment without a SHA is the floating ref wearing a
			# version's name.
			#
			# Matched with `<<<` rather than a pipe: `grep -q` exits at its first hit,
			# which SIGPIPEs a still-writing producer, and pipefail promotes that to
			# 141 — a MATCH reporting failure. Gated by `pipefail-grep-check`, which
			# is what caught both of these here.
			if ! grep -qE '^[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]' <<<"$ref"; then
				report "$workflow" "$uses_line" "release-tracking-unpinned"
			fi

			# The version must be BOUND, and what binds it is the profile's business.
			# In both cases the referenced name is read back out of the expression and
			# checked to be declared, so a reference to something nobody declares —
			# which expands to the empty string at run time, silently — is a finding
			# too. That is the half a looser regex would drop, and it is the half that
			# catches a rename.
			if ! version_is_bound "$code" "$profile" "$version"; then
				report "$workflow" "${version_line:-$uses_line}" "release-tracking-version-unbound"
			fi
		done <<<"$records"
	fi

	# Line 0 is "the file, not a line in it" — the same shape `attestation-check`
	# uses for a finding about an archive rather than a position inside one.
	[[ "$have_sync" = 1 ]] || report "$workflow" 0 "release-tracking-sync-missing"
	[[ "$have_complete" = 1 ]] || report "$workflow" 0 "release-tracking-complete-missing"

	# --- the credential precondition --------------------------------------------
	#
	# The emptiness TEST is the shape, not the secret's presence — nothing local can
	# confirm a secret exists. What this refuses is the silent form: a workflow that
	# hands an empty key to the action and stays green.
	if ! grep -qE '\-z[[:space:]]+"?\$\{?LINEAR_ACCESS_KEY' "$code"; then
		report "$workflow" 0 "release-tracking-precondition-missing"
	fi

	# --- history is reachable, in the job that reads it --------------------------
	#
	# `fetch-depth: 0` on the checkout of each job that invokes the action. Absent
	# is the default shallow clone and non-zero is a bounded one; neither carries
	# the commit range the action reads, and both attach nothing while reporting
	# success.
	#
	# PER JOB, because file-global was a pass earned somewhere else: in
	# `release-plz.yml` the `cache-warm-linux` job's checkout comes first and has no
	# `fetch-depth` line, so the probe both matched the release job's line from
	# three jobs away and pointed the finding at the wrong checkout. A judged job
	# with no checkout at all is the same finding — the action cannot read a history
	# that was never fetched.
	local job
	for job in $invoking_jobs; do
		if ! job_checkout_is_deep "$code" "$job"; then
			report "$workflow" "$(job_checkout_line "$code" "$job")" "release-tracking-shallow-checkout"
		fi
	done

	case "$profile" in
	push) judge_push "$workflow" "$code" ;;
	dispatch) judge_dispatch "$workflow" "$code" ;;
	esac

	summaries+=("release-tracking-check: $workflow records and completes a Linear release, pinned and bound to the tag ($profile path)")
}

# --- is the version bound? ----------------------------------------------------
#
# Two accepted forms, one per profile, and each reads the referenced name back out
# and requires it to be DECLARED in the same document.
version_is_bound() {
	local workflow="$1" profile="$2" version="$3" name

	case "$profile" in
	push)
		# A step OUTPUT reference, never a literal and never a second inline
		# expression. The step id is read back out and checked to exist.
		grep -qE '^\$\{\{[[:space:]]*steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+[[:space:]]*\}\}$' <<<"$version" || return 1
		name=$(sed -E 's/^\$\{\{[[:space:]]*steps\.([A-Za-z0-9_-]+)\..*$/\1/' <<<"$version")
		grep -qE "^[[:space:]]*id:[[:space:]]*${name}[[:space:]]*(#.*)?$" "$workflow" || return 1
		;;
	dispatch)
		# A `workflow_dispatch` INPUT reference. Both spellings GitHub accepts are
		# allowed — `inputs.x` and `github.event.inputs.x` — because they name the
		# same thing and refusing one would be a style rule wearing a gate's exit
		# code. The input name is read back out and checked to be declared.
		grep -qE '^\$\{\{[[:space:]]*(github\.event\.)?inputs\.[A-Za-z0-9_-]+[[:space:]]*\}\}$' <<<"$version" || return 1
		name=$(sed -E 's/^\$\{\{[[:space:]]*(github\.event\.)?inputs\.([A-Za-z0-9_-]+)[[:space:]]*\}\}$/\2/' <<<"$version")
		dispatch_input_declared "$workflow" "$name" || return 1
		;;
	*) return 1 ;;
	esac
	return 0
}

# Is `$2` declared under this workflow's `workflow_dispatch: inputs:`? Walked
# rather than grepped for the whole file, because a bare `tag:` also matches a
# step's `with: tag:` — which would let a `version:` reference an input nobody
# declares as long as some step happened to pass a key of the same name.
#
# INDENT IS MEASURED, NOT ASSUMED. The first key inside the `inputs:` block sets
# the level an input name sits at, and only keys at that exact level are names —
# anything deeper is one of an input's own keys (`description`, `required`,
# `type`), and `required` is a word somebody could plausibly want as an input.
# Hard-coding six spaces would have read a differently indented but perfectly
# valid workflow as declaring nothing.
#
# No interval expressions (`{0,2}`) anywhere in here: they are an ERE feature awk
# implementations disagree about, which is the class `awk-regex-check` exists for.
# The block-closing test compares computed indents instead.
dispatch_input_declared() {
	local workflow="$1" name="$2"
	awk -v want="$name" '
		function indent(s) {
			match(s, /^[[:space:]]*/)
			return RLENGTH
		}
		/^[[:space:]]*workflow_dispatch:[[:space:]]*(#.*)?$/ {
			in_wd = 1
			wd_indent = indent($0)
			next
		}
		# A key at or above `workflow_dispatch:`s own level closes the block.
		in_wd && /^[[:space:]]*[A-Za-z0-9_-]+:/ && indent($0) <= wd_indent {
			in_wd = 0
			in_inputs = 0
		}
		in_wd && /^[[:space:]]*inputs:[[:space:]]*(#.*)?$/ {
			in_inputs = 1
			inputs_indent = indent($0)
			name_indent = 0
			next
		}
		in_inputs && /^[[:space:]]*[A-Za-z0-9_-]+:/ {
			this = indent($0)
			# Back out to the `inputs:` level or shallower: the block is over.
			if (this <= inputs_indent) { in_inputs = 0; next }
			if (name_indent == 0) name_indent = this
			if (this != name_indent) next
			key = $0
			sub(/^[[:space:]]*/, "", key)
			sub(/:.*$/, "", key)
			if (key == want) { found = 1; exit }
		}
		END { exit(found ? 0 : 1) }
	' "$workflow"
}

# --- per-job checkout ---------------------------------------------------------
#
# Both helpers walk the same shape: the block of lines belonging to job `$2`.
# Split into two so a finding can name a line without the predicate having to
# return one, which is what kept the awk in each readable.
job_checkout_is_deep() {
	local workflow="$1" job="$2"
	awk -v want="$job" '
		/^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$/ {
			key = $0
			sub(/^[[:space:]]*/, "", key)
			sub(/:.*$/, "", key)
			in_job = (key == want)
			next
		}
		in_job && /^[[:space:]]+fetch-depth:[[:space:]]*0[[:space:]]*(#.*)?$/ { found = 1; exit }
		END { exit(found ? 0 : 1) }
	' "$workflow"
}

# The line to point at: this job's first `actions/checkout@`, or 0 when it has
# none — a job that invokes the action with no checkout at all is the same
# finding, and `0` is this file's "the file, not a line in it".
job_checkout_line() {
	local workflow="$1" job="$2"
	awk -v want="$job" '
		/^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$/ {
			key = $0
			sub(/^[[:space:]]*/, "", key)
			sub(/:.*$/, "", key)
			in_job = (key == want)
			next
		}
		in_job && /uses:[[:space:]]*actions\/checkout@/ { print NR; exit }
	' "$workflow"
}

# --- the release path's own two shapes ----------------------------------------
judge_push() {
	local workflow="$1" code="$2" resolver_line refresh_line

	# §1's "computed in exactly one place" needs the place to EXIST. Without it the
	# bound-version check above passes vacuously the moment someone deletes the
	# resolver and points `version:` at some other step's output.
	resolver_line=$(grep -nE 'git tag --points-at HEAD' "$code" | head -n1 | cut -d: -f1 || true)
	if [[ -z "$resolver_line" ]] || ! grep -qE '>>[[:space:]]*"?\$\{?GITHUB_OUTPUT' "$code"; then
		report "$workflow" 0 "release-tracking-tag-source-missing"
		# With no resolver there is no ordering question to ask, and reporting the
		# refresh as misplaced relative to a step that does not exist would name a
		# second defect for one cause.
		return 0
	fi

	# THE TAG DOES NOT EXIST AT CHECKOUT TIME. `release-plz release` creates and
	# pushes it from its own temporary clone several steps later, so the resolver
	# reads a ref set that predates the tag it is looking for — `fetch-depth: 0`
	# does not help, because the tag was not there to fetch. Measured at `v0.0.110`
	# (run 32665754952): tag created 20:53:13Z, resolver answered empty at
	# 20:54:21Z, three steps skipped, 32 releases unrecorded.
	#
	# BEFORE THE RESOLVER, not merely present: a refresh after it updates a ref set
	# nothing reads again. That comparison is the whole assertion — the workflow
	# that ran 32 times and recorded nothing would satisfy a presence-only form the
	# moment somebody moved the step one line down.
	refresh_line=$(grep -nE 'git fetch.*--tags' "$code" | head -n1 | cut -d: -f1 || true)
	if [[ -z "$refresh_line" ]] || ! [[ "$refresh_line" -lt "$resolver_line" ]]; then
		report "$workflow" "$resolver_line" "release-tracking-tag-refresh-missing"
	fi
}

# --- the backfill path's own shape --------------------------------------------
judge_dispatch() {
	local workflow="$1" code="$2"

	# A TYPO MUST NOT MINT A RELEASE RECORD. The release path cannot make this
	# mistake — its tag comes from git, so it either exists or is empty — but here
	# a human types it, and `sync` would create a release for a version that never
	# shipped. Nothing downstream reports that: the run is green and the pipeline
	# gains a row naming nothing.
	if ! grep -qE 'rev-parse.*refs/tags/' "$code"; then
		report "$workflow" 0 "release-tracking-tag-unverified"
	fi

	# THE CHECKOUT MUST SIT ON THE VERSION THE INVOCATION NAMES (CLOUD-1026).
	# `version:` names the release OBJECT; the commit range the action attaches
	# issues from comes from the checkout's HEAD. So `fetch-depth: 0` — which this
	# gate already demands — supplies the HISTORY and says nothing about where in
	# it HEAD sits, and a dispatch path checking out the default branch records a
	# release named for the tag against a range that has nothing to do with it.
	#
	# Measured on the first dispatch this workflow ever served, run 32762293169:
	# both steps green, the release Released, `commitSha` = `main`'s tip rather
	# than the tag's, ONE attached issue against the EIGHTEEN `mise run released`
	# reports. Green, complete and wrong — the class every rule in this file exists
	# for, and the one the depth assertion looks like it covers and does not.
	#
	# Asked of the DISPATCH profile ONLY. The release path resolves its tag from
	# `git tag --points-at HEAD`, so its HEAD and its version agree by
	# construction; demanding a `ref:` there would refuse the correct workflow.
	# The input name is READ BACK OUT and required to be declared, the same
	# discipline `version_is_bound` applies — and for the same reason, one step
	# nastier here: `ref: ${{ inputs.nonesuch }}` expands to the EMPTY STRING, and
	# an empty `ref` is `actions/checkout`'s default, which is the default branch.
	# So an undeclared name does not fail the checkout; it silently reproduces
	# exactly the defect this rule exists to refuse.
	local ref name
	ref=$(grep -oE '^[[:space:]]+ref:[[:space:]]*\$\{\{[[:space:]]*(github\.event\.)?inputs\.[A-Za-z0-9_-]+[[:space:]]*\}\}[[:space:]]*$' "$code" | head -n1 || true)
	name=""
	if [[ -n "$ref" ]]; then
		name=$(sed -E 's/^.*inputs\.([A-Za-z0-9_-]+).*$/\1/' <<<"$ref")
	fi
	if [[ -z "$name" ]] || ! dispatch_input_declared "$code" "$name"; then
		report "$workflow" "$(job_checkout_line "$code" "$(invoking_job "$code")")" "release-tracking-ref-unbound"
	fi

	# AND THE RANGE NEEDS A BASE, which `ref:` does not supply (CLOUD-1026).
	# Measured on run 32765173125, with HEAD correctly on the tag:
	#
	#   warn: None of the last 1 synced releases' commit SHAs exist in this
	#         repository's history. Syncing only the current commit until a scan
	#         base can be established … otherwise pass --base-ref …
	#   info: Inspected current commit 98e29b3; found 1 commit
	#
	# The CLI derives its base from the LAST SYNCED RELEASE's commit, which for a
	# backfill is a tag NEWER than this one and therefore not an ancestor — so the
	# base is never establishable and it silently narrows to one commit. `ref:`
	# decides WHICH commit; only `base_ref` decides the RANGE. Two rules rather
	# than one, because each is separately sufficient to produce a green wrong
	# record and the first fix shipped without the second.
	#
	# Bound to a step output, read back out and required to exist — the resolver
	# has to be a real step, not a name that expands to nothing.
	local base bname
	base=$(grep -oE '^[[:space:]]+base_ref:[[:space:]]*\$\{\{[[:space:]]*steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+[[:space:]]*\}\}[[:space:]]*$' "$code" | head -n1 || true)
	bname=""
	if [[ -n "$base" ]]; then
		bname=$(sed -E 's/^.*steps\.([A-Za-z0-9_-]+)\..*$/\1/' <<<"$base")
	fi
	if [[ -z "$bname" ]] || ! grep -qE "^[[:space:]]*id:[[:space:]]*${bname}[[:space:]]*$" "$code"; then
		report "$workflow" 0 "release-tracking-range-unbased"
	fi
}

# The first job that invokes the action, for a pointer. Recomputed rather than
# threaded through, because the per-step walk's records have gone out of scope by
# the time a profile arm runs, and a finding naming line 0 where a real checkout
# exists is a worse pointer than one more pass over a short document.
invoking_job() {
	awk '
		/^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$/ {
			job = $0
			sub(/^[[:space:]]*/, "", job)
			sub(/:.*$/, "", job)
		}
		/uses:[[:space:]]*linear\/linear-release-action@/ { print job; exit }
	' "$1"
}

judge "$RELEASE_WORKFLOW" push
judge "$BACKFILL_WORKFLOW" dispatch

if [[ "${#findings[@]}" -ne 0 ]]; then
	echo "::error:: release-tracking-check: ${#findings[@]} finding(s). A shipped tag would not reach the Linear release pipeline, and every shape below is one that stays GREEN while doing it:" >&2
	printf '%s\n' "${findings[@]}" | sort >&2
	exit 1
fi

printf '%s\n' "${summaries[@]}"

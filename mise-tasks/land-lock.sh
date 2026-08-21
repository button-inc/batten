#!/usr/bin/env bash
#MISE description="Effect: hold a rolling fleet-wide landing lease, so exactly one branch at a time spends CI on a landing attempt"
#
# WHY THIS EXISTS. Landing is fast-forward only, so a branch wins only while it
# is still a direct descendant of `main`. With several sessions landing at once
# every attempt races every other, and the loser has already paid for a full CI
# matrix by the time it asks. Measured 2026-08-11 21:31->22:01Z over the whole
# available `fast-forward.yml` history: 400 runs, 248 executed, **243 refusals
# against 5 merges** — a ~2% success rate per attempt. The bot was never the
# problem; it answered every one of those 248 within 23s (median 12s). The cost
# is a thundering herd (CLOUD-393, CLOUD-399).
#
# So the queue already exists — it is just implemented as 243 discarded CI
# matrices per half hour instead of as a lease. This is the lease. Waiting costs
# nothing; a lost lap costs a CI run, and turning the second into the first is
# the entire point.
#
# WHAT IT IS NOT. It does not change what CI proves, which SHA may land, or how
# `main` advances — `final` still gates the fast-forward and `main` still only
# ever takes an already-graded commit. It decides who goes first, nothing else.
# It also deliberately does NOT red or cancel anyone else's PR: red must keep
# meaning "this change is broken", and cancelling another ref's runs would
# reverse CLOUD-240's "supersede your own runs, never someone else's".
#
# HUMANS DO NOT TOUCH THIS, and that is the design rather than an omission.
# Commenting `/fast-forward` is unchanged and remains the whole landing action
# for a person: `fast-forward.yml` is not modified, this task is never on their
# path, and there is no second way to land — `land` ends in the same comment on
# the same workflow. What the lease governs is who SPENDS CI, and a person
# landing an already-green PR spends none, so there is nothing here for them to
# hold.
#
# The cost of exempting them is one number, and it is why the exemption is
# affordable: a human lands about once a day, so at worst one agent lap a day is
# voided by a merge it did not expect — against the 243 refusals per half hour
# this replaces. `land` already handles that case, since a moved `main` is the
# ordinary lap. It gets cheaper still in practice: agents colliding with each
# other far less means `main` is quieter when the person lands, so their
# `/fast-forward` succeeds more often than it does today.
#
# Making `fast-forward.yml` lease-aware was considered and refused. It would
# make a person wait out an agent's whole CI window, and a workflow waiting is a
# runner billing — worse for the human and more CI minutes, to serialise the one
# participant whose volume never needed serialising.
#
# THE PRIMITIVE: one operation, compare-and-swap, and nothing else.
# `git push --force-with-lease=<ref>:<expected>` is a server-side CAS. Measured
# against a real remote: the correct expected value wins, a stale one is rejected
# with `stale info`, and the empty expected value means "must not exist", so even
# the first claim is a CAS rather than a create-and-hope.
#
# Everything is that one operation. Acquiring CASes from the free state,
# renewing CASes the expiry forward, and releasing CASes the expiry to zero —
# there is deliberately no delete. A tombstoned lease is instantly claimable by
# anyone, which is all a release has to mean, and avoiding the delete removes
# every permission and namespace question from the design at once. It also
# removes the REST API from this task entirely, which matters more than it looks:
# the API budget is shared with `land`'s own polling and was measurably exhausted
# by the fleet during development.
#
# WHERE THE LEASE LIVES. `refs/heads/` today, a custom namespace later, and the
# code does not care — that is the point of CAS-only. A custom namespace is the
# better home (measured on a local remote: invisible to `git branch -r`,
# untouched by `git push --all`, absent from PR base pickers, and CAS behaves
# identically there), and it is deferred rather than chosen because THIS sandbox
# proxies git and its write policy 403s any push outside `refs/heads`. That is an
# environment limitation, not a property of GitHub, and a design must not be bent
# around it — humans and CI push straight to GitHub and never see it. Moving is a
# one-line default change once the proxy allows it.
#
# The holder id in the lease body is load-bearing rather than decorative: git
# addresses objects by content, so two sessions building an identical lease would
# build the SAME sha, and the second push would succeed as a no-op with both
# believing they hold it.
#
# LIVENESS: the TTL rolls, and that changes what the number has to mean. A static
# TTL has to bound how long a hold might legitimately take — a guess about the
# future, wrong in both directions: too low and a slow CI run has its lease stolen
# mid-flight, too high and a reclaimed VM blocks the fleet for the whole window. A
# rolling lease only has to bound how long until we NOTICE a holder stopped
# beating, which is small, stable, and independent of how long CI takes. Hence a
# 30s beat against a 120s TTL: three missed beats before a lease is declared dead
# is the usual Raft/etcd margin, so one transient failure never drops a live
# lease, and a dead holder blocks landing for ~2 minutes rather than ~17.
#
# WHO MAY SPEND A RUNNER, asked by the runner (CLOUD-420). The lease body carries
# `branch:` alongside the holder id, because the holder identifies a CLONE and a
# GitHub job has no clone to compare it with — a branch name is the one
# identifier both ends can see. `authorises <branch>` is the read-only verb that
# answers it, and it is the one place in this file that fails OPEN: a lease it
# cannot read stops every job in the fleet, where waving one matrix through costs
# one matrix.
#
# WHO MAY SPEND THE SECOND RUNNER (CLOUD-369). The lease bounds confirming runs
# at one, which is right for cost and wrong for latency: after every merge the
# queue is empty and the next branch starts cold. `next:` names ONE admitted
# successor, written by the waiter itself through `reserve` — the holder cannot
# name one, since waiters are registered nowhere — and `authorises` admits it
# alongside the holder. The bound is therefore two, enforced at the runner rather
# than merely agreed between cooperating sessions, and it does not grow with the
# fleet: one CAS-guarded slot cannot hold two branches.
#
# `head:` is the third advisory field, and it is what makes WAITING productive:
# it names the commit that is about to become `main`, so a waiter can rebase onto
# the trunk that is coming rather than onto the one the holder is about to
# replace. All three — `branch:`, `head:`, `next:` — are read by CI and by
# waiters, and by no predicate that decides ownership. `mine` compares holder ids
# and nothing else; an identity another clone could DERIVE is one it could
# accidentally claim.
#
# Output is pointer-only (non-negotiable 4): a holder id and an age in seconds,
# never a ref body. Exit codes follow the one contract: 0 acquired/held, 1 held
# by someone else, 2 could not look — plus 3 from `authorises` alone, for "stop",
# which is a third answer the 0/1 pair cannot carry (1 already means "held by
# someone else", a reason to stop rather than the instruction).
#
# MUTATION COVERAGE (CLOUD-418). `<slug>|<sed script>|<case name>`: applying
# the script to a throwaway copy of this file must turn the named case RED.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#
# The first row is the regression fixture CLOUD-418 names by hand: a lease that
# refuses nobody is the fail-open posture taken one step too far, and it is the
# whole point of the verb the runner spends money on.
#MUTANT authorises-never-stops|s/^	exit 3$/	exit 0/|THE STOP: a branch the lease does not name is refused with exit 3
# CLOUD-499's two bounds, declared separately because they catch different
# failures and a single row could not show that either one discriminates alone.
# The first neuters the stall comparison, so a holder that never advances is
# never bailed on; the second neuters the rival's steal, so a beating-but-
# stalled lease stays unstealable — the wedge this issue exists to end.
#MUTANT stall-never-bails|s/^\t\t\tif \[ "\$((\$(now) - advance))" -ge "\$((stall_beats \* beat))" \]; then$/\t\t\tif false; then/|a land that stops advancing loses its lease and is stopped
#MUTANT stalled-lease-unstealable|s/^\t\telif \[ -n "\$observed_progress" \] \&\& \[ "\$progress_for" -ge "\$((stall_beats \* beat))" \]; then$/\t\telif false; then/|A RIVAL MAY REAP A LEASE THAT BEATS WITHOUT PROGRESSING

set -euo pipefail

verb="${1:-}"
case "$verb" in
acquire | hold | renew | held | release | status) ;;
authorises)
	# The only verb that takes an argument, and it is required: `authorises`
	# with no branch cannot answer, and a verb that cannot answer must say so
	# rather than defaulting to either verdict. Exit 2 is that, matching the
	# "could not look" family the other verbs already use.
	if [ -z "${2:-}" ]; then
		echo "::error:: usage: land-lock authorises <branch>" >&2
		exit 2
	fi
	;;
reserve)
	# Takes the branch reserving, for the same reason `authorises` does: the
	# caller may be reserving on behalf of a checkout this process is not in.
	if [ -z "${2:-}" ]; then
		echo "::error:: usage: land-lock reserve <branch>" >&2
		exit 2
	fi
	;;
peek)
	case "${2:-}" in
	branch | head | next) ;;
	*)
		echo "::error:: usage: land-lock peek <branch|head|next>" >&2
		exit 2
		;;
	esac
	;;
*)
	echo "::error:: usage: land-lock <acquire|hold|renew|held|release|status|authorises|reserve|peek>" >&2
	exit 2
	;;
esac

remote="${LAND_LOCK_REMOTE:-origin}"
# The lease's OWN ref name. Deliberately not the branch a lease authorises —
# see `land_branch` below, which is a different thing with a confusingly similar
# name, and writing this one into the body would stamp `batten-land-lock` into
# every lease while looking correct.
branch="${LAND_LOCK_BRANCH:-batten-land-lock}"
ref="refs/heads/$branch"
ttl="${LAND_LOCK_TTL:-120}"
beat="${LAND_LOCK_HEARTBEAT:-30}"
# HOW LONG A HOLDER MAY STOP PROGRESSING BEFORE ITS LEASE IS DISBELIEVED
# (CLOUD-499). Neither of these bounds how long a landing may TAKE — both reset
# on every advance, so an arbitrarily long landing that keeps producing state
# changes never reaches either. They bound how long we keep believing a holder
# that has stopped producing evidence, which is what the rolling TTL above
# already does one signal shallower: the TTL notices a holder that stopped
# BEATING, these notice one that stopped LANDING.
#
# 60 beats = 30 minutes, against a measured floor of 1332s (~45 beats): the
# longest gap between consecutive check-run completions over the six most
# recently merged PRs on 2026-08-12. Deliberately generous — this exists to
# catch NEVER, not slow, and the cost of catching slow is a landing killed for
# being healthy. Re-measure if `CI_REQUIRED_CHECKS` grows.
stall_beats="${LAND_LOCK_STALL_BEATS:-60}"
# The hang bound is the same three-beat margin the TTL uses, and applies only
# while a fast loop is actually pushing ticks (see `holder_progress`): a poll
# iterating every ~1.5s that has produced nothing for 90s is blocked, not
# waiting. A phase with no loop is judged by the stall bound alone, because
# `verify`'s own steps legitimately run longer than this.
hang_beats="${LAND_LOCK_HANG_BEATS:-3}"
# How long `acquire` waits before handing the caller its turn back. Past one TTL
# the holder is either beating (and the wait is legitimate) or dead (and the
# lease is stealable), so a longer wait can only mean something more waiting will
# not fix.
wait_for="${LAND_LOCK_WAIT:-$ttl}"
# The branch this lease AUTHORISES — what CI checks itself against (CLOUD-420).
# The holder id identifies a clone, which a runner has nothing to compare with;
# a branch name is the one thing both ends can see. Derived from the checkout by
# default, the way `holder_id` is derived rather than configured, and overridable
# so the suites can drive it. Empty is a legitimate reading (a detached HEAD, a
# bare clone) and must never become the string "HEAD".
land_branch="${LAND_LOCK_LAND_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)}"
[ "$land_branch" != HEAD ] || land_branch=

# THE HEAD THIS LEASE IS LANDING (CLOUD-369). `branch:` says who may spend a
# matrix; `head:` says what the next `main` is about to be, which is the thing a
# WAITER needs. A waiter that rebases onto `origin/main` warms nothing — the
# holder is about to replace it — so pre-warming is only a linearization when it
# targets the commit that is about to become trunk.
#
# Advisory exactly like `branch:`: read by a waiter deciding what to rebase onto,
# never by any predicate that decides ownership. `mine` still compares holder ids
# and nothing else, and that separation is load-bearing — an identity another
# clone could DERIVE (from a branch, a head, an issue key) is an identity another
# clone could accidentally claim, which is the two-holders bug this file exists
# to prevent.
land_head="${LAND_LOCK_LAND_HEAD:-$(git rev-parse HEAD 2>/dev/null || true)}"

# THE ADMITTED SUCCESSOR (CLOUD-369). A branch that has reserved the right to
# spend the SECOND matrix — the one that overlaps the holder's merge instead of
# starting cold after it. Empty on every lease until a waiter reserves.
#
# Carried through every mint rather than re-derived, because the holder's
# heartbeat re-mints the lease every beat and a field it did not carry forward
# would be erased within 30 seconds of being written by someone else.
land_next="${LAND_LOCK_LAND_NEXT:-}"

# THE PROGRESS TOKEN (CLOUD-499). Opaque by design: a rival tests it for
# EQUALITY OVER TIME and never interprets it, so no clock crosses the wire and
# no field of it means anything to anyone but its writer. That keeps it in the
# advisory class with `branch:`, `head:` and `next:` — read by waiters, never by
# a predicate that decides ownership.
#
# Empty is the honest reading whenever the holder cannot see its own progress:
# no registry entry, or a heartbeat with no holder pid to look up. An empty
# token is never stall-stealable, which is also every lease minted before this
# change — during rollout that is not an edge case, it is all of them.
land_progress="${LAND_LOCK_LAND_PROGRESS:-}"

git rev-parse --git-dir >/dev/null 2>&1 || {
	echo "::error:: land-lock: not a git repository" >&2
	exit 2
}

state_dir="$(git rev-parse --git-dir)/batten-land-lock"
holder_file="$state_dir/holder"
# Per-process observation ref (see `observe`). Namespaced under refs/batten-lock
# so it is local bookkeeping and never confusable with the lease itself, and
# swept on exit so a clone does not accumulate one per land.
obs_ref="refs/batten-lock-obs/$$"
trap 'git update-ref -d "$obs_ref" 2>/dev/null || true' EXIT

now() { date -u +%s; }

# One id per clone, minted once and reused by every later verb, because `hold`,
# `held` and `release` run as separate processes from the `acquire` that won: a
# per-process id would leave the holder unable to recognise its own lease.
holder_id() {
	if [ ! -s "$holder_file" ]; then
		mkdir -p "$state_dir"
		printf '%s-%s-%s\n' "${HOSTNAME:-host}" "$$" \
			"$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')" >"$holder_file"
	fi
	cat "$holder_file"
}

# A lease is a parentless commit over the empty tree, so it shares no history
# with anything and can never fast-forward over a live lease.
#
# The nonce is not decoration. Git addresses objects by content, so two mints
# agreeing on holder and expiry — the same clone renewing twice inside one
# second, or two clones colliding on both fields — produce the SAME sha, and
# pushing a sha the ref already points at is an "up to date" no-op that reports
# success. That turns a rejected claim into an apparent win. Measured: without
# it, a second `acquire` from the holder reported "acquired" rather than
# recognising its own lease, and a renew left the ref unmoved.
# $1 is the lifetime in seconds; 0 mints a TOMBSTONE — a lease already expired,
# which is what a release leaves behind instead of deleting the ref.
mint() {
	local tree
	tree=$(git hash-object -t tree /dev/null)
	# A lifetime of 0 writes a literal `expires: 0` rather than "now", because a
	# release is a DECLARATION and an expiry is an INFERENCE, and only the second
	# needs a clock. Epoch 0 is unmistakable under any clock and on any machine,
	# so a released lease hands over immediately while a merely expired one still
	# has to be corroborated (see `sha_held_for`). Conflating the two made a
	# release wait a full beat before anyone could take it.
	# The identity is supplied explicitly, and that is a portability fix rather
	# than a style choice: `git commit-tree` refuses with "Author identity
	# unknown" on any machine with no configured `user.email` — a CI runner, a
	# fresh clone. Measured: every acquiring test in this suite passed locally and
	# failed in CI for exactly that reason. Pinning it also makes the lease object
	# independent of whoever runs it, which is the right property for a commit
	# nobody authored and nothing merges.
	# `branch:` is read by CI, never by this task's own predicates except
	# `authorises` (CLOUD-420). It is written from the `land_branch` global
	# rather than passed as a parameter because `mint` is only ever reached
	# through `swap`, and three of `swap`'s five call sites pass nothing but the
	# expected sha — threading a second argument through all of them to carry a
	# value that never varies within a process would be a wider change for no
	# added expressiveness. `nonce:` stays LAST: its uniqueness argument above is
	# what makes every mint a distinct sha, and `land-lock-check`'s fixture
	# treats it as the terminal line.
	# `head:`, `next:` and `progress:` join `branch:` as ADVISORY fields, on the
	# same terms: read by a waiter and by CI, never by an ownership predicate.
	# They sit between `branch:` and `nonce:` so the nonce stays terminal.
	#
	# Every one of the five is overridable through a `mint_*` global, and that is
	# what `reserve` needs rather than a convenience: a waiter appending itself as
	# `next:` must re-mint the HOLDER's lease — its holder, its expiry, its branch,
	# its head — changing one field and nothing else. Without the overrides that
	# path would have to duplicate this printf, and a second writer of the lease
	# body is precisely where a divergence from `observe` would be invisible.
	printf 'land-lock\nholder: %s\nexpires: %s\nbranch: %s\nhead: %s\nnext: %s\nprogress: %s\nnonce: %s\n' \
		"${mint_holder:-$(holder_id)}" \
		"${mint_expires:-$([ "${1:-}" = 0 ] && echo 0 || echo "$(($(now) + ${1:-$ttl}))")}" \
		"${mint_branch:-$land_branch}" \
		"${mint_head:-$land_head}" \
		"${mint_next:-$land_next}" \
		"${mint_progress:-$land_progress}" \
		"$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')" |
		GIT_AUTHOR_NAME=batten GIT_AUTHOR_EMAIL=batten@localhost \
			GIT_COMMITTER_NAME=batten GIT_COMMITTER_EMAIL=batten@localhost \
			git commit-tree "$tree"
}

observed_sha=
observed_holder=
observed_expires=
observed_branch=
observed_head=
observed_next=
observed_progress=
# Reads the remote lease, leaving the three `observed_*` empty when it is absent.
# Exit 2 is reserved for "could not look" — an unreachable remote must never read
# as an unheld lock, since that is precisely the misread that would let two
# sessions land at once.
observe() {
	local ls body
	observed_sha=
	observed_holder=
	observed_expires=
	# Cleared with the rest: a value left over from an earlier observe in this
	# same process is the FETCH_HEAD-class misread the comment below describes,
	# reached through a variable instead of a file.
	observed_branch=
	observed_head=
	observed_next=
	observed_progress=
	ls=$(git ls-remote "$remote" "$ref" 2>/dev/null) || {
		echo "::error:: land-lock: cannot reach $remote; read mem:github-access before concluding the network is blocked." >&2
		return 2
	}
	[ -n "$ls" ] || return 0
	# NOT FETCH_HEAD, and this is a correctness fix rather than a tidy-up.
	# FETCH_HEAD is ONE FILE PER CLONE, and this task runs concurrently inside a
	# single clone by design: `land` backgrounds the heartbeat's observe loop and
	# then runs `held` and `release` in the foreground of the same checkout. Two
	# fetches racing means a reader can be handed the other one's result.
	# Measured on a local remote: 16 of 40 concurrent reads returned the WRONG
	# lease body.
	#
	# What that costs is not a bad message. The sha comes from `ls-remote` and
	# the body came from FETCH_HEAD, so a collision pairs THIS lease's sha with
	# ANOTHER lease's holder — and `release` CASes against that sha while judging
	# ownership from that holder. It could tombstone a live lease belonging to
	# someone else, which is precisely the theft the CAS exists to prevent.
	#
	# A per-process ref has no such sharing. It is force-updated because a stale
	# one from an earlier run of the same pid must never be read as current.
	git fetch -q --force "$remote" "+$ref:$obs_ref" 2>/dev/null || {
		echo "::error:: land-lock: lease present but unreadable" >&2
		return 2
	}
	# Both readings come from the fetched ref, so the sha and the body are
	# guaranteed to describe the same lease. Taking the sha from `ls-remote` and
	# the body from the fetch is what allowed them to disagree at all.
	observed_sha=$(git rev-parse "$obs_ref" 2>/dev/null) || {
		echo "::error:: land-lock: lease fetched but unreadable" >&2
		return 2
	}
	body=$(git cat-file commit "$observed_sha" 2>/dev/null) || {
		echo "::error:: land-lock: lease object missing after fetch" >&2
		return 2
	}
	observed_holder=$(printf '%s\n' "$body" | sed -n 's/^holder: //p')
	observed_expires=$(printf '%s\n' "$body" | sed -n 's/^expires: //p')
	# Absent on every lease minted before CLOUD-420, and on a lease minted from a
	# detached HEAD. Empty is therefore a real state rather than an error, and
	# `authorises` treats it as "cannot tell" — which fails OPEN, since failing
	# closed on an unreadable lease would stop every PR in the fleet.
	observed_branch=$(printf '%s\n' "$body" | sed -n 's/^branch: //p')
	# Absent on every lease minted before CLOUD-369, exactly as `branch:` is
	# absent on every lease minted before CLOUD-420. Empty is a reading, not a
	# failure: a waiter that cannot learn the head speculates on `origin/main`
	# instead, and `authorises` admits nobody as `next` when none is named.
	observed_head=$(printf '%s\n' "$body" | sed -n 's/^head: //p')
	observed_next=$(printf '%s\n' "$body" | sed -n 's/^next: //p')
	# Absent on every lease minted before CLOUD-499, and on any holder that
	# cannot see its own progress. Empty means "no stall evidence exists", which
	# the steal path treats as not-stealable — the rival half fails CLOSED, the
	# opposite of the holder half, and deliberately: a wrongly released lease
	# costs its holder one lap, a wrongly STOLEN one puts two holders on the
	# same trunk.
	observed_progress=$(printf '%s\n' "$body" | sed -n 's/^progress: //p')
	# A lease we cannot parse is one we do not understand, and treating it as
	# free would be the same misread as an unreachable remote. Give it a full
	# TTL from now so it is respected until it ages out, never ignored.
	[ -n "$observed_expires" ] || observed_expires=$(($(now) + ttl))
	return 0
}

# Compare-and-swap the lease from $1 to a fresh one. The expected value is what
# makes this safe to call from a heartbeat: a lease that changed hands under us
# is rejected rather than clobbered. An empty $1 means "must not exist", which is
# how the very first claim is made without a separate create path.
# The expected value is passed EXPLICITLY (`<ref>:<sha>`) and must stay that way.
# Bare `--force-with-lease` compares against this clone's remote-tracking ref —
# what the last fetch happened to see — which for a ref other sessions are
# actively rewriting is precisely the stale value this must not trust. The two
# forms look interchangeable and are not: the bare one would let a holder whose
# lease had already been taken stamp its own back on top, which is the
# two-holders bug the whole task exists to prevent.
#
# The flag is also named backwards for what it does here. It is the OPPOSITE of a
# force push: it refuses in exactly the case a plain `--force` would clobber.
# A FAILED MINT MUST NEVER BECOME A DELETE. Interpolating `$(mint)` straight
# into the refspec meant an empty result produced `":$ref"` — which is git's
# delete refspec, not a no-op. On the renew path, whose expected value is our own
# live lease, that CAS would have succeeded and destroyed the lease we held. The
# mint is captured and checked first so a failure is a refused swap, which every
# caller already handles.
swap() {
	local lease
	lease=$(mint "${2:-}") || return 1
	[ -n "$lease" ] || return 1
	git push --quiet --force-with-lease="$ref:$1" "$remote" "$lease:$ref" 2>/dev/null || return 1
	# The receipt is written HERE rather than in `acquire`, because `swap` is the
	# lease's only writer: acquire, renew, the heartbeat's steal path and release
	# all reach the remote through it, so one line covers every way the lease can
	# change hands. A receipt minted at acquire alone would go stale mid-lap —
	# `verify` runs longer than a TTL — and `land` readies AFTER its push.
	#
	# Never fatal. The lease is taken the moment the push returns; a clone that
	# cannot write to its own `.git` has a problem, but it is not this one, and
	# failing here would report a held lease as unheld.
	lease_receipt "${2:-}" || true
}

# `ready-guard`'s offline half (CLOUD-420 §3). The guard must not touch the
# network — it runs in a PreToolUse hook — so what it reads is this: the instant
# this clone's lease expires, refreshed by every heartbeat. That makes the
# receipt accurate to within one beat rather than to within one acquire.
#
# Keyed by BRANCH, like `claim-check`'s and unlike `verify`'s: a lease attests to
# a decision about which branch may land, which every commit on that branch
# continues to serve. A sha-keyed one would demand a re-acquire per rebase, which
# is every lap.
lease_receipt() {
	local dir key
	[ -n "$land_branch" ] || return 0
	dir=$(git rev-parse --git-dir 2>/dev/null) || return 0
	dir="$dir/batten-receipts"
	# `/` -> `-`, the same transform `claim-check` and `receipt::branch_receipt_name`
	# already use
	# on their branch-keyed receipt. Every branch in this repository carries a
	# slash (`claude/…`, `wenzowski/…`), and a raw name makes `lease.claude/foo`
	# a path through a directory that does not exist — the write fails, no
	# receipt is left, and `ready-guard` then refuses every ready while looking
	# exactly like a mechanism that is working. The suites missed it because a
	# scratch repository's default branch is the one shape with no slash in it.
	key="lease.${land_branch//\//-}"
	# A release is a declaration that this clone no longer holds it, so the
	# receipt goes rather than ageing out — otherwise `ready-guard` would honour
	# a lease its holder had already handed on.
	if [ "${1:-}" = 0 ]; then
		rm -f "$dir/$key"
		return 0
	fi
	mkdir -p "$dir" || return 0
	echo "$(($(now) + ${1:-$ttl}))" >"$dir/$key"
}

# `-ge`, not `-gt`: a lease with zero seconds left has none, and the release
# tombstone sets the expiry to exactly now. Under `-gt` that read as still-held
# for one more second, so a release did not free the lease until the clock
# ticked — measured, as a release the releaser itself still saw as held.
expired() { [ "$(now)" -ge "${observed_expires:-0}" ]; }
# Explicitly handed over, as opposed to merely lapsed. No clock involved.
released() { [ "${observed_expires:-1}" = 0 ]; }

# How long THIS sha has been the lease, measured only on our own clock.
#
# Expiry alone is not safe to steal on, because `expires` is an absolute instant
# minted on the HOLDER's clock and compared against ours. Skew in one direction
# makes a live lease look expired, and stealing on that reading produces exactly
# the two holders this task exists to prevent. (Skew the other way makes a lease
# look far-future, which `land-lock-check` reports as WEDGED — so a WEDGED
# verdict on a healthy fleet is a clock complaint, not a vandalism report.)
#
# A heartbeat mints a new nonce every beat, so a live holder CHANGES THE SHA
# every beat. "This exact sha has been sitting there for longer than a beat" is
# therefore evidence of the same thing expiry claims, derived entirely from
# durations on one clock, and no skew can forge it. Cost is one extra beat before
# a dead lease can be taken, which `acquire` spends waiting anyway.
sha_held_for() {
	local seen prev_sha prev_at
	seen="$state_dir/seen"
	mkdir -p "$state_dir"
	prev_sha=
	prev_at=
	# Absence is guarded BEFORE the redirect, not caught after it (CLOUD-433).
	# Bash opens an input redirect before the `2>/dev/null` on the same command
	# is in effect, so `read <"$seen" 2>/dev/null` on a missing file still
	# printed `No such file or directory` to the CALLER's stderr — on every
	# first sighting of a sha, which is every acquire that reaches this path.
	if [ -f "$seen" ]; then
		read -r prev_sha prev_at <"$seen" 2>/dev/null || {
			prev_sha=
			prev_at=
		}
	fi
	if [ "$prev_sha" != "$observed_sha" ] || [ -z "$prev_at" ]; then
		printf '%s %s\n' "$observed_sha" "$(now)" >"$seen"
		echo 0
		return 0
	fi
	echo $(($(now) - prev_at))
}
# How long THIS progress token has been the lease's, on our own clock and by the
# same argument as `sha_held_for` above: the holder re-mints a nonce every beat,
# so a lease whose SHA keeps changing while its progress token does not is a
# holder that is beating without landing. Equality over time is the whole test —
# nothing here interprets the token, so the holder's clock never enters ours.
#
# Echoes seconds. A first sighting is 0, which is why a rival needs the full
# stall bound of observations before it can conclude anything.
progress_held_for() {
	local seen prev_tok prev_at
	seen="$state_dir/seen-progress"
	mkdir -p "$state_dir"
	prev_tok=
	prev_at=
	# Absence guarded before the redirect, per CLOUD-433 — see `sha_held_for`.
	if [ -f "$seen" ]; then
		read -r prev_tok prev_at <"$seen" 2>/dev/null || {
			prev_tok=
			prev_at=
		}
	fi
	if [ "$prev_tok" != "$observed_progress" ] || [ -z "$prev_at" ]; then
		printf '%s %s\n' "$observed_progress" "$(now)" >"$seen"
		echo 0
		return 0
	fi
	echo $(($(now) - prev_at))
}
mine() { [ -n "$observed_holder" ] && [ "$observed_holder" = "$(holder_id)" ]; }
# A tombstone is a HANDOVER, not an expiry, and every verb that renders seconds
# must say so (CLOUD-433). `expires: 0` is a sentinel, not an instant, so the
# ordinary arithmetic against it yields wall-clock epoch — `released after
# 1786501354s`, observed live. Written as an `if` rather than `released && …`
# because a false `&&` list would be the function's exit status under `set -e`.
age() {
	if released; then
		echo 0
		return 0
	fi
	echo $((ttl - (observed_expires - $(now))))
}

# CLOUD-432: is the land this heartbeat serves still alive? `land` passes its
# pid down as LAND_LOCK_HOLDER_PID; unset means "no holder declared", which is
# every other caller and keeps their behaviour. Existence is not enough — pids
# recycle, and this clone measurably wrapped its pid space inside 20 minutes —
# so the pid must still BE a mise-tasks/land.sh process. Any probe that cannot be
# evaluated reads as gone: a wrongly released lease costs one lap (the `held`
# fence catches it before the comment), a wrongly renewed one wedges the fleet
# for as long as nobody notices, so release is the cheap direction.
holder_alive() {
	local pid="${LAND_LOCK_HOLDER_PID:-}" cmd
	[ -n "$pid" ] || return 0
	kill -0 "$pid" 2>/dev/null || return 1
	cmd=$(tr '\0' ' ' </proc/"$pid"/cmdline 2>/dev/null) || return 1
	case "$cmd" in
	*"/mise-tasks/land.sh "*) return 0 ;;
	esac
	return 1
}

# CLOUD-499: is the land this heartbeat serves still MOVING? Liveness answers a
# different question, and answers it happily for a process wedged forever.
#
# The registry is the source, read through `task-registry` by path rather than
# parsed here — one owner of that file layout, and by path for the reason
# `ci-wait` already reads `checks-green` that way. Three stamps, and the reading
# is deliberately the LATEST of them rather than any single one:
#
#   phase_since  a lap step began (a task with no loop has only this)
#   sig_at       the world moved — `ci-wait`'s check-run reading changed
#   tick_at      a loop went round, whether or not it learned anything
#
# Echoes `<last_advance> <tick_at>`, or nothing at all when there is no entry to
# read. NOTHING is the honest answer there, and every caller treats it as "no
# verdict": a land whose bookkeeping never registered is not evidence of a
# stall, and killing one on that reading would be inventing the finding.
#
# The two are reported separately rather than folded into one maximum, because
# the hang bound may only be applied WHILE A LOOP IS ACTUALLY TICKING — which is
# exactly `tick_at > last_advance`. Folding them would apply a 90s bound to
# `verify`, whose single steps legitimately run for minutes without a tick, and
# the mechanism's first act would be to kill healthy landings.
holder_progress() {
	local pid="${LAND_LOCK_HOLDER_PID:-}" reg phase_since sig_at tick_at advance
	[ -n "$pid" ] || return 1
	reg="$(dirname "$0")/task-registry.sh"
	[ -x "$reg" ] || return 1
	phase_since=$("$reg" read "$pid" phase_since 2>/dev/null) || return 1
	sig_at=$("$reg" read "$pid" sig_at 2>/dev/null) || return 1
	tick_at=$("$reg" read "$pid" tick_at 2>/dev/null) || return 1
	advance=${phase_since:-0}
	[ "${sig_at:-0}" -le "$advance" ] 2>/dev/null || advance=$sig_at
	# An entry with no usable stamp at all is no evidence, not a stall at the
	# epoch — the same "cannot tell" the missing entry gets.
	[ "$advance" != 0 ] || return 1
	printf '%s %s\n' "$advance" "${tick_at:-0}"
}

case "$verb" in
acquire)
	deadline=$(($(now) + wait_for))
	# Jittered exponential backoff — the CSMA/CD posture mem:workflow/agent-fanout
	# already argues for. The jitter is the load-bearing half: without it every
	# waiter wakes on the same schedule and re-collides the instant a lease drops,
	# which is the herd this task exists to disperse.
	#
	# AGING (CLOUD-369), and it is what stops the capture effect the analogy
	# predicts. Backoff alone disperses a herd but does not make it FAIR: a branch
	# that has lost ten times re-enters on exactly the terms of one that just
	# arrived, so aggregate throughput stays healthy — `main` advancing is the
	# fleet working — while an individual station starves and then abandons its
	# lap budget having landed nothing. Measured on PR #325: 8 laps, 8 greens,
	# zero commits landed.
	#
	# So an aged waiter probes a freed lease SOONER: its ceiling falls as its
	# waits accumulate, which raises its chance of being the one holding the CAS
	# when the ref drops. Deliberately weaker than FIFO — strict ordering needs a
	# coordinator, which this design rules out — and deliberately not a priority
	# written anywhere: age is a count this process observed about itself, never
	# shared state, so two clones cannot disagree about it because they never
	# compare it.
	#
	# The floor is 1, never 0: a zero delay is a spin, and the busy loop is what
	# the backoff exists to prevent. The jitter survives every value of age, since
	# two equally-aged waiters are exactly the collision it disperses.
	age="${LAND_LOCK_AGE:-0}"
	case "$age" in
	'' | *[!0-9]*) age=0 ;;
	esac
	cap=30
	while [ "$age" -gt 0 ] && [ "$cap" -gt 2 ]; do
		cap=$((cap / 2))
		age=$((age - 1))
	done
	delay=2
	[ "$delay" -le "$cap" ] || delay="$cap"
	# CLOUD-450: how many observations this acquire spent looking at an EXPIRED
	# lease before it won. A count, on no clock, so the suite can assert the
	# "one extra beat" promise without grading wall time on a loaded runner.
	post_expiry_probes=0
	while :; do
		observe || exit 2
		# Record the sighting on EVERY observation, not only once expired
		# (CLOUD-433). The corroboration clock starts at the first time we saw
		# this sha, and starting it only after expiry meant it started when the
		# backoff had already grown to 8–30s: measured 19s from expiry to steal
		# at TTL=4/beat=2, against this file's own promise of one extra beat.
		# Recording here lands the steal on the FIRST post-expiry check.
		#
		# This shortens no precondition — the sha must still have sat unchanged
		# for a full beat, and a live holder still remints it every beat. It
		# removes an accidental delay, it does not make anything stealable
		# sooner than the design intends.
		held_for=0
		[ -z "$observed_sha" ] || held_for=$(sha_held_for)
		# Recorded on every observation for the same reason `held_for` is: the
		# corroboration clock starts at the first sighting, not at the first
		# sighting that happened to be interesting.
		progress_for=0
		[ -z "$observed_progress" ] || progress_for=$(progress_held_for)
		# Counted here, where every observation passes, so it measures probes and
		# not loop iterations that skipped the read (CLOUD-450).
		if [ -n "$observed_sha" ] && expired; then
			post_expiry_probes=$((post_expiry_probes + 1))
		fi
		if mine && ! expired; then
			echo "land-lock: already held by this clone"
			exit 0
		fi
		# One compare-and-swap covers all three ways in: the ref does not exist
		# yet (expected value empty), it was tombstoned by a release, or its
		# holder stopped beating. Two sessions racing the same free state CAS
		# from the same expected value, so exactly one wins and the other is told
		# `stale info` — which is why there is no separate create path to race.
		# An absent ref is unambiguous and needs no corroboration. An EXPIRED one
		# does: see `sha_held_for`. Requiring the sha to have sat unchanged for a
		# beat costs a dead lease one extra beat and makes the steal immune to a
		# holder whose clock disagrees with ours.
		steal=no
		if [ -z "$observed_sha" ] || released; then
			# Absent, or explicitly handed over. Both are statements rather than
			# deductions, so neither needs corroboration or a clock.
			steal=yes
		elif expired && [ "$held_for" -ge "$beat" ]; then
			steal=yes
		elif [ -n "$observed_progress" ] && [ "$progress_for" -ge "$((stall_beats * beat))" ]; then
			# THE BEATING-BUT-STALLED LEASE (CLOUD-499). Every branch above this
			# one waits for the holder to stop beating; this one is why a holder
			# that beats forever without landing is no longer unstealable.
			#
			# It fails CLOSED, unlike the holder's own bail: no token, no steal —
			# which is every lease minted before this change, and every holder
			# that cannot see its own progress. The asymmetry is deliberate and
			# is the same one CLOUD-432 argued in the other direction: releasing
			# a lease wrongly costs its holder one lap, stealing one wrongly puts
			# two holders on the same trunk.
			steal=yes
		fi
		if [ "$steal" = yes ]; then
			if swap "$observed_sha"; then
				if [ -n "$observed_holder" ] && [ "$observed_holder" != "$(holder_id)" ]; then
					# Seconds since the previous holder's expiry, computed here
					# rather than through `age`: that helper measures a lease
					# against OUR ttl, not the one its last holder ran under.
					# THE PROBE COUNT IS THE HONEST QUANTITY (CLOUD-450). The
					# seconds are kept because they are what a human reads, but
					# both ends of that delta are instants on one clock, so a
					# deschedule between the expiry and the winning probe inflates
					# it — which made `tests/land-lock.bats`'s duration assertion
					# a wall clock that failed under the parallel runner ~2 runs
					# in 4, and a flaky gate is a bypassed gate.
					#
					# `probes` counts the observations this acquire spent after
					# the lease expired. It is a count on no clock at all, so a
					# loaded box cannot move it: the promise "a dead lease costs
					# one extra beat" is exactly "the steal lands on the FIRST
					# post-expiry probe", and that is now stated rather than
					# inferred from elapsed time.
					if [ -n "$observed_progress" ] && [ "$progress_for" -ge "$((stall_beats * beat))" ] && ! expired; then
						# A steal from a holder that never stopped beating
						# reads as theft unless it says which evidence it
						# acted on (CLOUD-499). Pointer-only: two counts.
						echo "land-lock: took the lease from $observed_holder, which was still beating but had not progressed in ${progress_for}s (stall bound: $((stall_beats * beat))s)"
					elif released; then
						# A TOMBSTONE IS A HANDOVER, NOT AN EXPIRY, and the
						# arithmetic below renders one as wall-clock epoch —
						# `took the lease 1786577736s after …`, observed live
						# while probing CLOUD-499. Same defect CLOUD-433 fixed
						# in `status` and `release`; this third renderer was
						# missed because nothing printed it until a stalled
						# holder started releasing on its own.
						echo "land-lock: took the lease $observed_holder released"
					else
						echo "land-lock: took the lease $(($(now) - observed_expires))s after $observed_holder stopped holding it (probes since expiry: $post_expiry_probes)"
					fi
				else
					echo "land-lock: acquired by $(holder_id), ${ttl}s lease"
				fi
				exit 0
			fi
			# Lost the CAS: somebody claimed the same free state first. Fall
			# through to the deadline and the backoff rather than retrying at
			# once — an immediate retry is the tight spin that turns a contended
			# lease into a busy loop, measured when this `continue`d instead.
		fi
		if [ "$(now)" -ge "$deadline" ]; then
			echo "land-lock: still held by ${observed_holder:-another session} after ${wait_for}s"
			exit 1
		fi
		sleep $((delay + RANDOM % delay))
		[ "$delay" -ge "$cap" ] || delay=$((delay * 2))
	done
	;;

renew)
	observe || exit 2
	{ [ -n "$observed_sha" ] && mine; } || exit 1
	# CARRY THE RESERVATION FORWARD (CLOUD-369). A renewal re-mints the whole
	# body, so a `next:` written by a waiter between two beats would be erased
	# within 30 seconds of being written — by the holder, silently, and the
	# admitted successor would then be cancelled by CI mid-run.
	#
	# Renew and hold carry it; ACQUIRE DELIBERATELY DOES NOT. A fresh acquire is
	# a new turn, and the previous holder's successor has already had its
	# admission — carrying it forward would authorise a third branch, then a
	# fourth, and the bound this whole design rests on would drift upward one
	# handover at a time.
	land_next="$observed_next"
	# Carried for the same reason and against the same hazard (CLOUD-499): a
	# renew re-mints the whole body, so a progress token this caller cannot
	# compute — `renew` is a one-shot with no holder pid to look up — would be
	# erased by the act of renewing, and the lease would look unstealable-forever
	# to every rival.
	land_progress="$observed_progress"
	swap "$observed_sha" || exit 1
	exit 0
	;;

hold)
	# The heartbeat. `land` backgrounds this for the length of the hold and kills
	# it from the same trap that releases. It exits non-zero the moment the lease
	# stops being ours, which is the signal that something took it — the `held`
	# check before the comment is the backstop that acts on that.
	#
	# A FAILED PUSH IS NOT A LOST LEASE, and treating it as one was a real
	# fragility: `swap` returns non-zero both when the lease genuinely changed
	# hands AND when the push simply did not go through — a dropped connection, a
	# proxy hiccup, a rate limit. Exiting on the second hands the lease away over
	# a blip, and the whole reason the TTL is three beats wide is to survive
	# exactly that. So a push failure retries on the next beat, and only a lease
	# that is demonstrably no longer OURS ends the loop. Two consecutive failures
	# are tolerated; a third means the remaining TTL is about to run out anyway,
	# and continuing to believe we hold it past that point is the one thing this
	# must never do.
	# CLOUD-451's census rides this loop rather than running its own. This beat
	# ticks for exactly as long as a `land` holds the lease — the window "active
	# work is in flight" — so an `h` here, left in final position by a previous
	# boot, is the evidence that a container replacement interrupted real work.
	# By path, never `mise run`: this is a hot loop and the task runner costs
	# ~150ms a call (CLOUD-435). The task swallows its own failures, so a census
	# that cannot write can never end a landing.
	census="$(dirname -- "${BASH_SOURCE[0]}")/reclaim-census"
	[ -x "$census" ] || census=
	beat_note() { [ -n "$census" ] && "$census" note "$@" >/dev/null 2>&1 || true; }
	misses=0
	while :; do
		sleep "$beat"
		beat_note h
		# CLOUD-432, before anything else each beat: a heartbeat whose land is
		# gone must not renew a lease for nobody. SIGKILL, an OOM kill, and the
		# harness's un-reaped task stop all skip land's trap, and an orphan
		# that keeps renewing blocks every rival while land-lock-check reports
		# a healthy hold. Release first, then exit, so the lease frees now
		# rather than after a TTL nobody is refreshing.
		if ! holder_alive; then
			echo "land-lock: the land holding this lease (pid ${LAND_LOCK_HOLDER_PID:-?}) is gone; releasing rather than renewing for nobody"
			if observe && [ -n "$observed_sha" ] && mine; then
				swap "$observed_sha" 0 || true
			fi
			beat_note x holder-gone
			exit 1
		fi
		# CLOUD-499, the complementary case and the one liveness cannot see: the
		# land is alive, its trap would fire perfectly well, and it has stopped
		# landing. Read the progress stamps and publish them, so this beat's mint
		# carries what a rival needs to reach the same conclusion independently.
		bail=
		if progress=$(holder_progress); then
			advance=${progress% *}
			tick_at=${progress#* }
			land_progress="$advance.$tick_at"
			if [ "$(($(now) - advance))" -ge "$((stall_beats * beat))" ]; then
				bail="has not advanced in $stall_beats beats"
			elif [ "$tick_at" -gt "$advance" ] &&
				[ "$(($(now) - tick_at))" -ge "$((hang_beats * beat))" ]; then
				# Only while a loop is ticking — see `holder_progress` for why
				# folding the two stamps together would kill healthy landings.
				bail="stopped turning $hang_beats beats ago"
			fi
		else
			# No entry, no verdict. An unregistered land is not evidence of a
			# stall, and an empty token is never stall-stealable either, so this
			# clone and every rival agree to say nothing rather than guess.
			land_progress=
		fi
		if [ -n "$bail" ]; then
			# RELEASE FIRST, SIGNAL SECOND. The release is the half that frees
			# the fleet and it always lands; the signal's promptness depends on
			# what `land` is blocked in — immediate in a `wait`, which is every
			# long phase (its verify and CI waits are both raced, CLOUD-423),
			# and deferred to the end of a short foreground `git`/`gh` call
			# otherwise. Ordering them the other way would make a fleet-wide
			# unwedge wait on a signal that might be pending.
			echo "land-lock: the land holding this lease $bail; releasing and stopping it rather than holding the fleet"
			if observe && [ -n "$observed_sha" ] && mine; then
				swap "$observed_sha" 0 || true
			fi
			# WHY, where the agent will look (CLOUD-470). A landing that stops
			# without saying why reaches its agent as "verify and CI disagree",
			# and the remedy it then reaches for is wrong. `land`'s exit trap
			# prints this and removes it.
			mkdir -p "$state_dir" 2>/dev/null &&
				echo "the landing $bail, so its lease was released and it was stopped. Nothing is wrong with the branch: look at what its last phase was waiting for (\`mise run alive\`), fix that, and land again." \
					>"$state_dir/bail-reason" 2>/dev/null || true
			# Re-corroborated immediately before the kill, never inferred from
			# the probe at the top of this beat: pids recycle inside 20 minutes
			# on this clone, and the stall bound is longer than that.
			if holder_alive && [ -n "${LAND_LOCK_HOLDER_PID:-}" ]; then
				kill -TERM "$LAND_LOCK_HOLDER_PID" 2>/dev/null || true
			fi
			beat_note x stalled
			exit 1
		fi
		if ! observe; then
			misses=$((misses + 1))
		elif [ -n "$observed_sha" ] && ! mine; then
			# Unambiguous: somebody else's id is on the lease. No retry can undo
			# that, and pretending otherwise is how two sessions both comment.
			echo "land-lock: lease lost to $observed_holder"
			beat_note x lease-lost
			exit 1
		else
			# Carry the reservation across the beat. See `renew` for why this is
			# carried here and deliberately cleared on acquire.
			land_next="$observed_next"
			if swap "$observed_sha"; then
				misses=0
				continue
			fi
			misses=$((misses + 1))
		fi
		[ "$misses" -lt 3 ] || {
			echo "land-lock: could not renew for $misses beats; letting the lease lapse rather than assuming it"
			beat_note x lease-lapsed
			exit 1
		}
	done
	;;

held)
	# The pre-comment re-check, and the cheap stand-in for a fencing token. A
	# holder that was paused past its TTL and stolen from MUST discover that
	# before it comments `/fast-forward`, not after — acting on a lease you no
	# longer hold is how a lock protocol reintroduces the collision it removed.
	#
	# It demands MARGIN, not merely a lease that has not expired yet. "Not
	# expired" is a fact about the instant of the check, and the caller then goes
	# on to do something — post a comment, wait for a bot — so a lease with one
	# second left passes this and is gone before the action it authorised takes
	# effect. That is the same time-of-check/time-of-use gap the fence exists to
	# close, just moved a few lines later.
	#
	# One beat is the right margin because it is the interval at which the holder
	# proves it is alive: with at least a beat left, either the heartbeat renews
	# and the lease keeps rolling, or it does not and this check would have failed
	# anyway. Less than a beat means the next renewal is already overdue.
	observe || exit 2
	{ [ -n "$observed_sha" ] && mine; } || exit 1
	[ "$((observed_expires - $(now)))" -ge "$beat" ] || {
		echo "land-lock: lease has under ${beat}s left — too little to act on"
		exit 1
	}
	exit 0
	;;

release)
	observe || exit 2
	# Releasing a lease we do not hold is not an error: the trap that calls this
	# fires on every exit path, including ones that never acquired. Exiting
	# non-zero there would turn an orderly cleanup into a reported failure.
	{ [ -n "$observed_sha" ] && mine; } || exit 0
	# Already handed over: re-tombstoning it would mint a second release of the
	# same lease and report an epoch-scale age for it (CLOUD-433). A release is
	# idempotent in effect, so it must be idempotent in what it says too.
	if released; then
		echo "land-lock: already released"
		exit 0
	fi
	# A tombstone, not a delete: CAS the expiry to now, which leaves the lease
	# instantly claimable by anyone. That is all a release has to mean, and it
	# keeps every write in this task the same single operation.
	swap "$observed_sha" 0 || {
		echo "land-lock: could not release; it expires in $((observed_expires - $(now)))s"
		exit 0
	}
	echo "land-lock: released after $(age)s"
	exit 0
	;;

status)
	observe || exit 2
	# Expired and absent are one state to a caller: both mean the next `acquire`
	# will win. The distinction still matters for diagnosis, so an expired lease
	# names who left it and how long ago rather than vanishing from the report —
	# a lease nobody released is the tell for a session that died holding one.
	if [ -z "$observed_sha" ]; then
		echo "land-lock: unheld"
		exit 0
	fi
	# Checked BEFORE `expired`, because a tombstone satisfies both: its expiry is
	# 0, so `now >= 0` is trivially true and the expired branch would render
	# `free for <epoch>s` — `free for 1786499426s`, observed live after the
	# lease's first fleet release (CLOUD-433). `land-lock-check` already drew
	# this distinction; `status` never did.
	if released; then
		echo "land-lock: released — last held by $observed_holder"
		exit 0
	fi
	if expired; then
		echo "land-lock: unheld — last held by $observed_holder, free for $(($(now) - observed_expires))s"
		exit 0
	fi
	# The successor is named when there is one, because "who else may be spending
	# a matrix right now" is the question a reader of this verb is actually
	# asking, and a bound of two that reports as a bound of one is the kind of
	# gap between mechanism and diagnosis this file keeps closing. Pointer-only
	# still: a ref name, never a body.
	# HELD AND ADVANCING IS NOT HELD AND STALLED (CLOUD-499), and rendering them
	# identically is how a wedged fleet looked healthy for as long as anyone
	# cared to watch. A count of seconds this token has not moved, never what the
	# holder is doing — the phase belongs to `alive`, and the payload belongs
	# nowhere (non-negotiable 4).
	# READ FROM THE TOKEN, NOT FROM THE SIGHTING FILE, and that is a correctness
	# choice rather than a shortcut. `progress_held_for` RECORDS what it sees —
	# it is the corroboration `acquire` steals on — so calling it from a reader
	# would let a `status` run move the instant a rival's steal becomes due, and
	# would report nothing on a first call anyway, since a first sighting is 0 by
	# construction. The token's own first field is the holder's last advance, and
	# reading it here costs nothing and changes nothing.
	#
	# It is the holder's clock, which is exactly why no PREDICATE may use it. A
	# diagnostic line may: the worst a skewed reading does here is print a number
	# a human squints at, where the steal path stealing on one would put two
	# holders on the same trunk.
	stalled=
	if [ -n "$observed_progress" ]; then
		advance=${observed_progress%%.*}
		if [ "${advance:-0}" -gt 0 ] 2>/dev/null &&
			[ "$(($(now) - advance))" -ge "$((stall_beats * beat))" ]; then
			stalled=", stalled $(($(now) - advance))s"
		fi
	fi
	if [ -n "$observed_next" ]; then
		echo "land-lock: held by $observed_holder, $((observed_expires - $(now)))s left$stalled, $observed_next admitted behind it"
	else
		echo "land-lock: held by $observed_holder, $((observed_expires - $(now)))s left$stalled"
	fi
	mine && exit 0
	exit 1
	;;

authorises)
	# CLOUD-420. THE ONE QUESTION A RUNNER CAN ASK: may this branch spend a
	# matrix right now? Every other verb answers about THIS clone — `mine`
	# compares a holder id minted per clone, which a GitHub runner has nothing
	# to compare against. A branch name is the one identifier both ends see, and
	# `branch:` in the lease body is what makes the lease checkable by the thing
	# spending the money rather than only by the code path that cooperates.
	#
	# Read-only and side-effect free: no mint, no swap, no state file. It is a
	# pure function of (lease state, branch) so the suite can drive every row
	# without a second clone.
	#
	# THE EXIT CODES ARE NOT THIS FILE'S USUAL PAIR. 0 run / 3 stop / 2 could not
	# look, because "stop" is a third answer that the 0/1 vocabulary cannot
	# carry: 1 already means "held by someone else", which here is a REASON to
	# stop rather than the instruction. A caller keying on 3 cannot mistake a
	# refusal for an error.
	#
	# FAIL OPEN, EVERYWHERE IT CANNOT TELL. Every other refusal in this file
	# fails closed, and this one deliberately does not: a lease it cannot read
	# stops EVERY job in the fleet, where waving one matrix through costs one
	# matrix. The asymmetry is the whole justification, and it is why an
	# unreachable remote answers `run` here while it answers `exit 2` in
	# `status`. A lease minted before this change carries no `branch:` at all,
	# so during rollout that row is not an edge case, it is every lease.
	want="$2"
	if ! observe; then
		echo "land-lock: cannot read the lease; running rather than stopping the fleet"
		exit 0
	fi
	if [ -z "$observed_sha" ] || released || expired; then
		echo "land-lock: no lease is held; $want may run"
		exit 0
	fi
	if [ -z "$observed_branch" ]; then
		echo "land-lock: the lease names no branch; running rather than guessing"
		exit 0
	fi
	if [ "$observed_branch" = "$want" ]; then
		echo "land-lock: the lease authorises $want"
		exit 0
	fi
	# THE ADMITTED SUCCESSOR (CLOUD-369), and the reason the bound is two rather
	# than one. A branch that reserved the slot behind this holder is buying the
	# matrix that overlaps the holder's merge — so stopping it here would cancel
	# the very run the reservation exists to start, and the queue would be cold
	# again with the mechanism intact and useless.
	#
	# Exactly one, by construction: `reserve` fills the slot with a CAS, so the
	# lease can name one successor and never two. Nothing here counts, compares
	# ages or breaks ties — the field is either this branch or it is not.
	if [ -n "$observed_next" ] && [ "$observed_next" = "$want" ]; then
		echo "land-lock: the lease authorises $want as the successor behind $observed_branch"
		exit 0
	fi
	# Pointer-only (non-negotiable 4): the holder's branch is a ref name the
	# caller could read for itself, and naming it is what makes a stopped run
	# diagnosable rather than mysterious. No lease body, no expiry arithmetic.
	echo "land-lock: the lease authorises $observed_branch, not $want"
	exit 3
	;;

peek)
	# CLOUD-369. ONE ADVISORY FIELD, ON STDOUT, FOR A CALLER THAT MEANS TO ACT ON
	# IT. `status` is prose for a human; a caller parsing that sentence would turn
	# a message into an interface, and the next edit to the wording would be a
	# silent breakage. This prints the field alone, or nothing.
	#
	# Silent and 0 when the lease is absent, released or expired: "no lease names
	# a head" is a legitimate reading a waiter handles by staying on `origin/main`,
	# not an error it should report. Exit 2 stays reserved for "could not look".
	if ! observe; then
		exit 2
	fi
	if [ -z "$observed_sha" ] || released || expired; then
		exit 0
	fi
	case "$2" in
	branch) printf '%s\n' "$observed_branch" ;;
	head) printf '%s\n' "$observed_head" ;;
	next) printf '%s\n' "$observed_next" ;;
	esac
	exit 0
	;;

reserve)
	# CLOUD-369. THE SECOND MATRIX, AND THE ONLY ONE. The lease bounds confirming
	# runs at one, which is correct for cost and wrong for latency: after every
	# merge the queue is empty, and the next branch starts cold — a rebase, a
	# `verify` and a full matrix — before `main` can move again. Admitting one
	# successor while the holder is still merging is what overlaps that window.
	#
	# THE WAITER WRITES IT, NOT THE HOLDER, and that is forced rather than
	# chosen: waiters are not registered anywhere, so the holder has no way to
	# name one. A waiter appending itself is also what makes the slot a RACE with
	# exactly one winner — the same CAS that makes the lease itself safe, used for
	# a second, smaller decision.
	#
	# IT IS NOT A CLAIM ON THE LEASE. Every other field of the holder's lease is
	# re-minted verbatim: its holder id, its expiry, its branch, its head. The
	# holder keeps holding, its heartbeat carries the new field forward, and
	# `mine` — which compares holder ids and nothing else — still answers for the
	# holder. A reservation that moved the holder id would be a steal wearing a
	# different name.
	want="$2"
	if ! observe; then
		echo "::error:: land-lock: cannot read the lease to reserve behind it" >&2
		exit 2
	fi
	# Nothing to reserve behind. Not an error: a free lease means the caller
	# should be ACQUIRING, and reporting that is more useful than a refusal.
	if [ -z "$observed_sha" ] || released || expired; then
		echo "land-lock: no lease is held; acquire rather than reserve"
		exit 1
	fi
	# Reserving behind yourself would authorise your own branch twice and admit
	# nobody, which is worse than doing nothing: it consumes the one slot.
	if [ "$observed_branch" = "$want" ]; then
		echo "land-lock: $want already holds the lease; nothing to reserve"
		exit 1
	fi
	# The slot is taken. Idempotent for the branch that already holds it, so a
	# waiter re-reserving each lap is a read rather than a churn of the ref.
	if [ -n "$observed_next" ]; then
		if [ "$observed_next" = "$want" ]; then
			echo "land-lock: $want is already the admitted successor"
			exit 0
		fi
		echo "land-lock: $observed_next is already the admitted successor, not $want"
		exit 1
	fi
	# Re-mint the holder's lease with one field added. The `mint_*` overrides are
	# what keep this a single writer of the body: without them this path would
	# carry its own copy of the printf, and a copy is where a field silently
	# stops matching what `observe` reads.
	#
	# `mint_expires` is the holder's own instant, NOT recomputed — a reservation
	# must not extend somebody else's lease, and recomputing it here would hand
	# the holder a fresh TTL every time a waiter arrived.
	if mint_holder="$observed_holder" mint_expires="$observed_expires" \
		mint_branch="$observed_branch" mint_head="$observed_head" \
		mint_next="$want" mint_progress="$observed_progress" swap "$observed_sha"; then
		echo "land-lock: $want admitted as the successor behind $observed_branch"
		exit 0
	fi
	# Lost the CAS: the holder's heartbeat re-minted, or another waiter took the
	# slot first. Either way this is an ordinary loss, and the caller's next lap
	# re-reads and re-decides — no retry here, for the same reason `acquire`
	# does not retry inside its own CAS.
	echo "land-lock: could not reserve behind $observed_branch; the lease moved"
	exit 1
	;;
esac

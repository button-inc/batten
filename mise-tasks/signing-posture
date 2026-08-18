#!/usr/bin/env bash
#MISE description="Gate (and, with --repair, the write): no commit is signed by a key that cannot be verified or reproduced (CLOUD-669)"
#
# SIGNING IS GOOD. This gate is not against it, and a version of it that reads
# that way is wrong — signing in CI, with a key whose public half is published,
# is the desired end state and CLOUD-591 owns getting there. What this refuses is
# the narrower thing: a signature produced by a key that cannot be verified or
# reproduced, which is worse than no signature because it LOOKS like provenance
# and carries none.
#
# CLOUD-591 recorded the interim posture and shipped no mechanism, so nothing was
# in force. Non-negotiable rule 2: a rule without a runnable gate is half a
# change.
#
# WHAT WAS ACTUALLY HAPPENING. The launcher writes the signing configuration
# `--global` every session, and nothing repo-local overrode it. Measured
# 2026-08-18, all four global and none local:
#
#   commit.gpgsign    true
#   gpg.format        ssh
#   user.signingkey   /home/claude/.ssh/commit_signing_key.pub   <- 0 bytes
#   gpg.ssh.program   /tmp/code-sign -> /opt/env-runner/environment-manager
#
# Signatures were produced regardless of the empty key file, because
# `gpg.ssh.program` substitutes the harness's own signer for `ssh-keygen`. So the
# key never passes through the configured path, and it is the ENVIRONMENT's: this
# repository does not hold it, cannot publish it, and it need not survive a
# container. GitHub answers `verified: false, reason: unknown_key`.
#
# WHY THAT IS AN ATTRIBUTION DEFECT AND NOT A PREFERENCE. Every commit read:
# `author` and `committer` the accountable human — correct, and gated by
# `identity_deny` — and `gpgsig` a vendor-held key. CLOUD-268's position is that
# no vendor identity rides on the commit, and `Attribution` carries
# `identity_deny`, `trailer_deny`, `body_deny`, `trailer_allow` and `identity`
# with NO signature field. So the one commit field the attribution gate
# structurally cannot see is the one carrying a vendor identity. This gate is
# that blind spot's stand-in until CLOUD-440 lets the engine see a commit object.
#
# TWO MODES, ONE DEFINITION. The posture is a single fact, so the write and the
# check live in one file rather than drifting apart the way a paired task can.
# `--repair` is the write, self-declared per house style §5, scoped to this
# checkout's `.git/config` and NEVER `--global` — a developer's own unrelated
# repositories are not this repo's business, the same boundary
# `attribution-identity` draws.
#
# RANGE, NEVER HISTORY. The check judges `BASE_SHA..HEAD_SHA`, the range
# `commit-attribution` and `commit-lint` already share. Every commit on `main`
# predating this gate is signed by that environment key; judging history would
# make the gate permanently red for commits nobody can now unsign, which is how a
# gate gets switched off.
#
# Pointer-only per non-negotiable rule 4: a short SHA and a setting name. Never a
# signature block — it is a credential artefact this repo does not control.
#
# Exit 0 posture in force / 1 a signed commit in range, or the override missing /
# 2 could not look.
#
# The mutation drops the commit scan and keeps only the config check. Config is
# the cheap half and the one a session can satisfy after the damage: a checkout
# repaired late still carries the signed commits written before the repair, and
# those are exactly what must not reach `main`.
#MUTANT config-check-is-not-a-commit-check|s/for sha in \$range; do/for sha in ; do/|a signed commit in range is refused, and named by short sha
set -uo pipefail

repair=0
base="${BASE_SHA:-}"
head="${HEAD_SHA:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	--repair) repair=1 ;;
	--base)
		base="${2:-}"
		shift
		;;
	--head)
		head="${2:-}"
		shift
		;;
	*)
		echo "usage: signing-posture [--repair] [--base <sha>] [--head <sha>]" >&2
		exit 2
		;;
	esac
	shift
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
	echo "::error:: signing-posture: not a git repository — a gate that cannot look must not report the posture in force" >&2
	exit 2
fi

# WHAT "BROKEN" MEANS, measured rather than assumed. Two independent conditions,
# either of which makes a signature unverifiable by anyone, us included:
#
#   * `user.signingkey` names a file that is empty or unreadable. The public half
#     cannot be read, so no `allowed_signers` entry can be derived from it and
#     nothing downstream can check the signature. Measured here: 0 bytes.
#   * `gpg.ssh.program` resolves inside `/tmp`. The container reclaims it, so the
#     signer and whatever key it holds are not reproducible across sessions. A
#     signature nobody can re-verify later is provenance theatre.
#
# A signer failing NEITHER test is left alone and signing stays on.
broken_reason() {
	key=$(git config --get user.signingkey 2>/dev/null || true)
	prog=$(git config --get gpg.ssh.program 2>/dev/null || true)
	case "$prog" in
	/tmp/*)
		printf 'the signer resolves inside /tmp, which the container reclaims, so the key is not reproducible'
		return
		;;
	esac
	# A LITERAL KEY IS NOT A PATH. With `gpg.format ssh`, git accepts the public
	# key inline (`ssh-ed25519 AAAA...`) or via a `key::` prefix as well as a
	# filename. A literal is the MOST publishable form there is — it is already
	# the public half — so testing it as a file would report the healthiest
	# possible configuration as broken.
	case "$key" in
	'' | ssh-* | key::* | sk-ssh-* | sk-ecdsa-*) ;;
	*)
		# `-s` alone was the test here, and it is true for anything non-empty
		# that `stat` can size — an unreadable file, or a DIRECTORY. Both leave
		# the public half unreadable, which is the condition this is trying to
		# name, so all three tests are needed and each names its own reason.
		if [ ! -e "$key" ]; then
			printf 'user.signingkey names a path that does not exist, so the public half cannot be read or published'
			return
		fi
		if [ ! -f "$key" ]; then
			printf 'user.signingkey names something that is not a regular file, so the public half cannot be read or published'
			return
		fi
		if [ ! -r "$key" ]; then
			printf 'user.signingkey names a file this checkout cannot read, so the public half cannot be read or published'
			return
		fi
		if [ ! -s "$key" ]; then
			printf 'user.signingkey names an empty file, so the public half cannot be read or published'
			return
		fi
		;;
	esac
	printf ''
}
broken_signer() {
	if [ -n "$(broken_reason)" ]; then printf 'yes'; else printf 'no'; fi
}

# THE WRITE, and it fires ONLY against the broken configuration. Disabling
# signing unconditionally would be the wrong gate: it would also switch off a
# correctly configured signer, which is the outcome CLOUD-591 is working toward.
# Local-only, because local beats global and the launcher rewrites global every
# session.
if [ "$repair" = 1 ]; then
	if [ "$(broken_signer)" = "no" ]; then
		echo "signing-posture: signer is verifiable, leaving signing on"
		exit 0
	fi
	if ! git config --local commit.gpgsign false; then
		echo "::error:: signing-posture: could not write commit.gpgsign to this checkout's config" >&2
		exit 2
	fi
	echo "signing-posture: signing disabled in this checkout — $(broken_reason)"
	exit 0
fi

fail=0
report() {
	echo "::error:: signing-posture: $1" >&2
	fail=1
}

# The override is only OWED where something outside the checkout turns signing
# on. Demanding it unconditionally would red every CI run: a runner has no
# launcher and no global setting, so there is nothing to override and an absent
# local value is the correct state there. The predicate is therefore the
# CONFLICT — an inherited "sign" with nothing answering it — not the mere absence
# of a local key.
local_setting=$(git config --local --get commit.gpgsign 2>/dev/null || true)
inherited=$(git config --global --get commit.gpgsign 2>/dev/null || true)
# Only a BROKEN signer is a finding. A verifiable one may sign freely — that is
# the end state CLOUD-591 is working toward, and this gate must not block it.
if [ "$(broken_signer)" = "yes" ]; then
	case "$local_setting" in
	false) ;;
	*)
		case "$inherited$local_setting" in
		*true*) report "signing is on with an unverifiable signer — $(broken_reason). Run: mise run signing-posture --repair" ;;
		esac
		;;
	esac
fi

# The commits themselves. Config can be repaired after a commit was written, so
# the config check alone is not the predicate — that is this gate's declared
# mutation. `--repair` clears the config arm above and leaves this one firing on
# whatever was already written, which is what keeps the two arms distinct.
#
# SCOPED TO A BROKEN SIGNER, and this was a real defect rather than a
# refinement. The scan reported EVERY `gpgsig` in range, with no reference to
# whether the key behind it is verifiable — so it refused the exact end state
# this file's header promises to leave alone, and the row asserting that promise
# passed only because it commits with `--no-gpg-sign` and never produces a
# header for the scan to see. A vacuous row over a contradicted predicate
# (CLOUD-418); caught in review on PR #489.
#
# The signer configuration is the only evidence available about which key signed
# these commits, and it is honest evidence: a checkout whose signer is broken
# produced them with that broken signer. Verifying a signature properly needs an
# `allowed_signers` file this repository does not have, and PUBLISHING one is
# precisely CLOUD-591's deliverable — so this gate reads the configuration and
# says so, rather than pretending to a cryptographic check it cannot perform.
if [ -z "$base" ]; then
	base=$(git rev-parse --verify --quiet origin/main) || base=""
fi
[ -n "$head" ] || head=$(git rev-parse --verify --quiet HEAD) || head=""

if [ "$(broken_signer)" = "no" ]; then
	echo "signing-posture: signer is verifiable — commits in range not judged"
elif [ -n "$base" ] && [ -n "$head" ]; then
	range=$(git rev-list --no-merges "$base..$head" 2>/dev/null || true)
	for sha in $range; do
		# Captured, then matched in the shell. NOT `... | grep -q '^gpgsig'`:
		# under `pipefail` a `grep -q` exits the moment it matches, the producer
		# takes SIGPIPE, and the pipeline reports FAILURE on a match — so the
		# signed commit this gate exists to catch would read as clean. It passed
		# the suite anyway, because a commit header is small enough that the
		# producer finishes first; `pipefail-grep-check` caught what the tests
		# could not.
		header=$(git cat-file commit "$sha" 2>/dev/null | sed '/^$/q')
		case $'\n'"$header" in
		*$'\n'gpgsig' '*)
			report "${sha:0:8} carries a gpgsig — signed by a key this repo cannot verify or reproduce, which GitHub reports as unknown_key (CLOUD-591 owns publishing one; CLOUD-669 refuses the unverifiable case)"
			;;
		esac
	done
else
	echo "signing-posture: no origin/main to range against — commits not judged" >&2
fi

if [ "$fail" = 0 ]; then
	echo "signing-posture: no commit signed by an unverifiable key"
fi
exit "$fail"

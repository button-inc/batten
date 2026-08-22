#!/usr/bin/env bash
#MISE description="Gate: the crypto crates this workspace declares itself all resolve the same `digest` major (CLOUD-767)"
#
# THE RULE THIS REPLACES WAS A COMMENT, AND THE COMMENT WAS WRONG.
#
# `Cargo.toml` pinned `hmac = "0.12"` under a justification that read, in full,
# "0.13 wants `digest 0.11` and would put two majors of the same hashing
# substrate in the tree". Measured 2026-08-20 on `main`: the committed
# `Cargo.lock` already carried `digest 0.10.7` AND `digest 0.11.3`, the second
# arriving through `gix-hash` -> `sha2 0.11`. The claim had been false for as
# long as `gix` had been a dependency, nothing noticed, and the pin it justified
# went on being enforced by nobody but the reader.
#
# That is non-negotiable rule 2 stated from the failure end. Prose is feedforward
# only; a decision with no exit code is one that rots silently and is discovered
# by a bot proposing the bump it forbade (#503, CLOUD-767).
#
# WHAT IS ACTUALLY DECIDABLE, and the narrowing is the whole design. "One
# `digest` major in the tree" is NOT it: `gix` vendors what it vendors, the
# workspace has no say, and a gate asserting it would be red on the commit that
# introduced it and every commit after. A gate nobody can keep green is switched
# off within a day, and switching it off takes the real rule with it.
#
# The real rule is narrower and is true today: **the crypto crates this workspace
# declares FOR ITSELF must agree with each other.** `hmac` and `sha2` are both
# `[workspace.dependencies]` entries, both resolve a `digest`, and
# `crates/batten/src/identity.rs` composes them in one expression —
# `<Hmac<Sha256> as KeyInit>::new_from_slice`. Split them across majors and that
# type does not exist. Unlike `cap-drift`'s half-lift this direction does have a
# symptom; what it does not have is a symptom BEFORE a runner is spent, which is
# what this buys.
#
# READ FROM THE LOCKFILE, NEVER THE MANIFEST. `hmac = "0.12"` is a caret
# requirement, not a resolution: which `digest` it lands on is `Cargo.lock`'s
# answer and cannot be derived from the manifest without re-implementing the
# resolver. The manifest is consulted for ONE thing — which crates the workspace
# declares for itself — because that is the question `Cargo.lock` cannot answer:
# the lock cannot tell our direct dependency from `gix`'s transitive one, and
# conflating the two is exactly the mistake the old comment made.
#
# A DEPENDENCY-OF-A-DEPENDENCY IS NOT OUR AGREEMENT TO KEEP. `sha1-checked` and
# `sha1` sit under `gix` and resolve whatever they resolve. They are excluded by
# construction, being absent from `[workspace.dependencies]`.
#
# Pointer-only per non-negotiable rule 4: crate names and the majors they landed
# on. Never a version requirement, never a manifest line, never a lock stanza.
#
# Exit 0 they agree (or fewer than two are declared) / 1 they split / 2 could not
# look.
#
# The mutation stops reading the resolution and hardcodes agreement, which is the
# shortcut this gate exists to refuse: every pair then "agrees" and a lockfile
# that split them across two `digest` majors reads clean.
#MUTANT reads-no-resolution|s/^\tmajor=\$(digest_major_of "\$crate")$/\tmajor=0.10/|THE HALF-BUMP IS REFUSED — one crate moved and the other left behind
#PIN-OK: awk
set -uo pipefail

manifest="${DIGEST_AGREEMENT_MANIFEST:-Cargo.toml}"
lock="${DIGEST_AGREEMENT_LOCK:-Cargo.lock}"

# The crates whose `digest` major must agree. Named rather than sniffed: "does
# this crate depend on `digest`" is a question about the whole registry, and a
# gate that answered it by scanning the lock would silently widen to every
# transitive hasher the day one appeared. This is the workspace's own composition
# decision, and it is one line long.
CRYPTO_CRATES="${DIGEST_AGREEMENT_CRATES:-hmac sha2}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--manifest)
		manifest="${2:-}"
		shift 2
		;;
	--lock)
		lock="${2:-}"
		shift 2
		;;
	*)
		echo "usage: digest-major-agreement [--manifest <file>] [--lock <file>]" >&2
		exit 2
		;;
	esac
done

for f in "$manifest" "$lock"; do
	if [[ ! -r "$f" ]]; then
		echo "::error:: digest-major-agreement: cannot read $f — a gate that cannot look must not report agreement" >&2
		exit 2
	fi
done

# Is this crate one the workspace declares for itself? Scoped to the
# `[workspace.dependencies]` table alone, so a name in a comment, in
# `[workspace.lints]`, or as another table's key cannot enrol a crate `gix` owns.
declared() {
	awk -v want="$1" '
		/^\[workspace\.dependencies\]/ { in_deps = 1; next }
		/^\[/ { in_deps = 0 }
		in_deps && $1 == want { found = 1 }
		END { exit(found ? 0 : 1) }
	' "$manifest"
}

# The `digest` major this crate resolved to, read out of its own `[[package]]`
# stanza. Cargo writes a bare `"digest"` when one major is in the tree and
# `"digest <version>"` when several are, so both spellings are handled — `bare`
# is returned for the first and resolved by the caller, since with one major
# there is nothing to disambiguate.
#
# Prints the major, or nothing when the crate is absent or names no `digest`.
digest_major_of() {
	awk -v want="$1" '
		/^\[\[package\]\]/ { inpkg = 0 }
		/^name = "/ {
			line = $0
			gsub(/^name = "|"$/, "", line)
			if (line == want) inpkg = 1
		}
		inpkg && /^ "digest/ {
			line = $0
			gsub(/^ "|",$|"$/, "", line)
			n = split(line, parts, " ")
			if (n >= 2) { split(parts[2], v, "."); print v[1] "." v[2] }
			else print "bare"
			exit
		}
	' "$lock"
}

# Every `digest` major in the lock, for resolving a bare reference. More than one
# and a bare reference cannot occur, so a caller seeing several has been handed a
# lockfile that does not describe itself.
digest_majors_in_lock() {
	awk '
		/^\[\[package\]\]/ { isdigest = 0 }
		/^name = "digest"$/ { isdigest = 1; next }
		isdigest && /^version = "/ {
			line = $0
			gsub(/^version = "|"$/, "", line)
			split(line, v, ".")
			print v[1] "." v[2]
			isdigest = 0
		}
	' "$lock" | sort -u
}

seen=""
for crate in $CRYPTO_CRATES; do
	declared "$crate" || continue
	major=$(digest_major_of "$crate")
	if [[ -z "$major" ]]; then
		echo "::error:: digest-major-agreement: $crate is declared in $manifest and resolves no digest in $lock — the lockfile does not describe the manifest, so nothing here can be decided" >&2
		exit 2
	fi
	if [[ "$major" = bare ]]; then
		major=$(digest_majors_in_lock)
		if [[ "$(printf '%s\n' "$major" | grep -c .)" != 1 ]]; then
			echo "::error:: digest-major-agreement: $crate names digest without a version while $lock carries several — cannot tell which it resolved" >&2
			exit 2
		fi
	fi
	seen="$seen$crate $major"$'\n'
done

declared_count=$(printf '%s' "$seen" | grep -c . || true)
if [[ "$declared_count" -lt 2 ]]; then
	echo "digest-major-agreement: $declared_count declared crypto crate(s) — fewer than two can disagree"
	exit 0
fi

majors=$(printf '%s' "$seen" | awk '{ print $2 }' | sort -u)
if [[ "$(printf '%s\n' "$majors" | grep -c .)" != 1 ]]; then
	echo "::error:: digest-major-agreement: the workspace's own crypto crates resolved different digest majors, so \`Hmac<Sha256>\` composes two incompatible substrates and the workspace will not build:" >&2
	printf '%s' "$seen" | while read -r crate major; do
		[[ -n "$crate" ]] && echo "::error::   $crate -> digest $major" >&2
	done
	echo "::error:: bump them together or not at all — the manifest comments on both entries say so" >&2
	exit 1
fi

echo "digest-major-agreement: $declared_count declared crypto crate(s), all on digest $majors"
exit 0

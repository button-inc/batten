#!/usr/bin/env bash
#MISE description="Gate: a release carries one archive per target the dist matrix builds — the signal that six silently-failed releases had none"
#
# CLOUD-258. `release-artifacts.yml` failed on EVERY release from v0.0.31 to
# v0.0.36 — all seven dist legs built, then died on the attestation step, which
# is plan-gated and unavailable on a private repo. Because that step failed, the
# upload after it never ran, so `v0.0.36` carries one asset (the schema) and no
# binary has ever shipped.
#
# Six total failures in a row went unnoticed, and the reason is structural: a
# `release`-triggered run reaches no PR and no gate. `ci-local-parity` holds its
# properties over `pull_request` workflows; `land` watches a PR's check-runs. A
# workflow that fails on 100% of invocations therefore looks exactly like one
# that has never fired. This is the missing signal.
#
# A property of the WORLD, not of the commit (see lock-complete's header for the
# same split), so it runs on a clock rather than on the landing path — a release
# nobody is touching can go bad, and no branch is at fault when it does.
#
# ONE list of targets, and it is the workflow's. The matrix in
# release-artifacts.yml decides what a release contains; this reads that list
# rather than restating it, so a target added there is covered here with no
# second edit. Archive NAMING likewise stays in `mise-tasks/dist.sh` — matching on
# the target triple means the stem/extension rule is not re-derived here either.
#
# The same rule for the assets that are NOT per-target (CLOUD-262). A release also
# carries platform-independent files, and until now none was covered: the schema
# has shipped since CLOUD-33 with nothing asserting it arrived. They are derived
# the same way rather than listed — literal paths off the workflow's own upload
# lines, plus `mise-tasks/sbom.sh --names` for the two the workflow passes through a
# step output. So a new asset is covered by the edit that starts publishing it.
#
# The checksum manifest is the third rule set (CLOUD-278), and it is the one that
# reads BYTES rather than names. Coverage alone would miss the failure mode this
# file's own header documents: uploads are `--clobber` idempotent and the stated
# recovery is a per-target workflow_dispatch re-run, so an asset can be replaced
# after the manifest was cut and the manifest silently stops describing the
# release. Downloading the assets once a week is what turns "corrupting one byte
# makes the check fail" from a property of `sha256sum` into a property of THIS.
#
#   mise run release-assets-check v0.0.36
#   mise run release-assets-check            # the latest release
#
# Pointer-only (rule 4): target names and counts, never asset contents or URLs.
# Output is sorted, so re-running is byte-stable and diffable.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT missing-archive-passes|s/^\texit 1$/\texit 0/|a release with only the schema fails

set -euo pipefail

WORKFLOW="${BATTEN_RELEASE_WORKFLOW:-.github/workflows/release-artifacts.yml}"

if [[ ! -f "$WORKFLOW" ]]; then
	echo "::error:: cannot read $WORKFLOW, so the target list is unknown. That is a checkout problem, not an empty release." >&2
	exit 2
fi

# The matrix entries are `- target: <triple>` lines. Anchored on the list-item
# form so a `target:` appearing in prose or in another key cannot widen it.
targets=$(sed -nE 's/^[[:space:]]*-[[:space:]]+target:[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*$/\1/p' "$WORKFLOW" | sort -u)
if [[ -z "$targets" ]]; then
	echo "::error:: no matrix targets found in $WORKFLOW. A gate that checks nothing must not report green." >&2
	exit 2
fi

# The legs that also publish a binary-level SBOM (CLOUD-263) — the ones whose
# `build-tool` is not `cross`. Read from the matrix rather than listed, so a leg
# that changes wrapper is covered by that edit alone: the pair of lines is
# `- target: <triple>` followed by `build-tool: <tool>`, so the tool is the next
# `build-tool:` after each target.
composed=$(awk '
	/^[[:space:]]*-[[:space:]]+target:[[:space:]]*/ { t = $NF; next }
	/^[[:space:]]*build-tool:[[:space:]]*/ { if (t != "" && $NF != "cross") print t; t = "" }
' "$WORKFLOW" | sort -u)

# The platform-independent assets, from the places that decide them. `|| true`
# on the scrape because an empty result is a real answer the guard below judges,
# not a failure. Basenames, because a release asset is named by its basename.
TASKS="$(cd "$(dirname "$0")" && pwd)"
SBOM="$TASKS/sbom.sh"
# The CLI reference (CLOUD-171), asked the same way and for the same reason the
# SBOM is: it is uploaded through a step output, so the literal scrape below
# cannot see it — and widening that `.json` regex to admit `.md` would not help
# either, since the operand on the line is `"$REFERENCE"`.
RENDER_CLI="$TASKS/render/cli.sh"
uploads=$(grep -F 'gh release upload' "$WORKFLOW" || true)
# `.json` AND `.sh`, because `install.sh` is now an asset (CLOUD-65's script is
# what a container bootstrap fetches, and a shim can only verify it against the
# manifest if the release carries it). A `.json`-only scrape would have admitted
# that upload line and covered nothing new — the silent widening this file's own
# guard below is written against, one extension over.
literal=$(tr ' ' '\n' <<<"$uploads" | sed -nE 's#^"?([A-Za-z0-9_./-]+\.(json|sh))"?$#\1#p' || true)
derived=""
if [[ -x "$SBOM" ]]; then
	derived=$("$SBOM" --names | sed -nE 's/^(spdx|cdx)=//p' || true)
fi
if [[ -x "$RENDER_CLI" ]]; then
	derived=$(printf '%s\n%s\n' "$derived" "$("$RENDER_CLI" --names | sed -nE 's/^reference=//p' || true)")
fi
# The per-target documents, one per composed leg, named by the task that writes
# them so this file never re-derives the stem (CLOUD-263). They are PER-TARGET and
# therefore not "extras": they join the same exact-name set below, because a
# missing one is exactly the failure this clause exists to name.
SBOM_BINARY="$TASKS/sbom-binary.sh"
if [[ -x "$SBOM_BINARY" ]] && [[ -n "$composed" ]]; then
	while IFS= read -r leg; do
		[[ -n "$leg" ]] || continue
		derived=$(printf '%s\n%s\n' "$derived" "$("$SBOM_BINARY" --names "$leg" | sed -nE 's/^sbom=//p' || true)")
	done <<<"$composed"
fi
# shellcheck disable=SC2086 # both are newline-separated lists, not one word
extras=$(printf '%s\n%s\n' "$literal" "$derived" | sed 's#^.*/##' | sed '/^$/d' | sort -u)

# Guarded on the SCRAPE, not on the union: `sbom --names` always contributes two,
# so a union test could never reach zero and would be a guard that cannot fire.
# The scrape is the half that silently goes to zero — reformat the upload line and
# the schema stops being covered with nothing to say so.
if [[ -z "$literal" ]]; then
	echo "::error:: no literal asset operand found on a 'gh release upload' line in $WORKFLOW. The schema is uploaded there by name, so finding none means this parser is pointed at the wrong shape — and a gate that checks nothing must not report green." >&2
	exit 2
fi

tag="${1:-}"
if [[ -z "$tag" ]]; then
	if ! tag=$(gh release view --json tagName --jq .tagName 2>/dev/null) || [[ -z "$tag" ]]; then
		echo "::error:: no tag given and no latest release readable. Pass one: mise run release-assets-check <tag>" >&2
		exit 2
	fi
fi

# An unreadable release is exit 2 — "I could not look" — never exit 1, which
# would report a shipping release as broken on a network blip.
if ! assets=$(gh release view "$tag" --json assets --jq '.assets[].name' 2>/dev/null); then
	echo "::error:: cannot read release $tag. Fetch tags first; a release that does not exist is a caller error, not an empty one." >&2
	exit 2
fi

missing=0
present=0
while IFS= read -r target; do
	[[ -n "$target" ]] || continue
	# Matched against the ARCHIVE extensions, not the bare triple: since CLOUD-263
	# a composed leg also uploads `<stem>.spdx.json`, whose name contains the same
	# triple, and a bare substring test would let that document stand in for the
	# binary it describes — the archive missing, the gate green.
	if grep -qE -- "$target.*[.](tar[.]gz|zip)$" <<<"$assets"; then
		present=$((present + 1))
		continue
	fi
	[[ "$missing" = 0 ]] && echo "::error:: release $tag is missing an archive for targets the dist matrix builds:" >&2
	echo "  $target" >&2
	missing=$((missing + 1))
done <<<"$targets"

# Matched with -x, unlike the targets above: these are whole asset names rather
# than a triple appearing inside one, and an exact match is what keeps a new asset
# whose name contains another's from reading as both.
extras_missing=0
extras_present=0
while IFS= read -r asset; do
	[[ -n "$asset" ]] || continue
	if grep -qxF -- "$asset" <<<"$assets"; then
		extras_present=$((extras_present + 1))
		continue
	fi
	[[ "$extras_missing" = 0 ]] && echo "::error:: release $tag is missing platform-independent assets the release job uploads:" >&2
	echo "  $asset" >&2
	extras_missing=$((extras_missing + 1))
done <<<"$extras"

# --- the checksum manifest (CLOUD-278) ---------------------------------------
#
# The manifest's NAME comes from the one file that decides it, the same way the
# SBOM's does. It is deliberately NOT derived from the upload line: the literal
# scrape above recognises `.json` operands only, and widening that regex to admit
# an extensionless name would make it match far more of the line than intended.
CHECKSUMS="$(cd "$(dirname "$0")" && pwd)/checksums.sh"
manifest=""
if [[ -x "$CHECKSUMS" ]]; then
	manifest=$("$CHECKSUMS" --names | sed -nE 's#^sums=##p' | sed 's#^.*/##')
fi
if [[ -z "$manifest" ]]; then
	echo "::error:: cannot read the manifest name from '$CHECKSUMS --names', so a release's checksum coverage is unknown — and a gate that checks nothing must not report green." >&2
	exit 2
fi

sums_violations=0
covered_count=0
report_sums() { # pointer-only (rule 4): the asset name and the rule id, never bytes
	echo "  $1 $2" >&2
	sums_violations=$((sums_violations + 1))
}

if ! grep -qxF -- "$manifest" <<<"$assets"; then
	echo "::error:: release $tag carries no checksum manifest, so nothing downstream can pin its assets:" >&2
	report_sums "$manifest" "checksums-missing"
else
	scratch=$(mktemp -d)
	trap 'rm -rf "$scratch"' EXIT

	# Exit 2, not 1: a release whose assets cannot be fetched is one this gate
	# could not look at, and reporting a shipping release as corrupt on a network
	# blip is what gets a scheduled gate switched off.
	if ! gh release download "$tag" --dir "$scratch" --clobber >/dev/null 2>&1; then
		echo "::error:: cannot download the assets of release $tag, so its manifest is unverified." >&2
		exit 2
	fi

	# `sha256sum`'s own format: 64 hex, a space, then a mode byte (space for text,
	# `*` for binary). Anchored, so a line this parser cannot read contributes no
	# entry rather than a garbage one — and a manifest of nothing but unreadable
	# lines then fails coverage below, loudly.
	covered=$(sed -nE 's/^[0-9a-fA-F]{64} [ *](.+)$/\1/p' "$scratch/$manifest" | LC_ALL=C sort -u)

	# The release's assets minus the manifest itself: a manifest never covers its
	# own bytes, so it is not part of the set equality. `|| true` because grep
	# exits 1 on an empty result, which here is a real answer — a release carrying
	# nothing but the manifest — that the coverage check below judges.
	expected=$(grep -vxF -- "$manifest" <<<"$assets" | LC_ALL=C sort -u || true)

	# A manifest listing itself is unreproducible — the entry would describe the
	# bytes of the file the entry is in — and it is also how a vacuous manifest
	# disguises itself as a covering one. Dropped from the set equality and
	# reported on its own.
	if grep -qxF -- "$manifest" <<<"$covered"; then
		echo "::error:: the manifest on $tag has an entry for itself, which no run can reproduce:" >&2
		report_sums "$manifest" "checksums-self"
		covered=$(grep -vxF -- "$manifest" <<<"$covered" || true)
	fi

	if [[ -z "$covered" ]]; then
		# The vacuous manifest, including the one whose only entry was itself. A
		# release carrying nothing else would otherwise pass by having nothing to
		# disagree about — the silent false green this repo keeps re-meeting.
		echo "::error:: the manifest on $tag covers nothing, which is indistinguishable from carrying no manifest:" >&2
		report_sums "$manifest" "checksums-empty"
	else
		uncovered=0
		while IFS= read -r asset; do
			[[ -n "$asset" ]] || continue
			if grep -qxF -- "$asset" <<<"$covered"; then
				covered_count=$((covered_count + 1))
				continue
			fi
			[[ "$uncovered" = 0 ]] && echo "::error:: release $tag carries assets its manifest does not cover:" >&2
			uncovered=$((uncovered + 1))
			report_sums "$asset" "checksums-omits"
		done <<<"$expected"

		# The other direction. An entry naming a file the release does not carry
		# means the manifest describes some other set of bytes — a stale manifest
		# left behind by a partial re-run reads exactly like this.
		orphans=0
		while IFS= read -r name; do
			[[ -n "$name" ]] || continue
			if grep -qxF -- "$name" <<<"$assets"; then
				continue
			fi
			[[ "$orphans" = 0 ]] && echo "::error:: the manifest on $tag names files the release does not carry:" >&2
			orphans=$((orphans + 1))
			report_sums "$name" "checksums-orphan"
		done <<<"$covered"

		# Only once the names agree on both sides: with a name missing,
		# `sha256sum -c` reports that as a failure too, and one defect would be
		# counted twice under two rule ids.
		if [[ "$uncovered" = 0 ]] && [[ "$orphans" = 0 ]]; then
			if ! bad=$(cd "$scratch" && LC_ALL=C sha256sum -c --quiet -- "$manifest" 2>/dev/null); then
				if [[ -z "$bad" ]]; then
					echo "::error:: sha256sum could not read $manifest on $tag, so the assets' bytes are unverified." >&2
					exit 2
				fi
				echo "::error:: release $tag has assets whose bytes do not match its manifest:" >&2
				while IFS= read -r line; do
					[[ -n "$line" ]] || continue
					# `--quiet` prints only failures, as `<name>: FAILED`.
					report_sums "${line%%:*}" "checksums-mismatch"
				done <<<"$bad"
			fi
		fi
	fi
fi

if [[ "$missing" != 0 ]] || [[ "$extras_missing" != 0 ]] || [[ "$sums_violations" != 0 ]]; then
	[[ "$missing" = 0 ]] || echo "::error:: $missing of $((present + missing)) targets have no asset on $tag." >&2
	[[ "$extras_missing" = 0 ]] || echo "::error:: $extras_missing of $((extras_present + extras_missing)) non-target assets are absent from $tag." >&2
	[[ "$sums_violations" = 0 ]] || echo "::error:: $sums_violations checksum-manifest violation(s) on $tag." >&2
	echo "::error:: Re-run release-artifacts.yml via workflow_dispatch against that tag; uploads are --clobber idempotent." >&2
	exit 1
fi

echo "release-assets-check: $tag carries an archive for all $present matrix targets, all $extras_present non-target asset(s), and a manifest covering all $covered_count asset(s) (sha256 verified)"

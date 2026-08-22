#!/usr/bin/env bash
#MISE description="Gate: a release's binaries carry build provenance — or the platform gap is reported, never mistaken for an unverified artifact"
#
# CLOUD-583, adopting `gh attestation verify` (CLOUD-279 verdict 1) rather than
# `slsa-verifier` or `cosign`: the first is redundant against the same absent
# provenance, the second has no signing identity here.
#
# THE WHOLE DESIGN IS THE PRECONDITION. `gh attestation verify` exits 1 both when
# an artifact has no provenance and when the platform never offered any, and those
# are opposite facts: the first is a release that should be fixed, the second is a
# plan feature this private repo does not have. Measured 2026-08-14 on
# `batten-v0.0.74-x86_64-unknown-linux-gnu.tar.gz`, reproducing CLOUD-583's v0.0.52
# reading exactly — `Error: HTTP 404: Not Found`, exit 1.
#
# The control that separates them is the endpoint's own status code: where the
# feature IS available, an unknown digest answers **200** with an empty array;
# **404 on the resource** is the feature being absent for the repository.
# Measured here against an all-zeros digest: 404. So this reports the gap and
# exits 0 rather than calling anything unverified — a gate that cannot tell the
# two apart is worse than no gate, because it reds every release for a reason no
# branch causes.
#
# TWO MODES, and the split is the CLOUD-410 one (a gate on the landing path
# answers a question about THIS COMMIT; whether a published release is attested
# today is a question about the WORLD, and it changes with no diff):
#
#   --precondition   OFFLINE, and narrow on purpose: the verifier resolves. This
#                    is what the `release-attestation-precondition` row in
#                    batten.toml runs on every gate invocation, so the landing
#                    path makes no network call at all — see its own note below
#                    for why the credential is NOT part of it.
#   [<tag>]          The world question, on the `release-assets-check` model:
#                    probe the platform, then verify the release's binaries.
#                    Defaults to the latest release.
#
# IT VERIFIES THE BINARY, NOT THE ARCHIVE, and that is a correction to the issue's
# own wording rather than a detail. `release-artifacts.yml` attests
# `steps.dist.outputs.binary` — deliberately, so repackaging cannot launder the
# claim — so the digest provenance binds to is the executable's. Verifying the
# `.tar.gz` would compute a digest nothing ever attested and report a failure that
# means nothing, which is the same conflation this gate exists to prevent, one
# layer down.
#
# Exit 0 pass or reported gap / 1 an artifact failed to verify / 2 could-not-look,
# matching the other `*-check` programs. Pointer-only (rule 4): asset names,
# counts and status codes, never an attestation, a bundle, or a digest's contents.
set -euo pipefail

cd "${ATTESTATION_CHECK_ROOT:-$(git rev-parse --show-toplevel)}"

# The verifier, named through an override rather than taken off PATH alone — the
# `BATTEN_BIN` idiom, and load-bearing for the suite, which must be able to drive
# a `gh` whose answers it chooses without shadowing the real shim.
GH_BIN="${ATTESTATION_GH:-gh}"

# A digest no artifact has, which is what makes the probe a question about the
# REPOSITORY rather than about any file: where attestation is available the answer
# is 200 with an empty array, and where it is not the resource itself is 404.
readonly ZERO_DIGEST=0000000000000000000000000000000000000000000000000000000000000000

usage() {
	cat >&2 <<-EOF
		usage: mise run attestation-check [<tag>]
		       mise run attestation-check --precondition

		  <tag>            release tag to verify (defaults to the latest release)
		  --precondition   offline: the verifier resolves
	EOF
}

# The repository, read from the remote rather than written down: which repo this
# is belongs to the consumer, never to a task (non-negotiable rule 1, and the
# same derivation `[tasks.scorecard]` makes).
repo_slug() {
	local remote slug
	remote=$(git remote get-url origin) || return 1
	slug=${remote#*github.com[:/]}
	slug=${slug%.git}
	[[ -n "$slug" ]] || return 1
	printf '%s' "$slug"
}

# --- the offline half ---------------------------------------------------------
#
# ONE FACT, and the narrowness is the design. It asserts that the verifier
# resolves — nothing about the repository, the credential, or the platform —
# because this is what the `deny` row runs on every gate invocation, and a gate
# that blocks on ambient environment is a gate that blocks everything the moment
# an environment differs. Measured: an earlier version also required GH_TOKEN and
# a github.com remote, and it reported a violation inside
# `tests/prebuilt-lint.bats`' fixture repositories, which carry neither. A
# credential is "cannot look", and cannot-look is reported by the world half
# below rather than enforced here (the landing loop's fail-open rule).
precondition() {
	if ! command -v "$GH_BIN" >/dev/null 2>&1; then
		echo "::error:: attestation-check: no verifier at '$GH_BIN' (\$ATTESTATION_GH overrides), so no attestation could ever be checked. Run: mise install aqua:cli/cli" >&2
		return 2
	fi
	echo "attestation-check: precondition holds — the verifier resolves"
	return 0
}

if [[ "${1:-}" = "--precondition" ]]; then
	precondition
	exit $?
fi
case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

# --- the world half -----------------------------------------------------------

# The world half needs everything the precondition deliberately does not: a
# credential to read the endpoint with, and a repository to read it for. Each
# absent is "could not look" (exit 2), never a verdict about an artifact.
if ! precondition >/dev/null; then
	exit 2
fi
if [[ -z "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
	echo "::error:: attestation-check: no GH_TOKEN/GITHUB_TOKEN, so the attestations endpoint cannot be read and a 404 could not be told from a denial." >&2
	exit 2
fi
if ! slug=$(repo_slug); then
	echo "::error:: attestation-check: no github.com origin remote, so there is no repository to ask about." >&2
	exit 2
fi

# The status code IS the object this decides over — a protocol answer, not a
# report to interpret (rule 3). `-i` prints the status line; nothing else in the
# response is read.
status=$("$GH_BIN" api "repos/$slug/attestations/sha256:$ZERO_DIGEST" -i 2>/dev/null |
	awk 'NR==1 { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9][0-9][0-9]$/) { print $i; exit } }' || true)

case "$status" in
404)
	# THE REPORTED GAP, and the reason this exits 0: nothing here is a claim about
	# an artifact. `release-artifacts.yml` already runs its attestation step
	# `continue-on-error: true` for the same fact, so a release is published
	# unattested by design until the repository is public (CLOUD-585).
	echo "attestation-check: $slug:0 attestation-unavailable — the platform offers no attestation for this repository (endpoint 404), so no release artifact is judged"
	exit 0
	;;
200) ;;
"")
	echo "::error:: attestation-check: the attestations endpoint returned no readable status, so the platform's posture is unknown and nothing was judged." >&2
	exit 2
	;;
*)
	echo "::error:: attestation-check: the attestations endpoint answered $status — neither 200 (available) nor 404 (absent), so the platform's posture is unknown and nothing was judged." >&2
	exit 2
	;;
esac

tag="${1:-}"
if [[ -z "$tag" ]]; then
	if ! tag=$("$GH_BIN" release view --json tagName --jq '.tagName' 2>/dev/null) || [[ -z "$tag" ]]; then
		echo "::error:: attestation-check: no tag given and no latest release to read, so there is nothing to verify." >&2
		exit 2
	fi
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# Archives only: a release also carries a schema, an SBOM and a checksum manifest,
# and none of those is what the dist matrix attests.
if ! "$GH_BIN" release download "$tag" --dir "$scratch" --pattern '*.tar.gz' --pattern '*.zip' >/dev/null 2>&1; then
	echo "::error:: attestation-check: could not download $tag's archives, so their provenance is unverified." >&2
	exit 2
fi

violations=0
checked=0
report() { # pointer-only (rule 4): the asset name and the rule id, never a bundle
	echo "$1 $2" >&2
	violations=$((violations + 1))
}

for archive in "$scratch"/*.tar.gz "$scratch"/*.zip; do
	[[ -f "$archive" ]] || continue
	name=${archive##*/}
	# The attested subject is the BINARY inside, so the archive is opened and the
	# executable handed to the verifier — see the header.
	binary_dir="$scratch/x-$name"
	mkdir -p "$binary_dir"
	case "$name" in
	*.zip) unzip -q -o "$archive" -d "$binary_dir" || true ;;
	*) tar -xzf "$archive" -C "$binary_dir" || true ;;
	esac
	binary=$(find "$binary_dir" -type f \( -name batten -o -name batten.exe \) | head -n1)
	if [[ -z "$binary" ]]; then
		report "$name:0" "attestation-no-binary (the archive carries no batten executable to verify)"
		continue
	fi
	checked=$((checked + 1))
	# THE VERDICT, and the only thing that is one: the verifier's exit status. Its
	# own output is discarded rather than read (CLOUD-93), and it names the
	# attesting workflow and signer, which is not this gate's to republish.
	if ! "$GH_BIN" attestation verify "$binary" --repo "$slug" >/dev/null 2>&1; then
		report "$name:0" "attestation-unverified"
	fi
done

if [[ "$checked" -eq 0 ]] && [[ "$violations" -eq 0 ]]; then
	echo "::error:: attestation-check: $tag carries no archive to verify, so a green verdict would be about nothing." >&2
	exit 2
fi

if [[ "$violations" -ne 0 ]]; then
	echo "::error:: attestation-check: $violations of $checked archive(s) in $tag carry no verifiable provenance. The platform DOES offer attestation here, so this is a release to fix, not a gap to report." >&2
	exit 1
fi

echo "attestation-check: $checked archive(s) in $tag carry verifiable provenance for $slug"

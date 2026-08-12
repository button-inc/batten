#!/usr/bin/env bash
#MISE description="Gate: this repository cannot publish to a registry with a long-lived credential — the day publishing turns on, it turns on through OIDC"
#
# CLOUD-109 asked to "switch release-plz to OIDC trusted publishing", and
# measured against the tree neither half of its acceptance was a change that did
# anything:
#
#   * `release-plz.toml` sets `[workspace] publish = false`, so `release-plz
#     release` never contacts a registry. There is no publish for a trusted
#     publisher to authenticate, and `permissions: id-token: write` added today
#     would grant a capability no step uses — dead config that zizmor's
#     excessive-permissions audit reads as a finding.
#   * the `CARGO_REGISTRY_TOKEN` the issue asks to delete DOES NOT EXIST. The
#     repository carries exactly one Actions secret, `RELEASE_PLZ_TOKEN`, and a
#     tree-wide grep finds the registry name nowhere.
#
# So the deliverable is not an edit to today's workflow; it is a standing
# guarantee about the TRANSITION, which needs no credential and can be built now.
# That is this gate, and it is the whole of what CLOUD-109 can honestly close.
#
# The load-bearing rule is the implication, not the literal. While `publish` is
# false the OIDC permission is not required — requiring it would be requiring the
# dead config above. The moment `publish` becomes true, this refuses the commit
# unless the release-plz job carries `id-token: write`. Publishing therefore
# cannot be switched on except through OIDC, in the same commit that switches it.
#
# NOT IN SCOPE, and deliberately: `RELEASE_PLZ_TOKEN` itself. That is a GitHub
# credential, not a registry one, and crates.io trusted publishing does not reach
# it — the fix is an org-owned GitHub App (CLOUD-94). A rule here that fired on
# it would be answering a different question with this one's name.
#
# Pointer-only (non-negotiable rule 4): a key name and a `path:line`, never a
# secret's value and never a line of a workflow verbatim — the whole class of
# thing this gate looks for is the class that must not reach a log. Exit 0 pass /
# 1 fail / 2 could-not-look, the house-style §7 table.
set -euo pipefail

CONFIG="${BATTEN_RELEASE_PLZ_CONFIG:-release-plz.toml}"
WORKFLOW_DIR="${BATTEN_WORKFLOW_DIR:-.github/workflows}"
RELEASE_WORKFLOW="$WORKFLOW_DIR/release-plz.yml"

if [ ! -f "$CONFIG" ]; then
	echo "::error:: cannot read $CONFIG, so whether this repository publishes is unknown — and a gate that cannot answer its own question must not report green." >&2
	exit 2
fi

if [ ! -d "$WORKFLOW_DIR" ]; then
	echo "::error:: cannot read $WORKFLOW_DIR. That is a checkout problem, not a clean tree." >&2
	exit 2
fi

workflows=$(find "$WORKFLOW_DIR" -maxdepth 1 -name '*.yml' -o -maxdepth 1 -name '*.yaml' | sort)
if [ -z "$workflows" ]; then
	echo "::error:: no workflow files under $WORKFLOW_DIR. A gate that scans nothing must not report green." >&2
	exit 2
fi

fail=0
report() {
	[ "$fail" = 0 ] && echo "::error:: a long-lived registry credential can reach this repository's release path:" >&2
	echo "  $1 $2" >&2
	fail=$((fail + 1))
}

# --- rule 1: no long-lived registry credential, anywhere in a workflow --------
#
# The three spellings a cargo registry credential takes. `CARGO_REGISTRIES_` is
# the alternate-registry form and is matched on its prefix, since the middle
# segment is the registry's own name and cannot be enumerated here.
#
# Matched with `grep -n` over each file so the finding is a `path:line` pointer.
# The MATCHED TEXT IS NEVER PRINTED — a line carrying a credential reference is
# the one line this gate must not copy into a log.
while IFS= read -r workflow; do
	[ -n "$workflow" ] || continue
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		report "${workflow}:${hit%%:*}" "registry-token"
	done <<<"$(grep -n -E 'CARGO_REGISTRY_TOKEN|CARGO_REGISTRIES_[A-Z0-9_]*_TOKEN' "$workflow" | cut -d: -f1 || true)"
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		report "${workflow}:${hit%%:*}" "cargo-login"
	done <<<"$(grep -n -E '(^|[^A-Za-z0-9_-])cargo login([^A-Za-z0-9_-]|$)' "$workflow" | cut -d: -f1 || true)"
done <<<"$workflows"

# --- rule 2: publishing implies OIDC ------------------------------------------
#
# `publish` is read off the config rather than assumed, and an ABSENT key is not
# the same as false: release-plz's own default is to publish, so a config that
# says nothing publishes. Treating a missing key as `false` would make this gate
# silent in exactly the case it exists for.
publish=$(sed -nE 's/^[[:space:]]*publish[[:space:]]*=[[:space:]]*(true|false).*/\1/p' "$CONFIG" | head -n1)
if [ -z "$publish" ]; then
	publish=true
	echo "::notice:: $CONFIG declares no \`publish\` key; release-plz defaults to publishing, so this gate reads it as true." >&2
fi

if [ "$publish" = "true" ]; then
	if [ ! -f "$RELEASE_WORKFLOW" ]; then
		echo "::error:: $CONFIG publishes, but $RELEASE_WORKFLOW does not exist, so there is no workflow whose OIDC permission could be checked." >&2
		exit 2
	fi
	# `id-token: write` under any `permissions:` block in the release workflow.
	# Anchored on the key form so the phrase in a comment cannot satisfy it.
	if ! grep -qE '^[[:space:]]+id-token:[[:space:]]*write[[:space:]]*(#.*)?$' "$RELEASE_WORKFLOW"; then
		[ "$fail" = 0 ] && echo "::error:: publishing is on without the credential-free way to do it:" >&2
		echo "  $RELEASE_WORKFLOW no-oidc-permission" >&2
		echo "::error:: $CONFIG sets publish = true, so release-plz will authenticate to a registry. Add \`id-token: write\` to the release-plz job's permissions and register this repository as a trusted publisher (CLOUD-109); do not add a registry token." >&2
		fail=$((fail + 1))
	fi
fi

if [ "$fail" != 0 ]; then
	echo "::error:: publish-credential-check: $fail finding(s). A registry credential stored as a secret is the thing OIDC exists to retire — see CLOUD-109, and CLOUD-94 for the separate GitHub credential this does NOT cover." >&2
	exit 1
fi

count=$(printf '%s\n' "$workflows" | grep -c .)
echo "publish-credential-check: publish=$publish; $count workflow(s) carry no long-lived registry credential"

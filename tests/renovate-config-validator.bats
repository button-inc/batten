#!/usr/bin/env bats
# The second of CLOUD-655's two predicates. `ci-local-parity`'s property 13
# decides that the four CI-cost keys are PRESENT with the values that make them
# work; this decides that the file around them is one Renovate will accept.
#
# The distinction is the reason both exist: a config Renovate rejects is a lane
# that proposes nothing, silently — the same shape as `lock-currency` sitting
# green while the currency question it names went unasked, which is how
# `[tools] rust` reached twelve releases stale.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/renovate-config-validator"
	CONFIG="$BATS_TEST_TMPDIR/renovate.json5"
	export RENOVATE_CONFIG="$CONFIG"
}

# The committed config's own shape, minus the reasoning. Written per case rather
# than once, so each case differs from a valid one in exactly one way.
valid_config() {
	cat >"$CONFIG" <<-'EOF'
		{
		  $schema: "https://docs.renovatebot.com/renovate-schema.json",
		  extends: ["config:recommended"],
		  enabledManagers: ["mise"],
		  draftPR: true,
		  rebaseWhen: "never",
		  prConcurrentLimit: 1,
		  minimumReleaseAge: "7 days",
		}
	EOF
}

@test "a config Renovate accepts passes" {
	valid_config
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a config Renovate rejects is refused" {
	# A key Renovate has no schema for. This is the whole class property 13
	# cannot see: the four keys it looks for are all present and correct, and the
	# config is still one Renovate will not load.
	valid_config
	printf '{\n  enabledManagers: ["mise"],\n  draftPR: true,\n  rebaseWhen: "never",\n  prConcurrentLimit: 1,\n  minimumReleaseAge: "7 days",\n  notARenovateKeyAtAll: true,\n}\n' >"$CONFIG"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not a config Renovate will accept"* ]]
}

@test "a config that is not parseable at all is refused" {
	printf '{ this is not json5 at all ]\n' >"$CONFIG"
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "an unreadable config is exit 2, never a pass" {
	# The `lock-check` lesson applied to the smallest possible gate: a gate that
	# cannot look must not report that it looked and found nothing wrong.
	rm -f "$CONFIG"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"cannot read"* ]]
}

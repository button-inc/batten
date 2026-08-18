#!/usr/bin/env bash
#MISE description="Gate: the committed Renovate config is one Renovate will accept (CLOUD-655)"
#
# The second of CLOUD-655's two predicates, and it answers what the first cannot.
# `ci-local-parity`'s property 13 decides that the four CI-cost keys are PRESENT
# with the values that make them work; it says nothing about whether the file
# around them parses, or whether a key is spelled the way Renovate spells it. A
# config Renovate rejects is a lane that silently proposes nothing — the same
# shape as `lock-currency` being green while the question it names went unasked,
# which is what let `[tools] rust` sit twelve releases stale.
#
# `renovate-config-validator` is upstream's own answer, so this is adoption
# rather than a hand-rolled schema check: the validator ships inside the
# `renovate` package and moves with it, and a check written here would be a
# second authority for Renovate's schema that goes stale on every release.
#
# Pointer-only per non-negotiable rule 4 is satisfied structurally rather than by
# filtering: the validator reports a key path and a message, never a value, and
# the file it reads is committed config with no secret in it. Its own output is
# passed through, because a gate that swallowed the reason would leave the author
# guessing at which key it rejected.
#
# Exit 0 the config is valid / 1 it is not / 2 could not look.
#
# The mutation reports the validator's refusal and then exits 0 anyway — the
# "a log without a gate is sensor only" half of non-negotiable rule 2, and the
# single most likely wrong edit here, since the validator already prints a
# perfectly good diagnostic of its own.
#MUTANT reports-without-refusing|s/^\texit 1$/\texit 0/|a config Renovate rejects is refused
set -uo pipefail

config="${RENOVATE_CONFIG:-renovate.json5}"

if [ ! -r "$config" ]; then
	echo "::error:: renovate-config-validator: cannot read $config — a gate that cannot look must not report a valid config" >&2
	exit 2
fi

if ! command -v renovate-config-validator >/dev/null 2>&1; then
	echo "::error:: renovate-config-validator: the validator is not on PATH — run \`mise install\` (it is the \`npm:renovate\` pin in mise.toml)" >&2
	exit 2
fi

# `--strict` makes a warning fatal. The alternative is a gate that exits 0 while
# telling the author their config is wrong, which is the "a log without a gate is
# sensor only" half of non-negotiable rule 2.
if ! renovate-config-validator --strict "$config"; then
	echo "::error:: renovate-config-validator: $config is not a config Renovate will accept — the lane would propose nothing, silently" >&2
	exit 1
fi

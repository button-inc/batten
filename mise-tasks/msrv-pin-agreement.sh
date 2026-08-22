#!/usr/bin/env bash
#MISE description="Gate: `rust-version` and Renovate's `constraints.rust` are the toolchain pin's derived copies, so all three must agree (CLOUD-593, CLOUD-658)"
#
# Replaces `mise run msrv`, and the swap is the point rather than a saving.
#
# `msrv` answered "do the floor and the pin disagree?" by compiling the whole
# workspace a second time at a second toolchain — ~32-50s per PR, in
# `CI_REQUIRED_CHECKS`, and a rustup fetch. That was the right shape while the
# two numbers were deliberately INDEPENDENT: a floor below the pin is a claim
# about a compiler nothing here runs, and the only way to verify such a claim is
# to run it.
#
# CLOUD-593 removed the independence. Batten ships compiled binaries and its
# source is public so the community can maintain them; nobody consumes the crate
# as a library and nobody obtains it by compiling, so the floor promises nothing
# to nobody. What `rust-version` still does is feed Cargo's MSRV-aware
# resolution, keeping the dependency graph inside what we actually build with —
# and the honest value for that is the compiler we actually build with. Once the
# policy is "these are equal", the predicate is a text equality, and the second
# compile buys nothing the equality does not.
#
# The floor was 1.85 against a pin of 1.85.0 and a stable of 1.97.1 — twelve
# releases — which froze `ignore` at 0.4.29 and `globset` at 0.4.19 and rejected
# `regorus` outright on a 1.87 `const fn`. `msrv` was green throughout, because
# the two numbers agreed. It was never the gate that would notice.
#
# MAJOR.MINOR, AND ONLY THAT. `rust-version = "1.97"` and a pin of `"1.97.1"` are
# the same compiler line and must compare equal; Cargo treats the field as a
# minimum and a patch component there says nothing extra. Comparing the strings
# raw would demand `rust-version = "1.97.1"`, which is legal but claims a
# precision the field does not carry — and would redden on every patch bump of
# the pin, which is exactly the noise that gets a gate switched off.
#
# A THIRD PATH SINCE CLOUD-658, and it is what makes handing `cargo` to Renovate
# safe rather than a regression. Dependabot's cargo updater reads `rust-version`
# from the manifest natively; Renovate's does not (`renovatebot/renovate#26314`,
# open, no implementation), so MSRV-aware resolution survives the handover only
# if the number is written into `renovate.json5` by hand. CLOUD-593's whole
# argument applies unchanged: a copy is not the defect, an UNGATED copy is — so
# the third copy is one more path in this check rather than a new hazard.
#
# Pointer-only per non-negotiable rule 4: the values and the files they came
# from, never a line of any of the three.
#
# Exit 0 they agree / 1 they diverge / 2 could not look.
#
# The mutation compares only the first component, so `1.85` and `1.97.1` both
# fold to `1` and every divergence reads as agreement. A major-version-only
# comparison is the plausible wrong narrowing here, and it passes the whole
# defect this gate exists for: the floor and the pin were both `1.x` throughout
# the twelve releases they were apart.
#MUTANT compares-major-only|s/cut -d. -f1,2/cut -d. -f1/|the floor behind the pin is refused, and both values are named
# And the third path must actually be COMPARED, not merely read. Dropping it from
# the condition leaves the file parsed, the value extracted, and a Renovate
# constraint frozen at an old compiler line reading as agreement — which is the
# ungated third copy CLOUD-658 argues is safe only because this gate covers it.
#MUTANT constraint-read-but-not-compared|s/\[ "\$constraint_line" != "\$pin_line" \]/false/|a Renovate constraint naming a different compiler is refused
set -uo pipefail

manifest="${MSRV_PIN_MANIFEST:-Cargo.toml}"
pins="${MSRV_PIN_TOOLS:-mise.toml}"
renovate="${MSRV_PIN_RENOVATE:-renovate.json5}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--manifest)
		manifest="${2:-}"
		shift 2
		;;
	--tools)
		pins="${2:-}"
		shift 2
		;;
	--renovate)
		renovate="${2:-}"
		shift 2
		;;
	*)
		echo "usage: msrv-pin-agreement [--manifest <file>] [--tools <file>] [--renovate <file>]" >&2
		exit 2
		;;
	esac
done

for f in "$manifest" "$pins" "$renovate"; do
	if [[ ! -r "$f" ]]; then
		echo "::error:: msrv-pin-agreement: cannot read $f — a gate that cannot look must not report agreement" >&2
		exit 2
	fi
done

# `rust-version = "1.97"` in `[workspace.package]`. Anchored on the key at line
# start so a `rust-version` inside a dependency table cannot answer for the
# workspace's own declaration.
floor=$(sed -n 's/^rust-version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n 1)
if [[ -z "$floor" ]]; then
	echo "::error:: msrv-pin-agreement: no rust-version in $manifest — nothing to compare, and silence here would read as agreement" >&2
	exit 2
fi

# `rust = { version = "1.97.1", … }` in `[tools]`. The inline-table form is the
# only one this repo uses; a bare `rust = "1.97.1"` is accepted too, since the
# manifest format permits it and a gate that only understood one spelling would
# fail open on the other.
pin=$(sed -n 's/^rust[[:space:]]*=[[:space:]]*{[^}]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p;s/^rust[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$pins" | head -n 1)
if [[ -z "$pin" ]]; then
	echo "::error:: msrv-pin-agreement: no [tools] rust pin in $pins — nothing to compare" >&2
	exit 2
fi

# `constraints: { rust: "1.97" }` in the Renovate config (CLOUD-658). Read from
# INSIDE the `constraints` block rather than by grepping the file for a `rust`
# key: that file discusses the pin at length in its comments, and a gate a
# comment could answer is a gate satisfied by deleting the value it explains.
# Comments are stripped first for the same reason, with the `//` required at line
# start or after whitespace so the `https://` in `$schema` survives.
constraints_block=$(sed -e 's|^//.*$||' -e 's|[[:space:]]//.*$||' "$renovate" |
	awk '/constraints[[:space:]]*:/ { c = 1 } c { print } c && /\}/ { exit }')
constraint=$(sed -n 's/.*[\"'"'"']\{0,1\}rust[\"'"'"']\{0,1\}[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$constraints_block" | head -n 1)
if [[ -z "$constraint" ]]; then
	echo "::error:: msrv-pin-agreement: no constraints.rust in $renovate — Renovate's cargo updater does not read rust-version (renovatebot/renovate#26314), so an absent constraint is MSRV-aware resolution silently switched off, not a neutral omission" >&2
	exit 2
fi

floor_line=$(printf '%s' "$floor" | cut -d. -f1,2)
pin_line=$(printf '%s' "$pin" | cut -d. -f1,2)
constraint_line=$(printf '%s' "$constraint" | cut -d. -f1,2)

# Both derived copies are compared against the pin, and each in its own `if` —
# not one condition joined by `||`. A `#MUTANT` declaration is split on `|`, so a
# joined condition is one no mutation could name, and a path no mutation can name
# is a path nothing proves is load-bearing. Found by the mutant runner refusing
# the declaration on its first run.
divergent=0
if [[ "$floor_line" != "$pin_line" ]]; then
	divergent=1
fi
if [[ "$constraint_line" != "$pin_line" ]]; then
	divergent=1
fi

if [[ "$divergent" -ne 0 ]]; then
	echo "::error:: msrv-pin-agreement: the floor, the toolchain pin and the Renovate constraint do not all name the same compiler" >&2
	echo "  $manifest rust-version $floor" >&2
	echo "  $pins [tools] rust $pin" >&2
	echo "  $renovate constraints.rust $constraint" >&2
	echo "  Since CLOUD-593 the pin is the authority and the other two are its derived copies. Raise the pin, then set both to its major.minor." >&2
	exit 1
fi

echo "msrv-pin-agreement: rust-version $floor and constraints.rust $constraint both agree with the [tools] rust pin $pin"
exit 0

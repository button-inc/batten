#!/usr/bin/env bash
#MISE description="Gate: the install path resolves the assets the release actually publishes, and no binary is committed"
#
# CLOUD-65's three acceptance clauses, made computable. Before this, all three
# were prose: `install.sh` resolved an asset name, `[package.metadata.binstall]`
# resolved a URL, and `mise-tasks/dist.sh` decided what the release is actually
# called — three statements of one contract with nothing comparing them. A
# rename in `dist` is a build that still passes and an install path that 404s at
# the only moment anyone would notice, which is on a user's machine.
#
# THE CONTRACT IS PROVED BY RUNNING, NOT BY SCRAPING. `dist` owns archive naming
# (`archive_stem`, `archive_ext`), `install.sh` owns which targets it installs
# (`--targets`) and what it will ask for (`--asset-name`), and this gate calls
# each of them. The one restatement that cannot be avoided is the binstall
# manifest — cargo reads TOML, not a shell function — so that template is
# resolved here and compared against `dist`'s answer for every target.
#
# The target LIST likewise has one authority and it is the workflow's, the same
# property `release-assets-check` holds: `release-artifacts.yml`'s matrix decides
# what a release contains, and both this gate and that one read it rather than
# keeping a copy. A target added there is covered here with no second edit.
#
# The Windows exclusion is derived, never restated. `install.sh` is POSIX sh and
# does not install the `.zip` target; which targets those are is `dist`'s
# `is_windows_target`, so this gate subtracts using that function rather than
# matching on a triple of its own.
#
# Pointer-only (non-negotiable rule 4): target names, asset names, and paths.
# Never the contents of a file it judges. Exit 0 pass / 1 fail / 2 could-not-look,
# the house-style §7 table.
set -euo pipefail

# Paths are relative to the working directory, the same convention
# `release-assets-check` uses: every one of them is DATA this gate judges rather
# than a sibling program it calls, so resolving them against the script's own
# location would make it judge this checkout while pointed at another.
DIST="mise-tasks/dist.sh"
INSTALL="./install.sh"
MANIFEST="crates/batten/Cargo.toml"
WORKSPACE="Cargo.toml"
WORKFLOW="${BATTEN_RELEASE_WORKFLOW:-.github/workflows/release-artifacts.yml}"

# A version that is deliberately not this crate's. The comparison is about the
# template, and a sample equal to the real version would let a hardcoded version
# pass.
SAMPLE_VERSION="9.9.9"

for f in "$DIST" "$INSTALL" "$MANIFEST" "$WORKSPACE" "$WORKFLOW"; do
	if [ ! -f "$f" ]; then
		echo "::error:: cannot read $f, so the install contract is unknown. That is a checkout problem, not a failing contract." >&2
		exit 2
	fi
done

fail=0
report() {
	echo "  $1" >&2
	fail=$((fail + 1))
}

# --- the release matrix, from the workflow that decides it -------------------
#
# Same anchored `- target:` form `release-assets-check` reads, so a `target:` in
# prose or in another key cannot widen it.
matrix=$(sed -nE 's/^[[:space:]]*-[[:space:]]+target:[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*$/\1/p' "$WORKFLOW" | sort -u)
if [ -z "$matrix" ]; then
	echo "::error:: no matrix targets found in $WORKFLOW. A gate that checks nothing must not report green." >&2
	exit 2
fi

# --- `dist`'s answer, obtained by calling `dist` ------------------------------
#
# Sourced in a SUBSHELL: the script sets its own options and defines its own
# `main`, and neither belongs in this one. Same technique as tests/dist.bats,
# which strips the trailing invocation and keeps the pure functions.
dist_names() {
	(
		# shellcheck disable=SC1090 # sourcing a sibling task's pure functions by construction
		eval "$(sed '/^main "\$@"$/d' "$DIST")"
		while IFS= read -r t; do
			[ -n "$t" ] || continue
			printf '%s\t%s%s\n' "$t" "$(archive_stem "$SAMPLE_VERSION" "$t")" "$(archive_ext "$t")"
		done
	)
}

if ! expected=$(printf '%s\n' "$matrix" | dist_names) || [ -z "$expected" ]; then
	echo "::error:: could not resolve archive names from $DIST. Its pure functions (archive_stem, archive_ext) are what every other reader agrees with; if they cannot be called, nothing here has been checked." >&2
	exit 2
fi

# The targets `dist` calls non-Windows — derived, so this gate never carries its
# own idea of which platform has no POSIX shell.
installable=$(printf '%s\n' "$expected" | awk -F'\t' '$2 !~ /[.]zip$/ { print $1 }' | sort -u)
if [ -z "$installable" ]; then
	echo "::error:: every matrix target resolves to a .zip, so there is nothing install.sh could install. That is a parse failure, not a release." >&2
	exit 2
fi

# --- clause 1: install.sh installs exactly the non-Windows matrix -------------
if ! declared=$("$INSTALL" --targets 2>/dev/null | sort -u) || [ -z "$declared" ]; then
	echo "::error:: $INSTALL --targets printed nothing. That flag is how this gate reads the script's own list; without it nothing is compared." >&2
	exit 2
fi

if [ "$declared" != "$installable" ]; then
	echo "::error:: install.sh and the release matrix disagree about which targets are installable:" >&2
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		report "$t — built by the release matrix, absent from install.sh --targets"
	done <<<"$(comm -23 <(printf '%s\n' "$installable") <(printf '%s\n' "$declared"))"
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		report "$t — listed by install.sh --targets, built by no matrix leg"
	done <<<"$(comm -13 <(printf '%s\n' "$installable") <(printf '%s\n' "$declared"))"
fi

# --- clause 2: install.sh asks for the name dist writes ----------------------
#
# Every matrix target, including the Windows one: `--asset-name` is a pure
# naming query and answering it correctly for a target the script declines to
# INSTALL is still part of the contract binstall reads.
while IFS=$'\t' read -r target want; do
	[ -n "$target" ] || continue
	got=$("$INSTALL" --asset-name "$SAMPLE_VERSION" "$target" 2>/dev/null || true)
	if [ "$got" != "$want" ]; then
		[ "$fail" = 0 ] && echo "::error:: install.sh resolves an asset name mise-tasks/dist.sh does not write:" >&2
		report "$target — dist writes '$want', install.sh asks for '${got:-<nothing>}'"
	fi
done <<<"$expected"

# --- clause 2b: the binstall template resolves to the same name --------------
#
# The one restatement of the naming contract that has to exist, because cargo
# reads a manifest and cannot call a shell function. `pkg-fmt` decides
# `{ archive-suffix }`, and an override table may change it per target, so both
# are read the way cargo-binstall reads them.
pkg_url=$(sed -nE 's/^pkg-url[[:space:]]*=[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "$MANIFEST" | head -n1)
if [ -z "$pkg_url" ]; then
	echo "::error:: no pkg-url in $MANIFEST. [package.metadata.binstall] is how cargo binstall resolves a release asset; without it that half of CLOUD-65 is unchecked and unimplemented." >&2
	exit 2
fi

repo=$(sed -nE 's/^repository[[:space:]]*=[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "$WORKSPACE" | head -n1)
if [ -z "$repo" ]; then
	echo "::error:: no workspace repository URL to resolve binstall's { repo } against." >&2
	exit 2
fi

# The default pkg-fmt, and any per-target override. Read as data so a new
# override is honoured rather than silently ignored.
default_fmt=$(sed -nE 's/^pkg-fmt[[:space:]]*=[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "$MANIFEST" | head -n1)
[ -n "$default_fmt" ] || default_fmt=tgz

override_fmt() {
	awk -F'"' -v want="[package.metadata.binstall.overrides.$1]" '
		$0 == want { inside = 1; next }
		inside && /^\[/ { inside = 0 }
		inside && /^pkg-fmt[ \t]*=/ { print $2; exit }
	' "$MANIFEST"
}

# binstall's own mapping, narrowed to the formats this repo publishes. An
# unrecognised one is exit 2 rather than a guessed suffix: guessing would make
# the comparison below pass over a template nobody has checked.
suffix_for() {
	case "$1" in
	tgz) printf '.tar.gz' ;;
	zip) printf '.zip' ;;
	*) return 1 ;;
	esac
}

binstall_fail=0
while IFS=$'\t' read -r target want; do
	[ -n "$target" ] || continue
	fmt=$(override_fmt "$target")
	[ -n "$fmt" ] || fmt="$default_fmt"
	if ! suffix=$(suffix_for "$fmt"); then
		echo "::error:: binstall pkg-fmt '$fmt' (target $target) is one this gate has no suffix rule for. Add it here in the same change that adds it to the manifest — a guessed suffix would make this comparison vacuous." >&2
		exit 2
	fi
	resolved="$pkg_url"
	resolved=${resolved//\{ repo \}/$repo}
	resolved=${resolved//\{ name \}/batten}
	resolved=${resolved//\{ version \}/$SAMPLE_VERSION}
	resolved=${resolved//\{ target \}/$target}
	resolved=${resolved//\{ archive-suffix \}/$suffix}
	expect_url="$repo/releases/download/v$SAMPLE_VERSION/$want"
	if [ "$resolved" != "$expect_url" ]; then
		[ "$binstall_fail" = 0 ] && echo "::error:: [package.metadata.binstall]'s pkg-url does not resolve to the asset the release carries:" >&2
		binstall_fail=1
		report "$target — release has '$expect_url', binstall would fetch '$resolved'"
	fi
done <<<"$expected"

# --- clause 3: no binary is committed ----------------------------------------
#
# The clause the whole issue rests on: binaries come from a release, never from
# the tree. Judged on executable-format magic rather than on a path convention,
# because a convention is what someone works around. `MZ` is matched with the
# third byte a PE header carries, since two printable characters alone would
# fire on ordinary text.
#
# Reports the path only — never a byte of the file, which for a committed binary
# is exactly the payload rule 4 exists to keep out of a log.
if ! tracked=$(git ls-files 2>/dev/null); then
	echo "::error:: cannot list tracked files, so 'no binary is committed' has not been checked." >&2
	exit 2
fi

binary_fail=0
while IFS= read -r path; do
	[ -n "$path" ] || continue
	# A submodule is a gitlink, not a file; its contents are that repo's problem.
	[ -f "$path" ] || continue
	magic=$(od -An -tx1 -N4 -- "$path" 2>/dev/null | tr -d ' \n')
	case "$magic" in
	7f454c46* | feedface* | cefaedfe* | feedfacf* | cffaedfe* | cafebabe* | 4d5a90*)
		[ "$binary_fail" = 0 ] && echo "::error:: an executable binary is committed to the repository, which the install path exists to make unnecessary:" >&2
		binary_fail=1
		report "$path"
		;;
	esac
done <<<"$tracked"

if [ "$fail" != 0 ]; then
	echo "::error:: install-check: $fail disagreement(s). The install path resolves assets by name, so a mismatch here is a 404 on a user's machine and nowhere else." >&2
	exit 1
fi

echo "install-check: $(printf '%s\n' "$expected" | grep -c .) matrix target(s) name-agree across dist, install.sh and binstall; $(printf '%s\n' "$declared" | grep -c .) installable; $(printf '%s\n' "$tracked" | grep -c .) tracked file(s) carry no executable magic"

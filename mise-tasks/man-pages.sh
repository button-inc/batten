#!/usr/bin/env bash
#MISE description="List the man pages the command surface derives: one `<file>\\t<command path>` row per command (CLOUD-69)"
#
# The one authority for WHICH pages exist and WHAT each is called. Two callers
# need that list and they must not each derive it: `mise run man` writes the
# pages, `mise run derived-check` diffs them, and a list computed twice is the
# second authority that lets a renamed verb leave a stale page behind while both
# sides report green.
#
# The list is derived from the binary, never enumerated: `batten spec` walks the
# same SURFACE-built tree the pages are rendered from, so a verb added to the
# surface is covered here by the edit that declares it.
#
# The FILENAME rule is the man convention — a page is looked up by its `.TH`
# title, so `config show` must install as `batten-config-show.1` and not as
# `show.1`. `render::page_name` spells the same rule inside the binary for the
# `.TH` line; `tests/derived-check.bats` asserts the two agree over every
# committed page, so the pair is gated rather than merely intended.
#
# Output is `<file>\t<path>` — tab-separated because a command path contains
# spaces, and the root page's path is deliberately EMPTY (`batten generate man`
# with no argument is the root page).
set -euo pipefail

cd "${MAN_PAGES_ROOT:-$(git rev-parse --show-toplevel)}"

dir="${MAN_DIR:-man}"

# Read the spec into a variable before parsing it: a producer piped into a
# consumer that can exit early is the `pipefail` hazard this repo has already
# paid for twice (mem:toolchain-and-hooks). A here-string has no upstream
# process, so there is no status to promote.
if ! spec=$(cargo run --quiet -p batten -- spec --format json); then
	echo "::error:: man-pages: the binary could not emit its spec, so the page list is unknown" >&2
	exit 2
fi

program=$(jq -r '.path' <<<"$spec")
if [[ -z "$program" ]] || [[ "$program" = "null" ]]; then
	echo "::error:: man-pages: the spec carries no program name. A list that cannot name its own root must not report an empty set." >&2
	exit 2
fi

# The root page first, then every command path root-relative, in the spec's own
# (sorted) order — so the list is byte-stable and diffable like every other
# derived artifact (§6).
printf '%s/%s.1\t\n' "$dir" "$program"
jq -r --arg dir "$dir" --arg program "$program" '
	[.subcommands[] | recurse(.subcommands[]?) | .path]
	| .[]
	| [$dir + "/" + $program + "-" + (. | gsub(" "; "-")) + ".1", .]
	| @tsv
' <<<"$spec"

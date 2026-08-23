# A program that reaches for a sibling by a CONSTRUCTED path must name one that
# exists.
#
# `"$(dirname -- "${BASH_SOURCE[0]}")/helper"` is the portable way one script in a
# directory calls another, and it is invisible to every instrument that would
# otherwise catch a broken reference: the path is assembled at run time, so no
# grep for the callee's name finds it, no linter resolves it, and the callers
# measured here all guard it with `[ -x "$path" ]` and then `exit 0` — so a
# reference that stopped resolving does not fail, it goes QUIET. The gate keeps
# running, keeps exiting 0, and decides nothing.
#
# Measured on one tree during a rename of 138 programs: 16 such references across
# 9 files survived a textual pass over 788 sites, because the callee's name never
# appears next to its extension. Six were in the Stop hook alone, which therefore
# ran four rules over nothing. They were found by executing the suites, one
# failure at a time — which is the expensive way, and the reason this exists.
#
# Names no repository and no directory: the practice is that a constructed
# sibling resolves (non-negotiable rule 1). The consumer's `line_sources` decides
# which files are read, and `input.tree.tracked` — the walk the run already did —
# is what "exists" means here.
package batten.shell_hygiene

import rego.v1

rules contains "sibling-resolves"

# A line that computes THIS SCRIPT'S OWN directory. Both markers are required:
# `dirname` alone catches `dirname "$file"`, which is somebody else's directory,
# and `$0` alone catches ordinary argument handling.
#
# It is a line predicate rather than one pattern because the spelling varies more
# than a single regex should try to hold — `$(dirname "$0")`,
# `$(dirname -- "${BASH_SOURCE[0]}")` and `$(cd "$(dirname "$0")" && pwd)` all
# appear in the tree this was built from, and the third puts the closing paren
# five characters away from where the first two put it.
script_dir_line(line) if {
	contains(line, "dirname")
	regex.match(`\$\{?BASH_SOURCE|\$0`, line)
}

# A name is a name: never `..`, which is the PARENT directory and therefore not a
# sibling at all. Two callers here resolve a repository root that way, and
# reading `/..` as a filename would report every one of them missing. The leading
# character class is what excludes it — a name may not begin with a dot.
#
# `/` IS IN THE TRAILING CLASS, and its absence was a false positive this rule
# committed on its first full run. A sibling may sit in a subdirectory —
# `"$(cd "$(dirname "$0")" && pwd)/render/cli.sh"` — and a capture that stopped
# at the separator resolved the DIRECTORY instead, which `input.tree.tracked`
# lists no entry for because it carries files. The rule then reported a
# reference that resolves perfectly well as missing.
name_capture := `([A-Za-z0-9_][A-Za-z0-9._/-]*)`

# The directory the judged file sits in, as a prefix ready to concatenate. A
# top-level file has none, which is the empty string rather than a missing key.
dir_prefix(path) := prefix if {
	parts := split(path, "/")
	count(parts) > 1
	prefix := concat("/", array.slice(parts, 0, count(parts) - 1))
}

dir_prefix(path) := "" if not contains(path, "/")

# ARM 1 — the sibling is written on the same line as the dirname expression, so
# the `)/` closing it is the anchor. Gated on `script_dir_line` for a measured
# reason: `"$(git rev-parse --git-dir)/batten-land-lock"` has the identical shape
# and names a directory git owns, which is untracked by construction.
inline_names(line) := {m[1] |
	script_dir_line(line)
	some m in regex.find_all_string_submatch_n(sprintf(`\)/%s`, [name_capture]), line, -1)
}

# ARM 2 — the parameter-expansion spellings, which have no paren to anchor on.
expansion_names(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(
		sprintf(`\$\{(?:BASH_SOURCE\[0\]|0)%%/\*\}/%s`, [name_capture]),
		line,
		-1,
	)
}

# ARM 3 — the two-step form: the directory is stashed in a variable on one line
# and the sibling built from it on another. `here=$(cd "$(dirname "$0")" && pwd)`
# then `"$here/landed-check.sh"`. No single-line pattern can see this, and it is
# the spelling two of this tree's real callers use.
#
# A variable whose assignment reaches for `/..` is excluded: it holds the PARENT
# of this script's directory, so a name hung off it is not a sibling and would
# resolve against the wrong prefix.
dir_vars(path) := {m[1] |
	some line in input.tree.lines[path]
	script_dir_line(line)
	not contains(line, "/..")
	some m in regex.find_all_string_submatch_n(`^[\t ]*([A-Za-z_][A-Za-z0-9_]*)=`, line, -1)
}

var_names(path, line) := {m[1] |
	some variable in dir_vars(path)
	some m in regex.find_all_string_submatch_n(
		sprintf(`\$\{?%s\}?/%s`, [variable, name_capture]),
		line,
		-1,
	)
}

# Every sibling this file constructs, by any arm, resolved against its own
# directory. The path being judged supplies the prefix — never the text, which is
# what keeps a nested caller from resolving against the repository root.
constructed(path) := {resolved |
	some line in input.tree.lines[path]
	some name in ((inline_names(line) | expansion_names(line)) | var_names(path, line))
	resolved := concat("/", [dir_prefix(path), name])
}

# What the tree actually carries. A set rather than the array, so membership is a
# lookup instead of a scan over every tracked path per reference.
tracked_set contains entry if some entry in input.tree.tracked

violation contains {
	"rule": "sibling-resolves",
	"msg": sprintf(
		"%s builds the sibling path %s at run time and the tree carries no such file; every caller of this shape guards it with a test and exits 0, so the reference does not fail, it goes silent",
		[path, resolved],
	),
} if {
	some path, _ in input.tree.lines
	some resolved in constructed(path)
	not resolved in tracked_set
}

# --- tests ---
#
# The allows carry this rule: a predicate that fired on every constructed sibling
# would satisfy the denies alone and would refuse the whole idiom, which is a
# good idiom.

# The measured defect, in the spelling it was measured in.
test_a_sibling_that_lost_its_extension_is_a_finding if {
	some v in violation with input as {"tree": {
		"lines": {"mise-tasks/stop-guard.sh": [`field="$(dirname -- "${BASH_SOURCE[0]}")/payload-field"`]},
		"tracked": ["mise-tasks/stop-guard.sh", "mise-tasks/payload-field.sh"],
	}}
	v.rule == "sibling-resolves"
}

# THE LOAD-BEARING ALLOW: the same line, once the reference is repaired. Without
# this the rule above would pass while refusing correct code.
test_a_sibling_that_resolves_is_clean if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/stop-guard.sh": [`field="$(dirname -- "${BASH_SOURCE[0]}")/payload-field.sh"`]},
		"tracked": ["mise-tasks/stop-guard.sh", "mise-tasks/payload-field.sh"],
	}}
}

# The other two spellings reduce to the same question, which is why the pattern
# matches the shape rather than one literal.
test_the_dollar_zero_spelling_counts_too if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"mise-tasks/ntia-check.sh": [`SBOM="$(dirname "$0")/sbom"`]},
		"tracked": ["mise-tasks/ntia-check.sh", "mise-tasks/sbom.sh"],
	}}
}

test_the_parameter_expansion_spelling_counts_too if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"mise-tasks/land.sh": [`census="${BASH_SOURCE[0]%/*}/reclaim-census"`]},
		"tracked": ["mise-tasks/land.sh", "mise-tasks/reclaim-census.sh"],
	}}
}

# A nested directory resolves against ITS OWN directory, never the repository
# root — the bug a rule that hardcoded a prefix would ship with.
test_the_sibling_resolves_against_its_own_directory if {
	count(violation) == 0 with input as {"tree": {
		"lines": {".claude/hooks/git-hook.sh": [`h="$(dirname -- "${BASH_SOURCE[0]}")/session-start.sh"`]},
		"tracked": [".claude/hooks/git-hook.sh", ".claude/hooks/session-start.sh"],
	}}
}

# ...and the same name at the repository root is NOT the same file, so a tree
# carrying only the root copy is still a finding.
test_a_same_named_file_elsewhere_does_not_satisfy_the_reference if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"mise-tasks/land.sh": [`c="$(dirname -- "${BASH_SOURCE[0]}")/helper.sh"`]},
		"tracked": ["mise-tasks/land.sh", "helper.sh"],
	}}
}

# A SIBLING IN A SUBDIRECTORY resolves, and the capture has to cross the
# separator to see it. Measured as a false positive on this rule's first full
# run over its own tree: the reference is correct and the rule called it missing,
# because it resolved the directory rather than the file inside it.
test_a_sibling_below_the_directory_resolves if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/reference-check.sh": [`RENDER="$(cd "$(dirname "$0")" && pwd)/render/cli.sh"`]},
		"tracked": ["mise-tasks/reference-check.sh", "mise-tasks/render/cli.sh"],
	}}
}

# ...and it is still judged, rather than merely skipped: the same reference with
# nothing behind it is a finding.
test_a_missing_sibling_below_the_directory_is_still_a_finding if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"mise-tasks/reference-check.sh": [`RENDER="$(cd "$(dirname "$0")" && pwd)/render/cli.sh"`]},
		"tracked": ["mise-tasks/reference-check.sh"],
	}}
}

# A line that constructs nothing is not this rule's business, and neither is a
# path built from something other than the script's own location — that names a
# file this rule cannot resolve and must not guess at.
test_a_line_with_no_constructed_sibling_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/land.sh": ["set -euo pipefail", `census="$REPO_ROOT/tools/reclaim-census"`]},
		"tracked": ["mise-tasks/land.sh"],
	}}
}

# A git-dir path is built from the same `)/` shape and must not be caught: it
# names a directory git owns, which is untracked by construction.
test_a_git_dir_path_is_not_a_sibling if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/land-lock.sh": [`state_dir="$(git rev-parse --git-dir)/batten-land-lock"`]},
		"tracked": ["mise-tasks/land-lock.sh"],
	}}
}

# ARM 3, the two-step form, in the spelling `in-progress-drain.sh` uses. The
# directory is computed on one line and spent on another, which is why the arm
# has to carry state across the file rather than decide a line at a time.
test_a_directory_stashed_in_a_variable_is_still_a_sibling if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"mise-tasks/in-progress-drain.sh": [
			`here="$(cd "$(dirname "$0")" && pwd)"`,
			`report=$("$here/landed-check" <<<"$issues")`,
		]},
		"tracked": ["mise-tasks/in-progress-drain.sh", "mise-tasks/landed-check.sh"],
	}}
}

test_the_two_step_form_is_clean_once_the_name_resolves if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/in-progress-drain.sh": [
			`here="$(cd "$(dirname "$0")" && pwd)"`,
			`report=$("$here/landed-check.sh" <<<"$issues")`,
		]},
		"tracked": ["mise-tasks/in-progress-drain.sh", "mise-tasks/landed-check.sh"],
	}}
}

# A variable holding the PARENT directory is not a sibling source. `payload-field`
# and `ready-lint` both resolve the repository root this way, and reading `$root/`
# as this file's own directory would report every path under it missing.
test_a_variable_holding_the_parent_directory_is_not_a_sibling_source if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/ready-lint.sh": [
			`root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)`,
			`cfg="$root/batten.toml"`,
		]},
		"tracked": ["mise-tasks/ready-lint.sh", "batten.toml"],
	}}
}

# ...and the `/..` inside that assignment is not itself read as a sibling named
# `..`, which is what the capture's leading character class prevents.
test_a_parent_traversal_is_not_a_name if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/payload-field.sh": [`root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"`]},
		"tracked": ["mise-tasks/payload-field.sh"],
	}}
}

# A variable that holds SOMEBODY ELSE'S directory does not make its uses
# siblings: `dirname "$file"` is not this script's location, and the marker
# conjunction is what tells them apart.
test_a_dirname_of_another_path_is_not_this_scripts_directory if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"mise-tasks/land.sh": [
			`d="$(dirname "$file")"`,
			`out="$d/generated-thing"`,
		]},
		"tracked": ["mise-tasks/land.sh"],
	}}
}

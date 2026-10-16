# hk's version is pinned identically in `mise.toml`'s `[tools]` table, in
# `hk.pkl`'s `amends` URL, and in the `pkl-package` task that fetches it,
# retired off the `hk-version` task body under CLOUD-1991.
#
# `mise.toml` pins the hk BINARY; `hk.pkl` amends the hk CONFIG PACKAGE by URL;
# `[tasks.pkl-package]` DOWNLOADS that package by the same URL (CLOUD-2311).
# All three move independently, and a bump to one without the others is the
# moment the hook config silently runs against a schema its binary did not ship
# — so all three must name one version, and the refusal is also the reminder to
# revisit `hk.pkl` for what the new version offers. The predecessor was two
# `grep -oE` pipelines and a string comparison in shell.
#
# ─── WHY A MODULE AND NOT A PRESET ───────────────────────────────────────────
#
# It names one task runner's pin table and one hook runner's config file. Pulled
# out into consumer facts, what remains is "two files agree about a string",
# which decides nothing — `mise-pin-agreement.rego`'s reason, one tool over.
#
# ─── WHAT IS STRICTER THAN THE SHELL, SAID RATHER THAN SLIPPED IN ───────────
#
# The predecessor compared the FIRST `hk@<version>` in `hk.pkl` (`head -n1`).
# This compares every one, so a second amends line naming another version is
# refused rather than shadowed. Both of the predecessor's `:?` arms survive: an
# `hk.pkl` that names no version while `mise.toml` pins one is refused, and so is
# the mirror. A `mise.toml` this could not read decides nothing, since the
# document binding below is undefined then.
#
#MUTANT hk-pin-disagreement-passes|s@^\tamended.version != pin$@\tfalse@|a_version_the_amends_url_names_differently_is_refused
#MUTANT hk-amends-unnamed-passes|s@^\tcount(amends) == 0$@\tfalse@|an_hk_pkl_naming_no_version_is_refused
#MUTANT hk-package-disagreement-passes|s@^\tpackaged.version != pin$@\tfalse@|a_package_task_naming_another_version_is_refused
#MUTANT hk-amends-tag-disagreement-passes|s@^\ttagged.version != pin$@\tfalse@|an_amends_tag_segment_naming_another_version_is_refused
#
#MUTANT-SUITE crates/batten/tests/it/tracked_absent.rs

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.hk_pin_agreement

import rego.v1

rules contains "tool pin other"

config := "hk.pkl"

# The pin table, bound only when the manifest parsed to an object, so every arm
# below is UNDEFINED rather than vacuously clean when it was not read.
tools := t if {
	t := input.tree.documents["mise.toml"].tools
	is_object(t)
}

pin := v if {
	v := tools.hk
	is_string(v)
}

lines := ls if {
	ls := input.tree.lines[config]
	is_array(ls)
}

# Every version an `amends` URL in `hk.pkl` names, with its line.
amends contains {"line": i + 1, "version": match[1]} if {
	some i, line in lines
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-amends-version"], line, -1)
}

# The TAG SEGMENT of the same URLs, as a SET OF ITS OWN — and the separation is
# the point, not tidiness. `hk.pkl`'s URL names the version twice as well
# (`…/download/v<X>/hk@<Y>#/Config.pkl`), so reading only the fragment lets
# `v1.57.0/hk@1.56.1` pass while naming two. That is not cosmetic: `pkl-package`
# would warm the cache entry for one version while `pkl eval hk.pkl` resolves the
# other, so the eval reaches the network on a warm machine and records a
# could-not-fetch as a verdict about the bytes — the failure this module's whole
# neighbourhood exists to prevent. `hk.pkl`'s is also the one spelling that can
# never be templated away, since pkl `amends` needs a literal URI.
#
# WHY NOT FOLD IT INTO `amends`: that was tried on this branch and it narrowed
# ARM B. Arm B's test is `count(amends) == 0` — "`hk.pkl` names no version at
# all" — and a tag member satisfies that count, so `v1.56.1/hk@latest` went from
# refused to clean. Merging the sets would quietly reduce arm B's claim to "names
# none in EITHER spelling", which is weaker than its name, its comment and its
# mutant all assert. A separate set keeps arm B's reach exactly as it was and
# makes the tag reading purely additive.
amend_tags contains {"line": i + 1, "version": match[1]} if {
	some i, line in lines
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-download-tag"], line, -1)
}

# A: the config package names a different hk than the binary pin.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": config, "line": amended.line}, {"path": "mise.toml"}],
} if {
	some amended in amends
	amended.version != pin
}

# A2: the amends URL's TAG segment names a different hk than the binary pin.
# Arm A's claim over the other half of the same string, and a separate arm rather
# than a widened A so that `amends` — and with it arm B's count — keeps meaning
# "versions the FRAGMENT names". Same subject shape as A, so when both halves
# drift on one line the two findings collapse to one.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": config, "line": tagged.line}, {"path": "mise.toml"}],
} if {
	some tagged in amend_tags
	tagged.version != pin
}

# B: the binary is pinned and `hk.pkl` names no version at all.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": config}, {"path": "mise.toml"}],
} if {
	pin
	lines
	count(amends) == 0
}

# C: `hk.pkl` names a version and the pin table carries no `hk` string.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": "mise.toml"}, {"path": config, "line": amended.line}],
} if {
	# `object.get`, never `tools.hk`: the dotted read is hoisted into a binding
	# that fails on an absent key before the `not` ever sees it, which made this
	# arm undecidable — measured, by this file's own case below.
	#
	# `tools` FIRST, positively: the claim is about a pin table that WAS read.
	# regorus lets the `not` below succeed over an undefined `tools`, so an unread
	# manifest read as "no `hk` pin" and fired this arm over nothing.
	tools
	not is_string(object.get(tools, "hk", null))
	some amended in amends
}

# --- the third spelling (CLOUD-2311) -----------------------------------------
#
# `mise.toml`'s `[tasks.pkl-package]` fetches the very package `hk.pkl` amends,
# so its URL names the hk version a third time. Why that task exists at all is
# argued where it is declared, in `mise.toml`.
#
# What matters HERE is that a third spelling is a third thing to forget on a
# bump — the defect arms A–C exist for, one file over. Here it is worse than the
# mismatch it hides: the fetch of a package the pinned binary did not ship
# against SUCCEEDS, so nothing downstream reports anything at all.

# The `pkl-package` task's `run`, bound only when the manifest carried the task,
# so arm D is UNDEFINED rather than vacuously clean without it — the same
# discipline `tools` and `lines` keep above. An absent task is the structural
# suite's to refuse (`verify_chain.rs` asserts the task and both `depends`), not
# this module's: the question here is agreement, never presence, and a module
# refusing on absence would refuse every consumer that declares no such task.
package_run := r if {
	r := input.tree.documents["mise.toml"].tasks["pkl-package"].run
}

# `run` is one argv as a string, or an array of them — mise accepts both, so both
# are read. Reading one spelling only would leave the arm escapable by rewriting
# the task's shape instead of fixing the version it names.
package_steps contains step if {
	is_string(package_run)
	step := package_run
}

package_steps contains step if {
	is_array(package_run)
	some step in package_run
	is_string(step)
}

# Every version the fetch names, by the pattern the amends lines are read with.
# EVERY one, not the first: a second step naming another version is refused
# rather than shadowed, which is arm A's reason restated for this surface.
packages contains {"version": match[1]} if {
	some step in package_steps
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-amends-version"], step, -1)
}

# AND THE TAG SEGMENT, BECAUSE ONE URL NAMES THE VERSION TWICE. The rule above
# reads the `hk@<X>` fragment; this reads the `…/download/v<X>/` path. So
# `v1.57.0/hk@1.56.1` satisfies the fragment alone while naming two versions,
# and the `v` segment is the half that looks like the release tag — the
# plausible half-bump. Reading one spelling would govern part of the string the
# arm claims to govern, which is worse than no arm: its existence implies the
# URL is covered. Both rules feed ONE set, so one comparison still decides.
packages contains {"version": match[1]} if {
	some step in package_steps
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-download-tag"], step, -1)
}

# D: the fetch URL names a different hk than the binary pin. One subject, and
# `mise.toml`: the task and the pin table are two rows of the same file, so there
# is no second path to point at.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": "mise.toml"}],
} if {
	some packaged in packages
	packaged.version != pin
}

# --- the load-time tier ------------------------------------------------------
#
# The predicate over a fabricated input; `crates/batten/tests/it/tracked_absent.rs`
# shows the engine fills `documents` and `lines` for the committed row.

pattern := {
	"hk-amends-version": `hk@([0-9]+\.[0-9]+\.[0-9]+)`,
	"hk-download-tag": `/v([0-9]+\.[0-9]+\.[0-9]+)/hk@`,
}

amends_line(version) := sprintf("amends \"package://github.com/jdx/hk/releases/download/v%s/hk@%s#/Config.pkl\"", [version, version])

tree(pinned, pkl) := {"tree": {
	"documents": {"mise.toml": {"tools": pinned}},
	"lines": {"hk.pkl": pkl},
}}

package_line(version) := sprintf("pkl download-package package://github.com/jdx/hk/releases/download/v%s/hk@%s", [version, version])

# A manifest that also carries tasks. A SECOND constructor rather than a third
# parameter on `tree`: six cases call `tree` and none of them is about tasks, so
# widening it would make every one of them state a fact it does not depend on.
# Arm D is undefined over `tree`'s shape, which is what those six assert.
tree_with_tasks(pinned, tasks, pkl) := {"tree": {
	"documents": {"mise.toml": {"tasks": tasks, "tools": pinned}},
	"lines": {"hk.pkl": pkl},
}}

test_agreeing_versions_are_clean if {
	count(violation) == 0 with input as tree({"hk": "1.56.1"}, ["// header", amends_line("1.56.1")])
		with data.batten.patterns as pattern
}

test_a_version_the_amends_url_names_differently_is_refused if {
	found := violation with input as tree({"hk": "1.57.0"}, ["// header", amends_line("1.56.1")])
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 2}
}

test_an_hk_pkl_naming_no_version_is_refused if {
	found := violation with input as tree({"hk": "1.56.1"}, ["amends \"package://example/Config.pkl\""])
		with data.batten.patterns as pattern
	count(found) == 1
}

test_a_pin_table_without_hk_is_refused if {
	found := violation with input as tree({"rust": "1.90"}, [amends_line("1.56.1")])
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "mise.toml"}
}

test_a_second_amends_line_is_read_rather_than_shadowed if {
	found := violation with input as tree({"hk": "1.56.1"}, [amends_line("1.56.1"), amends_line("1.40.0")])
		with data.batten.patterns as pattern
	count(found) == 1
}

test_an_unread_manifest_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {}, "lines": {"hk.pkl": [amends_line("1.56.1")]}}}
		with data.batten.patterns as pattern
}

test_a_package_task_naming_another_version_is_refused if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": package_line("1.57.0")}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "mise.toml"}
}

test_a_package_task_naming_the_pin_is_clean if {
	count(violation) == 0 with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": package_line("1.56.1")}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
}

# `run` as an array is the same claim, and the arm reads it: a task rewritten
# from a string to one-element argv must not stop being judged.
test_a_package_task_run_array_is_read_too if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": [package_line("1.57.0")]}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# The half-bump on `hk.pkl`'s own URL, which arm A2 catches: the tag segment
# drifts while the fragment still names the pin, so arm A sees nothing. One
# finding at line 1 — A2's subject matches A's shape, so a line where BOTH halves
# drift still collapses to one.
#
# `#MUTANT hk-amends-tag-disagreement-passes` reddens on the Rust twin of this.
test_an_amends_url_whose_tag_segment_drifts_is_refused if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		["amends \"package://github.com/jdx/hk/releases/download/v1.57.0/hk@1.56.1#/Config.pkl\""],
	)
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 1}
}

# ARM B KEEPS ITS REACH, and this is the case that says so. A `latest` fragment
# over an AGREEING tag names no version where arm B looks, so arm B still
# refuses it. Folding the tag matches into `amends` made this clean, which is the
# regression the separate `amend_tags` set exists to prevent — if the sets are
# ever merged again, this case is what reddens.
test_an_amends_fragment_naming_no_version_is_still_refused if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		["amends \"package://github.com/jdx/hk/releases/download/v1.56.1/hk@latest#/Config.pkl\""],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# The same half-bump on the fetch URL, which only arm D can see: the task's tag
# segment drifts while its fragment still names the pin.
test_a_package_task_whose_tag_segment_drifts_is_refused if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": "pkl download-package package://github.com/jdx/hk/releases/download/v1.57.0/hk@1.56.1"}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# A manifest with tasks but no `pkl-package` leaves arm D undefined. Presence is
# `verify_chain.rs`'s question; this module answers agreement only.
test_a_manifest_without_the_package_task_decides_nothing_here if {
	count(violation) == 0 with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"hooks": {"run": "hk check --all"}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
}

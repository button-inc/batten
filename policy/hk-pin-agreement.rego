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
# ARM A'S MUTANT NAMES THE FRAGMENT-ONLY CASE, and must. Every case built with
# `amends_line`/`amends()` writes one version into BOTH halves of the URL, so
# arm A2 emits a byte-identical finding and neutering arm A changes no count —
# measured, by applying this mutant: before the case below existed, `policy
# test` passed every case with the arm `false`. A2 masks A on every such input.
# (`policy test`, not `opa test` — regorus is the shipped evaluator and opa only
# type-checks here, which `opa-tracks-regorus-compliance` exists to keep apart.)
# Only a
# URL whose FRAGMENT alone drifts leaves A the one arm that can fire.
#MUTANT hk-pin-disagreement-passes|s@^\tamended.version != pin$@\tfalse@|an_amends_fragment_naming_another_version_is_refused
#MUTANT hk-amends-unnamed-passes|s@^\tcount(amends) == 0$@\tfalse@|an_hk_pkl_naming_no_version_is_refused
#MUTANT hk-package-disagreement-passes|s@^\tpackaged.version != pin$@\tfalse@|a_package_task_naming_another_version_is_refused
#MUTANT hk-package-unnamed-passes|s@^\tcount(packages) == 0$@\tfalse@|a_package_task_naming_no_version_is_refused
#
# THE DEFECT THIS BRANCH MADE TWICE, DECLARED SO A MACHINE CATCHES THE THIRD.
# Folding a half-reading set into its sibling narrows the count arm above it:
# the count stops meaning "the fragment names nothing" and starts meaning
# "neither spelling does", and a URL whose fragment floats over an agreeing tag
# goes clean. It happened on the amends surface, was fixed, then happened
# identically on the packages surface. Both were caught by reading, not by the
# suite. These two mutate each count to the merged form; their cases are the
# floating-fragment pair, which is exactly what the merge lets through.
# The merged form is spelled `union({a, b})` and NOT `a | b`, because a `|` in a
# replacement is this directive's own field separator — the pipe spelling parsed
# as a fourth field and the row was reported `malformed-row (4 fields, want 3)`.
#MUTANT hk-amends-merge-narrows-arm-b|s@^\tcount(amends) == 0$@\tcount(union({amends, amend_tags})) == 0@|an_amends_fragment_floating_over_an_agreeing_tag_is_refused
#MUTANT hk-package-merge-narrows-arm-e|s@^\tcount(packages) == 0$@\tcount(union({packages, package_tags})) == 0@|a_package_fragment_floating_over_an_agreeing_tag_is_refused
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
# WHY NOT FOLD IT INTO `amends`: because arm B counts that set. Arm B's test is
# `count(amends) == 0`, and what it means is "the FRAGMENT spelling names
# nothing" — so it refuses a floating `hk@latest` even when the tag segment
# agrees. A tag member DEFEATS that count, which would reduce arm B's claim to
# "neither spelling names anything": strictly weaker, and weaker than its mutant
# and its case both assert. Keeping the sets apart leaves arm B's reach exactly
# as it was and makes the tag reading purely additive.
#
# The fetch URL below is read the same way and for the same reason: `packages`
# and `package_tags` are separate because arm E counts the fragment one, exactly
# as arm B counts `amends`. What is shared is the NEGATIVE: neither surface
# merges the halves into a counted set, so neither count is widened.
#
# HOW THEY COMPARE DIFFERS, and the asymmetry is deliberate. `hk.pkl`'s two
# halves are read by two arms (A and A2); the fetch URL's by one arm over their
# union. Two arms here because the tag reading's mutant can then anchor on a
# short comparison rather than on a ~97-character
# `regex.find_all_string_submatch_n` line; one arm there because arm D's
# subjects carry no line, so two arms would emit the same object anyway.
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

# B: the binary is pinned and `hk.pkl`'s `amends` FRAGMENT names no version — so
# a floating `hk@latest` is refused here even when its tag segment agrees.
#
# THE MIRROR IS NOT GOVERNED, and that is a decision rather than an oversight.
# Nothing counts `amend_tags`, so a floating or templated TAG over an agreeing
# fragment (`…/download/latest/hk@1.56.1`) is refused by no arm, here or on the
# fetch URL. A `count(amend_tags) == 0` arm would close it and would also refuse
# every URL that has no `/v<semver>/` segment at all — a package on a non-GitHub
# mirror, say — because this module cannot tell a missing tag from a floating
# one. The fragment is the spelling every `package://` URI must carry; the tag
# is a property of one host's release layout. So the mandatory half is required
# to name a version and the optional half is only required to agree when it
# names one. A consumer that wants the GitHub shape itself required owns that
# separately.
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
# TYPE-GUARDED like `tools`, `pin` and `lines`, and for their reason: a bare
# binding let a `run` of any shape reach arm E, where the result depended on
# truthiness rather than on anything this module decides — `false` fell through
# silently while a number or a table fired the arm. Neither is this module's
# question; a `run` mise cannot execute fails the manifest parse long before a
# gate sees it. mise accepts a string or an array of them, so those are the two
# shapes read, and every other leaves D and E undefined together, exactly as an
# absent task does.
package_run := r if {
	r := input.tree.documents["mise.toml"].tasks["pkl-package"].run
	is_string(r)
}

package_run := r if {
	r := input.tree.documents["mise.toml"].tasks["pkl-package"].run
	is_array(r)
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

# AND THE TAG SEGMENT, BECAUSE ONE URL NAMES THE VERSION TWICE — in its OWN set,
# for the reason `amend_tags` is separate from `amends` one surface up. The rule
# above reads the `hk@<X>` fragment; this reads the `…/download/v<X>/` path, so
# `v1.57.0/hk@1.56.1` satisfies the fragment alone while naming two versions, and
# the `v` segment is the half that looks like the release tag — the plausible
# half-bump.
#
# THEY ARE NOT ONE SET, because arm E counts the fragment one. Merging them makes
# arm E's claim "neither spelling names a version" instead of "the fragment names
# none", and `…/download/v1.56.1/hk@latest` then passes both arms: the fragment
# is empty so D has nothing to compare, and the tag equals the pin so the count
# is non-zero. The fetch floats to `latest` while `hk.pkl` amends a fixed
# version — the warm-cache-that-isn't, clean. That was measured on the merged
# shape this replaces.
package_tags contains {"version": match[1]} if {
	some step in package_steps
	some match in regex.find_all_string_submatch_n(data.batten.patterns["hk-download-tag"], step, -1)
}

# D: the fetch URL names a different hk than the binary pin, in EITHER spelling.
# One subject, and `mise.toml`: the task and the pin table are two rows of the
# same file, so there is no second path to point at. The union is read here
# rather than merged into a set, so that arm E below keeps counting the fragment
# alone — which is the whole of the paragraph above.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": "mise.toml"}],
} if {
	some packaged in packages | package_tags
	packaged.version != pin
}

# E: the task is DECLARED and its FRAGMENT names no version — arm B's claim for
# this surface, spelled the same way over the same half, and what the gloss on
# `tool pin other` promises ("or one of them names none"). Arm D alone would be
# vacuously clean on `hk@latest`, or on a version templated through a `[vars]`
# entry the way the CA selection is: the fetch then warms a package `hk.pkl`
# does not amend.
#
# `package_run` FIRST, positively: absence of the task is the structural suite's
# to refuse, never this module's, so the arm stays undefined without it and
# fires only over a task that was read.
violation contains {
	"rule": "tool pin other",
	"verdict": "tool pin other",
	"subjects": [{"path": "mise.toml"}],
} if {
	pin
	package_run
	count(packages) == 0
}

# --- the load-time tier ------------------------------------------------------
#
# The predicate over a fabricated input; `crates/batten/tests/it/tracked_absent.rs`
# shows the engine fills `documents` and `lines` for the committed row.

pattern := {
	"hk-amends-version": `hk@([0-9]+\.[0-9]+\.[0-9]+)`,
	"hk-download-tag": `/v([0-9]+\.[0-9]+\.[0-9]+)/hk@`,
}

# The two halves of an `amends` URL, separately — which half drifts is then the
# only thing a case states, instead of a reader spotting it in a 90-character
# literal. `amends_line` is the agreeing case of it.
amends_halves(tag, fragment) := sprintf("amends \"package://github.com/jdx/hk/releases/download/v%s/hk@%s#/Config.pkl\"", [tag, fragment])

amends_line(version) := amends_halves(version, version)

tree(pinned, pkl) := {"tree": {
	"documents": {"mise.toml": {"tools": pinned}},
	"lines": {"hk.pkl": pkl},
}}

package_halves(tag, fragment) := sprintf("pkl download-package package://github.com/jdx/hk/releases/download/v%s/hk@%s", [tag, fragment])

package_line(version) := package_halves(version, version)

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

# BOTH ARMS FIRE HERE. `amends_line` writes the version into both halves, so at
# pin 1.57.0 the fragment and the tag each disagree: arms A and A2 fire on line 2
# with byte-identical subjects, and `count == 1` is what pins that they collapse.
# If A2's object ever stopped matching A's, this reads 2 and the case reddens.
#
# It collapses two IDENTICAL members, though, because `amends_line` spells one
# version twice — so it cannot tell that apart from a collapse of two DISTINCT
# members. The case below it is the one that can.
test_a_version_the_amends_url_names_differently_is_refused if {
	found := violation with input as tree({"hk": "1.57.0"}, ["// header", amends_line("1.56.1")])
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 2}
}

# TWO DISTINCT BOUND VERSIONS, ONE FINDING — the case that measures the
# invariant the arms rest on. The halves name two different versions and neither
# is the pin, so arm A fires on the `amends` member (1.58.0) and arm A2 on the
# `amend_tags` member (1.57.0). The two bound versions genuinely differ, and the
# findings still collapse, because both arms emit the same `subjects[0]` —
# `{path, line}`, carrying nothing that says which spelling fired.
#
# WHAT ONLY THIS CASE CATCHES, said precisely because the loose version of this
# sentence has been wrong twice: a distinguishing field placed OUTSIDE
# `subjects[0]` — on the violation object, or on the `mise.toml` subject — makes
# this 2 while the case above stays green at 1. A field INSIDE `subjects[0]`
# breaks that case's own subject assertion, and one naming the spelling rather
# than the version splits it too, so neither needs this case to be caught.
test_two_drifting_halves_on_one_line_are_one_finding if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		[amends_halves("1.57.0", "1.58.0")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 1}
}

# FRAGMENT-ONLY DRIFT — the one input where arm A is the only arm that can
# fire, which is why `#MUTANT hk-pin-disagreement-passes` names its Rust twin.
# The tag segment equals the pin so A2 is silent; `amends` is non-empty so arm B
# is silent. Neuter arm A and this goes clean.
test_an_amends_fragment_naming_another_version_is_refused if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		[amends_halves("1.56.1", "1.57.0")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 1}
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

# The half-bump on `hk.pkl`'s own URL, which only arm A2 catches: the tag segment
# drifts while the fragment still names the pin, so arm A is silent. One finding
# because exactly one arm fires.
#
# `#MUTANT hk-amends-tag-disagreement-passes` reddens on the Rust twin of this.
test_an_amends_url_whose_tag_segment_drifts_is_refused if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		[amends_halves("1.57.0", "1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
	some finding in found
	finding.subjects[0] == {"path": "hk.pkl", "line": 1}
}

# ARM B KEEPS ITS REACH, and this is the case that says so: a `latest` fragment
# over an AGREEING tag names nothing where arm B looks, so arm B still refuses
# it. If the two sets are ever merged, this is what reddens — see `amend_tags`.
test_an_amends_fragment_naming_no_version_is_still_refused if {
	found := violation with input as tree(
		{"hk": "1.56.1"},
		[amends_halves("1.56.1", "latest")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# The same half-bump on the fetch URL, which only arm D can see: the task's tag
# segment drifts while its fragment still names the pin.
test_a_package_task_whose_tag_segment_drifts_is_refused if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": package_halves("1.57.0", "1.56.1")}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# ARM E: the task is declared and its URL names no version. `hk@latest` with no
# `/v<semver>/` segment matches neither pattern, so `packages` is empty — arm D
# has nothing to compare and would be vacuously clean without this arm.
test_a_package_task_naming_no_version_is_refused if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": "pkl download-package package://github.com/jdx/hk/releases/download/latest/hk@latest"}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# THE INPUT THE MERGED SET LET THROUGH: an AGREEING tag over a floating
# fragment. Arm D is silent (the tag equals the pin) and arm E fires only
# because it counts the fragment set alone — merge the two and `packages` is
# non-zero, both arms go quiet, and the fetch floats to `latest` while `hk.pkl`
# amends a fixed version. `#MUTANT hk-package-merge-narrows-arm-e` is this
# defect declared, and its Rust twin is what reddens.
test_a_package_task_whose_fragment_floats_is_refused if {
	found := violation with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"pkl-package": {"run": package_halves("1.56.1", "latest")}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
	count(found) == 1
}

# A manifest with tasks but no `pkl-package` leaves arms D and E undefined.
# Presence is `verify_chain.rs`'s question; this module answers agreement only.
test_a_manifest_without_the_package_task_decides_nothing_here if {
	count(violation) == 0 with input as tree_with_tasks(
		{"hk": "1.56.1"},
		{"hooks": {"run": "hk check --all"}},
		[amends_line("1.56.1")],
	)
		with data.batten.patterns as pattern
}

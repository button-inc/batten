#MUTANT-SUITE crates/batten/tests/it/mise_preset.rs
#MUTANT version-may-differ|s@declared != pinned@false@|a_step_declaring_another_version_is_refused
#MUTANT version-may-be-absent|s@not declares_a_version(step)@false@|a_step_declaring_no_version_is_refused

# The toolchain a workflow INSTALLS must be the one the tree PINS (CLOUD-1672).
#
# THE DEFECT CLASS IS TWO AUTHORITIES, not a missing pin, and the difference is
# what makes this a gate rather than a lint. A consumer pins its toolchain in a
# `[[provision]]` row — a version plus per-platform urls and digests, which is
# the whole point of pinning. The GitHub Action that installs that toolchain in
# CI resolves its OWN version, independently, at the moment each job starts.
# Nothing compares the two. So the repository can declare one toolchain and run
# another, for as long as nobody looks.
#
# MEASURED, AND THIS MODULE EXISTS BECAUSE OF IT. On 2026-09-08 the action
# resolved a release whose linux-x64 asset 404ed. Every job of every workflow in
# the consumer that found this died in the install step inside 11 seconds, a
# release published carrying its schema and none of its seven binaries, and the
# landing loop stalled across the whole fleet. The pin that would have prevented
# it was committed and correct the entire time; it simply did not reach the layer
# where the install happened. The provision row's own comment had even named the
# harm — a runner that updates itself under a container makes two sessions on one
# commit run different toolchains — one layer below where it then occurred.
#
# THE COMPARISON IS AGAINST THE COMMITTED ROW, NEVER A LITERAL. A module carrying
# the version itself would be a THIRD authority, and would go stale the first
# time the pin moved — reporting drift against a number nobody had updated, which
# is worse than the silence it replaces. The version never appears here.
#
# NO DOCUMENT PINS THE TOOL ⇒ THIS ROW ABSTAINS. A consumer that pins nothing has
# nothing to disagree with, and refusing there would be a verdict about their
# configuration rather than about drift between two of their own statements.
# That is also what keeps the rule honest about its own subject: it compares, and
# where there is nothing to compare it says nothing.
#
# STRUCTURAL DISCOVERY, NOT A FILENAME. A preset ships to every consumer, so
# non-negotiable rule 1 forbids naming their paths. The pin is found by selecting
# whichever parsed document carries a `provision` array; the workflows by
# selecting whichever carry a `jobs` object. Neither is named. The action
# coordinate IS written inline, and that is not a consumer fact: it is a public
# action, the same literal for everyone this preset reaches.

# METADATA
# description: |
#   Bound to the TREE surface: reads `input.tree.documents` and
#   `input.tree.lines`, never the mediated `{call, facts}` shape. The other
#   module in this preset is the mediated half; they are one preset because
#   they are one subject, and the manifest declares a scope per module.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
package batten.mise_action_version

import rego.v1

rules contains "action-version-matches-the-pin"

# --- the two documents, found by shape ----------------------------------------

# A workflow is a document declaring jobs. `ci-hygiene` selects the same way and
# for the same reason: the consumer's directory layout is theirs, not ours.
workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

# The pin table is a document carrying `provision` rows. There may be more than
# one such document in principle; every one is read, and a row is matched by the
# TOOL NAME rather than by which file it came from.
pinned[name] := version if {
	some _, doc in input.tree.documents
	some row in doc.provision
	name := row.name
	version := row.version
}

# The guard, for the reason `hk-fix-selection` measured on another module: an
# unguarded module reported findings against a fixture carrying none of its
# subjects. A tree with no workflow declaring jobs is answering for nothing here.
governed if count(object.keys(workflow)) > 0

# --- the action, and the tool it installs -------------------------------------

# THE COORDINATE IS INLINE AND THE PRESET EXEMPTION IS NOT SPENT ON IT. A
# `[[pattern]]` row is consumer config that a preset cannot read — it resolves to
# undefined and the rule decides nothing while loading clean, which is the dead
# gate `rules/policy-modules.md` records. But this is not a regex either: it is a
# substring test over a `uses:` value, so there is no pattern to declare and
# `patterns: &[]` on the manifest stays honest.
action := "jdx/mise-action"

# The tool the action installs, which is the `[[provision]]` row name to compare
# against. Derived from the action's own repository rather than written twice, so
# the two cannot drift apart inside this file.
tool := trim_suffix(split(action, "/")[1], "-action")

action_step(step) if contains(object.get(step, "uses", ""), action)

declares_a_version(step) if object.get(step, ["with", "version"], "") != ""

# --- the steps being judged ---------------------------------------------------

job_step contains [path, name, step] if {
	some path, _ in workflow
	some name, job in workflow[path].jobs
	some step in job.steps
}

# --- pointers -----------------------------------------------------------------
#
# Rule 4's shape: a finding resolves a `{path, line}` and nothing else. Neither
# the declared version nor the pinned one reaches a finding — a CI log is public,
# and a version is the consumer's business even when it is wrong.
#
# NOT A FUNCTION, for the reason the same construction carries elsewhere: a
# `pointer(path, line_of(path))` spelling makes the whole refusal undefined
# whenever the line index cannot place its subject, because Rego propagates
# undefined through arguments — so a `line_sources` glob that drifted would
# switch the gate off silently. As a set, an unplaceable pointer costs the LINE
# and never the finding.
job_line contains [path, name, number] if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	some index, line in input.tree.lines[path]
	trim_space(line) == concat("", [name, ":"])
	number := index + 1
}

job_placed(path, name) if {
	some placement in job_line
	placement[0] == path
	placement[1] == name
}

# --- 1. a declared version that disagrees with the pin ------------------------

disagrees(path, name) if {
	some entry in job_step
	entry[0] == path
	entry[1] == name
	step := entry[2]
	action_step(step)
	declares_a_version(step)
	pinned_version := pinned[tool]
	declared := object.get(step, ["with", "version"], "")
	declared != pinned_version
}

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "job pin other",
	"subjects": [{"path": path, "line": number}],
} if {
	governed
	some placement in job_line
	path := placement[0]
	name := placement[1]
	number := placement[2]
	disagrees(path, name)
}

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "job pin other",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	disagrees(path, name)
	not job_placed(path, name)
}

# --- 2. no declared version at all --------------------------------------------
#
# The direction that produced the incident. An absent `version:` is not a
# smaller version of a wrong one: it hands the choice to the action, which makes
# the answer a property of WHEN the job ran rather than of what the tree says.
# Conditioned on the tool being pinned, so a consumer who pins nothing is not
# told to match something that does not exist.

unpinned_reader(path, name) if {
	some entry in job_step
	entry[0] == path
	entry[1] == name
	step := entry[2]
	action_step(step)
	not declares_a_version(step)
	_ := pinned[tool]
}

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "job pin missing",
	"subjects": [{"path": path, "line": number}],
} if {
	governed
	some placement in job_line
	path := placement[0]
	name := placement[1]
	number := placement[2]
	unpinned_reader(path, name)
}

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "job pin missing",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	unpinned_reader(path, name)
	not job_placed(path, name)
}

# --- could not look -----------------------------------------------------------
#
# A declared source that would not parse is not an absent one. Absent is
# not-applicable — this tree runs no such workflow — and unparsed means the
# boundary tried and failed. Spelling those the same way is how a gate reports
# green over a file it never read.

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "workflow parse unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	endswith(path, ".yml")
}

violation contains {
	"rule": "action-version-matches-the-pin",
	"verdict": "workflow parse unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	endswith(path, ".yaml")
}

# --- cases --------------------------------------------------------------------
#
# The load-time tier. It pins the predicates; it cannot prove the ENGINE builds
# the documents these rules read, which is `crates/batten/tests/it/mise_preset.rs`'s
# whole reason to exist.

test_a_matching_version_is_clean if {
	count(violation) == 0 with input as tree(pin("2026.9.1"), reader_with("2026.9.1"))
}

test_a_step_declaring_another_version_is_refused if {
	some finding in violation with input as tree(pin("2026.9.1"), reader_with("2026.9.3"))
	finding.verdict == "job pin other"
}

test_a_step_declaring_no_version_is_refused if {
	some finding in violation with input as tree(pin("2026.9.1"), reader_bare)
	finding.verdict == "job pin missing"
}

# ANTI-VACUITY, AND IT IS WHAT SEPARATES THIS ROW FROM A BLANKET DEMAND: with no
# `provision` row for the tool there is nothing to compare against, so the same
# unpinned reader that is refused above is clean here. Without this case the
# second clause would pass for the wrong reason, and a consumer who pins no
# toolchain would be refused for a disagreement they are not having.
test_an_unpinned_tool_is_not_this_rules_business if {
	count(violation) == 0 with input as tree(no_pin, reader_bare)
}

# A step that is not this action is not this rule's business either, which is the
# other way a predicate over `uses:` goes wrong — matching a lookalike.
test_another_action_is_not_judged if {
	count(violation) == 0 with input as tree(pin("2026.9.1"), other_action)
}

test_an_unparsed_workflow_is_could_not_look if {
	some finding in violation with input as {"tree": {
		"documents": {".github/workflows/w.yml": {"jobs": {}}},
		"lines": {},
		"missing": {".github/workflows/broken.yml": "Unparsed"},
	}}
	finding.verdict == "workflow parse unread"
}

# --- fixtures -----------------------------------------------------------------

pin(version) := {"provision": [{"name": "mise", "version": version}]}

no_pin := {"provision": [{"name": "something-else", "version": "1.0.0"}]}

reader_with(version) := {"jobs": {"reader": {"steps": [{
	"uses": "jdx/mise-action@3c2e0cf8",
	"with": {"version": version},
}]}}}

reader_bare := {"jobs": {"reader": {"steps": [{"uses": "jdx/mise-action@3c2e0cf8"}]}}}

other_action := {"jobs": {"reader": {"steps": [{"uses": "actions/checkout@3d3c42e5"}]}}}

tree(pins, reader) := {"tree": {
	"documents": {
		"pins.toml": pins,
		".github/workflows/pr.yml": reader,
	},
	"lines": {".github/workflows/pr.yml": ["jobs:", "  reader:"]},
	"missing": {},
}}

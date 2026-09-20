# The memory graph's edges, retired out of `mise-tasks/memories-check.sh`
# (CLOUD-183 for the predicate, CLOUD-1163 for the retirement).
#
# The checked-in memories are a knowledge graph navigated by `mem:` references,
# and nothing gated its edges: the reference tooling's own integrity check is
# advisory by construction (read-only, always exits 0), and its rename command is
# the only thing that keeps referrers in sync — so a `git mv` of a memory, or any
# direct write, silently orphans every reference to it. A graph whose edges can
# dangle silently is prose pretending to be structure (non-negotiable rule 2).
#
# A PURE FUNCTION OF THE TRACKED TREE, which is why this is the campaign's
# cleanest port: the predecessor's own header already claimed that property, and
# it holds — `input.tree.tracked` answers "which memories exist" and
# `input.tree.lines` answers "who references one", with no tool dependency, so
# the gate still catches the damage no matter what performed the rename.
#
# THREE PROPERTIES LIVE HERE AND THEY ARE NOT ONE (CLOUD-1866, repairing a
# header that merged them). The paragraph this replaces was titled "WHAT IS
# DELIBERATELY NOT CHECKED IS MEMBERSHIP (CLOUD-683)" and closed "an unreferenced
# memory is not a defect and this module does not say it is". Read cold, that
# attributes to CLOUD-683 a refusal of graph reachability. CLOUD-683 REQUIRES
# reachability — its Mechanism §2 specifies a BFS from `core`, root and template
# exempt, and its acceptance is that "a memory referenced only through a chain
# from `core` passes the gate" while "a genuinely orphaned memory is still
# reported". The header asserted the opposite of the row it cited, and it misled
# a planning session into recording the question as closed.
#
# 1. TABLE-ROW MEMBERSHIP IN `AGENTS.md` — retired, and the reason is the whole
#    of CLOUD-683's title: `memories-check` forced every memory into an
#    always-loaded index whose line budget was full, so the repository could no
#    longer add a memory at all. An always-present index spends the context
#    window on every session to answer a question a graph answers on demand.
#    That is what was retired, and it is what the sentence above was about.
#
# 2. ONE-HOP REFERENCEDNESS — not this module's business, and that is the only
#    claim the retired closing sentence correctly supported. Whether some other
#    file happens to mention a memory is not a property this predicate decides.
#
# 3. REACHABILITY FROM THE ROOT — required, and ENFORCED, having moved to the
#    serena-held graph rather than being abandoned. It is not checked HERE; it is
#    not unchecked.
#
# SERENA IS SLATED FOR REMOVAL, so (3) needs a home. Python-interpreter fragility
# is not something to keep tolerating merely to surface memory, and the blocker is
# the tree-sitter cluster, since serena also supplies AST-driven text
# manipulation. When it goes, `crates/batten/src/graph.rs` is where this property
# lands: a bounded walk from `core` over `mem:` edges, terminating on the root,
# which is exactly CLOUD-683's BFS with a visit counter on it.
#
# THE REFERENCE SYNTAX IS A `[[pattern]]` ROW AND NOT A LITERAL HERE. The
# predecessor restated the tooling's matcher in its own body and said so in a
# comment — "restated HERE AND ONLY HERE" — which was the best a shell program
# could do. A module cannot even spell it: an inline regex is refused at load, so
# `mem-reference` and `memory-name` are registry rows and the one-spelling
# property is structural rather than a comment asking the next author to be
# careful.
#
# POINTER-ONLY (non-negotiable rule 4). A memory path, or a referrer's
# `path:line` — never the reference's surrounding prose, and never a line of a
# memory. The predecessor emitted the same shape for the same reason.
#
#MUTANT-EXEMPT CLOUD-1267|no `tests/memories.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `shell add refused` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/memories.rs`, neither of which is what the mutation runner drives

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.memories

import rego.v1

rules contains "memory point missing"

# --- the graph, as the tree holds it ------------------------------------------

memories_dir := ".serena/memories/"

root_memory := concat("", [memories_dir, "core.md"])

# The shipped convention template, exempt as a REFERRER below. It is supplied by
# the tooling and its examples reference memories that deliberately do not exist
# here; the tooling's own scanner excludes it for the same reason.
template := concat("", [memories_dir, "memory_maintenance.md"])

# A set rather than the array, so the membership tests below are one lookup and
# read as set logic rather than as a scan.
tracked_set := {path | some path in input.tree.tracked}

memory_files contains path if {
	some path in tracked_set
	startswith(path, memories_dir)
	endswith(path, ".md")
}

# The name a memory is ADDRESSED by: its path under the directory, without the
# extension. The tooling silently strips a trailing `.md`, which is what makes
# arm B below a real class rather than a typo.
name_of(path) := trim_suffix(trim_prefix(path, memories_dir), ".md")

# --- A: the graph root --------------------------------------------------------
#
# The reference model makes `mem:core` the discovery entry point; a graph with no
# root is only findable by directory listing.
#
# GUARDED ON THE GRAPH EXISTING AT ALL, which is the bound
# `suite-subject-retirable`'s arm C had to learn the hard way: a tree that is not
# this corpus has no memories, and a shipped ruleset that refuses an ordinary
# minimal repository is unshippable. A repository with no memory directory is not
# a repository with a broken memory graph.
violation contains {
	"rule": "memory point missing",
	"verdict": "memory resolve missing",
	"subjects": [{"path": root_memory}],
} if {
	count(memory_files) > 0
	not root_memory in tracked_set
}

# --- B: a name that cannot be addressed as written ----------------------------
#
# `foo.md.md` lists as `foo.md` and can never be addressed by its own filename,
# because the tooling strips one extension and the reference matcher stops at the
# first foreign character.
violation contains {
	"rule": "memory point missing",
	"verdict": "memory name duplicate",
	"subjects": [{"path": path}],
} if {
	some path in memory_files
	endswith(name_of(path), ".md")
}

violation contains {
	"rule": "memory point missing",
	"verdict": "memory name unseen",
	"subjects": [{"path": path}],
} if {
	some path in memory_files
	not regex.match(data.batten.patterns["memory-name"], name_of(path))
}

# --- C: a reference that resolves to nothing ----------------------------------
#
# The whole tracked tree is scanned rather than the memories alone: AGENTS.md and
# the rule files reference memories too, and an edge dangling from there is the
# same broken edge.
#
# CHANGELOG.md is excluded with the template because `release-plz` owns it — a
# stale reference there could only be fixed by hand-editing a generated file —
# and `tests/bats/` is a submodule, whose markdown is upstream's rather than
# this repository's.
referrer(path) if {
	endswith(path, ".md")
	not startswith(path, "tests/bats/")
	path != "CHANGELOG.md"
	path != template
}

violation contains {
	"rule": "memory point missing",
	"verdict": "memory point stale",
	"subjects": [{"path": path, "line": number}],
} if {
	some path, lines in input.tree.lines
	referrer(path)
	some index, line in lines
	some reference in regex.find_n(data.batten.patterns["mem-reference"], line, -1)
	name := substring(reference, count("mem:"), -1)
	not concat("", [memories_dir, name, ".md"]) in tracked_set
	number := index + 1
}

# --- could not look -----------------------------------------------------------
#
# A DECLARED SOURCE THAT WOULD NOT READ is not a file with no stale references. A
# module iterating only `lines` reports green over a file it never opened, which
# is the class `rules/policy-modules.md` records for this channel — and
# here it is the exact failure the predecessor could not have: a shell `grep` over
# an unreadable file is loud, and an absent map key is silent.
violation contains {
	"rule": "memory point missing",
	"verdict": "memory read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	referrer(path)
}

# --- the load-time tier -------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE selects the markdown
# this rule declares, nor that it populates `missing` for a file it could not
# read — `crates/batten/tests/memories.rs` is that tier, over the compiled binary
# and real scratch trees, and it is why that file exists.

graph(tracked, lines) := {"tree": {"tracked": tracked, "lines": lines, "missing": {}}}

# A coherent graph. THE ANTI-VACUITY MIRROR for every arm below: without it a
# module refusing everything would satisfy each case that follows.
test_a_coherent_graph_is_clean if {
	found := violation with input as graph(
		[".serena/memories/core.md", ".serena/memories/workflow/board-states.md", "AGENTS.md"],
		{"AGENTS.md": ["read mem:core and mem:workflow/board-states first"]},
	)
	count(found) == 0
}

test_a_missing_root_is_reported if {
	found := violation with input as graph([".serena/memories/other.md"], {})
	some finding in found
	finding.verdict == "memory resolve missing"
}

# THE BOUND ARM A NEEDS. A repository with no memories at all is not a repository
# with a broken graph, and refusing there would make this rule unshippable.
test_a_tree_with_no_memories_is_not_judged if {
	count(violation) == 0 with input as graph(["README.md"], {})
}

test_a_shadowed_name_is_reported if {
	found := violation with input as graph(
		[".serena/memories/core.md", ".serena/memories/notes.md.md"],
		{},
	)
	some finding in found
	finding.verdict == "memory name duplicate"
}

test_an_unreferencable_name_is_reported if {
	found := violation with input as graph(
		[".serena/memories/core.md", ".serena/memories/a name.md"],
		{},
	)
	some finding in found
	finding.verdict == "memory name unseen"
}

# The predicate that produced the row: a reference with no memory behind it,
# carrying the referrer's own `path:line`.
test_a_dangling_reference_is_reported_with_a_pointer if {
	found := violation with input as graph(
		[".serena/memories/core.md", "AGENTS.md"],
		{"AGENTS.md": ["intro", "see mem:gone-away for detail"]},
	)
	some finding in found
	finding.verdict == "memory point stale"
	finding.subjects[0].path == "AGENTS.md"
	finding.subjects[0].line == 2
}

# The three excluded referrers, each for its own reason. Without this a rename
# would be reported against a generated file and against a submodule.
test_the_excluded_referrers_are_not_scanned if {
	found := violation with input as graph(
		[".serena/memories/core.md"],
		{
			"CHANGELOG.md": ["mem:gone-away"],
			".serena/memories/memory_maintenance.md": ["mem:gone-away"],
			"tests/bats/README.md": ["mem:gone-away"],
		},
	)
	count(found) == 0
}

# A NON-MARKDOWN file carrying the token is not a referrer. The predecessor
# scanned `git ls-files '*.md'`, so this bound is conserved rather than new.
test_a_non_markdown_file_is_not_scanned if {
	found := violation with input as graph(
		[".serena/memories/core.md"],
		{"crates/batten/src/lib.rs": ["// mem:gone-away"]},
	)
	count(found) == 0
}

# COULD NOT LOOK stays loud, and is spelled differently from both answers.
test_an_unreadable_referrer_is_loud if {
	found := violation with input as {"tree": {
		"tracked": [".serena/memories/core.md"],
		"lines": {},
		"missing": {"AGENTS.md": "absent"},
	}}
	some finding in found
	finding.verdict == "memory read unread"
}

test_an_unreadable_non_referrer_is_not_this_rules_business if {
	found := {f |
		some f in violation with input as {"tree": {
			"tracked": [".serena/memories/core.md"],
			"lines": {},
			"missing": {"mise.toml": "absent"},
		}}
		f.verdict == "memory read unread"
	}
	count(found) == 0
}

# Nothing in the built macOS graph needs a real macOS SDK to link (ported off
# `mise-tasks/macos-link-check.sh` under CLOUD-1717).
#
# WHY IT MATTERS. The macOS release artifacts are linked on Linux by zig, with no
# Apple SDK present. That works only while nothing in the tree links a macOS
# *system framework* (CoreFoundation, Security, …): such a crate needs SDKROOT
# pointing at a genuine macOS SDK, which reintroduces both a toolchain dependency
# and Apple's licensing question.
#
# THE FAILURE IT MOVES IS A LATE ONE. `cross-check` runs `cargo check`, which
# stops at codegen-to-metadata and never links, so it cannot see this class at
# all — the first symptom would be the release workflow failing after a tag was
# already cut. This pair moves that signal to the moment the dependency is added.
#
# TWO RULES, AND THE SECOND IS INCOMPLETE BY CONSTRUCTION:
#
#   1. a package declaring a `links` key — the manifest's own statement that it
#      links a native library, general and needing no list;
#   2. a named set of crates that link Apple frameworks from a build script
#      WITHOUT declaring `links`, which rule 1 cannot see.
#
# A crate nobody has listed slips past rule 2. That residual gap is closed by
# actually linking the target, which `darwin-link` does; this is the fast,
# specific, early half of that pair rather than a replacement for it. The two
# classes stay distinct here because a reader acts on them differently: rule 1
# names the library the manifest itself declares, and rule 2 names only the
# crate.
#
# THE SPLIT IS FORCED. §5 makes `check` `read` and incapable of spawning
# `cargo metadata --filter-platform`, and the reachability walk is not
# expressible in Rego — a self-referential rule is a compile error and
# `graph.reachable` is not in this build's regorus feature set. The walk is
# `mise-tasks/cargo_graph.py`, shared with `evaluator-closure` so the two cannot
# drift; `mise-tasks/macos-link.py` is this gate's roots and predicates over it.
#
# THE RECORD IS THE PLATFORM-FILTERED GRAPH, which is the whole reason the
# producer passes `--filter-platform aarch64-apple-darwin`: a macOS-only
# transitive dep must be seen and a Linux-only one must not. A module reading an
# unfiltered graph would answer a different question with the same words.
#
#MUTANT-SUITE crates/batten/tests/it/macos_link.rs
#MUTANT links-key-passes|s@^\tstartswith(line, "links ")$@\tfalse@|a_package_declaring_a_native_links_key_is_caught_without_being_listed
#MUTANT framework-crate-passes|s@^\tstartswith(line, "framework ")$@\tfalse@|rule_2_still_fires_through_the_reachability_walk

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.macos_link

import rego.v1

rules contains "workspace carry unsafe"

# The record, or nothing. ABSENT IS NOT EMPTY: a checkout whose producer never
# ran has no key here, Rego reads that as *does not hold*, and every rule below
# is silent. The producer writes nothing when the graph will not resolve, and a
# module refusing there would refuse every checkout with no toolchain.
lines := input.tree.records["macos-link"]

# --- rule 1: the manifest's own declaration ----------------------------------

violation contains {
	"rule": "workspace carry unsafe",
	"verdict": "manifest carry unsafe",
	"subjects": [{"artifact": name}, {"artifact": library}],
} if {
	some line in lines
	startswith(line, "links ")
	parts := split(trim_space(substring(line, count("links "), -1)), " ")
	count(parts) == 2
	name := parts[0]
	library := parts[1]
}

# --- rule 2: the named set rule 1 cannot see ---------------------------------

violation contains {
	"rule": "workspace carry unsafe",
	"verdict": "workspace reach unsafe",
	"subjects": [{"artifact": name}],
} if {
	some line in lines
	startswith(line, "framework ")
	name := trim_space(substring(line, count("framework "), -1))
	name != ""
}

# --- cases -------------------------------------------------------------------

test_a_links_key_is_refused_and_names_the_library if {
	found := violation with input as {"tree": {"records": {"macos-link": [
		"scanned 200",
		"links openssl-sys openssl",
	]}}}
	count(found) == 1
}

test_a_framework_crate_is_refused if {
	found := violation with input as {"tree": {"records": {"macos-link": [
		"scanned 200",
		"framework core-foundation",
	]}}}
	count(found) == 1
}

# THE TWO CLASSES STAY DISTINCT, and a case counting findings cannot see that.
test_the_two_rules_are_separate_classes if {
	found := violation with input as {"tree": {"records": {"macos-link": [
		"scanned 200",
		"links openssl-sys openssl",
		"framework core-foundation",
	]}}}
	{entry.verdict | some entry in found} == {"manifest carry unsafe", "workspace reach unsafe"}
}

test_a_clean_graph_is_silent if {
	found := violation with input as {"tree": {"records": {"macos-link": ["scanned 200"]}}}
	count(found) == 0
}

test_an_absent_record_says_nothing_rather_than_refusing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}

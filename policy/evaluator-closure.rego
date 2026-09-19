# No IO-bearing crate is reachable from the evaluator's node in the resolved
# dependency graph (CLOUD-831, ported off `mise-tasks/evaluator-closure-check.sh`
# under CLOUD-1717).
#
# WHAT THE CLAIM IS AND WHY IT IS A SECURITY BOUNDARY. `crates/batten/src/policy.rs`
# admits consumer-authored code to the MEDIATED CALL on one claim: a policy
# module "cannot open a file, start a process, or reach the network". That claim
# decides a tool call, and until CLOUD-831 it rested on a single unenforced line
# of `Cargo.toml` — `default-features = false`, keeping regorus's `http` and
# `jsonschema` out of the closure.
#
# THE DRIFT IS NOT AN EDIT, which is why a `forbid` row over the manifest text
# would not do. Cargo unifies features across the graph, so a second crate in this
# workspace, or any dependency, taking `regorus` with default features unions them
# back on — with no edit to the line that states the pin and no diff a reviewer of
# that line would see. A renovate bump that changes regorus's own default feature
# set does the same. The predicate therefore has to read the RESOLVED GRAPH.
#
# THE SPLIT IS FORCED, NOT CHOSEN. The walk lives in
# `mise-tasks/evaluator-closure.py`, driven by `[tasks.evaluator-closure-record]`,
# for two reasons that are both about capability rather than taste. §5 makes
# `check` `read` and structurally incapable of spawning `cargo metadata`. And a
# reachability closure is not expressible here at all: a self-referential rule is
# a compile error in Rego, and `graph.reachable` is not in this build's regorus
# feature set — `ci-cache-declared`'s header records the same bound and expands
# its own walk by hand to a stated depth. An unbounded closure has no such
# spelling, so it stays a step.
#
# WHAT IS LEFT HERE IS THE WHOLE DECISION, AND IT IS THREE-VALUED. A record
# naming a crate is a refusal; a record saying `absent` is could-not-look and
# LOUD, because an evaluator that vanished from the graph means the question was
# never asked and reporting "nothing found" there is the vacuous pass this
# repository names CLOUD-251; no record at all is silence, because the producer
# writes nothing when it could not resolve the graph, and a module refusing there
# would refuse every checkout with no toolchain.
#
# THE COUNT IS REPORTED BY THE PRODUCER AND ASSERTED BY NOTHING. Which crates are
# absent is a property of THIS COMMIT and belongs in a gate; how many packages
# upstream happens to resolve to is a property of the world and would fire on
# every legitimate bump.
#
#MUTANT-SUITE crates/batten/tests/it/evaluator_closure.rs
#MUTANT io-crate-reachable-passes|s@^\tsome line in lines$@\tfalse #@|an_io_crate_in_the_recorded_closure_is_refused
#MUTANT absent-evaluator-passes|s@^\t"absent" in lines$@\tfalse@|a_recorded_absent_evaluator_is_loud_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.evaluator_closure

import rego.v1

rules contains "layer reach unsafe"

# The record, or nothing. ABSENT IS NOT EMPTY: a checkout whose producer never
# ran has no key here at all, Rego reads that as *does not hold*, and every rule
# below is silent. An empty list would be a measured nothing and would say the
# graph resolved and reached no package, which is a different claim.
lines := input.tree.records["evaluator-closure"]

# --- the refusal ------------------------------------------------------------

crate_named contains name if {
	some line in lines
	startswith(line, "crate ")
	name := trim_space(substring(line, count("crate "), -1))
	name != ""
}

violation contains {
	"rule": "layer reach unsafe",
	"verdict": "layer carry unsafe",
	"subjects": [{"artifact": name}],
} if {
	some name in crate_named
}

# --- could not look, and loud ------------------------------------------------
#
# The evaluator absent from the graph is a MEASUREMENT the producer made, not a
# failure to measure, so it is reported rather than silent. It is the one arm
# that distinguishes this module from one that has never run.
violation contains {
	"rule": "layer reach unsafe",
	"verdict": "layer read absent",
	"subjects": [{"artifact": "regorus"}],
} if {
	"absent" in lines
}

# --- cases ------------------------------------------------------------------

test_an_io_crate_in_the_recorded_closure_is_refused if {
	found := violation with input as {"tree": {"records": {"evaluator-closure": [
		"closure 41",
		"crate jsonschema",
	]}}}
	count(found) == 1
}

test_every_io_crate_is_named_separately if {
	found := violation with input as {"tree": {"records": {"evaluator-closure": [
		"closure 41",
		"crate jsonschema",
		"crate reqwest",
	]}}}
	count(found) == 2
}

test_a_clean_closure_is_silent if {
	found := violation with input as {"tree": {"records": {"evaluator-closure": ["closure 41"]}}}
	count(found) == 0
}

test_a_recorded_absent_evaluator_is_loud_rather_than_clean if {
	found := violation with input as {"tree": {"records": {"evaluator-closure": ["absent"]}}}
	count(found) == 1
}

# NO RECORD IS SILENCE, and it must not be spelled the same way as a clean
# closure. The producer writes nothing when `cargo metadata` could not resolve,
# and a module refusing there would refuse every checkout with no toolchain.
test_an_absent_record_says_nothing_rather_than_refusing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}

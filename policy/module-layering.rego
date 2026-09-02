# Module layering, enforced over the resolved `use` graph (CLOUD-359).
#
# THE LAYERINGS ARE DOCUMENTED AND GATED BY NOTHING, which is this row's finding.
# `module-map-check` asserts every module APPEARS in the map -- a membership
# check -- and says nothing about any edge, the same census-for-predicate
# substitution `tests-not-deleted` and `assertions-not-gutted` make. A back-edge
# compiled and passed every gate.
#
# WHAT THIS TABLE CONTAINS, AND WHAT IT DELIBERATELY DOES NOT. Only claims the
# tree already states in its own doc comments. The row puts reorganising modules
# out of scope and it is right to: inventing a rank for all 65 modules would be
# declaring an architecture nobody agreed to, under cover of enforcing one. So
# the table is a FORBIDDEN-EDGE set drawn from prose that already exists, and it
# grows when somebody documents another layering.
#
# ABSENCE IS AN ERROR, NOT AN ALLOW. `declared_modules` must name every module in
# the judged set. A module nobody has placed is a hole in the claim, and a table
# that silently allowed it would be the vacuous pass this row cites CLOUD-251
# for. It earned its keep on the first run: three modules were missing from the
# first draft of the table, and the rule named all three before a human read it.
#
# IT READS `input.tree.uses`, NOT LINES. CLOUD-762 measured a line predicate
# wrong in two classes in this tree -- edges it cannot see (`use crate::UsageError`,
# really onto `error`) and edges it invents (`use crate::Result`, really external)
# -- so a layering gate on lines would ship a known false green. The resolved fact
# costs the same parse and is right about every one of them. The CLASSES are the
# measurement rather than a site count: the second grows with every module that
# imports `crate::Result` (CLOUD-1121).
#
# COVERAGE IS AN EXEMPTION RATHER THAN FOUR MUTATIONS. Four mutation rows were
# written here first and `mise run mutant` refused every one with `no-suite`:
# the runner mutates a gate and asks a BATS suite to go red, and a policy module
# has none because `batten policy test` is wired to no task. That is CLOUD-931
# exactly, and the two sibling policy modules already carry this exemption.
# Writing the suite would add bash to the census CLOUD-843 is retiring, to test a
# module with nine passing cases of its own.
#
# WHAT STANDS IN FOR IT, so the gap is named rather than unmeasured: the
# acceptance clause was observed END TO END. `use crate::journal::Entry` was
# seeded into `cli.rs`, `batten enforce` reported `module-layering`, and the
# finding went away on revert -- clean tree zero, seeded tree one.
#MUTANT-EXEMPT CLOUD-845|no compiled-binary tier names this module at all, so there is no suite a declared mutation could redden. That is not the `tests/$gate.bats` hole CLOUD-1267 closed — a suite may now be DECLARED — it is that none exists to declare, and what is owed is the tier

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`:
#   OPA parses the whole contiguous block that starts the annotation, so prose
#   placed after it reaches the YAML parser and the module fails to load.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.module_layering

import rego.v1

rules contains "module-layering"

# Every module this table has placed. A module in the judged set and absent here
# is refused rather than allowed.
declared_modules := {
	"action", "admission", "attribution", "baseline", "budget", "bypass", "capture", "ci",
	"cli", "commit", "completion", "config", "contract", "decision", "defects",
	"design", "doctor", "drain", "effect", "emission", "epoch", "error", "exec",
	"exit", "facts", "findings", "git", "handler", "hook", "identity", "init",
	"invocation", "journal", "judge", "lib", "lint", "markers", "mint", "minted", "outputs",
	"output", "pattern", "policy", "provision", "receipt", "redirect", "refusal",
	"render", "resolve", "rules", "secrets", "session", "severity", "sink",
	"spec", "state", "stop", "store", "surface", "transcript", "trust", "uses",
	"verbs", "verdict", "waiver", "worktree",
	# `brief`, `main` and `selfwrite` were absent from the first draft of this
	# table, and the coverage rule caught all three on its first run against the
	# real tree — which is the property working before any human read it. `main`
	# is the binary entry point rather than a `pub mod` of the library, and it is
	# declared rather than excluded: it is a file in the judged set, and a
	# selector carve-out would be an exemption where a placement is honest.
	# `preset` arrived with CLOUD-1181 and this rule named it before a human did
	# — the same property the entries above record, working again. It sits BELOW
	# `policy` and `verdict`: both read it, and it reads neither. That direction is
	# the manifest's whole point — a preset's identity, scope, modules and
	# vocabulary are one declaration that the two consumers project, rather than
	# three tables that had to know about each other.
	"preset",
	"brief", "main", "selfwrite",
	# `patch` arrived with CLOUD-739 and this rule named it before a human did —
	# the same property the three above record, working a second time. `symbols`
	# arrived with CLOUD-760 and it worked a third. `semver` arrived with
	# CLOUD-1050 and it worked a fourth: the module was written, its tests were
	# green, and this rule is what said nobody had placed it.
	"patch", "symbols", "semver",
	# `recorder` arrived with CLOUD-1051 and it worked a fourth time: the module
	# landed undeclared and this rule named it, before any reviewer did. It is a
	# writer rather than a decider — it accumulates what a gate already said — so
	# it sits below `rules` and reaches `exec` for its one spawn, which is the
	# placed adapter `policy/spawn-adapters.rego` requires.
	"recorder",
	# `perf` arrived with CLOUD-875 and this rule named it too — a sixth time. It
	# is a measurement harness rather than a decider: it builds two binaries and
	# spawns a benchmark runner, so it sits with the acquisition modules below and
	# its back-edges are forbidden for their reason.
	"perf",
	# `pinned` arrived with CLOUD-1028 and it worked a fifth time: clippy green,
	# both test tiers green, and this rule is what said the module was unplaced.
	# It is an acquisition module in `symbols`' class — it spawns the mediator to
	# resolve one `Cost::Effect` fact — so it sits below the engine and its
	# back-edges are forbidden below for `symbols`' reason.
	"pinned",
	# `prune` arrived with CLOUD-1030 and this rule named it a seventh time. It
	# is an effect module rather than a decider — it removes superseded
	# artifacts and reads the volume — so it sits with the acquisition modules
	# and its back-edges are forbidden for their reason.
	"prune",
	# `wiring` arrived with CLOUD-893 and it worked a sixth time, on a rebase
	# rather than on a fresh write: the module landed on a branch based before
	# this table's last row and nothing said so until `main` moved under it.
	#
	# It is a REPAIRER — the one module that edits a hook surface rather than
	# reading one — so its placement is the interesting half. It sits beside
	# `doctor`, which diagnoses the same surfaces it repairs, and below `hook`,
	# whose `WiringFile` it reads to know which file is whose. It reaches no
	# decider: the verdict about whether a registration may stand is
	# `hooks-wiring-check`'s and the engine's `[hook] exclusive`, and this module
	# only carries out a removal something else already decided, which is what
	# keeps `batten wiring reclaim` from becoming a second authority on the
	# registration policy.
	"wiring",
	# `mutate` arrived with CLOUD-1267 and this rule named it too. It is a LEAF —
	# it reaches nothing in this crate at all, which is deliberate rather than
	# incidental: its whole input is a root path and an enforced set, and its
	# whole output is a verdict about whether a declared corruption reddened a
	# declared suite. It sits with the effect modules below the engine and its
	# back-edges are forbidden for `prune`'s reason — it is `Effect::Write` on
	# `Surface::VerifyOnly`, so reaching the module that adjudicates a mediated
	# call is exactly the reach the surface split exists to make unwritable.
	"mutate",
	# `ready` and `fetch` arrived with CLOUD-1121 and this rule worked a fifth and
	# sixth time: both modules were written, both compiled, and this is what said
	# nobody had placed them.
	#
	# `ready` is a PREDICATE over a payload and reaches nothing but `error` — it
	# holds the Definition-of-Ready grammar ported off `mise-tasks/ready-lint.sh`,
	# and it deliberately does not reach `rules` or `findings`: it renders a
	# verdict about an ISSUE rather than about the tree, so it mints no `Finding`
	# and joins no store. That is what keeps it below the engine rather than
	# beside it.
	#
	# `fetch` is an ADAPTER at the edge, the one module that reaches the network,
	# and it reaches nothing in this crate but `error` either. `hook` must never
	# reach it — a runtime on the mediated path is what CLOUD-689's ceiling and
	# CLOUD-747's no-runtime assertion both forbid — so that edge is forbidden
	# below rather than left to whoever remembers it.
	"ready", "fetch",
	# `forge`, `tools`, `captured`, `taskset` arrived with CLOUD-843's substrate
	# wave, and this rule named all four before a human did — the eighth time the
	# absence-is-an-error clause has earned its keep, and the first on a batch.
	#
	# All four are ACQUISITION modules in `pinned`'s class: each reads a record or
	# a store that something else wrote and hands the boundary a fact. None
	# decides anything, so none reaches `rules` for a verdict — `captured` and
	# `taskset` reach it for `parse_node` alone, which is the crate's ONE
	# `Format::read` call site (CLOUD-849) and an edge onto a parser rather than
	# onto a decider. `tools` reaches `forge` for the same reason one layer over:
	# the two families differ in their KEY and share one record-line parser, and a
	# second would be a second authority over one byte format.
	#
	# They sit below the engine and their back-edges are forbidden for `symbols`'
	# reason.
	"forge", "tools", "captured", "taskset",
	# `claim` arrived with CLOUD-1121 too, and this rule named it a seventh time.
	# It sits ABOVE `ready` and reaches it: the claim gate's readiness rule is the
	# refinement gate's own predicate rather than a second reading of the same
	# grammar, which is what keeps the two from drifting — that grammar is subtle
	# enough that CLOUD-290's whole-code-span anchor was found only by experiment.
	"claim",
	# `checks_green` arrived with CLOUD-1143, and this rule named it too — the
	# eighth time the coverage clause has caught a module nobody had placed.
	#
	# It is a LEAF and reaches nothing in this crate, deliberately: the decision is
	# a pure function of a reading the caller hands over, with no clock, no network
	# and no filesystem, which is what lets every case run offline exactly as the
	# bats suite it retires did. Listed beside `claim` because both arrived by the
	# same campaign, not because they sit at the same height — `claim` is above
	# `ready` and reaches it, where this reaches nobody and only `lib` reaches it.
	"checks_green",
	# `mcp` arrived with CLOUD-1260 and this rule named it a NINTH time: the module
	# was written, both test tiers were green, clippy was clean, and this is what
	# said nobody had placed it.
	#
	# It is a DISPATCHER at the edge, sitting directly above `fetch`: it owns the
	# JSON-RPC session and the declared reductions, and `fetch` is the transport
	# beneath it. It reaches `rules` for `parse_node` ALONE -- the crate's one
	# `Format::read` call site (CLOUD-849) -- which is `captured` and `taskset`'s
	# sanctioned edge above, onto a parser rather than onto a decider. Its other
	# edges are `error` and `facts`, and it reaches no store: what goes into the
	# capture store is written by `lib`, the caller that decided to dispatch.
	"mcp",
	# `pr_watch` is the poll around that decision, from the same row. It sits
	# ABOVE `checks_green` and reaches it — the request is one module's and the
	# verdict is the other's, which is the split (CLOUD-346) that stopped a second,
	# weaker copy of the predicate living in a workflow. It also reaches `rules`,
	# for the process ladder every spawning site in this crate shares.
	"pr_watch",
	# `record` arrived with CLOUD-1265 and this rule named it a ninth time — the
	# module was written, both tiers were green, and this is what said nobody had
	# placed it.
	#
	# It is the WRITE half of `forge` and `tools`, so it sits directly above both
	# and reaches both — and that direction is the placement's whole content. The
	# two acquisition modules compose a key and read; this composes the SAME key
	# through the same two functions and writes. Reaching them rather than
	# re-deriving a key is what keeps writer and reader from becoming two
	# authorities over one filename — the defect the `tools -> forge` edge above was
	# placed to avoid, one layer down.
	#
	# It also reaches `resolve`, because the `[[rule.tools]]` row it keys from is
	# the committed config's, and that edge is what makes a caller-supplied digest
	# unspellable rather than merely discouraged. It reaches no decider: what a
	# recorded verdict MEANS is `policy/validator-verdict-clean.rego`'s, and this
	# module never reads a finding.
	"record",
	# `advisory` arrived with CLOUD-896 and this rule named it a tenth time: the
	# module was written, `test:cargo` was green over its six cases, and this is
	# what said nobody had placed it.
	#
	# It is a LEAF beside `refusal`, and the pairing is the placement's content:
	# `refusal` bounds ONE emitted deny line and this bounds ONE emission of the
	# whole advisory channel, so the two answer the same question over the two
	# documents a boundary can produce. It reaches `severity` for the tier it
	# orders by and `budget` for the estimator — the same estimator `refusal`
	# reaches, because a second one would be a second authority over what a token
	# costs. It reaches no decider and no store: WHICH producers exist is `lib`'s,
	# and `lib` is the caller that hands the whole set over.
	"advisory",
	# `hookcost` arrived with CLOUD-417 and this rule named it an eleventh time.
	#
	# It is a MEASUREMENT module and it is placed by what it does NOT reach: it
	# reads a parsed `transcript` and counts, so it sits above `transcript` and
	# `budget` and below `lib`, and it reaches no decider, no store and no
	# `hook`. That last one is the placement's content rather than an omission --
	# a module measuring what the mediated boundary COSTS must not be reachable
	# from that boundary, or the measurement joins the thing it measures. It
	# reaches `budget` for the estimator every other ceiling here counts with,
	# and `findings` to mint the two engine-produced findings it raises.
	"hookcost",
}

# THE FORBIDDEN EDGES, each traceable to prose already in the tree.
#
# `rules -> hook` is the sharpest instance and the row says so: `refusal.rs`
# states that housing the refusal table in `hook` "would make `rules` import
# `hook` and close a module cycle", and `mem:core` repeats it. rustc permits
# mutual `use` inside one crate, so that reasoning is held today by whoever
# remembers it.
#
# The three chains are the layerings `mem:core` and the module docs state, read
# as "a lower tier must not reach a higher one":
#   surface (data) -> cli (typed values) -> lib (dispatch)
#   config (load) -> resolve (precedence) -> trust (judging) -> lint -> epoch
#   store (which store) / findings (what is in it) / journal (how it is written)
forbidden[from] contains to if {
	some from, targets in {
		"rules": {"hook"},
		# CLOUD-1121/CLOUD-745: `hook` adjudicates a mediated call under
		# CLOUD-689's 100 ms ceiling and CLOUD-747's "at most one runtime, never
		# multi-thread". `fetch` builds a runtime and reaches the network, so this
		# edge is the one that would put both on the hottest path in the binary.
		# Held by a rule rather than by whoever remembers the two issues.
		# `hook -> mcp` IS THE SAME ROW REACHED IN ONE MORE HOP, and it is listed
		# beside `fetch` rather than left to follow from it. `mcp` reaches `fetch`,
		# so a mediated call able to reach `mcp` reaches a runtime and the network
		# transitively -- and this table decides over DIRECT edges, so the reason
		# above would have said nothing about it. A guarantee routable around by one
		# hop is not one (CLOUD-1260).
		"hook": {"fetch", "mcp"},
		# And the other direction, which is `symbols`' and `pinned`'s row again: the
		# dispatcher sits below the engine and must not reach the module that
		# adjudicates a mediated call. `mcp -> rules` is deliberately NOT here --
		# what it reaches there is `parse_node`, a parser rather than a verdict.
		"mcp": {"hook"},
		"surface": {"cli", "lib"},
		"cli": {"lib", "journal"},
		"config": {"resolve", "trust", "lint", "epoch"},
		"resolve": {"trust", "lint", "epoch"},
		"trust": {"lint", "epoch"},
		"lint": {"epoch"},
		"store": {"findings", "journal"},
		# `patch -> git` would close a cycle, and the direction is prose the tree
		# already carries rather than an architecture invented here: `patch.rs`
		# opens by saying it computes the identity `git::landing` consumes, and
		# `git.rs` names `crate::patch` as that identity's authority. A back-edge
		# would make the identity depend on the module that asks it for one.
		"patch": {"git"},
		# `symbols -> rules` is `patch -> git` again, one fact family over, and the
		# prose is already in the tree: `symbols.rs` says acquisition is the
		# CALLER's, and `rules::symbols_fact` is that caller. An acquisition module
		# reaching back into the engine that decides when to acquire would make the
		# `Cost::Effect` boundary a convention rather than a direction — and the
		# whole point of the class is that a projection cannot reach the spawn.
		"symbols": {"rules", "hook"},
		# `pinned -> rules` / `pinned -> hook` is `symbols`' row again, one fact
		# family over, and for the identical reason: `pinned.rs` resolves a
		# `Cost::Effect` fact and `lib.rs` is the caller that decides when — at
		# `SessionStart` and nowhere else. A back-edge would let the acquisition
		# module reach the engine that adjudicates calls, and the whole guarantee
		# here is that the mediated path CANNOT reach the spawn.
		"pinned": {"rules", "hook"},
		# `perf -> rules`, and DELIBERATELY NOT `perf -> hook`, which the two rows
		# above both forbid. `perf.rs` is `Cost::Effect` on `Surface::VerifyOnly`
		# — it builds two binaries and materialises a worktree — so it sits below
		# the engine and must not reach the module that runs a `command` row.
		#
		# `hook` is the exception because of WHAT it is asked for: the harness
		# table, which is the one authority on where each host keeps its wiring.
		# The `wired` arm has to read that file to know what it is measuring, and
		# a `perf`-local copy would be a second authority over a path
		# `no_artifact_name_reaches_the_core` deliberately admits in exactly one
		# place. The edge is a data read, not a back-edge into adjudication, and
		# what actually keeps this module off the mediated call is
		# `Surface::VerifyOnly` and the verb's own effect class — never this row.
		"perf": {"rules"},
		# `prune -> {rules, hook}`, the full pair `pinned` carries rather than
		# `perf`'s narrowed one, because this module needs no harness table: its
		# whole input is a directory path and two numbers the config declares.
		# It is `Effect::Destructive` on `Surface::VerifyOnly`, so a back-edge
		# into the module that adjudicates a mediated call is exactly the reach
		# the surface split exists to make unwritable.
		"prune": {"rules", "hook"},
		# `mutate -> {rules, hook}`, `prune`'s pair for `prune`'s reason. It is
		# `Effect::Write` on `Surface::VerifyOnly` and stages a tree to re-run a
		# suite against it, so a back-edge into the module that adjudicates a
		# mediated call is the reach the surface split exists to make unwritable.
		"mutate": {"rules", "hook"},
	}
	some to in targets
}

# The module a judged path denotes. Stem of the file name, which is Rust's own
# mapping from `foo.rs` to module `foo`.
module_of(path) := name if {
	parts := split(path, "/")
	file := parts[count(parts) - 1]
	name := substring(file, 0, count(file) - 3)
}

# A forbidden edge, reported at the line that wrote it.
#
# Pointer-only (non-negotiable rule 4): the path, the line, and the two module
# names. Never the source line — `to` and `item` are path segments, and the text
# that produced them stays on the engine's side.
violation contains {
	"rule": "module-layering",
	"verdict": "layer reach refused",
	"subjects": [{"path": path, "line": edge.line}, {"artifact": edge.to}],
} if {
	some path, edges in input.tree.uses
	some edge in edges
	edge.origin == "internal"

	# Set INDEXING rather than a bare `in` expression: the pinned type checker
	# reports `undefined function internal.member_2` for the latter over a
	# computed set, and indexing says the same thing in a form it can type.
	forbidden[module_of(path)][edge.to]
}

# A module nobody placed. An implicit allow here is the hole this table exists to
# close, so it is a finding rather than silence.
violation contains {
	"rule": "module-layering",
	"verdict": "module place missing",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.uses
	not declared_modules[module_of(path)]
}

# THE VACUITY GUARD, and the row demands it by name: "an empty or unsatisfiable
# layer table fails rather than passing quietly". A table that forbids nothing
# reporting "no violations" is CLOUD-251's failure mode, and the reason a gate
# can be switched off by deletion without anything going red.
violation contains {
	"rule": "module-layering",
	"verdict": "layer table dead",
} if {
	count(forbidden) == 0
}

# THE OTHER HALF OF VACUITY IS THE ENGINE'S, NOT THIS MODULE'S. A selector that
# matched no file is `NotObserved::RuleSkipped` in `rules::evaluate` — reported
# as not-observed rather than as clean, which is the same three-valued answer
# this module would give and is given once rather than twice. A violation here
# too would fire in every consumer tree that carries no Rust, which is a rule
# refusing a repository for not being this one (measured: a fixture repo with no
# `crates/` tripped it).

# The predicate's own tests. The ALLOW cases are the load-bearing half: a rule
# that fired on everything would satisfy every deny below and gate nothing.

# One judged file whose module is declared and whose edges are given.
judging(path, edges) := {"tree": {"uses": {path: edges}}}

internal(to, line) := {"to": to, "item": "x", "origin": "internal", "via-root": false, "line": line}

test_the_documented_cycle_claim_is_refused if {
	some v in violation with input as judging(
		"crates/batten/src/rules.rs",
		[internal("hook", 52)],
	)
	v.rule == "module-layering"
}

# The row's own acceptance clause, spelled as a case.
test_the_acceptance_clause_edge_is_refused if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/cli.rs",
		[internal("journal", 17)],
	)
}

test_a_documented_chain_is_refused_in_the_wrong_direction if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/config.rs",
		[internal("trust", 44)],
	)
}

# THE DIRECTION IS THE POINT. The same pair the other way round is the layering
# working as documented, and a rule that refused both would be banning the edge
# rather than ordering it.
test_the_same_chain_is_clean_in_the_declared_direction if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/trust.rs",
		[internal("config", 44)],
	)
}

test_an_unrelated_edge_is_not_this_rules_business if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/hook.rs",
		[internal("receipt", 47)],
	)
}

# An EXTERNAL edge is not a module edge. Without this the rule would fire on a
# crate that happens to share a module's name.
test_an_external_edge_is_never_a_layering_violation if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/rules.rs",
		[{"to": "hook", "item": "x", "origin": "external", "via-root": false, "line": 9}],
	)
}

# The cycle CLOUD-739's module could close, in the direction that would close it.
test_the_identity_must_not_reach_its_caller if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/patch.rs",
		[internal("git", 12)],
	)
}

# And the declared direction is the whole point: `git` reaching `patch` is the
# arrangement, not a violation.
test_the_caller_may_reach_the_identity if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/git.rs",
		[internal("patch", 12)],
	)
}

# CLOUD-760's edge, and it is the `Cost::Effect` boundary stated as a direction:
# the acquisition module must not reach the engine that decides when to acquire.
test_the_effect_acquisition_must_not_reach_its_caller if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/symbols.rs",
		[internal("rules", 20)],
	)
}

# The declared direction, again the arrangement rather than a violation: `rules`
# resolves the fact once at the boundary, so it is the module that reaches.
test_the_engine_may_reach_the_effect_acquisition if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/rules.rs",
		[internal("symbols", 20)],
	)
}

# CLOUD-1260's pair, and the first is the one that would otherwise be reachable in
# one hop. `hook -> fetch` is forbidden because a runtime on the mediated path is
# what CLOUD-689's ceiling and CLOUD-747's bound both refuse; `mcp` reaches
# `fetch`, so without this row a mediated call could reach the network by naming
# the dispatcher instead of the transport.
test_the_mediated_path_must_not_reach_the_dispatcher if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/hook.rs",
		[internal("mcp", 31)],
	)
}

# The transport it stands in front of, still refused directly. Without this the
# case above could pass over a table that had dropped the original row.
test_the_mediated_path_must_not_reach_the_transport if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/hook.rs",
		[internal("fetch", 31)],
	)
}

# The dispatcher must not reach the adjudicator — `symbols`' row one family over.
test_the_dispatcher_must_not_reach_the_engine if {
	count(violation) == 1 with input as judging(
		"crates/batten/src/mcp.rs",
		[internal("hook", 44)],
	)
}

# THE ALLOW HALF, and it is what makes the three above statements about DIRECTION
# rather than a ban on the module. `mcp -> rules` is the `parse_node` edge every
# acquisition module carries, and `mcp -> fetch` is the arrangement itself: a rule
# refusing either would be forbidding the module rather than placing it.
test_the_dispatcher_may_reach_its_parser_and_its_transport if {
	count(violation) == 0 with input as judging(
		"crates/batten/src/mcp.rs",
		[internal("rules", 20), internal("fetch", 21), internal("facts", 22)],
	)
}

# The coverage half: a module the table never placed.
test_an_unplaced_module_is_refused_rather_than_allowed if {
	some v in violation with input as judging(
		"crates/batten/src/brand_new.rs",
		[internal("error", 3)],
	)

	# The TOKEN, not a substring of prose (CLOUD-1050). The predicate a test
	# pins is the class it raises, and a token is what makes that assertion
	# exact — a `contains` over a message passed for any rewording that kept
	# three words, and failed for any that did not.
	v.verdict == "module place missing"
}

# A selector that matched nothing reaches this module as an empty set and it says
# NOTHING, deliberately: the engine already skipped the row before evaluation, so
# a second refusal here would fire in every tree that carries no Rust.
test_an_empty_judged_set_is_the_engines_answer_not_this_modules if {
	count(violation) == 0 with input as {"tree": {"uses": {}}}
}

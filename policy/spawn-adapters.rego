# WHICH MODULES MAY SPAWN, decided by NAME RESOLUTION (CLOUD-760).
#
# This is the consumer that makes `Fact::Symbols` a fact rather than a facility.
# `.claude/rules/rust.md` states the rule it enforces -- a spawn is an inventory
# row, and the annotation beside it is where somebody wrote down whether it
# stays -- but the inventory has never had a gate over WHERE a spawn may appear.
# It has one now, and only this fact could carry it.
#
# WHY NO SCANNER CAN WRITE THIS RULE. `.claude/rules/scanning.md` records the
# three answers to "where is `std::process::Command`": a byte scan says 14, a
# tree-sitter matcher says 11, name resolution says 9. The spread is one import:
# `surface.rs` writes `use clap::{..., Command}`, so the token names a DIFFERENT
# TYPE there, and a call expression looks identical whichever type it names. A
# gate built on either scanner would report `surface.rs` as an unplaced spawning
# module, and the honest remedies for that false positive are all worse than the
# rule -- an exemption for a module that spawns nothing, or a deleted rule.
#
# So the input here is the resolved census, which excludes `surface.rs` because
# the compiler knows what the name means. The measurement is in
# `crates/batten/tests/symbols.rs`, which asserts that exclusion as a SET rather
# than as a count: on this tree the byte and resolved tiers both total 16 and
# disagree about which files they name, so a count comparison would have passed
# while the tiers agreed about nothing.
#
# THE TABLE IS A PLACEMENT, NOT AN ALLOW-LIST OF SITES. It says which modules own
# a delegated tool, each with the tool it delegates to. It deliberately does not
# bound how many spawns a placed module holds: that is the `#[expect(...)]`
# inventory's job, self-cleaning in both directions, and duplicating it here
# would be a second authority that drifts.
#
# COULD-NOT-LOOK IS NOT CLEAN (CLOUD-251). `input.tree.symbols` is `null` when no
# row declared the fact and when the analyser could not be run or parsed, and
# either way this module must not report a tree with no unplaced spawns. It
# refuses instead, which is the same posture `symbols.rs` carries from
# `secrets.rs`: clean is never inferred from a stream that failed to parse.
#
# NO BATS SUITE, for the reason its two siblings carry: `batten policy test` is
# wired to no task, so `mutant` cannot reach a policy module's own cases.
# WHAT STANDS IN FOR IT: the acceptance clause was observed END TO END. A
# `std::process::Command::new("true")` was seeded into `crates/batten/src/git.rs`
# -- a module the table does not place, and the one CLOUD-739/740 spent the
# campaign emptying of spawns -- `batten check` reported `spawn-adapters`, and the
# findings went away on revert. Clean tree ZERO, seeded tree TWO: the seed's
# signature and its call each resolve the type, which is the resolved tier
# counting a USE rather than an occurrence of `::new`, exactly as the fact's own
# suite records for `exec.rs`.
#MUTANT-EXEMPT CLOUD-845|no compiled-binary tier names this module at all, so there is no suite a declared mutation could redden. That is not the `tests/$gate.bats` hole CLOUD-1267 closed — a suite may now be DECLARED — it is that none exists to declare, and what is owed is the tier

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.spawn_adapters

import rego.v1

rules contains "spawn-adapters"

# The placed adapters, each named with what it delegates to. Measured against the
# tree rather than imagined: this is exactly the resolved set on the commit that
# introduced the rule, so the gate starts true and every later row is a decision
# somebody made.
#
# A SET, and deliberately not a name -> reason map, which is what this table was
# first written as. `descend` in `policy.rs` walks every object member looking for
# a `rules` rule, and one of the placements below IS the `rules` module — so the
# map's own key shadowed the bundle's published id and the engine refused the
# whole module with "answered `rules` with a shape that is not a set of ids".
# Measured here before the rule ever ran. The reasons live in the comment.
#
#   exec       the sanctioned child-process boundary
#   provision  installs the binaries the other adapters pin
#   secrets    the pinned ripsecrets adapter (CLOUD-59)
#   symbols    the pinned clippy adapter, this fact's own acquisition (CLOUD-760)
#   judge      the judge kind's delegated command
#   handler    the harness handler boundary
#   action     an action row RUNS a command; that is the kind's definition
#   rules      the engine that runs a `command` row's `check` and `fix`
#   semver     the pinned cargo-semver-checks adapter (CLOUD-1050), which also
#              builds its own baseline when the registry cannot resolve one
#   pinned     the toolchain-pin adapter (CLOUD-1028): it asks the pin what it
#              puts on PATH, which is the one question that cannot be answered
#              from the tree. Placed rather than folded into `exec` because the
#              call is a FACT's acquisition, and the module that owns the fact is
#              the one that owns its could-not-look — the same argument `symbols`
#              carries one row up
#   perf       the paired measurement (CLOUD-875), retired out of
#              `mise-tasks/perf-pair.sh`. It builds two release binaries,
#              materialises a detached worktree and spawns the benchmark runner —
#              a harness whose whole subject is what an EXTERNAL process costs, so
#              the spawns are the thing rather than an implementation of it.
#              `Surface::VerifyOnly` is what keeps the class off the mediated call
#   prune      the disk-floor reclaim (CLOUD-1030), retired out of
#              `mise-tasks/target-prune.sh`. Its one spawn is `df`, and it is here
#              for `symbols`' reason rather than `perf`'s: how much space the
#              VOLUME has left is not a property of the tree, so no amount of
#              walking it answers the question. The removals themselves are
#              `std::fs`, not a spawned `rm` — a shelled-out delete would be an
#              argv this module composes and nothing checks
#   pr_watch   the conditional poll (CLOUD-1143), retired out of
#              `mise-tasks/ci-wait.sh`. Two delegated programs and each is placed
#              for a reason already on this table: the forge's client is the
#              acquisition of a fact no walk of the tree can answer — whether a
#              commit's checks have graded is a property of the world —
#              which is `symbols`' argument, and the progress recorder is a
#              program the CALLER names, which is `handler`'s. What it delegates
#              is the READING; the verdict over that reading is `checks_green`'s
#              and spawns nothing, which is why only one of the pair is here
#   mutate     the mutation sweep (CLOUD-1267), retired out of
#              `mise-tasks/mutant.sh`. It is `perf`'s argument rather than
#              `symbols`': the subject IS an external process, because a
#              mutation is only shown to be CAUGHT by running the suite it names
#              against a corrupted tree, and a suite runner is a program by
#              definition. It spawns `git` to stage the copy and then `bats` or
#              `cargo` to re-run the declared tier. `Surface::VerifyOnly` and
#              `Effect::Write` are what keep the class off the mediated call
#   bot        the bot lane (CLOUD-1295), retired out of
#              `mise-tasks/bot-issue.sh`. Placed on `pr_watch`'s first argument
#              and nothing new: what a pull request's title, files and body say
#              is a property of the world rather than of the tree, so no walk
#              answers it. The forge's own client is the acquisition, chosen over
#              this crate's HTTP transport because it resolves the credential
#              OUTSIDE the crate. The predicates over that reading are the same
#              module's pure half and spawn nothing — the split `pr_watch` and
#              `checks_green` make across two modules, made inside one here
#              because the lane's facts and its matcher share a config table
#   lease      the landing lease (CLOUD-1274, CLOUD-393). One spawn, `kill -TERM`
#              against a wedged holder, and it is here for `symbols`' and
#              `prune`' argument rather than `perf`'s: the pid comes off the lease
#              record and whether that process is still there is a property of the
#              MACHINE, which no walk of the tree answers. It is a spawn only
#              because the workspace forbids `unsafe`, so `kill(2)` is unreachable
#              and `signal-hook` is the receiving half with no sending half.
#
#              PLACED HERE RATHER THAN `lib`, which is where it was written and
#              which this rule refused. Placing the CLI dispatch would admit every
#              future spawn in the crate's largest file at once — the table would
#              stop naming boundaries and start naming files
adapters := {
	"exec", "provision", "secrets", "symbols",
	"judge", "handler", "action", "rules", "semver",
	"pinned", "perf", "prune", "pr_watch", "mutate", "bot",
	"lease",
}

module_of(path) := name if {
	parts := split(path, "/")
	file := parts[count(parts) - 1]
	name := substring(file, 0, count(file) - 3)
}

# A spawn in a module the table has not placed.
#
# Pointer-only (non-negotiable rule 4): the path, the line and the module name.
# The analyser's diagnostic and the source line it quoted are not in the fact at
# all, so there is nothing here for this module to leak even by mistake.
violation contains {
	"rule": "spawn-adapters",
	"verdict": "spawn place missing",
	"subjects": [{"path": site.path, "line": site.line}, {"artifact": module_of(site.path)}],
} if {
	some site in input.tree.symbols.sites
	site.lint == "clippy::disallowed_types"
	not adapters[module_of(site.path)]
}

# COULD NOT LOOK. `null` is both did-not-look answers, and neither is clean.
#
# OVER `sites`, NOT OVER THE FACT, and both halves of that were measured here.
#
# `not input.tree.symbols` alone is wrong: `not x` holds when `x` is undefined or
# false, and `null` is NEITHER -- so the shape the projection actually emits for
# could-not-look walked straight through it, caught by this module's own case
# rather than in the field. And the obvious repair, `== null`, does not type: the
# schema declares `["object", "null"]`, the checker narrows the ref to the object
# arm, and `opa check -s` calls the comparison a match error.
#
# Asking for `sites` answers both. A key that is absent, a `null`, or an object
# with no census all leave it undefined; a real census always carries it, and an
# EMPTY one carries `[]`, which is defined -- so "ran and found nothing" stays
# clean and stays distinct from "did not look".
no_census if not input.tree.symbols.sites

violation contains {
	"rule": "spawn-adapters",
	"verdict": "symbol count absent",
} if {
	no_census
}

# THE VACUITY GUARD. A table placing nothing decides nothing, and a rule that
# cannot refuse is off.
violation contains {
	"rule": "spawn-adapters",
	"verdict": "adapter table empty",
} if {
	count(adapters) == 0
}

# The predicate's own tests. The ALLOW cases are the load-bearing half: a rule
# that fired on everything would satisfy every deny below and gate nothing.

census(sites) := {"tree": {"symbols": {
	"provenance": {"tool": "cargo", "version": "1.97.1", "invocation": ["clippy"]},
	"sites": sites,
}}}

at(path, line) := {"path": path, "line": line, "lint": "clippy::disallowed_types"}

# The case the rule exists for: a spawn in a module nobody placed.
test_a_spawn_in_an_unplaced_module_is_refused if {
	some v in violation with input as census([at("crates/batten/src/git.rs", 12)])
	v.rule == "spawn-adapters"
}

# And the placement is the point. `exec` is the sanctioned boundary; a spawn
# there is the arrangement, not a violation.
test_a_spawn_in_a_placed_adapter_is_clean if {
	count(violation) == 0 with input as census([at("crates/batten/src/exec.rs", 88)])
}

# THE TABLE DOES NOT BOUND HOW MANY. A placed adapter holding several spawns is
# the `#[expect]` inventory's business, and duplicating that bound here would be
# a second authority that drifts from it.
test_a_placed_adapter_may_hold_more_than_one_spawn if {
	count(violation) == 0 with input as census([
		at("crates/batten/src/exec.rs", 88),
		at("crates/batten/src/exec.rs", 140),
		at("crates/batten/src/secrets.rs", 31),
	])
}

# EVERY UNPLACED SITE IS ITS OWN FINDING, so a module with two of them is not
# reported once and half-fixed.
test_each_unplaced_site_is_reported if {
	count(violation) == 2 with input as census([
		at("crates/batten/src/git.rs", 12),
		at("crates/batten/src/git.rs", 30),
	])
}

# A DIFFERENT LINT IS NOT THIS RULE'S BUSINESS. The census carries whatever the
# analyser was asked for, and a rule reading every row would refuse on a lint it
# has no opinion about.
test_another_lints_site_is_not_a_spawn if {
	count(violation) == 0 with input as {"tree": {"symbols": {
		"provenance": {"tool": "cargo", "version": "1.97.1", "invocation": ["clippy"]},
		"sites": [{
			"path": "crates/batten/src/git.rs",
			"line": 12,
			"lint": "clippy::expect_used",
		}],
	}}}
}

# AN ANALYSER THAT RAN AND FOUND NOTHING IS CLEAN, and it is the answer `null`
# must never be confused with.
test_an_empty_census_is_a_real_clean if {
	count(violation) == 0 with input as census([])
}

# COULD NOT LOOK IS NOT CLEAN (CLOUD-251). `null` is both did-not-look answers --
# no row declared the fact, or the analyser could not be run -- and neither is a
# tree with no unplaced spawns.
test_an_absent_census_refuses_rather_than_passing if {
	some v in violation with input as {"tree": {"symbols": null}}
	v.rule == "spawn-adapters"
}

# The same answer when the key is missing altogether, which is what a row that
# forgot `symbols = true` produces.
test_an_undeclared_census_refuses_too if {
	count(violation) == 1 with input as {"tree": {}}
}

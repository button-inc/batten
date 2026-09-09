# The slow-test ban, and the ratchet that walks it down (CLOUD-1571 follow-on).
#
# WHAT ENFORCES THE BAN IS NOT THIS MODULE. `.config/nextest.toml` declares
# `slow-timeout = { period, terminate-after }`; nextest marks a case slow at
# `period` and KILLS it at `period x terminate-after`, reporting TIMEOUT, and a
# TIMEOUT is a failure because `on-timeout` defaults to "fail". That is the ban,
# in the runner, on every local run and in CI. Measured on this tree before this
# module was written: a case run under a 50ms period reported `TERMINATING`, then
# `TIMEOUT`, then `error: test run failed`, exit 100.
#
# THIS MODULE ONLY REFUSES WEAKENING IT. The split matters. A gate that
# re-derived per-case durations would be the instrument this repository has
# already refused twice — `mise-tasks/suite-bench-check.sh` records that a
# duration gate "would be red on every second run and would be bypassed within a
# day", and CLOUD-1419 wrote an aggregate ratchet and withdrew it in the same
# branch because its first firing was on the change that improved the thing it
# guarded. The runner's timeout has neither problem, so the honest division is:
# nextest measures and decides, batten guards the declaration.
#
# IT GATES THE KILL THRESHOLD, NOT THE PERIOD, AND THE FIRST VERSION GOT THAT
# WRONG. That version bounded `period` alone — which is only when a case is
# MARKED slow. `terminate-after` is the multiplier that decides when it is
# actually killed, so `period = "10s"` with `terminate-after = 10000` passed the
# gate while banning nothing at all. The bound has to be on the product, because
# the product is what refuses a test.
#
# THE CEILING IS A LITERAL HERE, exactly as `perf-assert.rego` holds its budgets.
# A `policy/*.rego` module IS consumer config, so a number is at home in it;
# non-negotiable rule 1 scopes to `crates/batten`. `rules/policy-modules.md`
# refuses a threshold spelled as a `[[pattern]]` row for the opposite reason —
# arithmetic is not a concept with one spelling — and this is not that.
#
# THE RATCHET IS "NEVER ABOVE", NOT "ALWAYS EXACTLY". `ceiling_seconds` is the
# committed maximum kill threshold. Lowering it in `.config/nextest.toml` is free,
# which is the whole point: a branch that makes the suite faster tightens the
# bound without negotiating with this gate. Raising it above the ceiling is
# refused, and lowering the CEILING is a reviewed edit to this file that a reader
# sees in the diff. That asymmetry is what a ratchet is.
#
# AND THE DAY-ONE CEILING IS A RUNAWAY GUARD RATHER THAN A PER-CASE SLOW BAN,
# which is a measured retreat rather than a preference. Three calibration attempts
# were each refused by CI: a 90s kill, then a 240s override, then 1200s, and the
# last refusal was the three `symbols` cases at exactly 90s. CLOUD-1439 documents
# why those three: they share one cold `cargo clippy` build, so under parallelism
# one builds and two WAIT, and nextest bills all three the build. On the Windows
# runner that build is far slower than on any box this repository can measure
# from. A fourth guess at a number nobody here can observe is the same mistake a
# fourth time.
#
# So the ceiling starts above the whole known band — Windows reports 8 cases over
# 10s and 3 over 90s — and the VISIBILITY period stays at 10s, so every one of
# those cases is named on every run. The ban today is on runaway and hung tests;
# tightening it toward the per-case target is exactly what this ratchet exists to
# do, one reviewed step at a time, on cross-platform data nobody had when it was
# armed.
#
# NO INLINE REGEX, AND THE PARSE IS STRING BUILTINS ONLY. An inline pattern is
# refused at load and this is not a concept the `[[pattern]]` registry should
# carry, so both halves are read by splitting the line.
#
# AND AN UNREADABLE DECLARATION REFUSES RATHER THAN PASSING, which is the
# direction that matters. nextest accepts `2m` and `500ms` as well as `10s`; both
# would leave `to_number` undefined, the comparison unreachable, and the gate
# silently green over a bound nobody is enforcing. So the absent, the
# unterminated and the unreadable are ONE class — every one of them means no ban
# is in force that this gate can vouch for.
#MUTANT-SUITE crates/batten/tests/it/nextest_slow.rs
#MUTANT terminator-unread|s@^\tcontains(line, "terminate-after")$@\ttrue@|a_declaration_without_terminate_after_is_refused
#MUTANT ceiling-may-rise|s@^\tkill > ceiling_seconds$@\tfalse@|a_kill_threshold_above_the_ceiling_is_refused
#MUTANT declaration-unread|s@^lines := input.tree.lines\[config\]$@lines := []@|the_committed_config_declares_a_terminating_slow_timeout
#MUTANT override-reason-unread|s@^\tnot filed(i)$@\ttrue@|an_override_that_cites_a_row_is_clean
#MUTANT multiplier-ignored|s@^\tkill := period \* multiplier$@\tkill := period@|a_kill_threshold_above_the_ceiling_is_refused
#
# THE THIRD MUTATION EMPTIES THE LINE WALK rather than negating a conjunct, for
# `landing-roster-guarded`'s reason: emptying it makes the declaration
# unreachable, which reddens the PASS case over the real committed file. The
# fourth is the one the first version of this module could not have: dropping the
# multiplier restores the period-only bound, which is precisely the hole that
# shipped, and it reddens the case where a large `terminate-after` carries the
# kill past the ceiling while the period stays small.

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.nextest_slow

import rego.v1

rules contains "suite bind missing"

rules contains "bound edit refused"

rules contains "waiver file missing"

# The runner's committed configuration. A consumer path in a consumer module,
# which is where non-negotiable rule 1 puts it.
config := ".config/nextest.toml"

# The ceiling, in seconds: the largest KILL THRESHOLD this repository accepts,
# where the threshold is `period x terminate-after` and not the period alone.
#
# Walked down as the suite gets faster, one reviewed step at a time. It sits above
# today's whole known band on the slowest runner, so the gate's first firing can
# only be on a change that loosens the bound — never on the tree it inherits,
# which is the shape `fixture-forks.rego` records as the one that gets an
# exception written for it "and the exception is what rots".
ceiling_seconds := 1200

# The committed runner config, by line index — the index is load-bearing, because
# which SECTION a `slow-timeout` sits under is what says whether it is the default
# bound or a named exception.
lines := input.tree.lines[config]

# The nearest section header at or before `i`. A TOML file is ordered, so the last
# header before a line is the table that line belongs to; there is no other way to
# tell a `[profile.default]` value from a `[[profile.default.overrides]]` one when
# reading lines.
section(i) := header if {
	before := [j |
		some j, line in lines
		j < i
		startswith(trim_space(line), "[")
	]
	count(before) > 0
	header := trim_space(lines[max(before)])
}

# A non-comment line declaring BOTH halves of the ban. `period` alone only
# reports; it is `terminate-after` that kills, so a declaration carrying one and
# not the other is not a ban and must not read as one.
terminating_at contains i if {
	some i, line in lines
	not startswith(trim_space(line), "#")
	contains(line, "slow-timeout")
	contains(line, "period")
	contains(line, "terminate-after")
}

# THE DEFAULT BOUND: what every case is held to, and the only thing the ceiling
# speaks about.
terminating contains lines[i] if {
	some i in terminating_at
	section(i) == "[profile.default]"
}

# AN EXCEPTION: a per-test override. The ceiling deliberately does NOT reach these
# — bounding them by the default's number would make the exception mechanism
# unusable, and a gate that forbids the sanctioned escape is the shape that gets
# switched off. What they owe instead is a filed reason, below.
override_at contains i if {
	some i in terminating_at
	startswith(section(i), "[[profile.default.overrides]]")
}

# An override whose preceding comment block cites a tracker row. The window is
# generous because the rationale for an exception is prose, and prose is the point
# — an exception nobody explained is the thing this refuses.
filed(i) if {
	some j, line in lines
	j < i
	i - j <= 30
	contains(line, "CLOUD-")
}

# The kill threshold in seconds: `period x terminate-after`, read with string
# builtins alone.
#
# Undefined where either half is not readable — a period that is not `<digits>s`,
# or a multiplier that is not an integer — which is deliberate and is what the
# `nextest-slow-unbounded` arm below turns into a refusal, rather than letting
# `2m` or `500ms` leave the comparison unreachable and the gate green.
kill_seconds contains kill if {
	some line in terminating
	quoted := split(line, "\"")
	count(quoted) > 1
	value := quoted[1]
	endswith(value, "s")
	not endswith(value, "ms")
	period := to_number(trim_suffix(value, "s"))

	after := split(line, "terminate-after")
	count(after) > 1
	assigned := split(after[1], "=")
	count(assigned) > 1
	multiplier := to_number(trim_space(trim_suffix(trim_space(assigned[1]), "}")))

	kill := period * multiplier
}

# NO TERMINATING DECLARATION THIS GATE CAN READ.
#
# Absent, comment-only, missing `terminate-after`, or carrying a period in a unit
# this module cannot convert — one class, because every one of them means no ban
# is in force that can be vouched for. Refusing on an unreadable unit is the
# fail-closed direction: the alternative is a silently unreachable comparison.
violation contains {
	"rule": "suite bind missing",
	"verdict": "suite bind missing",
	"subjects": [{"path": config}],
} if {
	count(kill_seconds) == 0
}

# THE RATCHET. A kill threshold above the committed ceiling is refused; below it
# is free, so making the suite faster never has to negotiate with this gate.
violation contains {
	"rule": "bound edit refused",
	"verdict": "bound edit refused",
	"subjects": [{"path": config}],
} if {
	some kill in kill_seconds
	kill > ceiling_seconds
}

# AN EXCEPTION NOBODY EXPLAINED. A per-test override is how a legitimately slow
# case keeps the ban in force everywhere else — but an override with no filed row
# behind it is just the ban switched off for whichever test was inconvenient, and
# it is the thing that rots.
violation contains {
	"rule": "waiver file missing",
	"verdict": "waiver file missing",
	"subjects": [{"path": config}],
} if {
	some i in override_at
	not filed(i)
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds the input the
# predicate reads — `with input as` fabricates the very shape the engine may be
# unable to produce — so `crates/batten/tests/it/nextest_slow.rs` runs the same
# questions over the compiled binary against the real committed file. Both tiers,
# per `rules/policy-modules.md`, and the second is not optional.

tree(lines) := {"tree": {"lines": lines}}

armed := ["[profile.default]", "slow-timeout = { period = \"10s\", terminate-after = 120 }"]

report_only := ["[profile.default]", "slow-timeout = \"10s\""]

raised := ["[profile.default]", "slow-timeout = { period = \"30s\", terminate-after = 60 }"]

minutes := ["[profile.default]", "slow-timeout = { period = \"2m\", terminate-after = 3 }"]

commented := ["[profile.default]", "# slow-timeout = { period = \"10s\", terminate-after = 30 }"]

# THE PASS SIDE FIRST: without it every refusal below is satisfied by a module
# that refuses everything.
test_an_armed_declaration_at_the_ceiling_is_clean if {
	count(violation) == 0 with input as tree({".config/nextest.toml": armed})
}

# LOWERING IS FREE, which is the ratchet's whole asymmetry.
test_a_kill_threshold_below_the_ceiling_is_clean if {
	count(violation) == 0 with input as tree({".config/nextest.toml": [
		"[profile.default]",
		"slow-timeout = { period = \"5s\", terminate-after = 4 }",
	]})
}

# `period` ALONE ONLY REPORTS. A declaration that marks a case slow and never
# kills it is not a ban, and must not read as one.
test_a_period_without_terminate_after_is_refused if {
	count(violation) == 1 with input as tree({".config/nextest.toml": report_only})
}

# THE HOLE THE FIRST VERSION SHIPPED WITH. A small period and a large multiplier
# carries the kill past the ceiling while the period alone stays well inside it —
# `10 x 100` is 1000s. A gate bounding the period would pass this and ban nothing.
test_a_small_period_with_a_large_multiplier_is_refused if {
	count(violation) == 1 with input as tree({".config/nextest.toml": [
		"[profile.default]",
		"slow-timeout = { period = \"10s\", terminate-after = 200 }",
	]})
}

test_a_kill_threshold_above_the_ceiling_is_refused if {
	count(violation) == 1 with input as tree({".config/nextest.toml": raised})
}

# A UNIT THIS MODULE CANNOT CONVERT REFUSES rather than leaving the comparison
# unreachable. `2m` is a legal nextest value and a silent hole without this.
test_a_period_in_an_unconvertible_unit_is_refused if {
	count(violation) == 1 with input as tree({".config/nextest.toml": minutes})
}

# A COMMENTED-OUT DECLARATION IS NOT A DECLARATION.
test_a_commented_declaration_does_not_arm_the_ban if {
	count(violation) == 1 with input as tree({".config/nextest.toml": commented})
}

# ABSENCE IS THE SAME CLASS: a tree with no runner config has no ban in force.
test_an_absent_config_is_refused if {
	count(violation) == 1 with input as tree({})
}

# THE POINTER IS THE FILE a reader opens (rule 4), and the class is the one the
# registry declares for it.
test_the_refusal_points_at_the_runner_config if {
	some v in violation with input as tree({".config/nextest.toml": raised})
	v.subjects[0].path == ".config/nextest.toml"
	v.verdict == "bound edit refused"
}

# --- the exception mechanism -------------------------------------------------

unfiled_override := [
	"[profile.default]",
	"slow-timeout = { period = \"10s\", terminate-after = 30 }",
	"",
	"[[profile.default.overrides]]",
	"filter = 'test(something_slow)'",
	"slow-timeout = { period = \"10s\", terminate-after = 120 }",
]

filed_override := [
	"[profile.default]",
	"slow-timeout = { period = \"10s\", terminate-after = 30 }",
	"",
	"# CLOUD-1641 owns making this case fast; deleting this row is its acceptance.",
	"[[profile.default.overrides]]",
	"filter = 'test(something_slow)'",
	"slow-timeout = { period = \"10s\", terminate-after = 120 }",
]

# AN EXCEPTION NOBODY EXPLAINED. The override is above the ceiling and that is
# FINE — the ceiling does not reach an override, deliberately. What is refused is
# that no row was cited for it.
test_an_override_citing_no_row_is_refused if {
	count(violation) == 1 with input as tree({".config/nextest.toml": unfiled_override})
}

# AND THE SAME OVERRIDE WITH A ROW IS CLEAN, which is what shows the refusal turns
# on the missing reason rather than on the override existing at all. Without this
# case the rule above is satisfied by a module that refuses every override.
test_an_override_that_cites_a_row_is_clean if {
	count(violation) == 0 with input as tree({".config/nextest.toml": filed_override})
}

# THE CEILING DOES NOT REACH AN OVERRIDE, stated as its own case because the first
# version conflated the two and refused the committed config: it bounded every
# `slow-timeout` line by the default's number, which makes the sanctioned
# exception mechanism unusable — the shape that gets a gate switched off.
test_an_override_above_the_ceiling_is_not_a_raise if {
	every v in violation {
		v.rule != "nextest-slow-raised"
	} with input as tree({".config/nextest.toml": filed_override})
}

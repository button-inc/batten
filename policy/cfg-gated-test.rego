# CLOUD-1148's missing mechanism: a `#[cfg(<platform>)]` is not ADDED to a
# `#[test]`.
#
# WHAT THE DEFECT WAS, MEASURED. `scratch.rs`'s reaper case asserted collection
# unconditionally; `pid_is_live` is two functions, and off unix the module
# abstains by construction, so the `windows` job reddened while every other leg
# was green. The first fix put `#[cfg(unix)]` over the case and added a
# `#[cfg(not(unix))]` twin. That turns a red leg green while leaving one arm
# NEVER COMPILED on the host that authors it — `cross-check` type-checks what
# `cfg` admits, so the off-unix arm goes unparsed locally and the next edit to it
# is discovered by CI. The second fix used `cfg!`, which keeps both arms compiled
# on every target and states the Windows contract inside the case.
#
# The doctrine landed as two doc comments and NO GATE, which is non-negotiable
# rule 2 violated by the commit that closed the class. This is the other half.
#
# A RATCHET OVER THE DIFF, NOT A STATE RULE, AND THAT IS THE WHOLE DESIGN.
# Measured before writing a line: this tree carries ~40 `#[cfg(unix)]` `#[test]`
# pairs, and they are not the defect. `hk_fix_selection.rs` runs a real hk gate,
# `bats_invocation.rs` runs bats, `stop_posture.rs` chmods a stub — their SUBJECT
# does not exist off unix, so the case cannot either. The defect is a case whose
# subject compiles everywhere being narrowed to one platform to silence a leg.
# A state rule cannot tell those apart and would refuse all 40 on its first run,
# which is the shape `batten.toml`'s own preamble to `bash-surface-not-growing`
# refuses in as many words: a gate whose first firing is a false positive gets an
# exception written for it, and the exception is what rots.
#
# So the decidable question is the DIRECTION: did this branch add one. That is
# exactly the class the first fix was, and `input.tree["base-delta"]` answers it
# without a spawn — `base-lines` is the base side of every edited path, so the
# comparison is the engine's rather than a second reading of git.
#
# WHY A COUNT PER PATH RATHER THAN A LINE IDENTITY. A line's text is not its
# identity across a rebase, and `land` rebases every lap — a predicate keyed on
# which line moved would re-fire on a change that moved nothing, which is the
# per-lap re-attestation `rules/policy-modules.md` names as the cost that gets a
# gate switched off. Counting the pairs on each side is stable under reordering
# and reindentation, and it under-denies in exactly one direction: swapping a
# legitimate unix-only case for an illegitimate one in the same file. That
# residue is named rather than silent.
#
# NO INLINE REGEX. The `[[pattern]]` rule refuses one at load, and none is needed:
# every test here is a string builtin over a trimmed line, which is the spelling
# `ci-cache-declared.rego` already uses for the same reason.
#
#MUTANT-SUITE crates/batten/tests/it/cfg_gated_test.rs
# `[12]` RATHER THAN `1`, AND THE FIRST SPELLING SURVIVED. Naming only
# `start + 1` neuters the two-hop body and the three-hop body's FIRST conjunct;
# its second, `attribute_or_doc(lines[start + 2])`, still reads the blank line in
# the named case's fixture and refutes the join, so the case stayed green and the
# sweep reported `SURVIVED` with no owner. A declared mutation whose named case
# cannot observe the change is a defect in the DECLARATION — `test-targets.rego`
# records the same lesson for `extension-may-widen` — so the expression has to
# reach every conjunct of the predicate it claims to neuter.
#MUTANT block-may-span-code|s@^\tattribute_or_doc(lines\[start + [12]\])$@\ttrue@|a_cfg_far_from_the_test_with_code_between_is_not_a_gated_test
#MUTANT reach-may-be-empty|s@^reach := \[1, 2, 3\]$@reach := []@|a_branch_that_adds_a_platform_gated_test_is_refused
#MUTANT direction-may-invert|s@\tafter > base@\tafter < base@|a_branch_that_adds_a_platform_gated_test_is_refused
#MUTANT base-may-read-as-empty|s@\tbase := gated_tests(base_lines_of(path))@\tbase := 0@|a_pre_existing_platform_gated_test_survives_an_edit
package batten

import rego.v1

rules contains "test cover unseen"

# The branch's own diff, BOUND THROUGH AN OBJECT GUARD because `null` is not
# `undefined`: the engine emits `null` where the base would not resolve, and
# `not input.tree["base-delta"]` is dead for exactly that value.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# THE COULD-NOT-LOOK ARM. A shallow clone, a detached CI checkout with the base
# unfetched, or a fork with no `origin/main` has no delta — and a rule that
# refuses nothing is byte-identical to a tree that added nothing on the decision
# surface, so the read failure is REPORTED rather than passed.
violation contains {
	"rule": "test cover unseen",
	"verdict": "diff read absent",
	"subjects": [{"path": "batten.toml"}],
} if {
	not delta
}

# The `cfg` predicates that name a PLATFORM. `#[cfg(test)]` on the module and
# `#[cfg(feature = "x")]` are deliberately absent: neither varies with the target,
# so neither can leave an arm uncompiled by `cross-check`.
platform_tokens := ["unix", "windows", "target_os", "target_family", "target_arch", "target_env"]

platform_cfg(line) if {
	trimmed := trim_space(line)
	startswith(trimmed, "#[cfg(")
	some token in platform_tokens
	contains(trimmed, token)
}

# NOT `test_attr`. A rule whose name begins `test_` IS the load-time tier, so the
# first spelling of this helper was RUN as a case and `policy test` reported
# `cfg-gated-test test-failed policy/cfg-gated-test.rego test_attr` — a naming
# collision that presents as a broken predicate.
case_attr(line) if {
	startswith(trim_space(line), "#[test]")
}

# An attribute or doc line — what may stand BETWEEN a `cfg` and the `#[test]` it
# gates without breaking the block.
#
# `//` rather than `///` so an ordinary comment inside an attribute run does not
# split the block; a one-keystroke evasion is the class the `words[0]` table in
# `rules/policy-modules.md` measures, and inserting `#[allow(…)]` or a comment
# between the two lines is exactly that keystroke.
attribute_or_doc(line) if {
	startswith(trim_space(line), "#[")
}

attribute_or_doc(line) if {
	startswith(trim_space(line), "//")
}

# THE REACH, DECLARED RATHER THAN SCANNED, AND IT IS WHAT MAKES THIS GATE
# RUNNABLE AT ALL.
#
# Two spellings preceded this one and both are unshippable — measured, not
# reasoned. The first was `every index, line in lines { block_ok(…) }`, which
# walks the whole file for every candidate `(cfg, test)` pair. The second kept
# the pairing and narrowed the inner test to `not gap_dirty`, which stops at the
# first breaking line. `batten check --rule 'test cover missing'` took **1099s** over
# this tree on the second spelling, where the same-`delta_sources`
# `test-targets` takes **1s**. So the PAIRING is the cost and no inner test
# removes it: `exec.rs` alone is ~30 `cfg` lines against ~60 `#[test]` lines over
# 2700 lines, which is ~1800 pairs for one file.
#
# A gate too slow to run inside `verify` is a gate that gets switched off, which
# is the same outcome as a gate that decides nothing.
#
# Rego has no fold to walk an attribute run with, so the reach is a DECLARED set
# of offsets and the predicate is linear in the file. Three is not a guess:
# `#[test]` is the item's own marker and stands LAST in the run by convention, so
# every instance measured here — the CLOUD-1148 defect itself, the three this
# gate found on its first run over this branch, and all ~40 pre-existing pairs —
# has its `cfg` on the line immediately beside the `#[test]`. The two spare hops
# cover an `#[allow]` or an `#[expect]` written between them, which is the
# one-keystroke evasion `rules/policy-modules.md`'s `words[0]` table exists to
# refuse.
#
# THE RESIDUE IS NAMED RATHER THAN SILENT: four or more attribute lines between
# the `cfg` and the `#[test]` reach no offset and are not refused. CLOUD-1669.
#
# THIS LINE SAID CLOUD-1667 AND THAT KEY IS SOMEBODY ELSE'S ROW — `perf` is CI's
# second pole at 574s. The key was predicted from the last one filed rather than
# read back from the row that was created, which is a misattribution wearing a
# filed row's clothes: a reader following it lands on unrelated work and reads it
# as an answer. `7426f8c6`'s `Refs:` trailer carries the same wrong key and is
# corrected here rather than by rewriting the record.
reach := [1, 2, 3]

# A platform `cfg` at `index` gates a `#[test]` standing BELOW it.
gates_below(lines, index) if {
	some hop in reach
	case_attr(lines[index + hop])
	run_is_clean(lines, index, hop)
}

# And ABOVE it. `#[test]` then `#[cfg(unix)]` compiles to exactly the same item,
# so a rule reading one order is a bypass with the two lines swapped.
gates_above(lines, index) if {
	some hop in reach
	case_attr(lines[index - hop])
	run_is_clean(lines, index - hop, hop)
}

# Every line strictly inside a hop of `hop` from `start` is an attribute or a
# comment, so the two ends are in ONE run rather than in two separated by code.
#
# Written out per offset because `reach` has three members: a loop over an index
# range is the scan the bound above exists to avoid, and at three members the
# enumeration is shorter than the arithmetic would be.
run_is_clean(_, _, 1) := true

run_is_clean(lines, start, 2) if {
	attribute_or_doc(lines[start + 1])
}

run_is_clean(lines, start, 3) if {
	attribute_or_doc(lines[start + 1])
	attribute_or_doc(lines[start + 2])
}

gated_here(lines, index) if {
	gates_below(lines, index)
}

gated_here(lines, index) if {
	gates_above(lines, index)
}

# How many `#[test]` cases in this file are narrowed to a platform.
#
# COUNTED OVER THE `cfg` LINES rather than over pairs, which is the same change
# read forwards: two `cfg` attributes on one case count two, and a ratchet only
# ever asks whether the number went up.
gated_tests(lines) := count([index |
	some index, line in lines
	platform_cfg(line)
	gated_here(lines, index)
])

# An ADDED path has no base side, and its base count is therefore zero rather
# than unreadable: a new file carrying a platform-gated test is the same defect
# arriving in one commit instead of two.
base_lines_of(path) := lines if {
	lines := delta["base-lines"][path]
}

base_lines_of(path) := [] if {
	not delta["base-lines"][path]
}

touched contains path if {
	some path in delta.added
}

touched contains path if {
	some path in delta.edited
}

grew contains [path, after] if {
	some path in touched
	endswith(path, ".rs")
	after := gated_tests(input.tree.lines[path])
	base := gated_tests(base_lines_of(path))
	after > base
}

violation contains {
	"rule": "test cover unseen",
	"verdict": "test cover partial",
	"subjects": [{"path": path}, {"count": after}],
} if {
	some [path, after] in grew
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/cfg_gated_test.rs` is the tier
# that proves the ENGINE builds `base-lines` at all — a `with input as` case
# fabricates the very shape the engine may be unable to produce, which is how a
# dead clause survives. Both tiers, and the second is not optional.

test_a_branch_that_adds_a_platform_gated_test_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"crates/batten/src/scratch.rs": ["#[cfg(unix)]", "#[test]", "fn a() {}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/scratch.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# THE ORDER THAT COMPILES THE SAME AND WOULD OTHERWISE BYPASS.
test_the_attribute_order_does_not_matter if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"crates/batten/src/scratch.rs": ["#[test]", "#[cfg(windows)]", "fn a() {}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/scratch.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# THE ONE-KEYSTROKE EVASION. An `#[allow]` or a comment between the two lines
# does not break the gate.
test_an_interleaved_attribute_does_not_break_the_block if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"crates/batten/src/scratch.rs": [
			"#[cfg(target_os = \"linux\")]",
			"#[allow(clippy::unwrap_used)]",
			"/// what it does",
			"#[test]",
			"fn a() {}",
		]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/scratch.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# THE CASE THAT MAKES THE RULE SURVIVABLE, and the reason this is a ratchet: the
# ~40 pairs already in the tree are not refused when their file is edited.
test_a_pre_existing_platform_gated_test_survives_an_edit if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/tests/it/bats_invocation.rs": ["#[cfg(unix)]", "#[test]", "fn a() {}", "// a new comment"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/tests/it/bats_invocation.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/tests/it/bats_invocation.rs": ["#[cfg(unix)]", "#[test]", "fn a() {}"]},
		},
	}}
}

# `#[cfg(unix)]` ON A HELPER is not this rule's business. It gates no case, and
# a unix-only fixture builder is how the legitimate pairs above are written.
test_a_cfg_on_a_plain_function_is_not_a_gated_test if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/tests/it/stop_posture.rs": ["#[cfg(unix)]", "fn stub() {}", "#[test]", "fn a() {}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/tests/it/stop_posture.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/tests/it/stop_posture.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# THE DISCRIMINATING PARTNER for `block-may-span-code`. Code between the two
# lines means the `cfg` gates the code, not the case — and with
# `attribute_or_doc` neutered to `true` this would be refused.
test_a_cfg_far_from_the_test_with_code_between_is_not_a_gated_test if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/src/task.rs": ["#[cfg(unix)]", "use rustix::process;", "#[test]", "fn a() {}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/task.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/task.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# `#[cfg(test)]` IS THE MODULE GATE and varies with no target, so it never
# leaves an arm uncompiled. Refusing it would refuse every unit-test module in
# the crate.
test_the_test_module_gate_is_not_a_platform_gate if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/src/scratch.rs": ["#[cfg(test)]", "mod tests {", "#[test]", "fn a() {}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/scratch.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# `cfg!` IS THE REMEDY, so the shape the doctrine asks for must pass.
test_the_cfg_macro_inside_the_body_is_the_remedy if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {", "if cfg!(unix) { assert!(true) }", "}"]},
		"base-delta": {
			"added": [],
			"edited": ["crates/batten/src/scratch.rs"],
			"deleted": [],
			"base-lines": {"crates/batten/src/scratch.rs": ["#[test]", "fn a() {}"]},
		},
	}}
}

# AN ADDED FILE HAS NO BASE SIDE, and its count is zero rather than unreadable.
test_an_added_file_carrying_a_gated_test_is_refused if {
	count(violation) == 1 with input as {"tree": {
		"lines": {"crates/batten/tests/it/new_gate.rs": ["#[cfg(unix)]", "#[test]", "fn a() {}"]},
		"base-delta": {
			"added": ["crates/batten/tests/it/new_gate.rs"],
			"edited": [],
			"deleted": [],
			"base-lines": {},
		},
	}}
}

# A NON-RUST PATH carries no attributes; reading its lines for them would be a
# gate looking in the wrong place and reporting clean from it.
test_a_non_rust_path_is_not_read_for_attributes if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"batten.toml": ["#[cfg(unix)]", "#[test]"]},
		"base-delta": {
			"added": [],
			"edited": ["batten.toml"],
			"deleted": [],
			"base-lines": {"batten.toml": []},
		},
	}}
}

# COULD NOT LOOK, reported rather than passed.
test_an_unresolvable_base_reports_rather_than_passing if {
	some v in violation with input as {"tree": {"lines": {}, "base-delta": null}}
	v.verdict == "diff read absent"
}

# AND THE ARM MUST NOT FIRE OVER A DELTA THAT DID RESOLVE, which is what says the
# object guard binds rather than that the arm is unconditional.
test_a_resolved_delta_reports_no_read_failure if {
	count(violation) == 0 with input as {"tree": {
		"lines": {},
		"base-delta": {"added": [], "edited": [], "deleted": [], "base-lines": {}},
	}}
}

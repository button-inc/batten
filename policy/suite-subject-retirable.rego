# A bats suite whose `# subject:` can never die is unreachable by the whole shell
# retirement campaign, and nothing said so (CLOUD-1156).
#
# `SubjectFacts::died` (`crates/batten/src/rules.rs`) is `subjects.iter().all(...)`:
# EVERY declared subject must be absent from the head tree before a suite's
# deletion is admitted. That rule is right, and its own comment says why — "a
# suite declaring two subjects of which one still stands has work left, and
# admitting it on the strength of the other is how a partial retirement passes as
# a whole one." This module does not touch it.
#
# What was never measured is the CONSEQUENCE. `governed_when_deleted`
# (`policy/shell-retirement.rego:138-140`) is `mise-tasks/**` minus `.py`/`.tsv`,
# plus any `tests/**/*.bats`. A suite subjecting `mise.toml`, `hk.pkl`,
# `batten.toml`, `clippy.toml`, `install.sh`, a workflow, a `.claude/hooks/`
# program or a Rust source file therefore names something no shell retirement
# deletes, so `.all()` can never hold, so the suite is undeletable BY
# CONSTRUCTION AND IN SILENCE.
#
# MEASURED AT `ccb40a13`: 19 of 144 suites, 302.0s of a 1440.9s serial corpus —
# 21.0% unreachable by the entire campaign. Two of them are worse than
# undeletable: they glue a GOVERNED program to an immortal subject, so that
# program has no landable retirement at all. Both are named in `exempt` below.
#
# ---------------------------------------------------------------------------
# WHY THE ANSWER IS A DECLARED EXEMPTION AND NOT THE TWO OBVIOUS ALTERNATIVES
# ---------------------------------------------------------------------------
#
# CLOUD-1156 offered three routes. Two of them cannot be landed by the gate they
# are about, which is the finding that decided this module's shape:
#
#   * RE-SUBJECT THEM — rewriting a `# subject:` line means editing a governed
#     `tests/**/*.bats`. `governed_at_head` selects every bats suite
#     (`shell-retirement.rego:135`), so each is `V-SHELL-RULE-EDITED`, which
#     declares one route and no `bypass_env`. The one admitted edit requires every
#     REMOVED line to name a path the same delta deletes, and a re-subjected header
#     names paths that are staying. Refused.
#
#   * AN IN-FILE MARKER, the way `privileged-lane` carries `#MUTANT-EXEMPT` —
#     that marker lives inside the file, so it is an ADDED line that is neither a
#     truncation nor a repointing. Refused by the same arm.
#
# So the exemption has to live somewhere ungoverned, and the suite file is never
# touched. This table is that place: `policy/` is not governed, since
# `governed_at_head` selects `mise-tasks/` paths and `.bats` suites and nothing
# else.
#
# THE THIRD ROUTE IS OPEN NOW, AND IT IS STILL NOT THIS MODULE'S. A suite over
# `batten.toml` has cases worth porting into `crates/batten/tests/*.rs` even
# though nothing dies — a port WITHOUT a retirement. This paragraph used to end
# "which the ledger has no spelling for"; CLOUD-1268 landed one, so the sentence
# is corrected rather than left to send the next reader looking for a route that
# now exists. The spelling is `[rule.conserves]`'s fifth arm, `// ported:`: a
# target the tree carries plus a `subject:` field naming the survivor, admitted
# only where that subject LIVES — the exact mirror of `// withdrawn:`, and
# refused over a subject the campaign governs, which is what keeps CLOUD-1130
# whole.
#
# EACH SUCH PORT IS STILL ITS OWN ROW, and a ported suite's row LEAVES the table
# below rather than staying in it: arm C holds the table in both directions, so an
# exemption outliving its suite is a finding. This module only refuses a new
# instance arriving unnoticed, which is the acceptance CLOUD-1156 owes.
#
# ABSENCE IS AN ERROR, NOT AN ALLOW, and the table is held in BOTH directions —
# `module-layering`'s posture, for its reason. An unexempted immortal subject is
# refused; an exemption for a suite that is gone, or that has become fully
# retirable, is refused too. Without the second arm the table only ever grows and
# becomes the stale census CLOUD-929 deleted four of.
#
# POINTER-ONLY. A suite path and a subject path, both of which the reader can open
# themselves. Never a case body, never a line of a suite — non-negotiable rule 4.
#
#MUTANT-EXEMPT CLOUD-931|no `tests/suite-subject-retirable.bats` exists and none may: `V-SHELL-RULE-ADDED` refuses adding a bats suite at `deny`, and this row's whole subject is suites that cannot be edited, so a suite named for it would be the thing it refuses. `mutant` resolves a gate's suite as `tests/$gate.bats`, so there is no named case a mutation could turn red. The second tier is `crates/batten/tests/suite_subjects.rs`, which drives the compiled binary

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.suite_subject_retirable

import rego.v1

rules contains "suite-subject-retirable"

# --- what the campaign can actually delete ------------------------------------

# `governed_when_deleted`, restated because a module cannot import another
# module's rules. Held to the original by
# `crates/batten/tests/suite_subjects.rs`, so this is a second SPELLING and never
# a second authority.
is_bats(path) if {
	startswith(path, "tests/")
	endswith(path, ".bats")
}

retirable(path) if {
	startswith(path, "mise-tasks/")
	not endswith(path, ".py")
	not endswith(path, ".tsv")
}

retirable(path) if is_bats(path)

# --- the suites in view, and what each declares -------------------------------

# THE ROW'S OWN `line_sources` IS THE BOUND. A suite the declaration does not
# select is not judged, which is the difference between this and a tree walk.
suites := {path | some path, _ in input.tree.lines; is_bats(path)}

# The `# subject:` header, split on whitespace.
#
# A partial rule keyed by path rather than a function, so a suite carrying no
# header simply has no entry — which is what `V-SUITE-SUBJECT-UNDECLARED` below
# catches, rather than letting it fall through as a suite with nothing wrong.
declared[path] := parts if {
	some path in suites
	some line in input.tree.lines[path]
	startswith(line, "# subject:")
	parts := {word |
		some word in split(trim_space(substring(line, 10, -1)), " ")
		word != ""
	}
}

# --- the exemptions, and why each one is here ---------------------------------
#
# The value is the immortal subject itself, not prose about the suite: what makes
# a suite unreachable is what its subject IS, and carrying that shows the reader
# this is five kinds rather than eighteen accidents — a task manifest, a hook
# config, the policy authority, a launcher hook, and a source file.
#
# WHAT AN EXEMPTION MEANS NOW, AND IT IS NO LONGER "THE SUBJECT CANNOT DIE"
# (CLOUD-1268). That reason was true when this table was written and is answered:
# `// ported:` admits a deletion whose subject survives, and two rows have already
# left this table by spending it.
#
# SO THE TABLE NOW HOLDS THREE KINDS, AND THIRTEEN OF THE SEVENTEEN ARE THE FIRST.
# Counting them is the point: a reader who takes "exempt on cost" for the whole
# table would conclude the other four are cheap ports nobody got to, which is the
# opposite of true for every one of them.
#
#   * COST (13 rows, 11.4s total against a 667.4s corpus). Portable today — each
#     would owe a ledger block and a Rust port spawning whatever its subject is,
#     for a sub-second yield. Unported, NOT unportable, and a row that wants one
#     only has to be worth writing.
#   * STRUCTURE (3 rows, 9.2s). `replay` subjects `mise-tasks/replay-pointers.py`,
#     which `governed_when_deleted` excludes by extension; `release-tracking-check`
#     and `remedy-payload-source` each name a subject that is GOVERNED and alive,
#     which `V-PORT-SUBJECT-GOVERNED` refuses on purpose — a live governed path is
#     something the campaign retires, and porting a suite away from one is the
#     claim `named_and_alive` already refuses under the other four markers. No
#     amount of willingness moves these; each owes its own row.
#   * ITS OWN ROW (`session-start`, 97.8s), below.
#
# ONE IS NOT ABOUT COST AND HAS ITS OWN ROW. `session-start` is the largest suite
# here by two orders of magnitude, and porting it would move its seconds rather
# than remove them — the cost is `mise install` in the two cases that opt back in
# through `real_install_or_skip`, not the bats harness. Its remedy is warming the
# toolchain once in `[tasks."test:bats"]`, which is CLOUD-1273's and is not a
# retirement at all. `.claude/hooks/session-start.sh` was never governed for edits
# OR for deletion either, so filing it under an immortal subject sent every pass at
# it toward a retirement it never needed.
#
# TWO CARRY A SECOND VERDICT THE ROW OWES SEPARATELY. `release-tracking-check` and
# `remedy-payload-source` each glue a GOVERNED program to an immortal subject, so
# `mise-tasks/release-tracking-check.sh` and `mise-tasks/board-payloads.sh` are
# STRANDED — no landable retirement exists for either while these suites stand.
# Exempting the suite does not unstrand the program, and each owes its own row.
# `board-payloads.sh` carries three reasons at once (this, CLOUD-1172's transcript
# read, and being the producer CLOUD-1154 needs), which is CLOUD-1174's
# "blockers are a set, not a partition" in the concrete.
exempt := {
	"tests/commit-attribution.bats": "hk.pkl mise.toml",
	"tests/commit-convention.bats": "batten.toml mise.toml",
	"tests/cross-check.bats": "mise.toml",
	"tests/fact-record-keying.bats": "crates/batten/src/facts.rs",
	"tests/git-hook.bats": ".claude/hooks/git-hook.sh",
	"tests/hk-selection.bats": "hk.pkl",
	"tests/install.bats": "install.sh",
	"tests/lint-deno.bats": "mise.toml",
	"tests/lint-rego.bats": "mise.toml",
	# THE MEMBER A PREFIX SCAN MISSES, and the reason this table is derived from
	# `retirable` rather than from "is it under `mise-tasks/`". A `.py` sibling
	# LOOKS governed and is excluded by extension, so a census testing the prefix
	# alone counts it retirable and drops the suite. That is exactly what happened
	# on the first pass here: 18 suites, and `this_repository_is_clean_today` in
	# `crates/batten/tests/suite_subjects.rs` returned the nineteenth.
	"tests/replay.bats": "mise-tasks/replay-pointers.py — `.py` is excluded from `governed_when_deleted`",
	"tests/release-tracking-check.bats": "workflow yaml — STRANDS mise-tasks/release-tracking-check.sh",
	"tests/remedy-payload-source.bats": "batten.toml — STRANDS mise-tasks/board-payloads.sh",
	"tests/session-start.bats": ".claude/hooks/session-start.sh",
	"tests/spawn-census.bats": "clippy.toml",
	"tests/task-fail-closed.bats": "mise.toml",
	"tests/verify.bats": "mise.toml",
	"tests/zizmor-split.bats": "mise.toml",
}

# --- A: an immortal subject nobody declared ------------------------------------

violation contains {
	"rule": "suite-subject-retirable",
	"verdict": "V-SUITE-SUBJECT-IMMORTAL",
	"subjects": [{"path": path}, {"path": subject}],
} if {
	some path, subjects in declared
	not exempt[path]
	some subject in subjects
	not retirable(subject)
}

# --- B: a suite declaring no subject at all ------------------------------------
#
# THE ANTI-VACUITY ARM, and it is not decoration. Arm A quantifies over a suite's
# declared subjects, so a suite with no header has none, so every subject of it is
# trivially retirable and it passes. Deleting the header would therefore be a way
# OUT of this gate — and a suite with no subject is not retirable either, because
# `SubjectFacts::died` would have nothing to decide over.
violation contains {
	"rule": "suite-subject-retirable",
	"verdict": "V-SUITE-SUBJECT-UNDECLARED",
	"subjects": [{"path": path}],
} if {
	some path in suites
	not declared[path]
}

# --- C: an exemption that is not answering anything ----------------------------
#
# The table held in the other direction, so it cannot only ever grow — otherwise
# it becomes the stale census CLOUD-929 deleted four of.
#
# ONE HALF OF THIS ARM WAS WRITTEN AND THEN REMOVED, and the reason is worth more
# than the check was. The obvious spelling also refuses an exemption whose suite
# is ABSENT — a suite retired out from under its row. Measured against the
# load-time tier: it fired 18 findings on every fixture carrying one suite,
# because a tree that is not this corpus has none of the other seventeen. That is
# exactly the regression #770 hit — *"a rule ported from a task pointed at one
# directory into a config rule now judges every fixture tree inheriting the
# config"* — and the fixture was right then and would be right here: a shipped
# ruleset must not refuse an ordinary minimal repository.
#
# The two cases are not distinguishable from inside the module. "This suite was
# retired" and "this tree is not that corpus" are the same observation — a path in
# neither `lines` nor `missing` — so refusing on it is a claim about the tree that
# the tree does not support. What is left below decides only over a suite that IS
# present, which is decidable everywhere. The cost is stated rather than hidden: a
# retired suite leaves a spent row until someone reads the table.
violation contains {
	"rule": "suite-subject-retirable",
	"verdict": "V-SUITE-EXEMPTION-STALE",
	"subjects": [{"path": path}],
} if {
	some path, _ in exempt
	subjects := declared[path]
	every subject in subjects {
		retirable(subject)
	}
}

# --- could not look ------------------------------------------------------------
#
# A DECLARED SOURCE THAT WOULD NOT READ is not a suite with nothing wrong. A
# module iterating only `lines` reports green over a file it never opened, which
# is the class `.claude/rules/policy-modules.md` records for this channel.
violation contains {
	"rule": "suite-subject-retirable",
	"verdict": "V-SUITE-SOURCE-UNREAD",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	is_bats(path)
}

# --- cases ---------------------------------------------------------------------
#
# The load-time tier. It pins the predicate; it cannot prove the ENGINE builds
# `input.tree.lines` for a `tests/*.bats` glob, which is
# `crates/batten/tests/suite_subjects.rs`'s job and the reason that file exists.

tree(lines, missing) := {"tree": {"lines": lines, "missing": missing}}

# A suite subjecting only governed programs is clean. THE ANTI-VACUITY MIRROR for
# arm A: without it, a rule flagging all 144 suites would satisfy the case below.
test_a_governed_subject_is_not_reported if {
	found := violation with input as tree({"tests/x.bats": ["# subject: mise-tasks/x.sh"]}, [])
	count(found) == 0
}

# The predicate that produced the row.
test_an_immortal_subject_is_reported if {
	found := violation with input as tree({"tests/x.bats": ["# subject: mise.toml"]}, [])
	count(found) == 1
	some finding in found
	finding.verdict == "V-SUITE-SUBJECT-IMMORTAL"
}

# A suite subjecting one retirable path AND one immortal one is reported — the
# `.all()` semantics this row is about, rather than "any subject is fine".
test_one_immortal_subject_among_several_is_reported if {
	found := violation with input as tree({"tests/x.bats": ["# subject: mise-tasks/x.sh hk.pkl"]}, [])
	some finding in found
	finding.verdict == "V-SUITE-SUBJECT-IMMORTAL"
}

# A declared exemption silences arm A and nothing else.
test_a_declared_exemption_is_not_reported if {
	found := violation with input as tree({"tests/verify.bats": ["# subject: mise.toml"]}, [])
	count(found) == 0
}

# A suite with no header is not a clean suite.
test_a_suite_declaring_no_subject_is_reported if {
	found := violation with input as tree({"tests/x.bats": ["@test 'a' { true; }"]}, [])
	count(found) == 1
	some finding in found
	finding.verdict == "V-SUITE-SUBJECT-UNDECLARED"
}

# AN EXEMPTION WHOSE SUITE IS SIMPLY NOT IN THIS TREE IS NOT A FINDING, which is
# the bound arm C's comment records: a fixture is not this corpus, and refusing
# there would make the rule unshippable over any minimal repository.
test_a_tree_that_is_not_this_corpus_is_not_judged_against_the_table if {
	count(violation) == 0 with input as tree({}, [])
}

# And for a suite that has become fully retirable.
test_an_exemption_for_a_now_retirable_suite_is_reported if {
	found := violation with input as tree({"tests/verify.bats": ["# subject: mise-tasks/verify.sh"]}, [])
	some finding in found
	finding.verdict == "V-SUITE-EXEMPTION-STALE"
}

# COULD NOT LOOK stays loud, and is spelled differently from both answers.
test_an_unreadable_suite_is_loud if {
	found := violation with input as tree({}, ["tests/x.bats"])
	some finding in found
	finding.verdict == "V-SUITE-SOURCE-UNREAD"
}

# A non-suite path in `missing` is not this rule's business.
test_an_unreadable_non_suite_is_not_this_rules_business if {
	found := {f |
		some f in violation with input as tree({}, ["mise.toml"])
		f.verdict == "V-SUITE-SOURCE-UNREAD"
	}
	count(found) == 0
}

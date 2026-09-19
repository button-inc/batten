# No commit is signed by a key that cannot be verified or reproduced (CLOUD-669,
# ported off `mise-tasks/signing-posture.sh` under CLOUD-1717).
#
# SIGNING IS GOOD AND THIS IS NOT AGAINST IT. Signing in CI, with a key whose
# public half is published, is the desired end state and CLOUD-591 owns getting
# there. What this refuses is the narrower thing: a signature produced by a key
# that cannot be verified or reproduced, which is WORSE than no signature because
# it looks like provenance and carries none.
#
# WHY IT IS AN ATTRIBUTION DEFECT RATHER THAN A PREFERENCE. Every commit read
# `author` and `committer` the accountable human — correct, and gated by
# `identity_deny` — and `gpgsig` a vendor-held key. `Attribution` carries
# `identity_deny`, `trailer_deny`, `body_deny`, `trailer_allow` and `identity`
# with NO signature field, so the one commit field the attribution gate
# structurally cannot see is the one carrying a vendor identity. This is that
# blind spot's stand-in until CLOUD-440 lets the engine see a commit object.
#
# TWO CLASSES, AND KEEPING THEM APART IS THE POINT. `config carry unsafe` is a
# posture that will produce bad signatures; `commit carry unsafe` is one that
# already did. Config can be repaired AFTER a commit was written, so a repaired
# checkout still carries the signed commits made before the repair — and those
# are exactly what must not reach `main`. Collapsing the two would let the cheap
# half stand in for the expensive one, which is this gate's declared mutation.
#
# BOTH ARE SCOPED TO A BROKEN SIGNER, and that was a real defect rather than a
# refinement. The commit scan once reported EVERY `gpgsig` in range with no
# reference to whether the key behind it is verifiable — so it refused the exact
# end state this gate promises to leave alone, and the row asserting that promise
# passed only because it commits with `--no-gpg-sign` and never produced a header
# for the scan to see. A vacuous row over a contradicted predicate (CLOUD-418);
# caught in review on PR #489.
#
# THE CONFIG CLASS IS THE CONFLICT, NEVER THE MERE ABSENCE OF A LOCAL KEY.
# Demanding a local override unconditionally would red every CI run: a runner has
# no launcher and no global setting, so there is nothing to override and an
# absent local value is the correct state there. The producer records what is
# INHERITED alongside what is local, and the refusal needs both.
#
# RANGE, NEVER HISTORY. The producer judges `BASE_SHA..HEAD_SHA`, the range
# `commit-attribution` and `commit-lint` already share. Every commit on `main`
# predating this gate is signed by that environment key; judging history would
# make the gate permanently red for commits nobody can now unsign, which is how a
# gate gets switched off.
#
# POINTER-ONLY (rule 4): a short SHA and a setting name. Never a signature block
# — it is a credential artefact this repository does not control.
#
#MUTANT-SUITE crates/batten/tests/it/signing_posture.rs
#MUTANT config-check-is-not-a-commit-check|s@^\tstartswith(line, "signed ")$@\tfalse@|a_signed_commit_in_range_is_refused_and_named_by_short_sha
#MUTANT verifiable-signer-still-refused|s@^\tbroken$@\ttrue@|signing_with_a_verifiable_signer_is_left_alone

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.signing_posture

import rego.v1

rules contains "commit grade unsafe"

# The record, or nothing. An absent record is "the producer did not run" — the
# checkout is not a git repository, or the range would not resolve — and is
# silence rather than a claim that the posture is in force.
lines := input.tree.records["signing-posture"]

# ONLY A BROKEN SIGNER IS A FINDING. A verifiable one may sign freely; that is
# the end state CLOUD-591 is working toward and this gate must not block it.
broken if {
	some line in lines
	startswith(line, "signer broken")
}

# --- the posture that will produce bad signatures ----------------------------

violation contains {
	"rule": "commit grade unsafe",
	"verdict": "config carry unsafe",
	"subjects": [{"artifact": "commit.gpgsign"}],
} if {
	broken
	"config conflict" in lines
}

# --- the commits that already carry one --------------------------------------

violation contains {
	"rule": "commit grade unsafe",
	"verdict": "commit carry unsafe",
	"subjects": [{"artifact": sha}],
} if {
	broken
	some line in lines
	startswith(line, "signed ")
	sha := trim_space(substring(line, count("signed "), -1))
	sha != ""
}

# --- cases -------------------------------------------------------------------

test_a_signed_commit_in_range_is_refused_and_named_by_short_sha if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer broken user.signingkey names an empty file",
		"signed 1a2b3c4d",
	]}}}
	count(found) == 1
}

test_signing_with_a_verifiable_signer_is_left_alone if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer verifiable",
		"config conflict",
		"signed 1a2b3c4d",
	]}}}
	count(found) == 0
}

test_a_missing_override_is_refused_when_the_environment_sets_signing_globally if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer broken the signer resolves inside /tmp",
		"config conflict",
	]}}}
	count(found) == 1
}

# A runner has no launcher and no global setting, so there is nothing to override
# and an absent local value is the correct state there.
test_a_missing_override_is_not_a_finding_when_nothing_sets_signing_globally if {
	found := violation with input as {"tree": {"records": {"signing-posture": ["signer broken the signer resolves inside /tmp"]}}}
	count(found) == 0
}

# REPAIRING THE CONFIG DOES NOT EXCUSE A COMMIT ALREADY SIGNED, which is the
# whole reason the two classes are separate.
test_repairing_the_config_does_not_excuse_a_commit_already_signed if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer broken user.signingkey names an empty file",
		"signed 1a2b3c4d",
	]}}}
	{entry.verdict | some entry in found} == {"commit carry unsafe"}
}

test_the_two_classes_stay_distinct if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer broken user.signingkey names an empty file",
		"config conflict",
		"signed 1a2b3c4d",
	]}}}
	{entry.verdict | some entry in found} == {"config carry unsafe", "commit carry unsafe"}
}

test_every_signed_commit_is_named_separately if {
	found := violation with input as {"tree": {"records": {"signing-posture": [
		"signer broken user.signingkey names an empty file",
		"signed 1a2b3c4d",
		"signed 5e6f7a8b",
	]}}}
	count(found) == 2
}

test_an_absent_record_says_nothing_rather_than_refusing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}

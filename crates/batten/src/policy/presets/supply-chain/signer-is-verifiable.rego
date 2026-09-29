# METADATA
# description: |
#   No commit is signed by a key that cannot be verified or reproduced (CLOUD-669,
#   ported off `signing-posture.sh` under CLOUD-1717 and off its producer task
#   onto the engine's own git facts under CLOUD-843).
#
#   SIGNING IS GOOD AND THIS IS NOT AGAINST IT. Signing in CI, with a key whose
#   public half is published, is the desired end state. What this refuses is the
#   narrower thing: a signature produced by a key that cannot be verified or
#   reproduced, which is WORSE than no signature because it looks like provenance
#   and carries none. A commit's author and committer can be accountable while
#   its `gpgsig` header is a key nobody holds, so an identity gate is blind to it.
#
#   THREE READINGS, AND ONLY ONE IS A RECORD. The signer's classification is
#   `batten record derive signing-posture`'s `signer` line: whether
#   `user.signingkey` names a readable, non-empty file, or the signer program
#   lives somewhere the environment reclaims, is a filesystem question no module
#   can ask. The CONFLICT is `input.tree["git-config"]` per scope, decided HERE —
#   the retired task body compared the two scopes in shell. The signed commits are
#   `input.tree["commit-meta"]`'s `signed` bit over whatever range the row
#   declares: header presence, never validity.
#
#   TWO CLASSES, AND KEEPING THEM APART IS THE POINT. `config carry unsafe` is a
#   posture that will produce bad signatures; `commit carry unsafe` is one that
#   already did. Config can be repaired AFTER a commit was written, so a repaired
#   checkout still carries the signed commits made before the repair — and those
#   are exactly what must not land. Collapsing the two would let the cheap half
#   stand in for the expensive one.
#
#   BOTH ARE SCOPED TO A BROKEN SIGNER. A verifiable signer may sign freely.
#
#   THE CONFIG CLASS IS THE CONFLICT, NEVER THE MERE ABSENCE OF A LOCAL VALUE. A
#   CI runner has no launcher and no global setting, so an absent local value is
#   correct there. The refusal needs something to turn signing on — the global
#   scope, or the local one itself — and no local `false` answering it.
#
#   RANGE, NEVER HISTORY: the row declares `commits = [...]`, and every declared
#   range is read. History predating a gate is signed by whatever key it was
#   signed by, and nobody can unsign it now.
#
#   POINTER-ONLY (rule 4): an eight-character sha and a setting name. Never a
#   signature block, never the key, never the signer's path.
#
#   EVERY NAME IS PREFIXED `signer_`, because a preset's modules share one
#   engine and a sibling binding the same helper name is a load fault.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.supply_chain_signing

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/signing_posture.rs
#MUTANT config-check-is-not-a-commit-check|s@^\tsigner_commit.signed == true$@\tfalse@|a_signed_commit_in_range_is_refused_and_named_by_short_sha
#MUTANT verifiable-signer-still-refused|s@^\tsigner_broken$@\ttrue@|signing_with_a_verifiable_signer_is_left_alone
#MUTANT local-override-unread|s@^\tnot signer_locally_off$@\ttrue@|a_local_override_answers_the_global_setting
#MUTANT global-scope-unread|s@^\tsigner_gpgsign.scopes.global.boolean == true$@\tfalse@|a_missing_override_is_refused_when_the_environment_sets_signing_globally

rules contains "config carry unsafe"

rules contains "commit carry unsafe"

# ONLY A BROKEN SIGNER IS A FINDING. The record, or nothing: an absent record is
# "the producer did not run" — the checkout is not a repository — and is silence
# rather than a claim that the posture is in force.
signer_broken if {
	some line in input.tree.records["signing-posture"]
	startswith(line, "signer broken")
}

# The declared key, as git resolves it per scope. `null` is could-not-look, and
# every rule below is then undefined rather than a claim.
signer_gpgsign := input.tree["git-config"]["commit.gpgsign"]

# A local `false` is the override that answers anything wider. git's boolean
# reading, never the text: `off`, `no` and `0` are all false.
signer_locally_off if signer_gpgsign.scopes.local.boolean == false

# Something turns signing on: the global scope, or the checkout itself.
signer_signs if {
	signer_gpgsign.scopes.global.boolean == true
}

signer_signs if {
	signer_gpgsign.scopes.local.boolean == true
}

# --- the posture that will produce bad signatures ----------------------------

violation contains {
	"rule": "config carry unsafe",
	"verdict": "config carry unsafe",
	"subjects": [{"artifact": "commit.gpgsign"}],
} if {
	signer_broken
	signer_signs
	not signer_locally_off
}

# --- the commits that already carry one --------------------------------------

violation contains {
	"rule": "commit carry unsafe",
	"verdict": "commit carry unsafe",
	"subjects": [{"artifact": substring(signer_commit.commit, 0, 8)}],
} if {
	signer_broken
	some range
	some signer_commit in input.tree["commit-meta"][range]
	signer_commit.signed == true
}

# --- cases -------------------------------------------------------------------

signer_tree(record, config, commits) := {"tree": {
	"records": {"signing-posture": record},
	"git-config": {"commit.gpgsign": config},
	"commit-meta": {"origin/main..HEAD": commits},
}}

signer_bad := ["signer broken user.signingkey names an empty file"]

signer_unset := {"effective": null, "scopes": {}}

signer_global_on := {
	"effective": {"value": "true", "boolean": true},
	"scopes": {"global": {"value": "true", "boolean": true}},
}

signer_one_signed := [
	{"commit": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", "signed": true},
	{"commit": "ffffffff5e6f708192a3b4c5d6e7f8091a2b3c4d", "signed": false},
]

test_a_signed_commit_in_range_is_refused_and_named_by_short_sha if {
	found := violation with input as signer_tree(signer_bad, signer_unset, signer_one_signed)
	found == {{
		"rule": "commit carry unsafe",
		"verdict": "commit carry unsafe",
		"subjects": [{"artifact": "1a2b3c4d"}],
	}}
}

test_signing_with_a_verifiable_signer_is_left_alone if {
	count(violation) == 0 with input as signer_tree(["signer verifiable"], signer_global_on, signer_one_signed)
}

test_a_missing_override_is_refused_when_the_environment_sets_signing_globally if {
	found := violation with input as signer_tree(signer_bad, signer_global_on, [])
	{entry.verdict | some entry in found} == {"config carry unsafe"}
}

# A runner has no launcher and no global setting, so there is nothing to override
# and an absent local value is the correct state there.
test_a_missing_override_is_not_a_finding_when_nothing_sets_signing_globally if {
	count(violation) == 0 with input as signer_tree(signer_bad, signer_unset, [])
}

# git's boolean reading: a local `off` answers a global `1`.
test_a_local_override_answers_the_global_setting if {
	answered := {
		"effective": {"value": "off", "boolean": false},
		"scopes": {
			"global": {"value": "1", "boolean": true},
			"local": {"value": "off", "boolean": false},
		},
	}
	count(violation) == 0 with input as signer_tree(signer_bad, answered, [])
}

# The checkout turning signing on for itself is a conflict too — nothing answers it.
test_a_local_setting_on_is_refused_when_the_signer_is_broken if {
	local_on := {
		"effective": {"value": "true", "boolean": true},
		"scopes": {"local": {"value": "true", "boolean": true}},
	}
	found := violation with input as signer_tree(signer_bad, local_on, [])
	{entry.verdict | some entry in found} == {"config carry unsafe"}
}

# REPAIRING THE CONFIG DOES NOT EXCUSE A COMMIT ALREADY SIGNED, which is the whole
# reason the two classes are separate.
test_repairing_the_config_does_not_excuse_a_commit_already_signed if {
	repaired := {
		"effective": {"value": "false", "boolean": false},
		"scopes": {
			"global": {"value": "true", "boolean": true},
			"local": {"value": "false", "boolean": false},
		},
	}
	found := violation with input as signer_tree(signer_bad, repaired, signer_one_signed)
	{entry.verdict | some entry in found} == {"commit carry unsafe"}
}

test_the_two_classes_stay_distinct if {
	found := violation with input as signer_tree(signer_bad, signer_global_on, signer_one_signed)
	{entry.verdict | some entry in found} == {"config carry unsafe", "commit carry unsafe"}
}

test_every_signed_commit_is_named_separately if {
	two := [
		{"commit": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", "signed": true},
		{"commit": "5e6f7a8b5e6f708192a3b4c5d6e7f8091a2b3c4d", "signed": true},
	]
	count(violation) == 2 with input as signer_tree(signer_bad, signer_unset, two)
}

test_an_absent_record_says_nothing_rather_than_refusing if {
	count(violation) == 0 with input as {"tree": {
		"records": {},
		"git-config": {"commit.gpgsign": signer_global_on},
		"commit-meta": {"origin/main..HEAD": signer_one_signed},
	}}
}

# COULD-NOT-LOOK IS NOT A CONFLICT: a config the engine could not open is `null`.
test_an_unread_config_is_no_conflict if {
	count(violation) == 0 with input as {"tree": {
		"records": {"signing-posture": signer_bad},
		"git-config": null,
		"commit-meta": null,
	}}
}

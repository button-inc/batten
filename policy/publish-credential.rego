# METADATA
# description: |
#   This repository cannot publish to a package registry with a long-lived
#   credential — the day publishing turns on, it turns on through OIDC. CLOUD-109,
#   ported from `mise-tasks/publish-credential-check.sh` under CLOUD-843.
#
#   CLOUD-109 asked to switch the release path to trusted publishing, and measured
#   against the tree neither half of its acceptance was a change that did anything.
#   The release config disables publishing, so the release verb never contacts a
#   registry: there is no publish for a trusted publisher to authenticate, and the
#   OIDC permission added today would grant a capability no step uses — dead config
#   that an excessive-permissions audit reads as a finding. And the registry token
#   the issue asks to delete DOES NOT EXIST; the repository carries one Actions
#   secret and it is not that one.
#
#   So the deliverable is not an edit to today's workflow; it is a standing
#   guarantee about the TRANSITION, which needs no credential and can be built now.
#   That is this rule, and it is the whole of what CLOUD-109 can honestly close.
#
#   THE LOAD-BEARING RULE IS THE IMPLICATION, not the literal. While publishing is
#   off the OIDC permission is not required — requiring it would be requiring the
#   dead config above. The moment publishing becomes true, this refuses the commit
#   unless the release job carries the OIDC permission. Publishing therefore cannot
#   be switched on except through OIDC, in the same commit that switches it.
#
#   AN ABSENT KEY IS NOT FALSE. The release tool's own default is to publish, so a
#   config that says nothing publishes. Treating a missing key as off would make
#   this silent in exactly the case it exists for.
#
#   NOT IN SCOPE, AND DELIBERATELY: the forge credential the release job already
#   carries. That is a forge credential, not a registry one, and registry trusted
#   publishing does not reach it — the fix there is an org-owned app (CLOUD-94). A
#   clause here that fired on it would be answering a different question under this
#   one's name.
#
#   POINTER, NEVER PAYLOAD (rule 4), and here the rule is load-bearing rather than
#   stylistic: a finding names a key class and a `path:line`, never the matched
#   text. The whole class of thing this looks for is the class that must not reach
#   a log, so a gate that echoed the line would be the leak it exists to prevent.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.publish_credential

import rego.v1

rules contains "release grant missing"

config_path := "release-plz.toml"

release_workflow := ".github/workflows/release-plz.yml"

config_lines := lines if {
	lines := input.tree.lines[config_path]
}

# --- rule 1: no long-lived registry credential, anywhere in a workflow -------
#
# The credential's spellings are declared patterns rather than inline literals,
# which is the module contract and is also right here: the alternate-registry form
# carries the registry's own name in its middle segment and cannot be enumerated.
workflow_line contains {"path": path, "line": i + 1, "class": "registry-token"} if {
	some path, lines in input.tree.lines
	startswith(path, ".github/workflows/")
	some i, line in lines
	regex.match(data.batten.patterns["cargo-registry-token"], line)
}

workflow_line contains {"path": path, "line": i + 1, "class": "registry-login"} if {
	some path, lines in input.tree.lines
	startswith(path, ".github/workflows/")
	some i, line in lines
	regex.match(data.batten.patterns["cargo-login-call"], line)
}

violation contains {
	"rule": "release grant missing",
	"verdict": "grant carry unsafe",
	"subjects": [{"path": sprintf("%s:%d", [hit.path, hit.line])}, {"artifact": hit.class}],
} if {
	some hit in workflow_line
}

# --- rule 2: publishing implies OIDC -----------------------------------------
#
# Read off the config rather than assumed.
#
# **A SET, NEVER A COMPLETE RULE** (CLOUD-1880, PR #928). This was
# `declared_publish := value`, and a manifest may legitimately carry more than
# one `publish =` line — `[workspace.package]` and `[package]` is the ordinary
# shape. Two lines with DIFFERENT values bind a complete rule twice, which
# regorus raises as `eval_conflict_error` AT EVALUATION; `policy_rule` discards
# the whole document on a fault, so every other predicate in this module —
# including rule 1's credential scan, which has nothing to do with publishing —
# stops deciding, silently, at exit 0. That is CLOUD-1049's fault class, and a
# gate that goes quiet on a shape the repository can hold is worse than no gate.
declared_publish contains value if {
	some line in config_lines
	startswith(trim_space(line), "publish")
	contains(line, "=")
	trim_space(substring(line, 0, indexof(line, "="))) == "publish"
	value := trim_space(without_comment(substring(line, indexof(line, "=") + 1, -1)))
}

# A TOML value with its trailing comment removed.
#
# **THE GATE WAS REFUSING ITS OWN REPOSITORY** (review of #928), and it could not
# have been seen before: this module was silently discarded by the
# `eval_conflict_error` the comment above records, so its first run on a real
# tree was the run that fixed that. `release-plz.toml` carries
# `publish = false           # do not publish to any cargo registry` — the
# ordinary annotated spelling — and the value read as
# `false           # do not publish to any cargo registry`, which is not the
# string `false`, so `publishes` held and the workflow was refused for lacking a
# grant it has no reason to carry.
#
# SPLIT AT THE FIRST `#`, which is safe for this key and only this key: the value
# is a bare boolean, so no `#` can be inside a string. A general TOML value would
# need the parser, and this module deliberately does not have one.
#
# AN EMPTY REMAINDER STAYS FAIL-CLOSED. `publish = # note` is malformed, and the
# empty string is not `"false"` — so it reads as publishing, which is the
# direction every ambiguous case in this module takes.
without_comment(text) := trim_space(substring(text, 0, indexof(text, "#"))) if {
	indexof(text, "#") >= 0
}

without_comment(text) := text if {
	indexof(text, "#") == -1
}

# PUBLISHING IS THE FAIL-CLOSED READING OF EVERY AMBIGUOUS CASE, and the three
# arms below are one sentence: this crate publishes unless every declaration it
# carries says otherwise.
#
# A single `publish = true`, a mix of `true` and `false`, and a value this does
# not recognise all land here. The risk being gated is a publishing lane with no
# OIDC grant, so the expensive mistake is reading a manifest as non-publishing
# and staying quiet; demanding a grant from a crate that turns out not to publish
# costs a reviewer one line.
publishes if {
	some value in declared_publish
	value != "false"
}

# THE DEFAULT IS TO PUBLISH. A config that says nothing publishes, and reading
# silence as `false` would make this silent in exactly the case it exists for.
publishes if {
	config_lines
	count(declared_publish) == 0
}

carries_oidc if {
	some line in input.tree.lines[release_workflow]
	regex.match(data.batten.patterns["oidc-token-permission"], line)
}

violation contains {
	"rule": "release grant missing",
	"verdict": "lane grant missing",
	"subjects": [{"path": release_workflow}],
} if {
	publishes
	input.tree.lines[release_workflow]
	not carries_oidc
}

# Publishing with no release workflow at all is a question this cannot ask: there
# is no job whose permission could carry the credential-free route.
violation contains {
	"rule": "release grant missing",
	"verdict": "lane grant missing",
	"subjects": [{"path": config_path}],
} if {
	publishes
	not input.tree.lines[release_workflow]
}

# THE SHAPE THIS REPOSITORY COMMITS, and the one the gate refused. A trailing
# comment on the declaration does not turn `false` into something else.
test_a_declaration_with_a_trailing_comment_is_still_false if {
	count(violation) == 0 with input as {"tree": {"lines": {
		"release-plz.toml": ["publish = false           # do not publish to any cargo registry"],
		".github/workflows/release-plz.yml": ["permissions: {}"],
	}}}
}

# AND THE COMMENT MAY NOT SUPPLY THE VALUE. A declaration whose only `false` is
# inside the comment still reads as publishing, which is the fail-closed
# direction.
test_a_declaration_whose_false_is_only_in_the_comment_still_publishes if {
	some v in violation with input as {"tree": {"lines": {
		"release-plz.toml": ["publish = true  # was false until CLOUD-205"],
		".github/workflows/release-plz.yml": ["permissions: {}"],
	}}}
	v.verdict == "lane grant missing"
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves a declared
# `line_sources` GLOB over every workflow (CLOUD-845), and that is the half rule 1
# rests on entirely: a credential can appear in ANY workflow, so a resolution that
# reached only the release one would leave the rest unscanned with nothing red.
# `crates/batten/tests/it/publish_credential.rs` is that tier.

tree(files) := {"tree": {"lines": files}}

oidc_job := [
	"jobs:",
	"  release-plz:",
	"    permissions:",
	"      contents: write",
	"      id-token: write",
]

plain_job := ["jobs:", "  release-plz:", "    permissions:", "      contents: write"]

test_publishing_off_needs_no_oidc_permission if {
	count(violation) == 0 with input as tree({
		"release-plz.toml": ["[workspace]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
	})
}

test_publishing_on_without_oidc_is_refused if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "publish = true"],
		".github/workflows/release-plz.yml": plain_job,
	})
	v.verdict == "lane grant missing"
}

test_publishing_on_with_oidc_is_clean if {
	count(violation) == 0 with input as tree({
		"release-plz.toml": ["[workspace]", "publish = true"],
		".github/workflows/release-plz.yml": oidc_job,
	})
}

# THE SHAPE THAT USED TO KILL THE MODULE (CLOUD-1880). Two `publish` lines with
# DIFFERENT values — `[workspace.package]` and `[package]`, the ordinary way a
# workspace overrides itself — bound the old complete rule twice and raised
# `eval_conflict_error`, taking every predicate in this module down with it.
#
# The assertion is that a VERDICT comes back at all. A module that faults returns
# no violations, so `count(violation) == 0` would have passed on the corpse; this
# requires the OIDC arm to have actually decided.
test_two_disagreeing_publish_keys_still_yield_a_verdict if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace.package]", "publish = true", "[package]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
	})
	v.verdict == "lane grant missing"
}

# AND THE FAIL-CLOSED DIRECTION IS THE ONE CHOSEN, stated as its own case because
# the opposite reading is defensible and was rejected. A mixed declaration asks
# for the grant: the expensive mistake is a publishing lane with no OIDC, and
# demanding a grant from a crate that turns out not to publish costs a reviewer
# one line.
test_every_declaration_saying_false_is_the_only_non_publishing_case if {
	count(violation) == 0 with input as tree({
		"release-plz.toml": ["[workspace.package]", "publish = false", "[package]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
	})
}

# AN ABSENT KEY IS NOT FALSE: the tool's own default is to publish.
test_an_absent_publish_key_reads_as_publishing if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "allow_dirty = false"],
		".github/workflows/release-plz.yml": plain_job,
	})
	v.verdict == "lane grant missing"
}

test_a_registry_token_in_any_workflow_is_refused if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
		".github/workflows/other.yml": ["    env:", "      CARGO_REGISTRY_TOKEN: ${{ secrets.X }}"],
	})
	v.verdict == "grant carry unsafe"
}

# The alternate-registry form carries the registry's own name in its middle
# segment, so it is matched on its shape rather than enumerated.
test_the_alternate_registry_form_is_refused_too if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
		".github/workflows/other.yml": ["      CARGO_REGISTRIES_MYREG_TOKEN: ${{ secrets.X }}"],
	})
	v.verdict == "grant carry unsafe"
}

test_a_login_call_is_refused if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "publish = false"],
		".github/workflows/release-plz.yml": plain_job,
		".github/workflows/other.yml": ["      run: cargo login \"$TOKEN\""],
	})
	v.verdict == "grant carry unsafe"
}

# The forge credential the release job already carries is a different question,
# and a clause firing on it would answer that one under this one's name.
test_the_forge_credential_is_not_this_rules_question if {
	count(violation) == 0 with input as tree({
		"release-plz.toml": ["[workspace]", "publish = false"],
		".github/workflows/release-plz.yml": array.concat(plain_job, ["      GITHUB_TOKEN: ${{ secrets.RELEASE_PLZ_TOKEN }}"]),
	})
}

# The permission is matched as a KEY, so the phrase in a comment cannot satisfy
# it.
test_the_permission_named_in_a_comment_does_not_satisfy_it if {
	some v in violation with input as tree({
		"release-plz.toml": ["[workspace]", "publish = true"],
		".github/workflows/release-plz.yml": array.concat(plain_job, ["      # id-token: write goes here when publishing turns on"]),
	})
	v.verdict == "lane grant missing"
}

#MUTANT-SUITE crates/batten/tests/it/publish_credential.rs
#MUTANT registry-token-passes|s@^\tsome hit in workflow_line$@\tfalse@|a_registry_token_in_any_workflow_is_refused
#MUTANT absent-publish-key-read-as-false|s@^\tnot declared_publish$@\tfalse@|an_absent_publish_key_reads_as_publishing
#MUTANT publishing-without-oidc-passes|s@^\tnot carries_oidc$@\tfalse@|publishing_on_without_oidc_is_refused

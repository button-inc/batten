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

rules contains "publish-credential"

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
	"rule": "publish-credential",
	"verdict": "grant carry unsafe",
	"subjects": [{"path": sprintf("%s:%d", [hit.path, hit.line])}, {"artifact": hit.class}],
} if {
	some hit in workflow_line
}

# --- rule 2: publishing implies OIDC -----------------------------------------
#
# Read off the config rather than assumed.
declared_publish := value if {
	some line in config_lines
	startswith(trim_space(line), "publish")
	contains(line, "=")
	trim_space(substring(line, 0, indexof(line, "="))) == "publish"
	value := trim_space(substring(line, indexof(line, "=") + 1, -1))
}

publishes if {
	declared_publish == "true"
}

# THE DEFAULT IS TO PUBLISH. A config that says nothing publishes, and reading
# silence as `false` would make this silent in exactly the case it exists for.
publishes if {
	config_lines
	not declared_publish
}

carries_oidc if {
	some line in input.tree.lines[release_workflow]
	regex.match(data.batten.patterns["oidc-token-permission"], line)
}

violation contains {
	"rule": "publish-credential",
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
	"rule": "publish-credential",
	"verdict": "lane grant missing",
	"subjects": [{"path": config_path}],
} if {
	publishes
	not input.tree.lines[release_workflow]
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

# `mise.toml`'s `[env]` still fences the resolver host out of the agent proxy
# (CLOUD-1399).
#
# ─── WHAT THIS PROTECTS, STATED NARROWLY ─────────────────────────────────────
#
# It protects a MITIGATION, not the decision. The decision — nothing in this
# container is carried by the agent proxy — is `batten doctor egress`'s subject
# and the `egress-is-unproxied` `[[startup]]` row's, both of which read the live
# environment. This module reads the TREE, and the only thing the tree owns here
# is the `[env]` block that prepends the GitHub hosts to `NO_PROXY` so mise's
# release resolver can reach them at all.
#
# Overstating that would be the defect `rules/scanning.md` records for
# its own case: this cannot tell you the container is unproxied, and a §7 saying
# otherwise would be worse than no gate.
#
# ─── WHY IT EXISTS: THE MITIGATION WAS ALREADY DELETED ONCE ──────────────────
#
# `65757c86` removed the fencing on the reasoning that honouring the CA bundle
# the environment declares made it unnecessary. That conflates two failures. The
# CA bundle addresses TLS RE-TERMINATION. The proxy also injects a repo-scoped
# token, so `api.github.com` answers 403 for third-party tool repos — an
# AUTHORIZATION failure no certificate helps with, and the one
# `mise-tasks/egress-check.sh`'s header has recorded all along.
#
# Nothing refused that commit. `egress-check`'s `ok` admitted a partial fence, so
# the container still read healthy, and no rule looked at the tree at all. This is
# the layer that was missing: `doctor egress` catches a bad container, this
# catches the commit.
#
# ─── BOTH SPELLINGS, BECAUSE A CLIENT READS THE LOWER-CASE ONE FIRST ─────────
#
# `[env]` sets `NO_PROXY` and `no_proxy`, and every client in this class resolves
# lower case before upper. Gating only the upper-case key would let a change that
# gutted `no_proxy` pass while leaving the gate green, and the tool that broke
# would be the one that reads the lower-case name.
#
# ─── WHY A MODULE AND NOT A PRESET ───────────────────────────────────────────
#
# The predicate names a task RUNNER's env block and one specific host. Pull the
# consumer's facts out and what remains is "a document mentions a string", which
# decides nothing. So it is an in-repo module by default, and non-negotiable rule
# 1 is why it may name `mise.toml` and the host at all.
#
#MUTANT dropped-fence-passes|s@not env\[key\]@false@|a_deleted_fence_is_refused
#MUTANT narrowed-fence-passes|s@not regex.match(data.batten.patterns\["egress-resolver-host"\], value)@false@|a_fence_that_no_longer_names_the_resolver_host_is_refused
# NO `#MUTANT` ROW FOR THE COULD-NOT-LOOK CLAUSE, for the reason
# `mise-pin-agreement.rego` measured and records: a declared mutation over a
# clause the engine cannot make fire is reported as a survivor and the runner is
# right to report it. The clause stays because it is correct.
#
#MUTANT-SUITE crates/batten/tests/it/egress_fencing.rs

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.egress_fencing

import rego.v1

rules contains "egress-fencing"

# ---------------------------------------------------------------------------
# The authority, bound through a rule so every predicate below is UNDEFINED
# rather than vacuously clean when `mise.toml` was not read.
# ---------------------------------------------------------------------------

env := e if {
	e := input.tree.documents["mise.toml"].env
	is_object(e)
}

# The two spellings a client may read, checked as a set so neither is the one
# somebody remembers to widen.
spellings := {"NO_PROXY", "no_proxy"}

# ---------------------------------------------------------------------------
# A: the fence is gone. `[env]` was read and carries no such key at all.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "egress-fencing",
	"verdict": "task declare dropped",
	"subjects": [{"path": "mise.toml"}, {"artifact": key}],
} if {
	some key in spellings
	env
	not env[key]
}

# ---------------------------------------------------------------------------
# B: the fence is present and no longer names the host it exists for.
#
# The value is a Tera template rather than a resolved list, which is exactly
# what makes this checkable in the tree: the host appears literally in the
# template's own text, so no evaluation is needed to see whether the block still
# intends to fence it.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "egress-fencing",
	"verdict": "task declare partial",
	"subjects": [{"path": "mise.toml"}, {"artifact": key}],
} if {
	some key in spellings
	value := env[key]
	is_string(value)
	not regex.match(data.batten.patterns["egress-resolver-host"], value)
}

# ---------------------------------------------------------------------------
# Could not look. A declared source that would not parse belongs here rather
# than being silently absent: a module that iterates only `documents` reports
# green over a file it never read.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "egress-fencing",
	"verdict": "task read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	path == "mise.toml"
}

# --- cases -----------------------------------------------------------------
#
# The load-time tier. It pins the PREDICATE.
# `crates/batten/tests/it/egress_fencing.rs` is the tier that proves the ENGINE
# builds the shape these fabricate — which is the whole reason both exist: a
# `with input as` block writes the shape it then reads, so it stays green over a
# key the engine never fills.

# The consumer's `[[pattern]]` row, injected. A module reads
# `data.batten.patterns[…]`, and Rego reads an undefined path as *does not hold*
# — so a case that omitted this would exercise a predicate that decides nothing
# and call it a pass.
patterns := {"egress-resolver-host": `api\.github\.com`}

fenced_value := "{% if 'api.github.com' in cur %}{{ cur }}{% else %}api.github.com,objects.githubusercontent.com{% endif %}"

tree(env_table) := {"tree": {"documents": {"mise.toml": {"env": env_table}}, "missing": {}}}

test_a_fence_naming_the_resolver_host_in_both_spellings_passes if {
	count(violation) == 0 with input as tree({
		"NO_PROXY": fenced_value,
		"no_proxy": fenced_value,
	})
		with data.batten.patterns as patterns
}

# TWO FINDINGS, ONE PER SPELLING, and the count is asserted rather than glossed:
# the predicate iterates the spellings as a set, so a fence deleted outright is
# two refusals and not one. A case asserting `== 1` here would be wrong about the
# rule it is pinning.
test_a_deleted_fence_is_refused if {
	found := violation with input as tree({"GH_TOKEN": "x"})
		with data.batten.patterns as patterns
	count(found) == 2
	every finding in found {
		finding.verdict == "task declare dropped"
	}
}

test_a_fence_that_no_longer_names_the_resolver_host_is_refused if {
	found := violation with input as tree({
		"NO_PROXY": "localhost,127.0.0.1",
		"no_proxy": "localhost,127.0.0.1",
	})
		with data.batten.patterns as patterns
	count(found) == 2
	every finding in found {
		finding.verdict == "task declare partial"
	}
}

# THE LOWER-CASE HALF ALONE. Every client in this class reads `no_proxy` first,
# so a gate watching only the upper-case name would stay green while the tool
# that actually broke is the one reading the other.
test_fencing_only_the_upper_case_spelling_is_refused if {
	found := violation with input as tree({
		"NO_PROXY": fenced_value,
		"no_proxy": "localhost",
	})
		with data.batten.patterns as patterns
	count(found) == 1
	some finding in found
	finding.verdict == "task declare partial"
	finding.subjects[1].artifact == "no_proxy"
}

test_fencing_only_the_lower_case_spelling_is_refused if {
	found := violation with input as tree({
		"NO_PROXY": "localhost",
		"no_proxy": fenced_value,
	})
		with data.batten.patterns as patterns
	count(found) == 1
	some finding in found
	finding.subjects[1].artifact == "NO_PROXY"
}

# COULD NOT LOOK IS NOT A PASS. The document is absent from `documents` and named
# in `missing`, so `env` is unbound and the two clauses above cannot fire — which
# is exactly the state that would report a clean tree without this arm.
test_an_unreadable_authority_is_could_not_look if {
	found := violation with input as {"tree": {
		"documents": {},
		"missing": {"mise.toml": "Unparsed"},
	}}
		with data.batten.patterns as patterns
	count(found) == 1
	some finding in found
	finding.verdict == "task read unread"
}

# A DIFFERENT unreadable document says nothing about this fence, so the arm has
# to be keyed on the path and not merely on `missing` being non-empty.
test_an_unrelated_missing_document_is_not_this_rules_business if {
	count(violation) == 0 with input as {"tree": {
		"documents": {"mise.toml": {"env": {
			"NO_PROXY": fenced_value,
			"no_proxy": fenced_value,
		}}},
		"missing": {"Cargo.toml": "Unparsed"},
	}}
		with data.batten.patterns as patterns
}

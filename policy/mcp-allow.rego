# No MCP permission rule in `.claude/settings.json` is silently skipped by the
# host (CLOUD-843, retiring `[tasks.mcp-allow-check]`'s commit-scoped half).
#
# A rule that grants nothing is silent by construction: its only symptom is an
# approval prompt, which reads as harness behaviour rather than as a settings
# bug. This repository shipped exactly that — `mcp__Linear` allowed, Linear
# arriving under another prefix, no rule matching either way. Three predicates
# are pure functions of the committed files, so they are a TREE module and run
# wherever `batten check` runs, the commit gate and CI included:
#
#   grant spelling wrong  a glob in an allow rule's SERVER segment, or a bare
#                         `*`: the host skips it with a warning and it grants
#                         nothing.
#   grant name missing    a server `enabledMcpjsonServers` turns on that no
#                         allow rule names — every call to it prompts.
#   connector deny loose  a deny naming ONE host-supplied server and ONE tool
#                         literally, whose tool suffix no `mediated_call` row
#                         with a `tool` covers. The host picks that server's
#                         exposed name per registration episode (CLOUD-178), so
#                         the deny enforces nothing the moment the name moves.
#
# The world-scoped half — which grants a connector would still prompt for, and
# which enabled servers this session attached — needs the host-injected wiring
# and the host's own logs, which a tree module cannot read and CI does not have.
# That is `batten mcp posture`, a session-start handler.
#
# COVERAGE IS READ FROM THE AUTHORITY AS A DOCUMENT, and that is the one change
# of source. The retired body spawned `batten policy tools`, which lists the
# `tool` of every `mediated_call` row in the RESOLVED config; this reads the same
# rows out of the committed `batten.toml`. The committed rows are the ones a deny
# may rely on — a local layer can raise, never be what a committed rule rests
# on — so reading the committed set is the stricter of the two. The retired
# guard `--covers` probe is withdrawn: no `*-guard.sh` exists, so it answered
# nothing by construction.
#
# POINTER-ONLY: the settings path and the offending rule or server segment — the
# retired gate's own pointers — never the settings content at large.
#
#MUTANT-SUITE crates/batten/tests/it/mcp_allow.rs
#MUTANT server-glob-accepted|s@^\tcontains(server_of(rule), "\*")$@\tfalse@|a_glob_in_the_server_segment_is_reported
#MUTANT enabled-grant-unchecked|s@^\tnot granted_servers\[server\]$@\tfalse@|an_enabled_server_that_no_allow_rule_names_is_reported
#MUTANT deny-coverage-unread|s@^\tnot covered\[suffix\]$@\ttrue@|a_deny_whose_suffix_the_mediated_rows_cover_passes_under_any_server_spelling
#MUTANT declared-server-unread|s@^\tnot declared\[server\]$@\ttrue@|a_deny_on_a_declared_or_non_mcp_server_is_not_this_predicates

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.mcp_allow

import rego.v1

rules contains "grant spelling wrong"

rules contains "grant name missing"

rules contains "connector deny loose"

rules contains "grant read unread"

# --- the three documents ------------------------------------------------------

settings_path := ".claude/settings.json"

project_path := ".mcp.json"

authority_path := "batten.toml"

settings := input.tree.documents[settings_path]

# One `permissions.<arm>` list's string rules. EMPTY, never undefined, where the
# file states no such arm: a settings file that parses and grants nothing has
# answered. Where the file itself is absent the set is empty too, and the
# `missing` clause below is what keeps an unreadable file from reading as clean.
permission_list(arm) := {rule |
	permissions := settings.permissions
	is_object(permissions)
	list := permissions[arm]
	is_array(list)
	some rule in list
	is_string(rule)
}

# The server segment of an MCP rule: what sits between `mcp__` and the next
# `__`, or the rest of the rule where there is no tool segment. Undefined for a
# rule that is not an MCP rule at all.
server_of(rule) := parts[1] if {
	startswith(rule, "mcp__")
	parts := split(rule, "__")
}

# The servers `enabledMcpjsonServers` turns on. A value that is not a list —
# `true` is one the host accepts — enumerates nothing, so it has nothing to say.
enabled := {server |
	list := settings.enabledMcpjsonServers
	is_array(list)
	some server in list
	is_string(server)
	server != ""
}

granted_servers := {server |
	some rule in permission_list("allow")
	server := server_of(rule)
}

# The servers this repository DECLARES: the enabled ones, plus every key of its
# own project file. A deny on a server the repository names itself is spelled
# with a name the repository controls, so the host cannot rename it away.
project_servers := {key |
	servers := input.tree.documents[project_path].mcpServers
	is_object(servers)
	some key, _ in servers
}

declared := enabled | project_servers

# The tool suffixes a `mediated_call` row decides whatever the server is called:
# its `tool`, matched by `__`-delimited segment (CLOUD-178). Read from the
# committed authority as a document.
covered := {tool |
	some row in input.tree.documents[authority_path].rule
	row.scope == "mediated_call"
	tool := row.tool
	is_string(tool)
}

# Whether the authority was read at all. Without it coverage is unknown, and the
# deny predicate abstains rather than reporting every deny as uncovered — the
# retired gate's "deny coverage not judged" arm.
authority_read if is_object(input.tree.documents[authority_path])

# --- the refusals --------------------------------------------------------------

violation contains {
	"rule": "grant spelling wrong",
	"verdict": "grant spelling wrong",
	"subjects": [{"path": settings_path}, {"artifact": rule}],
} if {
	some rule in permission_list("allow")
	contains(server_of(rule), "*")
}

violation contains {
	"rule": "grant spelling wrong",
	"verdict": "grant spelling wrong",
	"subjects": [{"path": settings_path}, {"artifact": "*"}],
} if {
	"*" in permission_list("allow")
}

violation contains {
	"rule": "grant name missing",
	"verdict": "grant name missing",
	"subjects": [{"path": settings_path}, {"artifact": server}],
} if {
	some server in enabled
	not granted_servers[server]
}

violation contains {
	"rule": "connector deny loose",
	"verdict": "connector deny loose",
	"subjects": [{"path": settings_path}, {"artifact": rule}],
} if {
	authority_read
	some rule in permission_list("deny")
	parts := split(rule, "__")
	startswith(rule, "mcp__")
	server := parts[1]
	suffix := parts[count(parts) - 1]
	not contains(concat("", [server, suffix]), "*")
	not declared[server]
	not covered[suffix]
}

# --- could not look -----------------------------------------------------------

# A DECLARED DOCUMENT THAT WOULD NOT PARSE is not an absent one. An absent
# settings file is a repository with nothing to check, and an absent project
# file declares no server; either unparsed means the boundary tried and failed,
# and a gate that read that as clean would be judging a file it never read.
violation contains {
	"rule": "grant read unread",
	"verdict": "grant read unread",
	"subjects": [{"path": path}],
} if {
	some path, cause in input.tree.missing
	path in {settings_path, project_path}
	cause != "absent"
}

# --- the load-time tier -------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds these three
# documents — a dotfile, a JSON file and the authority itself — which is
# `crates/batten/tests/it/mcp_allow.rs`'s job over the compiled binary.

tree(settings_doc, project_doc, rows) := {"tree": {
	"documents": {
		".claude/settings.json": settings_doc,
		".mcp.json": project_doc,
		"batten.toml": {"rule": rows},
	},
	"missing": {},
}}

allows_doc(rules) := {"permissions": {"allow": rules, "deny": []}}

denies_doc(rules) := {"permissions": {"allow": [], "deny": rules}}

no_project := {"mcpServers": {}}

timer_row := [{"id": "timer", "scope": "mediated_call", "tool": "send_later"}]

verdicts(found) := {v.verdict | some v in found}

test_well_formed_allow_rules_pass if {
	count(violation) == 0 with input as tree(allows_doc(["mcp__Linear"]), no_project, [])
	count(violation) == 0 with input as tree(allows_doc(["mcp__Linear", "mcp__claude_ai_Linear__*"]), no_project, [])
	count(violation) == 0 with input as tree(allows_doc(["mcp__claude_ai_Slack__slack_send_message"]), no_project, [])
	count(violation) == 0 with input as tree(allows_doc(["Bash(git:*)", "Bash(mise:*)"]), no_project, [])

	# An under-matching ALLOW fails closed, into a prompt a human sees.
	count(violation) == 0 with input as tree(allows_doc(["mcp__Claude_Code_Remote__get_session"]), no_project, [])
}

test_a_glob_in_the_server_segment_is_reported if {
	found := violation with input as tree(allows_doc(["mcp__claude_ai_*__read", "mcp__Linear"]), no_project, [])
	some v in found
	v.verdict == "grant spelling wrong"
	{"artifact": "mcp__claude_ai_*__read"} in v.subjects
}

test_a_bare_unanchored_allow_glob_is_reported if {
	found := violation with input as tree(allows_doc(["*"]), no_project, [])
	verdicts(found) == {"grant spelling wrong"}
}

test_deny_rules_may_glob_freely if {
	count(violation) == 0 with input as tree(denies_doc(["mcp__*", "*"]), no_project, [])
}

test_an_enabled_server_that_no_allow_rule_names_is_reported if {
	doc := object.union(allows_doc(["Bash(git:*)", "mcp__Linear__*"]), {"enabledMcpjsonServers": ["serena"]})
	found := violation with input as tree(doc, no_project, [])
	some v in found
	v.verdict == "grant name missing"
	{"artifact": "serena"} in v.subjects
}

enabled_serena(rules) := object.union(allows_doc(rules), {"enabledMcpjsonServers": ["serena"]})

test_an_enabled_server_granted_any_way_passes if {
	count(violation) == 0 with input as tree(enabled_serena(["mcp__serena__*"]), no_project, [])
	count(violation) == 0 with input as tree(enabled_serena(["mcp__serena__read_memory"]), no_project, [])
	count(violation) == 0 with input as tree(enabled_serena(["mcp__serena"]), no_project, [])
}

test_every_enabled_server_needs_its_own_grant if {
	doc := object.union(allows_doc(["mcp__serena__*"]), {"enabledMcpjsonServers": ["serena", "other"]})
	found := violation with input as tree(doc, no_project, [])
	count(found) == 1
	some v in found
	{"artifact": "other"} in v.subjects
}

test_an_enabled_value_that_is_not_a_list_says_nothing if {
	doc := object.union(allows_doc(["Bash(git:*)"]), {"enabledMcpjsonServers": true})
	count(violation) == 0 with input as tree(doc, no_project, [])
}

test_a_deny_on_a_host_supplied_connector_with_no_coverage_fails if {
	found := violation with input as tree(denies_doc(["mcp__Claude_Code_Remote__archive_session"]), no_project, timer_row)
	some v in found
	v.verdict == "connector deny loose"
	{"artifact": "mcp__Claude_Code_Remote__archive_session"} in v.subjects
}

test_a_deny_whose_suffix_a_mediated_row_covers_passes_under_any_spelling if {
	rules := ["mcp__Claude_Code_Remote__send_later", "mcp__bf7c680d__send_later"]
	count(violation) == 0 with input as tree(denies_doc(rules), no_project, timer_row)
}

# A TREE-SCOPED ROW NAMING THE SAME TOOL IS NOT COVERAGE: only a mediated-call
# row decides a call, so the anti-vacuity mirror of the case above.
test_a_tool_on_a_row_of_another_scope_does_not_cover if {
	rows := [{"id": "t", "scope": "tree", "tool": "send_later"}]
	found := violation with input as tree(denies_doc(["mcp__Claude_Code_Remote__send_later"]), no_project, rows)
	verdicts(found) == {"connector deny loose"}
}

test_a_deny_on_a_declared_server_needs_no_coverage if {
	doc := {
		"enabledMcpjsonServers": ["serena"],
		"permissions": {"allow": ["mcp__serena__*"], "deny": ["mcp__serena__delete_memory"]},
	}
	count(violation) == 0 with input as tree(doc, no_project, [])
	project := {"mcpServers": {"local": {}}}
	count(violation) == 0 with input as tree(denies_doc(["mcp__local__drop"]), project, [])
}

test_a_non_mcp_deny_is_not_this_predicates if {
	count(violation) == 0 with input as tree(denies_doc(["Bash(rm -rf *)"]), no_project, [])
}

# COULD NOT LOOK AT THE AUTHORITY: coverage is unknown, so the deny predicate
# abstains rather than reporting every deny as uncovered.
test_an_unread_authority_skips_the_coverage_predicate if {
	doc := {"tree": {
		"documents": {".claude/settings.json": denies_doc(["mcp__Claude_Code_Remote__archive_session"])},
		"missing": {},
	}}
	count(violation) == 0 with input as doc
}

test_an_unparsed_settings_file_cannot_look if {
	doc := {"tree": {"documents": {}, "missing": {".claude/settings.json": "unparsed"}}}
	found := violation with input as doc
	verdicts(found) == {"grant read unread"}
}

# ABSENT IS NOT UNPARSED: a repository with no settings file, or no project
# file, has nothing here to check.
test_an_absent_settings_or_project_file_is_nothing_to_check if {
	doc := {"tree": {"documents": {}, "missing": {".claude/settings.json": "absent", ".mcp.json": "absent"}}}
	count(violation) == 0 with input as doc
}

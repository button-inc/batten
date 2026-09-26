# A shipped tag reaches Linear: both release-tracking invocations present, pinned,
# and bound to the tag, on the release path and the backfill path alike (CLOUD-618,
# CLOUD-1026; ported off `mise-tasks/release-tracking-check.sh` under CLOUD-1717).
#
# `release-plz.yml` publishes a tag, and until CLOUD-618 nothing told Linear it
# existed. The wiring then ran ZERO times: `release-plz release` pushes the tag from
# its own temporary clone, so `git tag --points-at HEAD` in the outer checkout
# answered empty and every tracking step skipped (`v0.0.110`, run 32665754952). A
# gate that holds every node and misses the ORDER of two of them certifies a broken
# path, which is why the refresh is asserted BEFORE the resolver.
#
# THE PROGRAM WAS A `command` ROW because no rule kind could address a node in a
# document (CLOUD-452). `line_sources` is that kind now: this module walks the
# workflow's lines, so the row collapses into it as the program's own header said.
#
# TWO SUBJECTS, ONE SET OF SHAPES, per profile. `push` resolves its tag from git;
# `dispatch` (`linear-release-backfill.yml`) is named by an operator through a
# `workflow_dispatch` input. Everything the two share is asserted of both.
#
# EACH SHAPE FAILS SILENTLY, which is why each is here:
#   * `unpinned`             — a ref that is not a 40-hex SHA plus `# vX.Y.Z`
#   * `version-unbound`      — `version:` not a declared step output (push) or a
#                              declared dispatch input (dispatch); an undeclared
#                              name expands to the empty string at run time
#   * `sync-missing`, `complete-missing` — the pipeline is scheduled, so `sync`
#                              alone leaves the release started forever
#   * `precondition-missing` — no `-z` test on `LINEAR_ACCESS_KEY`
#   * `shallow-checkout`     — an invoking job without `fetch-depth: 0` attaches
#                              NOTHING and says so nowhere; asked per job, because
#                              file-global was a pass earned in another job
#   * `tag-source-missing`   — push: no `git tag --points-at HEAD` resolver writing
#                              `$GITHUB_OUTPUT`
#   * `tag-refresh-missing`  — push: no `git fetch … --tags` BEFORE the resolver
#   * `tag-unverified`       — dispatch: no `rev-parse … refs/tags/` probe, so a
#                              typo mints a release record
#   * `ref-unbound`          — dispatch: the checkout's `ref:` is not a declared
#                              input, so HEAD is the default branch (run 32762293169)
#   * `range-unbased`        — dispatch: `base_ref:` is not a real step's output,
#                              so the range narrows to one commit (run 32765173125)
#
# THE TOKEN RIDES IN THE POINTER, `<workflow>#<token>` plus the line, and a
# finding about the file rather than a line in it carries no line (rule 4).
#
# COMMENTS ARE NOT CODE: every probe reads a comment-stripped copy, line for line,
# because the workflows quote `git tag --points-at HEAD` in prose 29 lines above the
# real resolver and the program's first run matched the prose. The ONE exception is
# the invocation walk, which reads the original so the pin's `# vX.Y.Z` survives —
# skipping comment-only lines so prose cannot mint a phantom invocation.
#
# COULD-NOT-LOOK IS A FINDING, not silence: either workflow absent from the read is
# `release wire unread`, never a pass earned on the strength of the other one.
#
#MUTANT-SUITE crates/batten/tests/it/release_tracking.rs
#MUTANT unpinned-sha-passes|s@^\tnot regex.match(data.batten.patterns\["action-sha-pin"\], call.ref)$@\tfalse@|a_sha_pin_without_its_version_comment_is_a_violation
#MUTANT refresh-order-ignored|s@^\trefresh < resolver$@\ttrue@|a_tag_refresh_after_the_resolver_is_a_violation

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads `input.tree.lines`
#   and never the mediated `{call, facts}` shape.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_tracking

import rego.v1

rules contains "release wire other"

# Consumer paths in a consumer module, which is where rule 1 puts them.
profiles := {
	".github/workflows/release-plz.yml": "push",
	".github/workflows/linear-release-backfill.yml": "dispatch",
}

raw(path) := input.tree.lines[path]

# YAML's comment rule applied literally: `#` at line start or after whitespace.
# A `#` inside a quoted scalar is stripped too, which loses a match and reports a
# node MISSING — the loud direction.
code(path) := [strip(line) | some line in raw(path)]

# The comment match is anchored at `$`, so it is always the line's tail.
strip(line) := substring(line, 0, count(line) - count(tail)) if {
	some tail in regex.find_n(data.batten.patterns["yaml-comment"], line, 1)
} else := line

indent(line) := count(line) - count(trim_left(line, " \t"))

# `[indent, key, value]` of a `key: value` line, value trimmed; undefined otherwise.
key_line(line) := [indent(line), parts[2], trim_space(parts[3])] if {
	some parts in regex.find_all_string_submatch_n(data.batten.patterns["yaml-key-line"], line, 1)
}

comment_only(line) if startswith(trim_left(line, " \t"), "#")

# A job header: exactly two spaces, a bare key, nothing after the colon. Any such
# key counts, as the program's walk counted it.
headers(path) := {i: key |
	some i, line in code(path)
	[2, key, ""] = key_line(line)
}

# A sequence item opens a step: `-` then whitespace, after any indent.
items(path) := {i |
	some i, line in raw(path)
	not comment_only(line)
	some opener in ["- ", "-\t"]
	startswith(trim_left(line, " \t"), opener)
}

boundaries(path) := {i | some i, _ in headers(path)} | items(path)

# --- the invocations, one per `uses:` of the action ---------------------------

calls(path) := {call |
	some u, line in raw(path)
	not comment_only(line)
	some found in regex.find_all_string_submatch_n(data.batten.patterns["linear-release-uses"], line, 1)
	bounds := boundaries(path)
	start := max({b | some b in bounds; b <= u} | {-1})
	stop := min({b | some b in bounds; b > u} | {count(raw(path))})
	call := {
		"line": u + 1,
		"ref": trim_space(found[1]),
		"job": job_of(path, u),
		"command": step_value(path, start, stop, "command"),
		"version": step_value(path, start, stop, "version"),
		"version_line": step_line(path, start, stop, u),
	}
}

job_of(path, u) := key if {
	found := headers(path)
	j := max({i | some i, _ in found; i <= u})
	key := found[j]
} else := ""

step_lines(path, start, stop, key) := {i |
	some i, line in raw(path)
	i >= start
	i < stop
	not comment_only(line)
	[_, key, _] = key_line(line)
}

# The LAST such key in the step, as the program's walk overwrote.
step_value(path, start, stop, key) := value if {
	i := max(step_lines(path, start, stop, key))
	[_, _, value] = key_line(raw(path)[i])
} else := ""

# The finding points at `version:`, or at the invocation when there is none.
step_line(path, start, stop, _) := max(step_lines(path, start, stop, "version")) + 1 if {
	count(step_lines(path, start, stop, "version")) > 0
}

step_line(path, start, stop, u) := u + 1 if count(step_lines(path, start, stop, "version")) == 0

# --- is the version bound? ------------------------------------------------------

bound(path, "push", version) if {
	some m in regex.find_all_string_submatch_n(data.batten.patterns["gha-step-output"], version, 1)
	step_declared(path, m[1])
}

bound(path, "dispatch", version) if {
	some m in regex.find_all_string_submatch_n(data.batten.patterns["gha-dispatch-input"], version, 1)
	input_declared(path, m[2])
}

step_declared(path, name) if {
	some line in code(path)
	[_, "id", name] = key_line(line)
}

# Declared under `workflow_dispatch: inputs:`, at the level the FIRST key inside
# `inputs:` sets. Walked rather than grepped: a bare `tag:` also matches a step's
# `with: tag:`, and `required` is an input's own key one level deeper.
input_declared(path, name) if {
	lines := code(path)
	some w, wd in lines
	[wd_indent, "workflow_dispatch", ""] = key_line(wd)
	wd_end := min({j | some j, l in lines; j > w; [n, _, _] = key_line(l); n <= wd_indent} | {count(lines)})
	some k, block in lines
	k > w
	k < wd_end
	[in_indent, "inputs", ""] = key_line(block)
	in_end := min({j | some j, l in lines; j > k; [n, _, _] = key_line(l); n <= in_indent} | {wd_end})
	first := min({j | some j, l in lines; j > k; j < in_end; key_line(l)})
	[name_indent, _, _] = key_line(lines[first])
	some j, l in lines
	j > k
	j < in_end
	[name_indent, name, _] = key_line(l)
}

# --- per-job checkout -----------------------------------------------------------

job_span(path, job) := [start, stop] if {
	some start, name in headers(path)
	name == job
	stop := min({i | some i, _ in headers(path); i > start} | {count(code(path))})
}

deep(path, job) if {
	[start, stop] := job_span(path, job)
	some i, line in code(path)
	i > start
	i < stop
	[n, "fetch-depth", "0"] = key_line(line)
	n > 0
}

# The job's first checkout, or 0 — "the file, not a line in it": a job invoking the
# action with no checkout at all is the same finding.
checkout_line(path, job) := min(lines) + 1 if {
	[start, stop] := job_span(path, job)
	lines := {i | some i, line in code(path); i > start; i < stop; regex.match(data.batten.patterns["checkout-uses"], line)}
	count(lines) > 0
} else := 0

# --- the release path's own shapes ----------------------------------------------

first_line(path, pattern) := min({i | some i, line in code(path); regex.match(pattern, line)})

resolver_at(path) := min({i | some i, line in code(path); contains(line, "git tag --points-at HEAD")})

sourced(path) if {
	resolver_at(path)
	some line in code(path)
	regex.match(data.batten.patterns["gha-output-write"], line)
}

refreshed(path) if {
	refresh := first_line(path, data.batten.patterns["git-tag-refresh"])
	resolver := resolver_at(path)
	refresh < resolver
}

# --- findings ---------------------------------------------------------------------
#
# THE SHAPE RIDES IN THE POINTER as a fragment, `<workflow>#<token>`, because the
# pointer is the first subject's only (rule 4) and two shapes share a line — the
# backfill checkout is where both `shallow-checkout` and `ref-unbound` point. Line
# 0 is the program's "the file, not a line in it", and prints no line.
at(path, token, 0) := {"path": sprintf("%s#%s", [path, token])}

at(path, token, line) := {"path": sprintf("%s#%s", [path, token]), "line": line} if line > 0

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "unpinned", call.line)],
} if {
	some path, _ in profiles
	raw(path)
	some call in calls(path)
	not regex.match(data.batten.patterns["action-sha-pin"], call.ref)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "version-unbound", call.version_line)],
} if {
	some path, profile in profiles
	raw(path)
	some call in calls(path)
	not bound(path, profile, call.version)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, sprintf("%s-missing", [command]), 0)],
} if {
	some path, _ in profiles
	raw(path)
	some command in ["sync", "complete"]
	count({call | some call in calls(path); call.command == command}) == 0
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "precondition-missing", 0)],
} if {
	some path, _ in profiles
	raw(path)
	not any_line(path, data.batten.patterns["linear-key-guard"])
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "shallow-checkout", checkout_line(path, job))],
} if {
	some path, _ in profiles
	raw(path)
	some job in {call.job | some call in calls(path)}
	not deep(path, job)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "tag-source-missing", 0)],
} if {
	some path, "push" in profiles
	raw(path)
	not sourced(path)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "tag-refresh-missing", resolver_at(path) + 1)],
} if {
	some path, "push" in profiles
	sourced(path)
	not refreshed(path)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "tag-unverified", 0)],
} if {
	some path, "dispatch" in profiles
	raw(path)
	not any_line(path, data.batten.patterns["tag-exists-probe"])
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "ref-unbound", checkout_line(path, first_job(path)))],
} if {
	some path, "dispatch" in profiles
	raw(path)
	not ref_bound(path)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire missing",
	"subjects": [at(path, "range-unbased", 0)],
} if {
	some path, "dispatch" in profiles
	raw(path)
	not range_based(path)
}

violation contains {
	"rule": "release wire other",
	"verdict": "release wire unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in profiles
	not raw(path)
}

any_line(path, pattern) if {
	some line in code(path)
	regex.match(pattern, line)
}

first_job(path) := call.job if {
	lines := {call.line | some call in calls(path)}
	some call in calls(path)
	call.line == min(lines)
} else := ""

# The FIRST `ref:` line bound to an input, read back out and required declared: an
# undeclared name expands empty, which is checkout's default branch.
ref_bound(path) if {
	lines := code(path)
	refs := {i | some i, l in lines; [n, "ref", _] = key_line(l); n > 0; dispatch_input(key_line(l)[2])}
	first := min(refs)
	input_declared(path, dispatch_input(key_line(lines[first])[2]))
}

dispatch_input(value) := m[2] if {
	some m in regex.find_all_string_submatch_n(data.batten.patterns["gha-dispatch-input"], value, 1)
}

range_based(path) if {
	lines := code(path)
	bases := {i | some i, l in lines; [n, "base_ref", _] = key_line(l); n > 0; step_output(key_line(l)[2])}
	first := min(bases)
	step_declared(path, step_output(key_line(lines[first])[2]))
}

step_output(value) := m[1] if {
	some m in regex.find_all_string_submatch_n(data.batten.patterns["gha-step-output"], value, 1)
}

deny contains finding if {
	some finding in violation
}

# --- cases -----------------------------------------------------------------------
#
# The module's OWN cases; `release_tracking.rs` drives the committed workflows over
# the compiled engine. Paths are literals, never the `profiles` rule in key
# position, which regorus did not resolve inside a helper (`sbom-actions.rego`).

push_path := ".github/workflows/release-plz.yml"

dispatch_path := ".github/workflows/linear-release-backfill.yml"

pointers(found) := {s.path | some v in found; some s in v.subjects}

test_neither_workflow_read_is_two_findings_never_a_pass if {
	found := violation with input as {"tree": {"lines": {}}}
	pointers(found) == {push_path, dispatch_path}
	{v.verdict | some v in found} == {"release wire unread"}
}

test_one_workflow_read_does_not_excuse_the_other if {
	found := violation with input as {"tree": {"lines": {push_path: ["name: release"]}}}
	dispatch_path in pointers(found)
}

test_an_unpinned_invocation_is_named_by_its_shape if {
	found := violation with input as {"tree": {"lines": {
		push_path: [
			"jobs:",
			"  track:",
			"    steps:",
			"      - uses: linear/linear-release-action@main",
		],
		dispatch_path: ["name: backfill"],
	}}}
	sprintf("%s#unpinned", [push_path]) in pointers(found)
}

test_a_pinned_invocation_is_not_unpinned if {
	found := violation with input as {"tree": {"lines": {
		push_path: [
			"jobs:",
			"  track:",
			"    steps:",
			"      - uses: linear/linear-release-action@0123456789abcdef0123456789abcdef01234567 # v1.2.3",
		],
		dispatch_path: ["name: backfill"],
	}}}
	not sprintf("%s#unpinned", [push_path]) in pointers(found)
}

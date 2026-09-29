#MUTANT-SUITE crates/batten/tests/it/shell_banned.rs
#MUTANT task-growth-unchecked|s@^\thead > base_count\[path\]$@\tfalse@|a_task_body_grown_by_one_line_is_refused
#MUTANT task-appearance-unchecked|s@^\tnot trim_space(head\[h\]) in base_units$@\tfalse@|a_body_moved_into_a_new_task_is_refused_even_when_the_total_falls
#MUTANT one-liner-unread|s@^\tshell_syntax(value)$@\tfalse@|a_shell_one_liner_added_to_a_task_is_refused
#MUTANT workflow-growth-unchecked|s@^\tworkflow_count(head) > workflow_count(base)$@\tfalse@|a_workflow_run_block_grown_is_refused
#MUTANT file-extension-unread|s@^shell_file(path) if shell_path(path)$@shell_file(path) if false@|an_added_shell_script_is_refused
#MUTANT exempt-unread|s@^\tsome glob in exempt_globs$@\tsome glob in set()@|an_exempt_file_is_admitted
#MUTANT declaration-unread|s@^\tshell := doc.census.shell$@\tshell := doc.census.absent@|a_task_body_grown_by_one_line_is_refused

# No NEW shell, measured in lines: a repository that has decided to stop writing
# shell can declare it, and this refuses the change that writes more.
#
# ─── WHY LINES, AND NOT BODIES ───────────────────────────────────────────────
#
# A count of task BODIES reads a 245-line body as one. Measured on one tree: a
# single change moved 2,720 lines of shell out of standalone programs into task
# strings, and a body-count ratchet over the manifest read that as the surface
# shrinking, because two programs became two strings. Counting code lines is what
# makes relocation visible: the lines did not go anywhere, so the count does not
# fall.
#
# ─── WHAT IT COUNTS ──────────────────────────────────────────────────────────
#
# * A declared manifest's command keys: every non-blank, non-comment line of a
#   triple-quoted body, and every one-line value or multi-line array entry that
#   carries shell syntax (a metacharacter, a control keyword, a `VAR=` prefix). A
#   plain argv is not shell.
# * A declared workflow's steps: every code line of a `run: |` / `run: >` block,
#   bounded by indentation, and a one-line `run:` carrying shell syntax.
# * A file: a `.sh`, `.bash` or `.bats` path, or a first line naming a shell.
#
# This is the grammar `batten census shell` counts with, clause for clause, so
# "the census fell" and "the ban passes" are two readings of one detection rather
# than two claims that can disagree.
#
# ─── WHAT IT REFUSES: GROWTH AND APPEARANCE, NEVER AN EDIT ───────────────────
#
# An edit-level ban refuses a one-line fix to a live body, which deadlocks the
# very bodies a retirement is trying to unwind. So:
#
# * `task write refused`  — a manifest's shell line count rose against the base.
# * `task add refused`    — a unit that carried no shell at the base carries some
#   now. Relocation cannot offset this arm: moving a body into a new unit while
#   deleting a bigger one elsewhere keeps the total level and still adds a unit.
# * `step write refused`  — a workflow's shell line count rose.
# * `shell place refused` — a shell file was added outside the exempt set.
#
# Deleting shell is always free.
#
# ─── WHAT IS THE CONSUMER'S (NON-NEGOTIABLE RULE 1) ──────────────────────────
#
# Which manifests, which command keys, which unit header, which workflow globs and
# which files must stay shell are the consumer's `[census.shell]` table — the
# same declaration the census reads. The row hands it over by declaring the
# config document in `documents`; this module finds it by SHAPE, as the document
# carrying `census.shell`, and names no file. A row that declares no such table
# makes this module abstain entirely: a consumer that has not said where its
# shell lives has not asked for a ban on it.
#
# The declaration must also reach the row's `line_sources`: a manifest or
# workflow the row does not read as lines is a file this module cannot see, and
# it decides nothing about it.
#
# Globs are read as the census reads them, with `*` and `?` stopping at `/` and
# `**` crossing it. Braces and classes are matched literally.

# METADATA
# description: |
#   Bound to the TREE surface: reads `input.tree.documents`, `input.tree.lines`
#   and `input.tree["base-delta"]`, never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: `base-delta` carries a hyphen, so the dotted
#   form is a parse error.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
package batten.shell_growth

import rego.v1

rules contains "shell write other"

# NULL when the base rev did not resolve, and `null` is not `undefined`, so the
# delta is bound only for an object and every arm is undefined without it rather
# than vacuously clean.
delta := d if {
	d := input.tree["base-delta"]
	is_object(d)
}

# ---------------------------------------------------------------------------
# The consumer's declaration, found by shape.
# ---------------------------------------------------------------------------

declarations contains shell if {
	some doc in input.tree.documents
	shell := doc.census.shell
	is_object(shell)
}

governed if count(declarations) > 0

manifests contains row if {
	some shell in declarations
	some row in object.get(shell, "manifest", [])
	is_string(row.path)
}

workflow_globs contains pattern if {
	some shell in declarations
	some pattern in object.get(shell, "workflows", [])
	is_string(pattern)
}

exempt_globs contains pattern if {
	some shell in declarations
	some pattern in object.get(shell, "exempt", [])
	is_string(pattern)
}

# Every command key a manifest declares, unioned across rows naming one path.
manifest_keys[path] := keys if {
	some row in manifests
	path := row.path
	keys := {key | some other in manifests; other.path == path; some key in other.keys; is_string(key)}
}

# `[path, unit]` for every manifest that declares a unit header.
units contains [row.path, row.unit] if {
	some row in manifests
	is_string(row.unit)
	row.unit != ""
}

# A glob as an anchored expression. Every regex metacharacter is escaped first,
# so only the three glob operators survive to be rewritten; the placeholders keep
# `**` from being read as two `*`.
glob_pattern(pattern) := concat("", ["^", body, "$"]) if {
	escaped := regex.replace(pattern, `[.+^$(){}\[\]|\\]`, `\${0}`)
	segments := replace(escaped, "**/", "<SEGMENTS>")
	anything := replace(segments, "**", "<ANYTHING>")
	star := replace(anything, "*", "[^/]*")
	single := replace(star, "?", "[^/]")
	opened := replace(single, "<SEGMENTS>", "(?:.*/)?")
	body := replace(opened, "<ANYTHING>", ".*")
}

matches_glob(path, pattern) if regex.match(glob_pattern(pattern), path)

exempt(path) if {
	some glob in exempt_globs
	matches_glob(path, glob)
}

is_workflow(path) if {
	some pattern in workflow_globs
	matches_glob(path, pattern)
}

# ---------------------------------------------------------------------------
# What counts as shell.
# ---------------------------------------------------------------------------

metacharacters := ["|", ";", "&", "$", "`", "<", ">", "(", ")"]

keywords := {"if", "for", "while", "until", "case", "set", "export", "source", "."}

code_line(line) if {
	text := trim_space(line)
	text != ""
	not startswith(text, "#")
}

# A command string that a shell, rather than an argv, is needed to run. The first
# word is read as written, quote included — the census's reading, kept so the two
# can never disagree about one value.
shell_syntax(value) if {
	some character in metacharacters
	contains(value, character)
}

shell_syntax(value) if {
	first := split(trim_space(value), " ")[0]
	first in keywords
}

shell_syntax(value) if {
	first := split(trim_space(value), " ")[0]
	contains(first, "=")
}

shell_path(path) if endswith(path, ".sh")

shell_path(path) if endswith(path, ".bash")

shell_path(path) if endswith(path, ".bats")

shell_shebang(path) if {
	first := input.tree.lines[path][0]
	startswith(first, "#!")
	some shell in ["sh", "bash", "zsh", "dash", "ksh"]
	some word in split(replace(first, "/", " "), " ")
	word == shell
}

shell_file(path) if shell_path(path)

shell_file(path) if shell_shebang(path)

# ---------------------------------------------------------------------------
# A manifest: bodies, one-liners and array entries, per declared key.
# ---------------------------------------------------------------------------

quotes := [`"""`, `'''`]

assignment(key) := concat("", [key, " = "])

# An opener is `<key> = """` or `<key> = '''` whose string does not close on the
# same line. Keyed index -> the quote that closes it.
openers(lines, key) := {i: quote |
	some i, line in lines
	text := trim_space(line)
	some quote in quotes
	startswith(text, concat("", [assignment(key), quote]))
	not contains(substring(text, count(assignment(key)) + 3, -1), quote)
}

# Every line index carrying a quote, per quote, computed once so a body's closer
# is a lookup over a few hundred indices rather than a scan of the whole file.
quoted(lines) := {quote: indices |
	some quote in quotes
	indices := {j | some j, line in lines; contains(line, quote)}
}

bodies(lines, key) := {j |
	carrying := quoted(lines)
	some i, quote in openers(lines, key)
	closer := min({j | some j in carrying[quote]; j > i})
	closer > i + 1
	some j in numbers.range(i + 1, closer - 1)
}

# A single-line value, or `<key> = [...]` on one line.
one_liner(line, key) := value if {
	text := trim_space(line)
	startswith(text, assignment(key))
	value := substring(text, count(assignment(key)), -1)
	not startswith(value, `"""`)
	not startswith(value, `'''`)
	value != "["
}

# The string entries of a multi-line `<key> = [` array.
array_entries(lines, key) := {j |
	some i, line in lines
	trim_space(line) == concat("", [key, " = ["])
	closer := min({k | some k, other in lines; k > i; startswith(trim_space(other), "]")})
	closer > i + 1
	some j in numbers.range(i + 1, closer - 1)
}

single_liners(lines, key) := {j |
	some j, line in lines
	value := one_liner(line, key)
	shell_syntax(value)
}

array_liners(lines, key) := {j |
	some j in array_entries(lines, key)
	value := trim_space(lines[j])
	shell_syntax(value)
}

key_lines(lines, key) := ({j | some j in bodies(lines, key); code_line(lines[j])} | single_liners(lines, key)) | array_liners(lines, key)

shell_lines(lines, keys) := {j |
	some key in keys
	some j in key_lines(lines, key)
}

# Each unit's span: its header's index to the next header's, over the headers in
# file order. Computed once per side, so finding which unit a shell line belongs
# to is a range walk over one unit rather than a scan of every header per line.
headers(lines, unit) := sort([h | some h, line in lines; startswith(trim_space(line), unit)])

span_end(starts, k, total) := starts[k + 1] if k + 1 < count(starts)

span_end(starts, k, total) := total if k + 1 >= count(starts)

unit_spans(lines, unit) := {h: finish |
	starts := headers(lines, unit)
	some k, h in starts
	finish := span_end(starts, k, count(lines))
}

# The header index of every unit carrying at least one shell line.
shell_units(lines, keys, unit) := {h |
	shell := shell_lines(lines, keys)
	some h, finish in unit_spans(lines, unit)
	some j in numbers.range(h, finish - 1)
	j in shell
}

units_with_shell(lines, keys, unit) := {trim_space(lines[h]) | some h in shell_units(lines, keys, unit)}

# ---------------------------------------------------------------------------
# A workflow: `run: |` blocks by indentation, and one-line `run:` steps.
# ---------------------------------------------------------------------------

indent(line) := count(line) - count(trim_left(line, " "))

run_key(line) := rest if {
	text := trim_space(line)
	some prefix in ["- run:", "run:"]
	startswith(text, prefix)
	rest := trim_space(substring(text, count(prefix), -1))
}

# The indentation a block's lines must exceed: the `run:` key's own column.
key_column(line) := indent(line) + 2 if startswith(trim_space(line), "- ")

key_column(line) := indent(line) if not startswith(trim_space(line), "- ")

block_openers(lines) := {i |
	some i, line in lines
	rest := run_key(line)
	some marker in ["|", ">"]
	startswith(rest, marker)
}

workflow_blocks(lines) := {j |
	some i in block_openers(lines)
	column := key_column(lines[i])
	ends := {k | some k, other in lines; k > i; trim_space(other) != ""; indent(other) <= column}
	closer := min(ends | {count(lines)})
	closer > i + 1
	some j in numbers.range(i + 1, closer - 1)
}

workflow_one_liners(lines) := {j |
	some j, line in lines
	rest := run_key(line)
	rest != ""
	not startswith(rest, "|")
	not startswith(rest, ">")
	shell_syntax(rest)
}

workflow_count(lines) := count({j | some j in workflow_blocks(lines); code_line(lines[j])} | workflow_one_liners(lines))

# ---------------------------------------------------------------------------
# The refusals.
# ---------------------------------------------------------------------------

# Both sides of each edited manifest, bound once as PARTIAL RULES keyed by path,
# so every arm below reads a cached value: a function over the file would be
# re-derived at each call site.
head_count[path] := count(shell_lines(input.tree.lines[path], keys)) if {
	some path, keys in manifest_keys
	path in delta.edited
}

base_count[path] := count(shell_lines(delta["base-lines"][path], keys)) if {
	some path, keys in manifest_keys
	path in delta.edited
}

violation contains {
	"rule": "shell write other",
	"verdict": "task write refused",
	"subjects": [{"path": path}, {"count": head - base_count[path]}],
} if {
	some path, head in head_count
	head > base_count[path]
}

violation contains {
	"rule": "shell write other",
	"verdict": "task add refused",
	"subjects": [{"path": path, "line": h + 1}],
} if {
	some pair in units
	path := pair[0]
	unit := pair[1]
	path in delta.edited
	head := input.tree.lines[path]
	keys := manifest_keys[path]
	base_units := units_with_shell(delta["base-lines"][path], keys, unit)
	some h in shell_units(head, keys, unit)
	not trim_space(head[h]) in base_units
}

violation contains {
	"rule": "shell write other",
	"verdict": "step write refused",
	"subjects": [{"path": path}, {"count": workflow_count(head) - workflow_count(base)}],
} if {
	some path in delta.edited
	is_workflow(path)
	head := input.tree.lines[path]
	base := delta["base-lines"][path]
	workflow_count(head) > workflow_count(base)
}

violation contains {
	"rule": "shell write other",
	"verdict": "shell place refused",
	"subjects": [{"path": path}],
} if {
	governed
	some path in delta.added
	shell_file(path)
	not exempt(path)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE over a fabricated input, for a consumer that is
# deliberately not the one this preset was lifted from: its manifest is
# `tasks.toml` with a `cmd` key and `[task.` units, its workflows live under
# `ci/`, and the one file it keeps as shell is `bootstrap.sh`. That the ENGINE
# builds `documents`, `lines` and `base-lines` for these paths is the compiled
# tier's to show (`crates/batten/tests/it/shell_banned.rs`).

declared := {"census": {"shell": {
	"workflows": ["ci/*.yml"],
	"exempt": ["bootstrap.sh", "vendor/**"],
	"manifest": [{"path": "tasks.toml", "keys": ["cmd"], "unit": "[task."}],
}}}

edited(path, base, head) := {"tree": {
	"documents": {"config.toml": declared},
	"base-delta": {"added": [], "edited": [path], "deleted": [], "base-lines": {path: base}},
	"lines": {path: head},
}}

added(path, head) := {"tree": {
	"documents": {"config.toml": declared},
	"base-delta": {"added": [path], "edited": [], "deleted": [], "base-lines": {}},
	"lines": {path: head},
}}

task(name, body) := array.concat(array.concat([concat("", ["[task.", name, "]"]), `cmd = '''`], body), [`'''`])

verdicts(input_document) := {v.verdict | some v in violation with input as input_document}

test_a_body_grown_by_one_line_is_refused if {
	base := task("a", ["echo one"])
	head := task("a", ["echo one", "echo two"])
	"task write refused" in verdicts(edited("tasks.toml", base, head))
}

test_an_edit_that_does_not_grow_a_body_is_admitted if {
	base := task("a", ["echo one"])
	head := task("a", ["echo uno"])
	count(verdicts(edited("tasks.toml", base, head))) == 0
}

test_a_deleted_body_is_admitted if {
	base := array.concat(task("a", ["echo one"]), task("b", ["echo two"]))
	head := task("a", ["echo one"])
	count(verdicts(edited("tasks.toml", base, head))) == 0
}

test_a_body_moved_into_a_new_unit_is_refused_even_when_the_total_falls if {
	base := task("a", ["echo 1", "echo 2", "echo 3"])
	head := task("b", ["echo 1"])
	"task add refused" in verdicts(edited("tasks.toml", base, head))
}

test_comments_and_blank_lines_are_not_shell if {
	base := task("a", ["echo one"])
	head := task("a", ["# why", "", "echo one"])
	count(verdicts(edited("tasks.toml", base, head))) == 0
}

test_a_plain_argv_one_liner_is_not_shell if {
	base := ["[task.a]", `cmd = "cargo build"`]
	head := array.concat(base, ["[task.b]", `cmd = "cargo nextest run"`])
	count(verdicts(edited("tasks.toml", base, head))) == 0
}

test_a_shell_one_liner_added_to_a_unit_is_refused if {
	base := ["[task.a]", `cmd = "cargo build"`]
	head := array.concat(base, ["[task.b]", `cmd = "cargo build && cargo test"`])
	"task add refused" in verdicts(edited("tasks.toml", base, head))
}

test_a_shell_array_entry_is_counted if {
	base := ["[task.a]", "cmd = [", `  "cargo build",`, "]"]
	head := ["[task.a]", "cmd = [", `  "cargo build",`, `  "a && b",`, "]"]
	"task write refused" in verdicts(edited("tasks.toml", base, head))
}

# A key the consumer did not declare is not a command, whatever it holds: `run`
# is somebody else's key here.
test_an_undeclared_key_is_not_read if {
	base := ["[task.a]", `cmd = "cargo build"`]
	head := array.concat(base, [`run = "a | b"`])
	count(verdicts(edited("tasks.toml", base, head))) == 0
}

# ...and a manifest the consumer did not declare is not read at all.
test_an_undeclared_manifest_is_not_read if {
	base := ["[task.a]", `cmd = '''`, "echo one", `'''`]
	head := ["[task.a]", `cmd = '''`, "echo one", "echo two", `'''`]
	count(verdicts(edited("other.toml", base, head))) == 0
}

test_a_workflow_run_block_grown_is_refused if {
	base := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "      - uses: x"]
	head := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two", "      - uses: x"]
	"step write refused" in verdicts(edited("ci/build.yml", base, head))
}

# The workflow glob is `ci/*.yml`, so a nested file is not a declared workflow.
test_a_workflow_outside_the_declared_glob_is_not_read if {
	base := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one"]
	head := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two"]
	count(verdicts(edited("ci/nested/build.yml", base, head))) == 0
}

test_a_plain_workflow_step_is_not_shell if {
	base := ["jobs:", "  a:", "    steps:", "      - run: make verify"]
	head := array.concat(base, ["      - run: make lint"])
	count(verdicts(edited("ci/build.yml", base, head))) == 0
}

test_an_added_shell_script_is_refused if {
	"shell place refused" in verdicts(added("scripts/x.sh", ["echo"]))
}

test_an_added_shebang_program_is_refused if {
	"shell place refused" in verdicts(added("tools/run", ["#!/usr/bin/env bash", "echo"]))
}

test_a_shebang_naming_another_language_is_not_shell if {
	count(verdicts(added("tools/run", ["#!/usr/bin/env python3", "print(1)"]))) == 0
}

test_an_exempt_file_is_admitted if {
	count(verdicts(added("bootstrap.sh", ["#!/bin/sh"]))) == 0
}

# `**` crosses directories; the exemption is read as a glob, not as a literal.
test_an_exempt_glob_reaches_below_its_directory if {
	count(verdicts(added("vendor/lib/x.sh", ["echo"]))) == 0
}

# `.` is a regex metacharacter and must not be one here: `bootstrapXsh` is not
# `bootstrap.sh`.
test_a_glob_dot_is_literal if {
	"shell place refused" in verdicts(added("bootstrapXsh", ["#!/bin/sh"]))
}

# NO DECLARATION, NO BAN. A consumer enabling the preset for its other modules
# has not said where its shell lives, so the file arm abstains too.
test_a_consumer_declaring_no_census_is_not_banned if {
	count(violation) == 0 with input as {"tree": {
		"documents": {"config.toml": {"version": 1}},
		"base-delta": {"added": ["scripts/x.sh"], "edited": [], "deleted": [], "base-lines": {}},
		"lines": {"scripts/x.sh": ["echo"]},
	}}
}

test_a_base_that_did_not_resolve_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {"config.toml": declared}, "base-delta": null, "lines": {}}}
}

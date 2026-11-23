#MUTANT-SUITE crates/batten/tests/it/shell_banned.rs
#MUTANT task-growth-unchecked|s@^\thead > base_count\[path\]$@\tfalse@|a_task_body_grown_by_one_line_is_refused
#MUTANT task-appearance-unchecked|s@^\tnot trim_space(head\[h\]) in units_with_shell(base_side(path), shell_lines(base_entry(path)), unit)$@\tfalse@|a_body_moved_into_a_new_task_is_refused_even_when_the_total_falls
#MUTANT workflow-growth-unchecked|s@^\tcount(shell_lines(head_entry(path))) > count(shell_lines(base_entry(path)))$@\tfalse@|a_workflow_run_block_grown_is_refused
#MUTANT exempt-unread|s@^\tsome glob in exempt_globs$@\tsome glob in set()@|an_exempt_file_is_admitted
#MUTANT declaration-unread|s@^\tshell := doc.census.shell$@\tshell := doc.census.absent@|shell_standing_at_the_base_is_admitted_by_the_declared_migration
#MUTANT presence-arm-unread|s@^presence if not migrating$@presence if false@|a_base_tree_shell_file_is_refused_by_default_and_admitted_under_migrate
#MUTANT legacy-exempt-read-as-presence|s@^migrating if count(exempt_globs) > 0$@migrating if false@|a_config_that_still_carries_exempt_keeps_its_growth_meaning
#MUTANT generated-entry-for-absent-file-admitted|s@^\tmeasured.matches == 0$@\tfalse@|a_generated_entry_covering_no_file_is_a_finding
#MUTANT generated-check-not-found-admitted|s@^\tnot measured.check_found$@\tfalse@|a_generated_entry_whose_check_is_not_found_is_a_finding
#MUTANT file-growth-unchecked|s@^\tgrown > 0$@\tfalse@|an_existing_shell_file_that_grows_under_migrate_is_refused
#MUTANT engine-shell-spawn-unread|s@^\tnot declared_spawn(site)$@\tfalse@|an_undeclared_engine_shell_spawn_is_refused

# No shell, and while migrating, no NEW shell, measured in lines.
#
# ─── PRESENCE BY DEFAULT, GROWTH WHILE MIGRATING (CLOUD-2628) ────────────────
#
# A consumer enabling this preset is refused any authored shell: every path the
# fact's head side carries as shell — a shell file anywhere in the tracked tree,
# a declared manifest's shell command lines, a declared workflow's shell steps —
# is `shell present refused` unless a `[[census.shell.generated]]` entry covers
# it. A consumer declaring no `[census.shell]` at all is judged the same way:
# the census table is the only channel for consumer facts, so no declaration
# is not migrating, and that is the presence path, never an exemption.
#
# `[census.shell] mode = "migrate"` is the one knob. Under it presence is not
# judged and the growth arms below run instead, so the existing surface may
# only shrink. A LEGACY `exempt` list that is non-empty, with no `mode`, reads
# as migrate with those files exempt, exactly as before; `exempt = []` is the
# same as absent and is presence.
#
# The generated table is held in BOTH directions: shell outside it is refused,
# and an entry with nothing behind it — a glob matching no tracked path
# (`shell path missing`), or a check whose test name no line of its file holds
# (`shell test missing`) — is refused too. Both are the engine's measurements,
# on `input.tree.shell.generated`; this module only reads them.
#
# ─── MIGRATING: NO NEW SHELL, MEASURED IN LINES ──────────────────────────────
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
# ─── WHAT COUNTS IS NOT THIS MODULE'S TO DECIDE (CLOUD-2625) ─────────────────
#
# Which lines are shell is `input.tree.shell`, computed in Rust by the one
# detector the census also counts with (`crates/batten/src/shell.rs`, decided on
# the parser's AST): a declared manifest's command keys and a declared
# workflow's `run:` steps, judged as shell logic or plain argv, and every shell
# file by its extension or its shebang. The fact carries both sides of the
# delta, so "the census fell" and "the ban passes" are one detection read twice
# rather than two scans kept in step by comment. This module compares the two
# sides and decides nothing about a line's content.
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
# * `shell place refused` — a shell file was added outside the legacy exempt
#   set and the generated table.
# * `file write refused`  — an existing shell file's code lines rose against the
#   base, or it became shell by gaining a shebang. Head and base are both read
#   at check time, so no count is stored.
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
# is judged for presence over every tracked file (above): enabling the ban is
# the request for it.
#
# The fact reads past the row's `line_sources` (CLOUD-2628): every tracked file
# that can be shell, every declared manifest and every path a workflow glob
# selects. Unit headers are still read off `input.tree.lines`, since a header is
# where a unit starts and not a judgement about shell, so the `task add` arm
# needs the manifests in `line_sources`.
#
# Globs are read as the census reads them, with `*` and `?` stopping at `/` and
# `**` crossing it. Those three are the whole glob language here: a declaration
# spelling a brace, a class or a backslash escape is refused when the config
# loads (`ShellCensus::validate`), because `globset` would read it as an operator
# and this module as a literal, and the census and the ban would then judge
# different files off one list.
#
# ─── A BASE THAT COULD NOT BE READ ───────────────────────────────────────────
#
# The engine hands every edited path a base side, and a base blob it could not
# read (or that is not UTF-8) arrives as the EMPTY side, which the fact reads as
# no shell at the base. Every arm reads that as nothing at the base, so each
# shell line and shell unit the head carries is growth and is refused — "cannot
# tell" is never read as "nothing was added". `base_entry` and `base_side` give a
# path missing from either map the same reading, so no arm depends on which of
# the two shapes an unread base takes.

# METADATA
# description: |
#   Bound to the TREE surface: reads `input.tree.documents`, `input.tree.lines`,
#   `input.tree.shell` and `input.tree["base-delta"]`, never the mediated
#   `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: `base-delta` carries a hyphen, so the dotted
#   form is a parse error.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.shell_growth

import rego.v1

rules contains "shell write other"

# NULL when the base rev did not resolve, and `null` is not `undefined`, so the
# delta is bound only for an object and every arm is undefined without it rather
# than vacuously clean.
delta := d if {
	d = input.tree["base-delta"]
	is_object(d)
}

# ---------------------------------------------------------------------------
# The consumer's declaration, found by shape.
# ---------------------------------------------------------------------------

declarations contains shell if {
	some doc in input.tree.documents
	shell = doc.census.shell
	is_object(shell)
}

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

generated_globs contains pattern if {
	some shell in declarations
	some row in object.get(shell, "generated", [])
	pattern = row.path
	is_string(pattern)
}

# ---------------------------------------------------------------------------
# The mode: presence unless the consumer declares it is migrating.
# ---------------------------------------------------------------------------

migrating if {
	some shell in declarations
	object.get(shell, "mode", null) == "migrate"
}

# LEGACY: a non-empty `exempt` with no `mode` is migrate, as before CLOUD-2628.
# An empty list never reaches here, so `exempt = []` stays presence.
migrating if count(exempt_globs) > 0

# No declaration at all is not migrating, so it is presence too.
presence if not migrating

# Every declared manifest path.
manifest_paths contains row.path if some row in manifests

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

generated(path) if {
	some glob in generated_globs
	matches_glob(path, glob)
}

# ---------------------------------------------------------------------------
# What is shell: the fact, read and never re-derived.
# ---------------------------------------------------------------------------

shell_fact := s if {
	s = input.tree.shell
	is_object(s)
}

# A path's entry on one side, or `{}` for a path that side does not carry —
# which every arm reads as no shell there.
head_entry(path) := object.get(object.get(shell_fact, "head", {}), path, {})

base_entry(path) := object.get(object.get(shell_fact, "base", {}), path, {})

# An entry's shell lines as 0-based indices, the indexing `input.tree.lines` uses.
shell_lines(entry) := {j |
	some l in object.get(entry, "lines", [])
	j := l.line - 1
}

shell_file(path) if head_entry(path).kind == "file"

# An entry carries shell: any shell FILE, whatever its lines, and a manifest or
# workflow with at least one shell line.
carries_shell(entry) if entry.kind == "file"

carries_shell(entry) if count(object.get(entry, "lines", [])) > 0

# ---------------------------------------------------------------------------
# A manifest's units: which unit each shell line belongs to.
# ---------------------------------------------------------------------------

# Each unit's span: its header's index to the next header's, over the headers in
# file order. Computed once per side, so finding which unit a shell line belongs
# to is a range walk over one unit rather than a scan of every header per line.
headers(lines, unit) := sort([h | some h, line in lines; startswith(trim_space(line), unit)])

span_end(starts, k, total) := starts[k + 1] if k + 1 < count(starts)

span_end(starts, k, total) := total if k + 1 >= count(starts)

unit_spans(lines, unit) := {h: finish |
	starts = headers(lines, unit)
	some k, h in starts
	finish = span_end(starts, k, count(lines))
}

# The header index of every unit carrying at least one shell line.
shell_units(lines, shell, unit) := {h |
	some h, finish in unit_spans(lines, unit)
	some j in numbers.range(h, finish - 1)
	j in shell
}

units_with_shell(lines, shell, unit) := {trim_space(lines[h]) | some h in shell_units(lines, shell, unit)}

# ---------------------------------------------------------------------------
# The refusals.
# ---------------------------------------------------------------------------

# Both sides of each edited manifest, bound once as PARTIAL RULES keyed by path,
# so every arm below reads a cached value.
head_count[path] := count(shell_lines(head_entry(path))) if {
	some path in manifest_paths
	path in delta.edited
}

base_count[path] := count(shell_lines(base_entry(path))) if {
	some path in manifest_paths
	path in delta.edited
}

violation contains {
	"rule": "shell write other",
	"verdict": "task write refused",
	"subjects": [{"path": path}, {"count": head - base_count[path]}],
} if {
	migrating
	some path, head in head_count
	head > base_count[path]
}

violation contains {
	"rule": "shell write other",
	"verdict": "task add refused",
	"subjects": [{"path": path, "line": h + 1}],
} if {
	migrating
	some pair in units
	path = pair[0]
	unit = pair[1]
	path in delta.edited
	head = input.tree.lines[path]
	some h in shell_units(head, shell_lines(head_entry(path)), unit)
	not trim_space(head[h]) in units_with_shell(base_side(path), shell_lines(base_entry(path)), unit)
}

# The base side's LINES of an edited path, for its unit headers. An unreadable
# or non-UTF-8 base blob arrives as the EMPTY side (`git.rs`, `base_text` and the
# `base_lines` insert below it), and a path missing from the map is read the same
# way rather than left undefined — undefined would fail the arm above and admit
# the edit — so no input shape turns "cannot tell" into "nothing was added".
base_side(path) := object.get(object.get(delta, "base-lines", {}), path, [])

violation contains {
	"rule": "shell write other",
	"verdict": "step write refused",
	"subjects": [{"path": path}, {"count": count(shell_lines(head_entry(path))) - count(shell_lines(base_entry(path)))}],
} if {
	migrating
	some path in delta.edited
	is_workflow(path)
	count(shell_lines(head_entry(path))) > count(shell_lines(base_entry(path)))
}

violation contains {
	"rule": "shell write other",
	"verdict": "shell place refused",
	"subjects": [{"path": path}],
} if {
	migrating
	some path in delta.added
	shell_file(path)
	not exempt(path)
	not generated(path)
}

# An existing shell file may not gain shell lines while migrating. Both sides
# are the fact's, computed at check time: the base side from `base-lines`, so
# an unread base is no shell there and every line the head carries is growth.
violation contains {
	"rule": "shell write other",
	"verdict": "file write refused",
	"subjects": [{"path": path}, {"count": grown}],
} if {
	migrating
	some path in delta.edited
	shell_file(path)
	not exempt(path)
	not generated(path)
	grown := count(shell_lines(head_entry(path))) - count(shell_lines(base_entry(path)))
	grown > 0
}

# ---------------------------------------------------------------------------
# Presence (CLOUD-2628): any shell the head carries that no generated entry
# covers. The head side reads every tracked file that can be shell, so this is
# the whole tree, not the row's line sources.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "shell write other",
	"verdict": "shell present refused",
	"subjects": [{"path": path}],
} if {
	presence
	some path, side in object.get(shell_fact, "head", {})
	carries_shell(side)
	not generated(path)
}

# The table held in the other direction: an entry with nothing behind it.
# `matches` and `check_found` are the engine's, measured over the tracked tree.
violation contains {
	"rule": "shell write other",
	"verdict": "shell path missing",
	"subjects": [{"path": measured.path}],
} if {
	some measured in object.get(shell_fact, "generated", [])
	measured.matches == 0
}

violation contains {
	"rule": "shell write other",
	"verdict": "shell test missing",
	"subjects": [{"path": measured.path}],
} if {
	some measured in object.get(shell_fact, "generated", [])
	not measured.check_found
}

# ---------------------------------------------------------------------------
# Engine source that spawns a shell (CLOUD-2770). The sites are the fact's: a
# string-literal argv outside test code whose program the detector reads as a
# shell. A site no `[[census.shell.spawn]]` row declares is refused, and a row
# naming no site is refused too.
#
# PRESENCE ONLY: WHILE `[census.shell]` IS MIGRATING, BOTH ARMS ABSTAIN (owner
# ruling, 2026-11-22, recorded in 383746da). The spawn table is the presence
# regime's declaration, written in the same change that retires the migrating
# `exempt` list, so judging spawns under migrate refused a consumer for a table
# its own mode has not reached yet. Presence holds it in both directions.
# ---------------------------------------------------------------------------

spawn_rows contains [row.path, row.function] if {
	some shell in declarations
	some row in object.get(shell, "spawn", [])
	is_string(row.path)
	is_string(row.function)
}

# Absent when the fact did not read the whole tree, so neither arm decides.
spawn_sites := s if {
	s = shell_fact.spawn
	is_array(s)
}

declared_spawn(site) if [site.path, site.function] in spawn_rows

violation contains {
	"rule": "shell write other",
	"verdict": "shell spawn refused",
	"subjects": [{"path": site.path, "line": site.line}],
} if {
	presence
	some site in spawn_sites
	not declared_spawn(site)
}

spawn_found(pair) if {
	some site in spawn_sites
	[site.path, site.function] == pair
}

violation contains {
	"rule": "shell write other",
	"verdict": "shell spawn missing",
	"subjects": [{"path": pair[0]}],
} if {
	presence
	is_array(spawn_sites)
	some pair in spawn_rows
	not spawn_found(pair)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE over a fabricated input, for a consumer that is
# deliberately not the one this preset was lifted from: its manifest is
# `tasks.toml` with a `cmd` key and `[task.` units, its workflows live under
# `ci/`, and the one file it keeps as shell is `bootstrap.sh`. The `shell` fact
# is fabricated too: which lines are shell is the detector's, pinned by
# `shell.rs`'s own cases, and that the ENGINE builds `documents`, `lines`,
# `base-lines` and `shell` for these paths is the compiled tier's to show
# (`crates/batten/tests/it/shell_banned.rs`).

declared := {"census": {"shell": {
	"workflows": ["ci/*.yml"],
	"exempt": ["bootstrap.sh", "vendor/**"],
	"manifest": [{"path": "tasks.toml", "keys": ["cmd"], "unit": "[task."}],
}}}

# A fact entry of `kind` whose shell lines are the 1-based `numbers`.
entry(kind, numbers) := {"kind": kind, "lines": [line |
	some n in numbers
	line := {"line": n, "reason": "multi-command"}
]}

edited(path, kind, base, head, base_shell, head_shell) := {"tree": {
	"documents": {"config.toml": declared},
	"base-delta": {"added": [], "edited": [path], "deleted": [], "base-lines": {path: base}},
	"lines": {path: head},
	"shell": {"head": {path: entry(kind, head_shell)}, "base": {path: entry(kind, base_shell)}},
}}

added(path, head, shell) := {"tree": {
	"documents": {"config.toml": declared},
	"base-delta": {"added": [path], "edited": [], "deleted": [], "base-lines": {}},
	"lines": {path: head},
	"shell": {"head": shell, "base": {}},
}}

# An added path the fact reads as a shell file.
shell_file_fact(path) := {path: entry("file", [1])}

task(name, body) := array.concat(array.concat([concat("", ["[task.", name, "]"]), `cmd = '''`], body), [`'''`])

verdicts(input_document) := {v.verdict | some v in violation with input as input_document}

test_a_body_grown_by_one_line_is_refused if {
	base = task("a", ["echo one", "echo two"])
	head = task("a", ["echo one", "echo two", "echo three"])
	"task write refused" in verdicts(edited("tasks.toml", "manifest", base, head, [3, 4], [3, 4, 5]))
}

test_an_edit_that_does_not_grow_a_body_is_admitted if {
	base = task("a", ["echo one", "echo two"])
	head = task("a", ["echo uno", "echo two"])
	count(verdicts(edited("tasks.toml", "manifest", base, head, [3, 4], [3, 4]))) == 0
}

test_a_deleted_body_is_admitted if {
	base := array.concat(task("a", ["echo 1", "echo 2"]), task("b", ["echo 3", "echo 4"]))
	head = task("a", ["echo 1", "echo 2"])
	count(verdicts(edited("tasks.toml", "manifest", base, head, [3, 4, 8, 9], [3, 4]))) == 0
}

test_a_body_moved_into_a_new_unit_is_refused_even_when_the_total_falls if {
	base = task("a", ["echo 1", "echo 2", "echo 3"])
	head = task("b", ["echo 1", "echo 2"])
	found = verdicts(edited("tasks.toml", "manifest", base, head, [3, 4, 5], [3, 4]))
	"task add refused" in found
	not "task write refused" in found
}

test_a_shell_one_liner_added_to_a_unit_is_refused if {
	base := ["[task.a]", `cmd = "cargo build"`]
	head := array.concat(base, ["[task.b]", `cmd = "cargo build && cargo test"`])
	"task add refused" in verdicts(edited("tasks.toml", "manifest", base, head, [], [4]))
}

test_a_shell_array_entry_is_counted if {
	base := ["[task.a]", "cmd = [", `  "cargo build",`, "]"]
	head := ["[task.a]", "cmd = [", `  "cargo build",`, `  "a && b",`, "]"]
	"task write refused" in verdicts(edited("tasks.toml", "manifest", base, head, [], [4]))
}

# ...and a manifest the consumer did not declare is not read at all, whatever
# the fact says of it.
test_an_undeclared_manifest_is_not_read if {
	base := ["[task.a]", `cmd = '''`, "echo one", "echo two", `'''`]
	head := ["[task.a]", `cmd = '''`, "echo one", "echo two", "echo three", `'''`]
	count(verdicts(edited("other.toml", "manifest", base, head, [3, 4], [3, 4, 5]))) == 0
}

test_a_workflow_run_block_grown_is_refused if {
	base := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two", "      - uses: x"]
	head := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two", "          echo three", "      - uses: x"]
	"step write refused" in verdicts(edited("ci/build.yml", "workflow", base, head, [5, 6], [5, 6, 7]))
}

# The workflow glob is `ci/*.yml`, so a nested file is not a declared workflow.
test_a_workflow_outside_the_declared_glob_is_not_read if {
	base := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two"]
	head := ["jobs:", "  a:", "    steps:", "      - run: |", "          echo one", "          echo two", "          echo three"]
	count(verdicts(edited("ci/nested/build.yml", "workflow", base, head, [5, 6], [5, 6, 7]))) == 0
}

test_a_workflow_the_fact_reads_no_shell_in_is_admitted if {
	base := ["jobs:", "  a:", "    steps:", "      - run: make verify"]
	head := array.concat(base, ["      - run: make lint"])
	count(verdicts(edited("ci/build.yml", "workflow", base, head, [], []))) == 0
}

test_an_added_shell_script_is_refused if {
	"shell place refused" in verdicts(added("scripts/x.sh", ["echo"], shell_file_fact("scripts/x.sh")))
}

test_an_added_shebang_program_is_refused if {
	"shell place refused" in verdicts(added("tools/run", ["#!/usr/bin/env bash", "echo"], shell_file_fact("tools/run")))
}

test_a_path_the_fact_does_not_call_a_shell_file_is_not_shell if {
	count(verdicts(added("tools/run", ["#!/usr/bin/env python3", "print(1)"], {}))) == 0
}

test_an_exempt_file_is_admitted if {
	count(verdicts(added("bootstrap.sh", ["#!/bin/sh"], shell_file_fact("bootstrap.sh")))) == 0
}

# `**` crosses directories; the exemption is read as a glob, not as a literal.
test_an_exempt_glob_reaches_below_its_directory if {
	count(verdicts(added("vendor/lib/x.sh", ["echo"], shell_file_fact("vendor/lib/x.sh")))) == 0
}

# `.` is a regex metacharacter and must not be one here: `bootstrapXsh` is not
# `bootstrap.sh`.
test_a_glob_dot_is_literal if {
	"shell place refused" in verdicts(added("bootstrapXsh", ["#!/bin/sh"], shell_file_fact("bootstrapXsh")))
}

# NO DECLARATION IS PRESENCE (CLOUD-2628, absorbing CLOUD-1809). A consumer
# enabling the preset has asked for the ban; the census table is only where it
# says what it admits, so its absence admits nothing.
test_a_consumer_declaring_no_census_is_judged_for_presence if {
	found := {[v.verdict, v.subjects] | some v in violation} with input as {"tree": {
		"documents": {"config.toml": {"version": 1}},
		"base-delta": {"added": [], "edited": [], "deleted": [], "base-lines": {}},
		"lines": {},
		"shell": {"head": shell_file_fact("scripts/x.sh"), "base": {}},
	}}
	found == {["shell present refused", [{"path": "scripts/x.sh"}]]}
}

# --- presence and the generated table (CLOUD-2628) ---------------------------

# A declaration with no `mode` and no `exempt`, carrying `generated` rows.
presence_declared(generated) := {"census": {"shell": {
	"workflows": ["ci/*.yml"],
	"manifest": [{"path": "tasks.toml", "keys": ["cmd"], "unit": "[task."}],
	"generated": generated,
}}}

# A tree whose head carries `head` as shell, under `declaration`, with the
# engine's `generated` measurements; nothing changed against the base.
standing(declaration, head, generated) := {"tree": {
	"documents": {"config.toml": declaration},
	"base-delta": {"added": [], "edited": [], "deleted": [], "base-lines": {}},
	"lines": {},
	"shell": {"head": head, "base": {}, "generated": generated},
}}

gen_row := {"path": "gen/*.sh", "generator": "batten completions", "check": "t.rs::pins_it"}

test_a_shell_file_standing_at_the_base_is_refused_by_default if {
	found = verdicts(standing(presence_declared([]), shell_file_fact("tools/x.sh"), []))
	found == {"shell present refused"}
}

test_a_manifest_carrying_shell_lines_is_refused_by_default if {
	head := {"tasks.toml": entry("manifest", [3])}
	"shell present refused" in verdicts(standing(presence_declared([]), head, []))
}

test_a_manifest_carrying_no_shell_is_not_present if {
	head := {"tasks.toml": entry("manifest", [])}
	count(verdicts(standing(presence_declared([]), head, []))) == 0
}

test_migrate_judges_growth_and_not_presence if {
	declaration := {"census": {"shell": {"mode": "migrate"}}}
	count(verdicts(standing(declaration, shell_file_fact("tools/x.sh"), []))) == 0
}

# `exempt = []` is the same as absent: presence.
test_an_empty_exempt_list_is_presence if {
	declaration := {"census": {"shell": {"exempt": []}}}
	"shell present refused" in verdicts(standing(declaration, shell_file_fact("tools/x.sh"), []))
}

test_a_generated_file_is_admitted if {
	measured := [{"path": "gen/*.sh", "matches": 1, "check_found": true}]
	found = verdicts(standing(presence_declared([gen_row]), shell_file_fact("gen/a.sh"), measured))
	count(found) == 0
}

test_a_generated_entry_covering_no_file_is_refused if {
	measured := [{"path": "gen/*.sh", "matches": 0, "check_found": true}]
	found = verdicts(standing(presence_declared([gen_row]), {}, measured))
	found == {"shell path missing"}
}

test_a_generated_entry_whose_check_is_not_found_is_refused if {
	measured := [{"path": "gen/*.sh", "matches": 1, "check_found": false}]
	found = verdicts(standing(presence_declared([gen_row]), shell_file_fact("gen/a.sh"), measured))
	found == {"shell test missing"}
}

test_an_existing_shell_file_that_grows_while_migrating_is_refused if {
	document := {"tree": {
		"documents": {"config.toml": declared},
		"base-delta": {"added": [], "edited": ["tools/x.sh"], "deleted": [], "base-lines": {"tools/x.sh": ["echo one"]}},
		"lines": {},
		"shell": {
			"head": {"tools/x.sh": entry("file", [1, 2])},
			"base": {"tools/x.sh": entry("file", [1])},
		},
	}}
	found := {[v.verdict, v.subjects] | some v in violation with input as document}
	found == {["file write refused", [{"path": "tools/x.sh"}, {"count": 1}]]}
}

test_an_existing_shell_file_that_does_not_grow_is_admitted if {
	document := {"tree": {
		"documents": {"config.toml": declared},
		"base-delta": {"added": [], "edited": ["tools/x.sh"], "deleted": [], "base-lines": {"tools/x.sh": ["echo one"]}},
		"lines": {},
		"shell": {
			"head": {"tools/x.sh": entry("file", [1])},
			"base": {"tools/x.sh": entry("file", [1, 2])},
		},
	}}
	count(violation) == 0 with input as document
}

# COULD-NOT-LOOK IS NOT CLEAN: an edited manifest whose base could not be read
# refuses every shell line and unit it carries, rather than reading the unread
# base as holding them all. The engine's shape is the empty side; the missing key
# is read alike, so both are pinned by one case.
test_an_unread_base_refuses_every_shell_unit if {
	head = task("a", ["echo one", "echo two"])
	every base_lines in [{"tasks.toml": []}, {}] {
		document := {"tree": {
			"documents": {"config.toml": declared},
			"base-delta": {"added": [], "edited": ["tasks.toml"], "deleted": [], "base-lines": base_lines},
			"lines": {"tasks.toml": head},
			"shell": {"head": {"tasks.toml": entry("manifest", [3, 4])}, "base": {}},
		}}
		found := {[v.verdict, v.subjects] | some v in violation with input as document}
		found == {
			["task write refused", [{"path": "tasks.toml"}, {"count": 2}]],
			["task add refused", [{"path": "tasks.toml", "line": 1}]],
		}
	}
}

# --- engine spawn sites (CLOUD-2770) ----------------------------------------

# Presence (no `mode`, no `exempt`): the regime the spawn table belongs to.
spawn_declared(rows) := {"census": {"shell": {"spawn": rows}}}

# The same table under migrate: both spawn arms abstain.
spawn_migrating(rows) := {"census": {"shell": {"mode": "migrate", "spawn": rows}}}

spawn_row := {"path": "src/lib.rs", "function": "run", "contract": "https://example.com/format"}

spawn_site := {"path": "src/lib.rs", "line": 3, "function": "run"}

test_an_undeclared_spawn_is_refused if {
	found = verdicts({"tree": {
		"documents": {"config.toml": spawn_declared([])},
		"shell": {"head": {}, "base": {}, "spawn": [spawn_site]},
	}})
	found == {"shell spawn refused"}
}

test_a_declared_spawn_is_admitted if {
	count(verdicts({"tree": {
		"documents": {"config.toml": spawn_declared([spawn_row])},
		"shell": {"head": {}, "base": {}, "spawn": [spawn_site]},
	}})) == 0
}

test_a_spawn_row_naming_no_site_is_refused if {
	found = verdicts({"tree": {
		"documents": {"config.toml": spawn_declared([spawn_row])},
		"shell": {"head": {}, "base": {}, "spawn": []},
	}})
	found == {"shell spawn missing"}
}

test_an_undeclared_spawn_is_not_judged_while_migrating if {
	not "shell spawn refused" in verdicts({"tree": {
		"documents": {"config.toml": spawn_migrating([])},
		"shell": {"head": {}, "base": {}, "spawn": [spawn_site]},
	}})
}

test_a_spawn_row_naming_no_site_is_not_judged_while_migrating if {
	not "shell spawn missing" in verdicts({"tree": {
		"documents": {"config.toml": spawn_migrating([spawn_row])},
		"shell": {"head": {}, "base": {}, "spawn": []},
	}})
}

test_a_spawn_row_is_not_judged_when_the_sites_were_not_read if {
	count(verdicts({"tree": {
		"documents": {"config.toml": spawn_declared([spawn_row])},
		"shell": {"head": {}, "base": {}},
	}})) == 0
}

test_a_base_that_did_not_resolve_decides_nothing if {
	count(violation) == 0 with input as {"tree": {"documents": {"config.toml": declared}, "base-delta": null, "lines": {}, "shell": {"head": {}, "base": {}}}}
}

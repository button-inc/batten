# durable-write: every file this crate mutates goes through `durable` (CLOUD-1919).
#
# A write interrupted at any point must leave the previous state or the new one,
# never a torn one. `crates/batten/src/durable.rs` is where that holds — one
# `write(2)` plus `fsync` per append, temp + `fsync` + `rename` + directory
# `fsync` per replace — and this module is what stops a new site bypassing it.
# The measured failure it exists for: two host-transcript lines on 2026-09-27,
# each one record cut mid-string with another spliced in, which is the shape a
# `writeln!` split across writes produces under concurrent appenders.
#
# WHY A MODULE AND NOT `clippy.toml`. `disallowed-methods` applies to every
# target, and the test crate builds its fixtures with `fs::write` thousands of
# times; a crate-level allow there would also lift the `sleep` ban beside it. And
# WHY A MODULE AND NOT A `forbid` ROW: this crate's `#[cfg(test)]` modules live in
# the same files, and a line scan cannot tell a fixture write from a production
# one. Here the file's own `#[cfg(test)]` line is the boundary, and only lines
# above it are production.
#
# `// stream:` ON THE LINE is the one exemption, for a byte stream being captured
# rather than state being committed — a child's stdout sink, a spool whose
# commit point is a watermark `durable::replace` publishes. It names the reason
# where a reviewer reads the diff.
#
# NO INLINE REGEX, for the `[[pattern]]` rule: every test is a string builtin.
#
#MUTANT-SUITE crates/batten/tests/it/durable_write.rs
#MUTANT fs-write-unseen|s@^raw_write(line) if contains(line, "fs::write(")$@raw_write(line) if false@|a_raw_fs_write_in_production_is_refused
#MUTANT append-unseen|s@^raw_write(line) if contains(line, ".append(true)")$@raw_write(line) if false@|a_raw_append_open_in_production_is_refused
#MUTANT test-boundary-ignored|s@^\tnot after_test_boundary(lines, i)$@\ttrue@|a_write_inside_a_test_module_is_not_refused
#MUTANT module-never-closes|s@^\tline == "}"$@\tfalse@|production_after_a_closed_test_module_is_refused
#MUTANT stream-mark-ignored|s@^\tnot contains(line, "// stream:")$@\ttrue@|a_line_marked_as_a_stream_is_not_refused
#MUTANT production-one-crate|s@^\tparts\[0\] == "crates"$@\tstartswith(path, "crates/batten/src/")@|a_raw_write_in_another_crate_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree.lines` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.durable_write

import rego.v1

rules contains "path write unsafe"

raw_write(line) if contains(line, "fs::write(")

raw_write(line) if contains(line, "File::create(")

raw_write(line) if contains(line, ".append(true)")

# Inside a test module: after a line that IS `#[cfg(test)]` at column zero,
# which is how every module in this crate opens its unit tier, and before the
# `}` at column zero that closes it.
#
# A MODULE ENDS (review of #962). The first version treated everything after
# the FIRST `#[cfg(test)]` as test code, which assumes the test module is last.
# `forge.rs` has production after it, and its `conditional_get` wrote the ETag
# and the body raw, green, because the gate had stopped reading at line 146.
#
# THE SEAM IS A BOUNDARY TOO (#1276). The crate split gated fixture code on
# `#[cfg(any(test, feature = "seam"))]` so a dependent's suites can reach it, and
# `seam` is enabled only from a `[dev-dependencies]` entry: no shipped build
# compiles that code, exactly as none compiles a `#[cfg(test)]` module.
#
# A ONE-LINE GATED ITEM OPENS NOTHING: `#[cfg(test)]` over `use std::fmt;` ends
# at its `;`, and reading on to the next column-0 brace would mask the
# production function after it.
after_test_boundary(lines, i) if {
	some j, boundary in lines
	gated_boundary(boundary)
	j < i
	not one_line_item(lines, j)
	not closed_between(lines, j, i)
}

gated_boundary(line) if line == "#[cfg(test)]"

gated_boundary(line) if line == "#[cfg(any(test, feature = \"seam\"))]"

one_line_item(lines, j) if {
	item = lines[j + 1]
	not startswith(item, "#[")
	endswith(trim_space(item), ";")
}

closed_between(lines, j, i) if {
	some k, line in lines
	j < k
	k < i
	line == "}"
	rust_item_follows(lines, k)
}

# A column-0 `}` CLOSES THE MODULE ONLY WHERE A RUST ITEM FOLLOWS IT. A test
# module embeds other languages in raw strings — a Rego rule's closing brace is
# also `}` at column zero — so the brace alone read `hook.rs`'s fixtures as
# production. An item after it (optionally past one blank line) is what a real
# module end looks like; `"#;` or more Rego is not.
rust_item_follows(lines, k) if item_start(lines[k + 1])

rust_item_follows(lines, k) if {
	lines[k + 1] == ""
	item_start(lines[k + 2])
}

item_start(line) if {
	some prefix in ["fn ", "pub ", "pub(", "impl", "struct ", "enum ", "const ", "static ", "use ", "mod ", "type ", "trait ", "#[", "///", "//"]
	startswith(line, prefix)
}

# EVERY PACKAGE'S SOURCE, read from the path rather than a list of crates
# (#1276): `crates/<crate>/src/**`. The split moved `durable` into
# `batten-facts`, and a prefix naming one crate stopped judging every module it
# moved while the row's globs still listed them.
production(path) if {
	parts := split(path, "/")
	count(parts) > 3
	parts[0] == "crates"
	parts[2] == "src"
	endswith(path, ".rs")
	path != "crates/batten-facts/src/durable.rs"
}

violation contains {
	"rule": "path write unsafe",
	"verdict": "path write unsafe",
	"subjects": [{"path": path, "line": i + 1}],
} if {
	some path, lines in input.tree.lines
	production(path)
	some i, line in lines
	raw_write(line)
	not contains(line, "// stream:")
	not after_test_boundary(lines, i)
}

# ---------------------------------------------------------------------------
# Load-time tier.
# ---------------------------------------------------------------------------

test_a_raw_write_above_the_test_boundary_is_refused if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/src/a.rs": [
		"fn f() { std::fs::write(p, b); }",
		"#[cfg(test)]",
		"mod tests { fn g() { std::fs::write(p, b); } }",
	]}}}
}

test_production_after_a_closed_test_module_is_still_judged if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/src/a.rs": [
		"#[cfg(test)]",
		"mod tests {",
		"    fn g() { std::fs::write(p, b); }",
		"}",
		"fn f() { std::fs::write(p, b); }",
	]}}}
}

test_a_brace_inside_an_embedded_string_does_not_close_the_module if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/src/a.rs": [
		"#[cfg(test)]",
		"mod tests {",
		"    const MODULE: &str = r#\"",
		"deny contains \"x\" if {",
		"}",
		"\"#;",
		"    fn g() { std::fs::write(p, b); }",
		"}",
	]}}}
}

test_durable_itself_is_exempt if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten-facts/src/durable.rs": ["std::fs::OpenOptions::new().append(true)"]}}}
}

test_the_test_crate_is_out_of_scope if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/tests/it/a.rs": ["std::fs::write(p, b);"]}}}
}

# EVERY PACKAGE'S SOURCE (#1276). The crate split moved `durable` itself and
# half the crate into sibling packages; a predicate keyed on one crate's prefix
# stopped judging all of them while every row still listed their globs.
test_a_raw_write_in_another_crates_source_is_refused if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten-base/src/a.rs": ["fn f() { std::fs::write(p, b); }"]}}}
}

test_a_nested_module_in_another_crate_is_judged if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten-core/src/m/a.rs": ["fn f() { std::fs::write(p, b); }"]}}}
}

test_the_old_durable_path_is_no_longer_exempt if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/src/durable.rs": ["std::fs::write(p, b);"]}}}
}

test_another_crates_tests_are_out_of_scope if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten-base/tests/a.rs": ["std::fs::write(p, b);"]}}}
}

# THE SEAM IS A TEST BOUNDARY. `feature = "seam"` is enabled only from a
# dependent's `[dev-dependencies]`, so an item gated on it is fixture code that
# no shipped build compiles.
test_a_write_inside_a_seam_gated_item_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten-base/src/a.rs": [
		"#[cfg(any(test, feature = \"seam\"))]",
		"pub fn routed() {",
		"    std::fs::write(p, b).expect(\"x\");",
		"}",
	]}}}
}

test_production_after_a_closed_seam_item_is_refused if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten-base/src/a.rs": [
		"#[cfg(any(test, feature = \"seam\"))]",
		"pub fn routed() {",
		"    std::fs::write(p, b).expect(\"x\");",
		"}",
		"fn f() { std::fs::write(p, b); }",
	]}}}
}

# A ONE-LINE GATED ITEM OPENS NO MODULE. `#[cfg(test)]` over a `use` ends at its
# `;`, so the production function after it is judged, not read as test code up
# to the next column-0 brace.
test_production_after_a_one_line_gated_item_is_refused if {
	count(violation) == 1 with input as {"tree": {"lines": {"crates/batten/src/a.rs": [
		"#[cfg(test)]",
		"use std::fmt;",
		"fn f() {",
		"    std::fs::write(p, b);",
		"}",
	]}}}
}

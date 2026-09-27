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
#MUTANT stream-mark-ignored|s@^\tnot contains(line, "// stream:")$@\ttrue@|a_line_marked_as_a_stream_is_not_refused

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

# The file's own test boundary: a line that IS `#[cfg(test)]`, at column zero,
# which is how every module in this crate opens its unit tier.
after_test_boundary(lines, i) if {
	some j, boundary in lines
	boundary == "#[cfg(test)]"
	j < i
}

production(path) if {
	startswith(path, "crates/batten/src/")
	endswith(path, ".rs")
	path != "crates/batten/src/durable.rs"
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

test_durable_itself_is_exempt if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/src/durable.rs": ["std::fs::OpenOptions::new().append(true)"]}}}
}

test_the_test_crate_is_out_of_scope if {
	count(violation) == 0 with input as {"tree": {"lines": {"crates/batten/tests/it/a.rs": ["std::fs::write(p, b);"]}}}
}

# Crash-only file writes

Trigger: writing or reviewing any code in `crates/batten/src` that creates, appends to, or overwrites a file.

## The rule

A write interrupted at any point (a crash, a kill, a reboot, or a second writer arriving mid-record) leaves either the previous state or the new one, never a torn one. A reader that refuses a torn record is doing its job, so the defect is always the writer's.

Every production file mutation goes through `crates/batten/src/durable.rs` (CLOUD-1919):

- `durable::append(path, text)`: the whole record in ONE `write(2)` on an `O_APPEND` handle, then `fsync`.
  - `writeln!` on an unbuffered `File` is NOT one write. It may issue one write per format piece, so concurrent appenders interleave mid-line.
- `durable::append_with_mode(path, text, mode)`: the same, for a ledger that must be private from its first byte.
- `durable::replace(path, bytes)`: temp file in the same directory, `fsync`, `rename`, then `fsync` the directory.
  - It resolves a symlinked target and keeps an existing file's permission bits.
  - `fs::write` and `File::create` truncate first, so a crash leaves a partial file.

A genuine byte stream is marked `// stream:` on the line, naming its commit point. Two cases qualify: a child process's stdout sink, and the capture spool, whose commit point is a watermark published by `replace`.

## Enforced, not remembered

`path write unsafe` (rule and verdict share the name, as the engine requires of a sole raiser; `policy/durable-write.rego`, `[[rule]]` in `batten.toml`) refuses `fs::write(`, `File::create(` and `.append(true)` in `crates/batten/src/**`. The exemptions are `durable.rs` itself, anything below a file's `#[cfg(test)]` line, and a line marked `// stream:`. The tier is `crates/batten/tests/it/durable_write.rs`, and it includes a live case over this crate's own tree.

Why not `clippy.toml` `disallowed-methods`: it applies to every target. The test crate builds fixtures with `fs::write` thousands of times, and a crate-level allow there would also lift the `std::thread::sleep` ban.

## Measured origin

On 2026-09-27, a host session transcript (`.claude/.transcript.jsonl`) had two corrupt lines out of 21,179. Each was one record cut mid-string with a second record spliced into it. That shape is what concurrent appenders produce when a line spans several `write(2)` calls. The host writes that file, not batten, but batten had the same class of defect in `recorder.rs`, `land.rs`, `lib.rs`, `capture.rs`, `decision.rs`, `journal.rs` and `mcp.rs`. Its `.git/config` writer (`git.rs`) also rewrote the file in place.

Repairing such a transcript: back it up, keep each line's parsable complete record, and drop only the fragment bytes, which were never fully written. Confirm afterwards that the host still appends to the repaired file by path.

Related: `mem:core`.

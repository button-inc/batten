# Crash reproducers

libFuzzer writes a reproducer here when a target fails. **Commit it.**

`crates/batten/tests/fuzz_corpus.rs` replays every file under this directory on
the landing path, under the stable toolchain, against the same properties the
target asserts — `fuzz/properties.rs` is included by both. So committing the
file is what turns a one-off finding into a regression test; nothing else has to
be written, and the fix cannot land while the reproducer still fails.

Reproduce one by hand with:

    mise run fuzz -- <target> fuzz/artifacts/<target>/<file>

An empty directory is the ordinary state. An empty `fuzz/corpus/<target>/` is
not: the replay refuses it, because a gate that read nothing must not report
green.

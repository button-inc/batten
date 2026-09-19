# Which of three things a probe build did, from its exit status and its log
# (CLOUD-418, ported off `mise-tasks/evaluator-io-check.sh` under CLOUD-1717).
#
# THE VERDICT IS THE HARNESS'S OWN LINE, NEVER THE EXIT CODE ALONE, and that is
# the whole reason this reading is a file rather than three lines in a task body.
# `cargo test` exits non-zero for a compile error, an unresolved feature, an
# absent toolchain and a panic in another test — every one of which would read as
# "the probe falsified the assertion" and hand the gate a pass it did not earn.
# Worse, that pass gets MORE likely as the crate breaks, so the gate would be
# loudest exactly when it was lying.
#
# ONE READING, TWO CALLERS. `[tasks.evaluator-io-record]` calls this to write the
# record; `crates/batten/tests/it/evaluator_io_probe.rs` calls it to assert all
# four arms without a two-minute rebuild per case. A copy of these three branches
# inside the tier would be a second authority over the classification — the drift
# `cargo_graph.py` was extracted to remove one gate over.
#
# THE `failures:` LISTING RATHER THAN THE PER-TEST LINE, because the per-test line
# is not stable across harness modes: plain prints `test <name> ... FAILED` and
# `--quiet` prints `<name> --- FAILED`. The listing is one indented name in both,
# and anchoring on it is what stops this going quietly could-not-look the day
# someone adds or drops `--quiet`.
#
# Emits exactly one of:
#
#   probe passed   the build succeeded — the test stayed green with `http` on
#   probe failed   the named test RAN and FAILED — the discrimination wanted
#   probe unread   non-zero for some other reason — could not look
#
# POINTER-ONLY (rule 4): one token. The log carries module bodies and paths and
# no byte of it is emitted.

import re
import sys


def verdict(status, log, test):
    if status == 0:
        # A probe build that SUCCEEDED means the test stayed green with `http`
        # on, so it discriminates nothing.
        return "probe passed"
    listed = re.compile(r"^[ \t]+%s[ \t]*$" % re.escape(test), re.MULTILINE)
    if re.search(r"^test result: FAILED", log, re.MULTILINE) and listed.search(log):
        return "probe failed"
    return "probe unread"


def main(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: probe_verdict.py <status> <log-path> <test-name>\n")
        return 2
    try:
        status = int(argv[1])
    except ValueError:
        sys.stderr.write("probe-verdict: status must be a whole number\n")
        return 2
    try:
        with open(argv[2], "r", encoding="utf-8", errors="replace") as handle:
            log = handle.read()
    except OSError as failed:
        sys.stderr.write("probe-verdict: could not read the log: %s\n" % failed)
        return 2
    sys.stdout.write(verdict(status, log, argv[3]) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

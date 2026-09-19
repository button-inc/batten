# The evaluator's activated sub-closure, over a `cargo metadata` document on
# stdin (CLOUD-831, ported off `mise-tasks/evaluator-closure-check.sh` under
# CLOUD-1717).
#
# THIS IS THE STEP, NEVER THE DECISION. It walks a graph and names what it
# reached; whether reaching one of them is a refusal is
# `policy/evaluator-closure.rego`'s question. The split is forced rather than
# chosen: a reachability closure is not expressible in Rego — a self-referential
# rule is a compile error and `graph.reachable` is not in this build's regorus
# feature set (`Cargo.toml` is the one authority on that list).
#
# THE WALK ITSELF IS `cargo_graph.py`'s, SHARED WITH `macos-link`. Both gates ask
# the same structural question of the same graph and differ only in their roots
# and in what they look for; both headers used to say "if one is corrected,
# correct both", which is a rule with no mechanism. There is one walk now.
#
# Output is the record's own lines, on stdout, for `batten record named`:
#
#   absent                 no evaluator node in the graph — could-not-look
#   closure <count>        packages reached from the evaluator
#   crate <name>           one per IO-bearing crate in that closure
#
# Pointer-only (non-negotiable rule 4): a crate NAME and a count. Never a
# dependency tree, never a path through the graph, never a version chain.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cargo_graph import Graph  # noqa: E402

# The evaluator's package name. Named once: it is the node the walk starts from
# AND the word the refusal uses, and two spellings of it is how a rename turns
# this gate silent instead of red.
EVALUATOR = "regorus"

# `Cargo.toml`'s pin names. Not a heuristic and not "crates that look networky":
# this is the list the manifest comment claims is absent, restated here as the
# thing that is looked for. The manifest comment points AT this file rather than
# repeating the list a third time.
IO_CRATES = frozenset(
    "reqwest jsonschema hyper rustls openssl-sys native-tls ring globset glob".split()
)


def walk(meta):
    graph = Graph(meta)

    # THE SCOPE IS THE EVALUATOR'S SUB-CLOSURE, NOT THE WORKSPACE'S, and that was
    # measured before it was written because the obvious spelling is wrong.
    # Walking from the workspace members instead reaches 281 packages including
    # `globset` AND `jsonschema` — both direct dependencies of `batten` itself,
    # entering by paths that have nothing to do with the evaluator. The wider
    # spelling fired on all 5 lockfile-touching commits reachable from HEAD and
    # every firing was a false positive.
    roots = graph.named_roots(EVALUATOR)
    if not roots:
        # NOT a pass. The evaluator vanishing from the graph means the question
        # could not be asked, and reporting 'nothing found' there is the vacuous
        # pass this repository names CLOUD-251.
        return ["absent"]

    reached = graph.reachable(roots)
    found = sorted({graph.packages[i]["name"] for i in reached} & IO_CRATES)
    return ["closure %d" % len(reached)] + ["crate %s" % name for name in found]


def main():
    try:
        meta = json.load(sys.stdin)
    except (ValueError, OSError) as failed:
        # The producer writes NOTHING when it could not look, which is the record
        # contract: an absent record is "the producer did not run", and it must
        # not be spelled the same way as a graph that resolved.
        sys.stderr.write("evaluator-closure: could not read the graph: %s\n" % failed)
        return 1
    for line in walk(meta):
        sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

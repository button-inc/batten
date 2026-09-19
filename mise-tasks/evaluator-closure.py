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
# IT IS A `.py` SIBLING RATHER THAN A TASK BODY, AND THAT IS WHAT KEEPS THE WALK
# UNDER TEST. `mise-tasks/replay-pointers.py` is the precedent and
# `shell-retirement.rego:159-163` is the reason it is admissible: `.py` is
# excluded from `under_mise_tasks`, so this is not an added shell rule. The four
# cases the dying suite carried about the WALK — an unactivated optional
# dependency, the same one activated, a dev-dependency, and a crate the workspace
# reaches but the evaluator does not — assert against this file directly from
# `crates/batten/tests/it/evaluator_closure.rs`. Inlining it into the task body
# would have made all four untestable, and they are the security-critical half.
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
import sys

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


def activated_keys(package, enabled):
    """Three spellings reach a dependency and all three must be read, or an
    activated dep looks dormant: the implicit feature (a bare 'foo'), the
    namespaced form ('dep:foo'), and enabling one of the dep's own features
    ('foo/bar'). The WEAK form ('foo?/bar') is deliberately not one — it applies
    only if something else already activated the dep."""
    keys = set(enabled)
    declared = package.get("features", {})
    for feature in enabled:
        for token in declared.get(feature, []):
            if token.startswith("dep:"):
                keys.add(token[4:])
            elif "/" in token:
                head = token.split("/", 1)[0]
                if not head.endswith("?"):
                    keys.add(head)
    return keys


def edges(node_id, packages, nodes, members):
    node = nodes.get(node_id)
    package = packages.get(node_id)
    if node is None or package is None:
        return
    enabled = activated_keys(package, set(node.get("features", [])))
    is_member = node_id in members
    for dep in node.get("deps", []):
        target = packages.get(dep["pkg"])
        if target is None:
            continue
        kinds = {k.get("kind") for k in dep.get("dep_kinds", [{}])}
        if kinds == {"dev"} and not is_member:
            continue
        matching = [
            d for d in package.get("dependencies", []) if d["name"] == target["name"]
        ]
        if not matching:
            # An edge the manifest does not explain: keep it rather than drop it.
            # Unexplained means unmeasured, and unmeasured fails closed.
            yield dep["pkg"]
            continue
        for entry in matching:
            if not entry.get("optional"):
                yield dep["pkg"]
                break
            if (entry.get("rename") or entry["name"]) in enabled:
                yield dep["pkg"]
                break


def walk(meta):
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in (meta.get("resolve") or {}).get("nodes", [])}
    members = set(meta.get("workspace_members", []))

    # THE SCOPE IS THE EVALUATOR'S SUB-CLOSURE, NOT THE WORKSPACE'S, and that was
    # measured before it was written because the obvious spelling is wrong.
    # Walking from the workspace members instead reaches 281 packages including
    # `globset` AND `jsonschema` — both direct dependencies of `batten` itself,
    # entering by paths that have nothing to do with the evaluator. The wider
    # spelling fired on all 5 lockfile-touching commits reachable from HEAD and
    # every firing was a false positive.
    roots = [i for i, p in packages.items() if p["name"] == EVALUATOR and i in nodes]
    if not roots:
        # NOT a pass. The evaluator vanishing from the graph means the question
        # could not be asked, and reporting 'nothing found' there is the vacuous
        # pass this repository names CLOUD-251.
        return ["absent"]

    reached = set()
    frontier = list(roots)
    while frontier:
        current = frontier.pop()
        if current in reached:
            continue
        reached.add(current)
        frontier.extend(edges(current, packages, nodes, members))

    found = sorted({packages[i]["name"] for i in reached} & IO_CRATES)
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

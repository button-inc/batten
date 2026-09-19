# The ACTIVATED dependency graph, read from a `cargo metadata` document.
#
# ONE WALK, TWO GATES, AND THAT IS THE WHOLE REASON THIS FILE EXISTS.
# `evaluator-closure` asks whether an IO-bearing crate is reachable from the
# evaluator's node; `macos-link` asks whether anything in the built graph needs a
# real macOS SDK to link. The questions differ only in their ROOTS and in what
# they look for once there — the reachability underneath is the same, down to the
# weak-dependency rule.
#
# Both programs carried their own copy, and both headers said so in prose:
# "The activation reading is deliberately IDENTICAL to `macos-link-check`'s, down
# to the weak-dependency rule, because the two gates ask the same structural
# question of the same graph and a second, subtly different walk is how a pair
# like this drifts. If one is corrected, correct both."
#
# That is a rule with no mechanism, which is half a change. This file is the
# mechanism: there is now one walk to correct, so the two cannot disagree. The
# `#MUTANT` rows that used to be stated twice are stated once, over the code they
# actually mutate.
#
# `.py` rather than a task body, and `mise-tasks/replay-pointers.py` is the
# precedent: `shell-retirement.rego:159-163` excludes `.py` from
# `under_mise_tasks`, so this adds no shell rule and both callers' compiled tiers
# can drive it directly.

# Reverting the activation filter to the whole resolve is the defect this exists
# to prevent: an optional dependency nobody enabled reads as linked, and the gate
# refuses a link that succeeds. Measured on `defmt` — an embedded-logging crate,
# an unactivated optional dependency of `jiff`, reaching no Apple framework and
# never compiled — which made `macos-link-check` refuse a link `darwin-link` then
# completed on the same tree.
#MUTANT-SUITE crates/batten/tests/it/evaluator_closure.rs
#MUTANT graph-scans-unactivated|s@^        if (entry.get("rename") or entry\["name"\]) in enabled:$@        if True:@|an_unactivated_optional_io_dependency_of_the_evaluator_is_not_reported
#MUTANT graph-weak-dep-activates|s@^                head = token.split("/", 1)\[0\]$@                head = token.split("/", 1)[0].rstrip("?")@|a_weak_reference_is_not_an_activation
#MUTANT graph-keeps-dev-edges|s@^        if kinds == {"dev"} and not is_member:$@        if False:@|a_dev_dependency_of_the_evaluator_is_not_in_the_built_closure


def activated_keys(package, enabled):
    """The dependency names this package's enabled features actually turn on.

    Three spellings reach a dependency and all three must be read, or an
    activated dep looks dormant: the implicit feature (a bare 'foo'), the
    namespaced form ('dep:foo'), and enabling one of the dep's own features
    ('foo/bar'). The WEAK form ('foo?/bar') is deliberately not one — it applies
    only if something else already activated the dep, and reading it as an
    activation drifts back toward the whole-resolve scan this replaces."""
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


class Graph:
    """A resolved `cargo metadata` document, walked along ACTIVATED edges only.

    `cargo metadata` lists every package the resolver CONSIDERED, including
    optional dependencies nothing turned on. Scanning that asks "could some
    configuration of this tree reach X" where both callers mean "does this one".
    """

    def __init__(self, meta):
        self.packages = {p["id"]: p for p in meta["packages"]}
        self.nodes = {n["id"]: n for n in (meta.get("resolve") or {}).get("nodes", [])}
        self.members = set(meta.get("workspace_members", []))

    def edges(self, node_id):
        node = self.nodes.get(node_id)
        package = self.packages.get(node_id)
        if node is None or package is None:
            return
        enabled = activated_keys(package, set(node.get("features", [])))
        is_member = node_id in self.members
        for dep in node.get("deps", []):
            target = self.packages.get(dep["pkg"])
            if target is None:
                continue
            # A dev-dependency of a *dependency* is never built. One of a
            # workspace member is: the test binaries link too.
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [{}])}
            if kinds == {"dev"} and not is_member:
                continue
            matching = [
                d
                for d in package.get("dependencies", [])
                if d["name"] == target["name"]
            ]
            if not matching:
                # An edge the manifest does not explain: keep it rather than drop
                # it. Unexplained means unmeasured, and unmeasured fails closed.
                yield dep["pkg"]
                continue
            for entry in matching:
                if not entry.get("optional"):
                    yield dep["pkg"]
                    break
                if (entry.get("rename") or entry["name"]) in enabled:
                    yield dep["pkg"]
                    break

    def reachable(self, roots):
        """Every package id reachable from `roots` along activated edges."""
        seen = set()
        frontier = list(roots)
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            frontier.extend(self.edges(current))
        return seen

    def member_roots(self):
        """The workspace members — `macos-link`'s starting set, because its
        question is about everything this tree builds."""
        return [m for m in self.members if m in self.nodes]

    def named_roots(self, name):
        """Every node for a package of this name — `evaluator-closure`'s
        starting set, because its question is about ONE package's sub-closure."""
        return [i for i, p in self.packages.items() if p["name"] == name and i in self.nodes]

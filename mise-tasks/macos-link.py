# What in the built macOS graph would need a real macOS SDK to link, over a
# `cargo metadata` document on stdin (ported off `mise-tasks/macos-link-check.sh`
# under CLOUD-1717).
#
# THIS IS THE STEP, NEVER THE DECISION. It names what it found; whether finding
# one is a refusal is `policy/macos-link.rego`'s question. The split is forced:
# §5 makes `check` `read` and incapable of spawning `cargo metadata`, and the
# reachability walk is not expressible in Rego at all.
#
# THE WALK IS `cargo_graph.py`'s, SHARED WITH `evaluator-closure`, which is what
# closes the drift both programs' headers warned about in prose and neither could
# enforce.
#
# TWO RULES, and rule 2 is a list and therefore incomplete by construction:
#
#   1. any package declaring a `links` key — the manifest's own statement that it
#      links a native library, which is general and needs no list; minus the
#      crates that vendor and compile their own C, for which "links a native
#      library" does not imply "needs an SDK to find one";
#   2. a named set of crates that link Apple frameworks from a build script
#      WITHOUT declaring `links`, which rule 1 cannot see.
#
# A crate nobody has listed slips past rule 2. That residual gap is closed by
# actually linking the target, which `darwin-link` does; this pair is the fast,
# specific, early half of that, not a replacement for it.
#
# Output is the record's own lines, on stdout, for `batten record named`:
#
#   scanned <count>              packages in the built macOS graph
#   links <name> <library>       rule 1: declares links=<library>
#   framework <name>             rule 2: links an Apple system framework
#
# Pointer-only (non-negotiable rule 4): a crate NAME and, for rule 1, the library
# the manifest itself names. Never a version chain, never a path through the
# graph. The VERSION the retired program printed is deliberately dropped — it is
# not needed to act on the finding and it dates the record against a lockfile
# the module never reads.

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cargo_graph import Graph  # noqa: E402

# Crates that pull in an Apple system framework. Extend as new ones are met — and
# when you do, prefer proving it with a link (`darwin-link`) over trusting this
# list.
FRAMEWORK_CRATES = re.compile(
    r"^(security-framework|security-framework-sys|core-foundation"
    r"|core-foundation-sys|native-tls|openssl-sys|cocoa|objc|objc2"
    r"|system-configuration|system-configuration-sys)$"
)

# Crates whose `links` key names a library they VENDOR AND COMPILE THEMSELVES,
# reaching no Apple system framework — so rule 1's proxy is wrong about them.
#
# ADDING A NAME HERE REQUIRES A LINK, never a reading of the crate. Measured
# 2026-08-21: this gate refused `tree-sitter` and `tree-sitter-language`, and
# `darwin-link` then linked the same tree with no SDK present. A gate that
# refuses what the linker accepts is measuring something other than what it
# names. The fail-safe is unchanged in the direction that matters: an UNKNOWN
# `links` crate is still a finding, so this narrows the gate rather than opening
# it.
VENDORED_LINKS = re.compile(r"^(tree-sitter|tree-sitter-language)$")


def walk(meta):
    graph = Graph(meta)

    # THE WALK STARTS AT THE WORKSPACE MEMBERS, because the question is about
    # everything this tree builds — unlike `evaluator-closure`, whose question is
    # about one package's sub-closure. That is the only difference between the
    # two callers of this graph.
    built = graph.reachable(graph.member_roots())

    lines = ["scanned %d" % len(built)]
    for package_id in sorted(built, key=lambda i: graph.packages[i]["name"]):
        package = graph.packages[package_id]
        name = package["name"]
        if package.get("links") and not VENDORED_LINKS.match(name):
            lines.append("links %s %s" % (name, package["links"]))
        elif FRAMEWORK_CRATES.match(name):
            lines.append("framework %s" % name)
    return lines


def main():
    try:
        meta = json.load(sys.stdin)
    except (ValueError, OSError) as failed:
        sys.stderr.write("macos-link: could not read the graph: %s\n" % failed)
        return 1
    for line in walk(meta):
        sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

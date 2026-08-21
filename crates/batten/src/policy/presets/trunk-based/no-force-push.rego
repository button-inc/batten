# Trunk-based development: a shared branch is not rewritten under its readers.
#
# `--force-with-lease` is deliberately NOT matched. It is the sanctioned form —
# it refuses when the remote moved, which is the whole difference between
# "I know what I am replacing" and "replace whatever is there". A preset that
# banned both would push its consumers toward the bypass rather than toward the
# safer flag.
#
# Names no repository, no ref and no task: this is true of the practice, which is
# what a vendored preset may contain (non-negotiable rule 1).
package batten.trunk_based

import rego.v1

rules contains "no-force-push"

violation contains {
	"rule": "no-force-push",
	"msg": "a force push rewrites a shared branch under whoever already fetched it; use --force-with-lease, which refuses when the remote moved",
} if {
	words := split(input.call.command, " ")
	words[0] == "git"
	"push" in words
	some word in words
	word in {"--force", "-f"}
}

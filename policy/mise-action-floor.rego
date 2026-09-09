# METADATA
# description: |
#   No workflow pins a toolchain-install action commit known to predate its
#   download retry — CLOUD-404, ported from `mise-tasks/mise-action-floor.sh`
#   under CLOUD-843.
#
#   The toolchain install action fetched its own binary with a bare download and
#   no retry, so a transient release-asset error killed a job in provisioning:
#   spending its minutes, redding the branch, and answering nothing. Three
#   occurrences in two days. Upstream added a retry after our report and we
#   adopted that commit directly, because it ships its own built output.
#
#   WHY THIS GATE EXISTS, AND IT IS NOT ABOUT HUMANS FORGETTING. The adopted
#   commit is UNRELEASED, so the pin no longer corresponds to a release tag. The
#   dependency bot tracks the actions ecosystem and this repository lands bot
#   bumps with NO HUMAN IN THE LOOP — every check green is the only condition. A
#   bot resolving that major back to the pre-retry commit would be a silent
#   DOWNGRADE to the un-retried install, auto-landed. That is strictly worse than
#   the transient it reverts, because nothing announces it and the next occurrence
#   reads as fresh. So the rule ships with its mechanism (non-negotiable 2): this
#   reds such a pin at check time, the bot's PR cannot go green, and the
#   auto-lander cannot land it. The accepted cost is that such a PR then sits open
#   and red until somebody closes it — stated here rather than discovered later.
#
#   A DENYLIST OF KNOWN-BAD PINS, NOT A REQUIRED SHA. An "equals the expected
#   commit" gate would fail every legitimate forward bump and demand a hand edit in
#   lockstep with the bot — which is how a gate earns a bypass and then gets
#   switched off. A denylist is silent on the next release and every one after it,
#   and speaks only for the backslide. It also cannot answer "is this pin new
#   enough", which is the honest limit: ancestry needs the network, so it lives on
#   the tracker as a checkable acceptance line rather than being faked offline here.
#
#   THE PREDICATE IS THIS CONSUMER'S. Which action this repository installs its
#   toolchain with, and which of that action's commits predate a fix this
#   repository depends on, are facts about this consumer — non-negotiable rule 1 —
#   so both live here and not in engine source.
#
#   ANTI-VACUITY, and the precedent is explicit: the retired `ci-tools-check`'s
#   "no lists found" refusal exists precisely so the thing under test cannot
#   quietly vanish. A tree with no pin of this action at all is not a clean tree —
#   it is a question this module could not ask, so it is a could-not-look finding
#   rather than a pass.
#
#   THE SUCCESSOR READS THE SAME BYTES THE SHELL DID. The shell read the INDEX
#   (`git show :<path>`) precisely so the judgement was of the bytes a commit would
#   carry rather than whatever an editor left in the tree; `input.tree.lines` is
#   the committed bytes of a declared `line_sources` path, which is the same claim
#   reached by the engine instead of by a subprocess.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the workflow, its line and a
#   short sha. Never a line of workflow content.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.mise_action_floor

import rego.v1

rules contains "mise-action-floor"

# ONE COORDINATE, and both the action name and the denylist are derived from it,
# so the sha appears once and the name and the denylisted pin cannot drift.
#
# Written as a real pinned coordinate rather than a bare vendor string on purpose:
# the attribution rule exempts a line that NAMES a dependency (`uses:`, `@<40
# hex>`) and flags the same name in prose as an appeal to authority — and the
# exemption is per LINE, so the spelling has to live where it reads as a
# coordinate.
#
# This is the pin that predates the retry: the latest release and the floating
# major tag both resolve to it, which is exactly what makes it the reachable
# backslide rather than a hypothetical one.
#
# Add a coordinate here when a pin is found to predate a fix this repository
# depends on; never remove one, because a commit does not stop being pre-retry.
pre_retry_coordinates := {"uses: jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654"}

# Everything left of the `@`, with the `uses: ` prefix dropped.
action := name if {
	some coordinate in pre_retry_coordinates
	after_prefix := substring(coordinate, count("uses: "), -1)
	name := substring(after_prefix, 0, indexof(after_prefix, "@"))
}

pre_retry_pins contains sha if {
	some coordinate in pre_retry_coordinates
	sha := substring(coordinate, indexof(coordinate, "@") + 1, -1)
}

marker := sprintf("%s@", [action])

# Every pin of THIS action, as a path, a line and the sha itself.
#
# Scoped to this one action deliberately: the same sha prefix appearing in another
# coordinate, or in prose, is not this defect, and a gate that fires on a lookalike
# is a gate whose failures stop being read.
pin contains {"path": path, "line": i + 1, "sha": sha} if {
	some path, lines in input.tree.lines
	some i, line in lines
	contains(line, marker)
	sha := substring(line, indexof(line, marker) + count(marker), 40)

	# A FLOATING REF IS NOT A PIN THIS MODULE CAN JUDGE. `@v4` carries no sha, so
	# the denylist cannot speak about it at all — and it must not read as a
	# forward pin either, which is why it falls through to the could-not-look arm
	# below rather than being counted clean here.
	regex.match(data.batten.patterns["git-object-id"], sha)
}

# THE ANTI-VACUITY ARM. A tree with no pin of this action is a question this
# module could not ask, never a clean answer.
violation contains {
	"rule": "mise-action-floor",
	"verdict": "pin read unread",
	"subjects": [{"count": 0}],
} if {
	input.tree.lines
	count(pin) == 0
}

violation contains {
	"rule": "mise-action-floor",
	"verdict": "pin read stale",
	"subjects": [{"path": sprintf("%s:%d", [row.path, row.line])}],
} if {
	some row in pin
	row.sha in pre_retry_pins
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves a declared
# `line_sources` GLOB to the committed bytes of every workflow it matches — a
# `with input as` block fabricates the very shape the engine may be unable to
# produce (CLOUD-845), and here it would fabricate the multi-path resolution the
# anti-vacuity arm turns on. `crates/batten/tests/it/mise_action_floor.rs` is
# that tier.

workflows(files) := {"tree": {"lines": files}}

good := "        uses: jdx/mise-action@1111111111111111111111111111111111111111"

bad := "        uses: jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654"

test_a_forward_pin_is_clean if {
	count(violation) == 0 with input as workflows({".github/workflows/ci.yml": ["jobs:", good]})
}

test_a_pre_retry_pin_is_refused if {
	some v in violation with input as workflows({".github/workflows/ci.yml": ["jobs:", bad]})
	v.verdict == "pin read stale"
}

test_a_tree_with_no_pin_of_this_action_is_could_not_look if {
	some v in violation with input as workflows({".github/workflows/ci.yml": ["jobs:", "        uses: actions/checkout@v4"]})
	v.verdict == "pin read unread"
}

# A lookalike sha under a DIFFERENT action is not this defect, and firing on it
# is how a gate's failures stop being read.
test_another_actions_pin_is_not_this_defect if {
	some v in violation with input as workflows({".github/workflows/ci.yml": ["        uses: other/action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654"]})
	v.verdict == "pin read unread"
}

# `@v4` carries no sha, so the denylist cannot speak about it — and reporting
# green over it would be a claim this module cannot support.
test_a_floating_ref_is_not_a_pin_this_module_can_judge if {
	some v in violation with input as workflows({".github/workflows/ci.yml": ["        uses: jdx/mise-action@v4"]})
	v.verdict == "pin read unread"
}

# A sha in prose or a comment is not a pin: the coordinate is what scopes it.
test_a_sha_in_prose_is_not_a_pin if {
	count(violation) == 0 with input as workflows({".github/workflows/ci.yml": [
		good,
		"      # was 7e36c90d9ab29c415a2384db3006f3ec8a8cc654 before the retry landed",
	]})
}

test_the_backslide_is_found_in_any_workflow if {
	some v in violation with input as workflows({
		".github/workflows/ci.yml": [good],
		".github/workflows/release.yml": [bad],
	})
	v.verdict == "pin read stale"
}

#MUTANT-SUITE crates/batten/tests/it/mise_action_floor.rs
#MUTANT pre-retry-pin-unread|s@^\trow.sha in pre_retry_pins$@\tfalse@|a_pre_retry_pin_is_refused_and_named
#MUTANT vacuous-tree-unpriced|s@^\tcount(pin) == 0$@\tfalse@|a_tree_with_no_pin_of_this_action_is_not_clean

# A privileged lane must test the head's origin (CLOUD-867).
#
# THE DEFECT THIS EXISTS FOR. Both auto-landers selected the head they would
# fast-forward onto `main` by matching a BRANCH NAME PREFIX — `renovate/`,
# `release-plz-`. A branch name is a string the PR author chooses, so the
# predicate admitted anyone who named a branch to match. It was inert only
# because the repository was private, and CLOUD-585 removes exactly that.
#
# WHY A GATE AND NOT A COMMENT. The next lane gets written by copying one of
# these, and a copied `startsWith` reads exactly as correct as the original — the
# shape prose cannot hold. `ci-local-parity` already reasons about these branch
# prefixes and could not see it, because it asks whether a lane HAS a watcher,
# never what that watcher ADMITS.
#
# PRESENCE, NOT SHAPE. This asserts that a subject job mentions the head's origin
# somewhere. It deliberately does not judge WHICH comparison is made: asking that
# would make this module reason about landing policy, and non-negotiable rule 3
# says a gate resolves to a command and an exit code over an object it decides,
# never a model verdict. A lane that tests origin and gets the comparison wrong is
# a code review's finding, not this file's.

# The `package batten` schema binding lives in `policy/opa-compliance.rego`, not
# here. A `# METADATA schemas:` block has PACKAGE scope, and OPA refuses a
# redeclaration -- `rego_type_error: package annotation redeclared` -- so the two
# tree-scoped modules sharing this package share one binding.
#
# THAT IS A COUPLING, and it is what the Regal aggregate rule has to reason about:
# the requirement is that every rule is COVERED by a schemas annotation, not that
# every file carries one. Deleting the module that owns the binding would leave
# this one silently unchecked, which is the failure the annotation exists to close.

package batten

import rego.v1

# A gate outside $MUTANT_GATES with no row here fails `mise run mutant-census`.
#
# The exemption is DISCHARGED as of CLOUD-931: `tests/privileged-lane.bats` drives
# the compiled binary over a real tree, so there is now a named case a mutation
# can turn red, and this gate joins $MUTANT_GATES.
#
# THE HEAD-RESOLUTION CONJUNCT IS THE ONE WORTH CORRUPTING, and choosing an input
# for it took two attempts — which is the whole value of declaring a mutation
# rather than assuming one. A mutation over the trigger list proves little: both
# spellings deny the lanes that matter, so it would pass under the corruption.
#
# THE FIRST CHOICE SURVIVED, AND THAT IS HOW THIS PARAGRAPH GOT CORRECTED. It
# named `perf.yml` as what the conjunct keeps out of the subject set. It is not:
# `perf.yml` triggers only on `schedule` and `workflow_dispatch`, neither of which
# is in `outsider_reachable`, so the FIRST conjunct already excludes it and
# dropping this one changes nothing about it. A mutation over a conjunct that
# another conjunct already excludes cannot discriminate, and surviving is the only
# way that gets found.
#
# What discriminates is an outsider-reachable writer that resolves no outside
# head: `issue_comment` plus `contents: write`, with no `pull_request` or
# `workflow_run` trigger and no `/pulls` reference anywhere. Clean today, a
# finding the moment `resolves_head` stops being asked.
#
# The row moved with the split (CLOUD-1317): the conjunct it corrupts is now
# `resolves_head(body)` inside the `lane resolve missing` arm, which is where that
# question is asked. The named case is unchanged, because the input that
# discriminates it is unchanged.
#MUTANT resolution-conjunct-dropped|s@^\tresolves_head(body)$@\ttrue@|an_outsider_reachable_writer_that_resolves_no_outside_head_is_not_a_subject
#MUTANT-SUITE crates/batten/tests/it/privileged_lane.rs

rules contains "privileged-lane-tests-origin"

# A file this build could not parse lands in `input.tree.missing` rather than in
# `documents` (CLOUD-845). Without this clause a workflow that fails to parse is
# simply absent from every rule below and the module reports GREEN over a file it
# never read — a vacuous pass, which is worse than a wrong answer because it is
# indistinguishable from a real one.
violation contains {
	"rule": "privileged-lane-tests-origin",
	"verdict": "workflow parse broken",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	is_workflow(path)
}

# The finding, in two classes, because the two have DIFFERENT REMEDIES
# (CLOUD-1317). The subject set is unchanged and so is the finding count; what
# changed is that the refusal now says which field its reader must test.
#
# Arm one: the EVENT carries the head, so the test is on the event.
violation contains {
	"rule": "privileged-lane-tests-origin",
	"verdict": "lane guard missing",
	"subjects": [{"path": path}, {"artifact": job}],
} if {
	some path, doc in input.tree.documents
	is_workflow(path)
	some job, body in doc.jobs
	outsider_reachable(doc)
	grants_write(doc, body)
	trigger_carries_head(doc)
	not tests_origin(body)
}

# Arm two: no trigger carries a head, so the job LOOKED ONE UP, and the test
# belongs on what the lookup returned.
#
# `not trigger_carries_head(doc)` is what keeps the arms disjoint. Without it a
# `workflow_run` job that also calls `/pulls` would raise BOTH classes for one
# job, doubling the finding count over a tree nothing changed — and the reader
# would get two remedies for one fix. Arm one wins that overlap deliberately: its
# remedy is the earlier of the two, applied before the lookup happens at all.
violation contains {
	"rule": "privileged-lane-tests-origin",
	"verdict": "lane resolve missing",
	"subjects": [{"path": path}, {"artifact": job}],
} if {
	some path, doc in input.tree.documents
	is_workflow(path)
	some job, body in doc.jobs
	outsider_reachable(doc)
	grants_write(doc, body)
	not trigger_carries_head(doc)
	resolves_head(body)
	not tests_origin(body)
}

is_workflow(path) if {
	startswith(path, ".github/workflows/")
}

# THREE CONJUNCTS, AND THE THIRD IS LOAD-BEARING. A subject is reachable by an
# outside author, holds `contents: write`, and selects a head that an outside
# author can influence. A gate whose first firing is a false positive gets an
# exception written for it, and the exception is what rots.
#
# THE THIRD IS ALSO WHERE THE CLASS SPLIT LIVES (CLOUD-1317), which is why it is
# no longer wrapped in an `is_subject` helper. `selects_outside_head` was a
# disjunction over two arms with two different remedies, so collapsing them into
# one predicate was exactly what made the refusal unable to say which field to
# test. The two arms are named separately below and each `violation` asks for one.
#
# THIS PARAGRAPH USED TO NAME `perf.yml` AS WHAT THE THIRD CONJUNCT SPARES, AND
# THAT WAS WRONG (CLOUD-931). Measured: `perf.yml` triggers on `schedule` and
# `workflow_dispatch`, and neither is in `outsider_reachable`'s list below — so it
# is excluded by the FIRST conjunct, and dropping the third changes nothing about
# it. The declared mutation above SURVIVED against exactly that reading, which is
# how the error was found rather than inherited by the next lane.
#
# The input that actually discriminates the third conjunct is outsider-reachable
# AND write-granting AND resolving no outside head: an `issue_comment` job with no
# `/pulls` lookup. `crates/batten/tests/it/privileged_lane.rs` carries it and the
# mutation names it, so the claim is held by a case rather than by this paragraph.
# Note that `test_a_scheduled_writer_with_no_outside_head_is_not_a_subject` below
# does NOT hold it either: that input is not outsider-reachable, so it passes with
# the conjunct deleted.

outsider_reachable(doc) if {
	some trigger in ["pull_request", "pull_request_target", "issue_comment", "workflow_run"]
	doc.on[trigger]
}

grants_write(_, body) if {
	body.permissions.contents == "write"
}

grants_write(doc, _) if {
	doc.permissions.contents == "write"
}

# The trigger inherently carries an outside head. `github.event.<trigger>` then
# holds `head_repository.full_name`, which is the field this arm's remedy names.
trigger_carries_head(doc) if {
	some trigger in ["pull_request", "pull_request_target", "workflow_run"]
	doc.on[trigger]
}

# The job goes and finds a head through the pulls API. This is what keeps a
# schedule-driven resolver — `auto-bot-land`'s cron arm is exactly one — inside
# the subject set, and its remedy names `.head.repo.full_name` on the RESOLVED
# pull request, because the event payload carries no head to test.
resolves_head(body) if {
	contains(json.marshal(body), "/pulls")
}

# Marshalled rather than walked, so one clause covers every place an origin test
# can legitimately live: a job-level `if:` expression, a step's `run:` body, or a
# filter passed to `jq`. A structural walk would have to enumerate those, and the
# enumeration is what goes stale when the next lane puts the test somewhere new.
tests_origin(body) if {
	some field in ["head_repository.full_name", "head.repo.full_name"]
	contains(json.marshal(body), field)
}

# --- tests -----------------------------------------------------------------
#
# `with input as` throughout: these assert the PREDICATE, and a suite that read
# the real tree would go quiet the moment the tree was fixed — passing forever
# after, including through a regression.

test_bot_lane_without_an_origin_test_denies if {
	count(violation) == 1 with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"if": "startsWith(github.event.workflow_run.head_branch, 'renovate/')",
			}},
		}},
		"missing": [],
	}}
}

test_a_lane_that_tests_origin_passes if {
	count(violation) == 0 with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"if": "github.event.workflow_run.head_repository.full_name == github.repository",
			}},
		}},
		"missing": [],
	}}
}

# The origin test living in a step's jq filter rather than the job `if:` — the
# cron arm's only gate, and the reason `tests_origin` marshals the whole job.
test_origin_in_a_step_body_passes if {
	count(violation) == 0 with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "gh api repos/x/pulls | jq 'select(.head.repo.full_name == $repo)'"}],
			}},
		}},
		"missing": [],
	}}
}

# THE FALSE POSITIVE THE THIRD CONJUNCT EXISTS FOR. Scheduled, holds
# contents:write, selects no outside head.
test_a_scheduled_writer_with_no_outside_head_is_not_a_subject if {
	count(violation) == 0 with input as {"tree": {
		"documents": {".github/workflows/perf.yml": {
			"on": {"schedule": [], "workflow_dispatch": {}},
			"jobs": {"measure": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "git push origin refs/notes/perf"}],
			}},
		}},
		"missing": [],
	}}
}

# A schedule-only lane that DOES go looking for pull requests is a subject, even
# though no trigger carries a head — and it raises the RESOLVE class, because the
# field its remedy names is on the pull request rather than on the event.
#
# Asserting the class rather than only the count is what makes this case
# discriminate the split: a single-class implementation still counts one here.
test_a_resolver_of_pulls_raises_the_resolve_class if {
	found := violation with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"issue_comment": {}},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "gh api repos/$REPO/pulls?state=open"}],
			}},
		}},
		"missing": [],
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "lane resolve missing"
}

# A trigger-carried head raises the GUARD class, which is the other half of the
# same discrimination: if both inputs raised one class, this pair would be green
# over an unsplit module.
test_a_trigger_carried_head_raises_the_guard_class if {
	found := violation with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"if": "startsWith(github.event.workflow_run.head_branch, 'renovate/')",
			}},
		}},
		"missing": [],
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "lane guard missing"
}

# A job that is BOTH — a trigger carries a head and it also calls `/pulls` — is
# reported once, under the guard class. Without the `not trigger_carries_head`
# conjunct this counts two, which is the overlap the arms are made disjoint for.
test_a_job_matching_both_arms_is_reported_once if {
	found := violation with input as {"tree": {
		"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "gh api repos/$REPO/pulls?state=open"}],
			}},
		}},
		"missing": [],
	}}
	count(found) == 1
	some finding in found
	finding.verdict == "lane guard missing"
}

test_a_read_only_lane_is_not_a_subject if {
	count(violation) == 0 with input as {"tree": {
		"documents": {".github/workflows/ci.yml": {
			"on": {"pull_request": {}},
			"jobs": {"gate": {"permissions": {"contents": "read"}}},
		}},
		"missing": [],
	}}
}

# Workflow-level permissions, not job-level — the same grant written one level up.
test_workflow_level_write_is_still_a_grant if {
	count(violation) == 1 with input as {"tree": {
		"documents": {".github/workflows/auto-release-land.yml": {
			"on": {"workflow_run": {}},
			"permissions": {"contents": "write"},
			"jobs": {"land": {"if": "startsWith(x, 'release-plz-')"}},
		}},
		"missing": [],
	}}
}

test_an_unparseable_workflow_denies_rather_than_passing if {
	count(violation) == 1 with input as {"tree": {
		"documents": {},
		"missing": [".github/workflows/auto-bot-land.yml"],
	}}
}

# `missing` carrying something that is not a workflow is not this rule's finding.
test_a_missing_non_workflow_is_not_this_rules_finding if {
	count(violation) == 0 with input as {"tree": {
		"documents": {},
		"missing": ["README.md"],
	}}
}

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
#MUTANT-EXEMPT CLOUD-931|no bats suite exists for a policy module: `batten policy test` is wired to no task, so there is no named case a mutation could turn red

rules contains "privileged-lane-tests-origin"

# A file this build could not parse lands in `input.tree.missing` rather than in
# `documents` (CLOUD-845). Without this clause a workflow that fails to parse is
# simply absent from every rule below and the module reports GREEN over a file it
# never read — a vacuous pass, which is worse than a wrong answer because it is
# indistinguishable from a real one.
violation contains {
	"rule": "privileged-lane-tests-origin",
	"msg": sprintf("%s could not be parsed, so its lanes were never judged", [path]),
} if {
	some path in input.tree.missing
	is_workflow(path)
}

# The finding itself: a subject job that never mentions the head's origin.
violation contains {
	"rule": "privileged-lane-tests-origin",
	"msg": sprintf(
		"%s job `%s` can be reached by an outside author and holds contents:write, but tests no head origin",
		[path, job],
	),
} if {
	some path, doc in input.tree.documents
	is_workflow(path)
	some job, body in doc.jobs
	is_subject(doc, body)
	not tests_origin(body)
}

is_workflow(path) if {
	startswith(path, ".github/workflows/")
}

# THREE CONJUNCTS, AND THE THIRD IS LOAD-BEARING. A subject is reachable by an
# outside author, holds `contents: write`, and selects a head that an outside
# author can influence. Drop the third and `perf.yml` is a finding: it is
# scheduled, it holds `contents: write` to push its own measurement series, and it
# resolves no outside head at all. A gate whose first firing is a false positive
# gets an exception written for it, and the exception is what rots.
is_subject(doc, body) if {
	outsider_reachable(doc)
	grants_write(doc, body)
	selects_outside_head(doc, body)
}

# `schedule` and `workflow_dispatch` are deliberately absent: neither is reachable
# by someone without write access. A schedule that goes on to resolve an outside
# head is still caught, by `selects_outside_head` below — which is why that clause
# reads the job body and not only the trigger.
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

# Either the trigger inherently carries an outside head, or the job goes and finds
# one through the pulls API. The second arm is what keeps a schedule-driven
# resolver — `auto-bot-land`'s cron arm is exactly one — inside the subject set.
selects_outside_head(doc, _) if {
	some trigger in ["pull_request", "pull_request_target", "workflow_run"]
	doc.on[trigger]
}

selects_outside_head(_, body) if {
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
	count(violation) == 1 with input as {
		"tree": {"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"if": "startsWith(github.event.workflow_run.head_branch, 'renovate/')",
			}},
		}}, "missing": []},
	}
}

test_a_lane_that_tests_origin_passes if {
	count(violation) == 0 with input as {
		"tree": {"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"if": "github.event.workflow_run.head_repository.full_name == github.repository",
			}},
		}}, "missing": []},
	}
}

# The origin test living in a step's jq filter rather than the job `if:` — the
# cron arm's only gate, and the reason `tests_origin` marshals the whole job.
test_origin_in_a_step_body_passes if {
	count(violation) == 0 with input as {
		"tree": {"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"workflow_run": {}, "schedule": []},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "gh api repos/x/pulls | jq 'select(.head.repo.full_name == $repo)'"}],
			}},
		}}, "missing": []},
	}
}

# THE FALSE POSITIVE THE THIRD CONJUNCT EXISTS FOR. Scheduled, holds
# contents:write, selects no outside head.
test_a_scheduled_writer_with_no_outside_head_is_not_a_subject if {
	count(violation) == 0 with input as {
		"tree": {"documents": {".github/workflows/perf.yml": {
			"on": {"schedule": [], "workflow_dispatch": {}},
			"jobs": {"measure": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "git push origin refs/notes/perf"}],
			}},
		}}, "missing": []},
	}
}

# A schedule-only lane that DOES go looking for pull requests is a subject, even
# though no trigger carries a head.
test_a_scheduled_resolver_of_pulls_is_a_subject if {
	count(violation) == 1 with input as {
		"tree": {"documents": {".github/workflows/auto-bot-land.yml": {
			"on": {"issue_comment": {}},
			"jobs": {"land": {
				"permissions": {"contents": "write"},
				"steps": [{"run": "gh api repos/$REPO/pulls?state=open"}],
			}},
		}}, "missing": []},
	}
}

test_a_read_only_lane_is_not_a_subject if {
	count(violation) == 0 with input as {
		"tree": {"documents": {".github/workflows/ci.yml": {
			"on": {"pull_request": {}},
			"jobs": {"gate": {"permissions": {"contents": "read"}}},
		}}, "missing": []},
	}
}

# Workflow-level permissions, not job-level — the same grant written one level up.
test_workflow_level_write_is_still_a_grant if {
	count(violation) == 1 with input as {
		"tree": {"documents": {".github/workflows/auto-release-land.yml": {
			"on": {"workflow_run": {}},
			"permissions": {"contents": "write"},
			"jobs": {"land": {"if": "startsWith(x, 'release-plz-')"}},
		}}, "missing": []},
	}
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

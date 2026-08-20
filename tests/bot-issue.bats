#!/usr/bin/env bats
# CLOUD-693. A bot proposes work with no issue and no session, so every lifecycle
# gate refuses it by construction. `bot-issue` is the step that turns the proposal
# into a refined row before the lifecycle sees it — and the rows below are the
# ones the issue declares, in its own order.
#
# EVERY CASE RUNS OFFLINE. `gh` and `curl` are stubbed on PATH, which is what lets
# this suite run inside the gate on a machine with no tracker credential — the
# same shape `tests/checks-green.bats` uses for the same reason. The one thing not
# stubbed is `ready-lint`: the composition case runs the REAL gate over the REAL
# derived payload, because "the derived block is checkable by the same gate that
# checks a human's" is the claim that makes a mechanical row honest, and a stub
# would assert it rather than test it.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/bot-issue"
	STUB="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$STUB"
	export PATH="$STUB:$PATH"
	export BOT_ISSUE_REPO="demo/repo"
	export BOT_ISSUE_LINEAR_API="https://tracker.invalid/graphql"
	export LINEAR_ACCESS_KEY="lin_api_stub"
	# The PR the stubs describe. Each case rewrites only the field it is about.
	PR_TITLE="build(deps): update cargo"
	PR_LOGIN="renovate[bot]"
	PR_BODY="This PR contains the following updates."
	PR_FILES=$'Cargo.toml\nCargo.lock'
	CREATE_OK=yes
	STATES=todo
	AUTH=bare
	HTTP=200
}

# `gh` dispatches on the endpoint and returns what `--jq` would have produced, so
# the stub answers the call rather than re-implementing the tool.
stub_gh() {
	cat >"$STUB/gh" <<-EOF
		#!/usr/bin/env bash
		args="\$*"
		case "\$args" in
		  *"-X PATCH"*)
		    for a in "\$@"; do
		      case "\$a" in body=@*) cp "\${a#body=@}" "$BATS_TEST_TMPDIR/patched-body" ;; esac
		    done
		    echo '{}'
		    ;;
		  *"/files"*)
		    printf '%s\n' '$PR_FILES'
		    ;;
		  *"pulls?state=open"*)
		    printf '%s\n' "\${STUB_OPEN_PR:-7}"
		    ;;
		  *".body // "*)
		    printf '%s\n' '$PR_BODY'
		    ;;
		  *"repos/demo/repo/pulls/"*)
		    printf '{"number":7,"title":"%s","body":"%s","login":"%s","head":"renovate/cargo","draft":true}\n' \\
		      '$PR_TITLE' '$PR_BODY' '$PR_LOGIN'
		    ;;
		  *) echo "unstubbed gh call: \$args" >&2; exit 1 ;;
		esac
	EOF
	chmod +x "$STUB/gh"
}

# `curl` answers the two GraphQL calls `file` makes, told apart by the mutation
# name in the request body, and appends the status line `-w` asks for. The knobs
# are the three failures the task has to tell APART: `CREATE_OK=no` is a refused
# create, `STATES=none` is a workspace with no Todo state, `AUTH=bearer` is a
# credential that only authenticates with the `Bearer` prefix, and `HTTP=<code>`
# is a transport-level answer.
stub_curl() {
	cat >"$STUB/curl" <<-EOF
		#!/usr/bin/env bash
		body=""; auth=""
		prev=""
		for a in "\$@"; do
		  case "\$prev" in
		    -d) body="\$a" ;;
		    -H) case "\$a" in Authorization:*) auth="\${a#Authorization: }" ;; esac ;;
		  esac
		  prev="\$a"
		done
		echo "\$body" >>"$BATS_TEST_TMPDIR/graphql"
		echo "\$auth" >>"$BATS_TEST_TMPDIR/auth"
		emit() { printf '%s\n%s' "\$1" "\${HTTP:-$HTTP}"; }
		if [ "$AUTH" = bearer ] && [ "\${auth#Bearer }" = "\$auth" ]; then
		  emit '{"errors":[{"message":"nope","extensions":{"code":"AUTHENTICATION_ERROR"}}]}'
		  exit 0
		fi
		case "\$body" in
		  *issueCreate*)
		    if [ "$CREATE_OK" = yes ]; then
		      emit '{"data":{"issueCreate":{"success":true,"issue":{"identifier":"CLOUD-700","url":"https://linear.app/x"}}}}'
		    else
		      emit '{"errors":[{"message":"refused","extensions":{"code":"INVALID_INPUT"}}]}'
		    fi
		    ;;
		  *)
		    if [ "$STATES" = none ]; then
		      emit '{"data":{"workflowStates":{"nodes":[]}}}'
		    else
		      emit '{"data":{"workflowStates":{"nodes":[{"id":"state-todo","name":"Todo"}]}}}'
		    fi
		    ;;
		esac
	EOF
	chmod +x "$STUB/curl"
}

stubs() {
	stub_gh
	stub_curl
}

@test "a bump PR with no row gets one, and the PR is told which row it closes" {
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"#7 -> CLOUD-700"* ]]
	# The closing key is what makes the merge move the board — `closing-key-check`
	# refuses a body that names a key any other way.
	[[ "$(cat "$BATS_TEST_TMPDIR/patched-body")" == *"Closes CLOUD-700"* ]]
}

@test "the row is filed into the ready queue, not into whatever state id was pinned" {
	# Todo is the ready queue (mem:workflow/board-states): the row is pullable the
	# moment it exists. The state id is RESOLVED because it is a workspace-side
	# object nobody here controls, and a stale pin would file into whatever that id
	# has since become.
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/graphql")" == *"state-todo"* ]]
	# Asked for by name in the filter rather than fetched-and-picked here.
	[[ "$(cat "$BATS_TEST_TMPDIR/graphql")" == *'name: {eq: \"Todo\"}'* ]]
}

@test "IDEMPOTENCE: a second call on the same PR files nothing" {
	# `ensure` runs on every lander tick, twice an hour for as long as the PR is
	# open. The key travels in the BODY rather than in a local record, because the
	# body is what the merge reads and a local record could go missing.
	PR_BODY="a bump, Closes CLOUD-700"
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"already names CLOUD-700"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/graphql" ]
}

@test "a non-bot PR is untouched, and the refusal says whose it is" {
	# An agent's branch carries its own claim receipt and its own issue; filing a
	# second row for it would put two rows on one change.
	PR_LOGIN="wenzowski"
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 1 ]
	[[ "$output" == *"wenzowski"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/graphql" ]
}

@test "the retired bot is not on the allowlist either (CLOUD-660)" {
	# Dependabot cannot open a PR here any more, so a row filed for one would
	# assert a lane this repository does not have.
	PR_LOGIN="dependabot[bot]"
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 1 ]
	[[ "$output" == *"dependabot[bot]"* ]]
}

@test "a PR touching no owned manifest is REFUSED, never given an invented row" {
	# The alternative is a tracker row asserting a bump nobody proposed.
	PR_FILES=$'README.md\ndocs/notes.md'
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 1 ]
	[[ "$output" == *"touches no manifest this lane owns"* ]]
	# Pointer-only: the paths it did touch, so a lane that grew a manifest is a
	# one-line fix rather than a mystery.
	[[ "$output" == *"README.md"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/graphql" ]
}

@test "a workflow bump is owned too — that manager is in the same lane" {
	PR_FILES=".github/workflows/ci.yml"
	PR_TITLE="ci(deps): update actions"
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"CLOUD-700"* ]]
}

@test "a subject with no Conventional type is refused, because that commit could never land" {
	# `commit-lint` gates every fast-forward, so the honest answer is to name the
	# lane defect rather than to invent a type the config did not set (CLOUD-676).
	PR_TITLE="update cargo"
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 1 ]
	[[ "$output" == *"no Conventional type"* ]]
}

@test "THE DERIVED BLOCK PASSES ready-lint — the same gate a human's row passes" {
	# The claim that makes a mechanical row honest, tested rather than asserted.
	stubs
	run "$TASK" derive 7
	[ "$status" -eq 0 ]
	printf '%s' "$output" >"$BATS_TEST_TMPDIR/payload.json"
	run "$BATS_TEST_DIRNAME/../mise-tasks/ready-lint" <"$BATS_TEST_TMPDIR/payload.json"
	[ "$status" -eq 0 ]
}

@test "the §6 type is READ from the subject, not chosen here" {
	# `renovate.json5`'s packageRules already decided it. Re-deciding would be a
	# second authority for one fact.
	PR_TITLE="ci(deps): update actions"
	PR_FILES=".github/workflows/ci.yml"
	stubs
	run "$TASK" derive 7
	[ "$status" -eq 0 ]
	[[ "$output" == *'`ci` → no bump'* ]]
}

@test "derive writes nothing — it is the half a gate can read" {
	stubs
	run "$TASK" derive 7
	[ "$status" -eq 0 ]
	[ ! -e "$BATS_TEST_TMPDIR/graphql" ]
	[ ! -e "$BATS_TEST_TMPDIR/patched-body" ]
}

@test "an absent tracker credential is exit 2, never a silent skip" {
	# A bot PR landing with no row is the board quietly stopping describing what
	# shipped. That is a defect to see, not one to route around.
	unset LINEAR_ACCESS_KEY
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"LINEAR_ACCESS_KEY"* ]]
}

@test "THE THREE TRACKER FAILURES ARE TOLD APART, which the first production run needed" {
	# The lane's first scheduled tick died on "no Todo state on the team" — one
	# message standing for a transport error, a refused query and a genuinely
	# absent state. A diagnosis that cannot separate those makes the next step a
	# guess.
	stubs
	HTTP=503 stub_curl
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"HTTP 503"* ]]

	STATES=none stub_curl
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"no workflow state named Todo"* ]]
	[[ "$output" == *"tracker answered"* ]]
}

@test "a credential that needs Bearer is tried, and the form that worked is named" {
	# A personal API key authenticates raw; an OAuth token needs the prefix. The
	# secret does not say which it is, and a lane that fails twice a day until
	# someone guesses is worse than one extra request on the first call.
	AUTH=bearer stub_curl
	stub_gh
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"authenticates as a bearer token"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/auth")" == *"Bearer "* ]]
}

@test "a credential neither form authenticates names both codes, and blames the credential" {
	stubs
	cat >"$STUB/curl" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n200' '{"errors":[{"message":"nope","extensions":{"code":"AUTHENTICATION_ERROR"}}]}'
	EOF
	chmod +x "$STUB/curl"
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"AUTHENTICATION_ERROR"* ]]
	[[ "$output" == *"the credential is the thing to look at"* ]]
}

@test "a tracker that refuses the create is exit 2, and no key is invented" {
	CREATE_OK=no
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"refused the create"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/patched-body" ]
}

@test "the refusal carries no response body — a tracker error can echo the request back" {
	CREATE_OK=no
	stubs
	run "$TASK" ensure 7
	[[ "$output" != *"lin_api_stub"* ]]
}

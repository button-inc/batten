#!/usr/bin/env bats
# CLOUD-693. A bot proposes work with no issue and no session, so every lifecycle
# gate refuses it by construction. `bot-issue` is the step that turns the proposal
# into a refined row before the lifecycle sees it — and the rows below are the
# ones the issue declares, in its own order.
#
# THE ROW IS A GITHUB ISSUE THAT LINEAR MIRRORS (CLOUD-750), so there is no
# tracker credential anywhere in this suite — the `curl` stub the GraphQL shape
# needed is gone with it. What replaces it is three `gh` endpoints: opening an
# issue, listing issues to find a mirror this PR already has, and reading the
# `linear-code[bot]` linkback comment for the key.
#
# EVERY CASE RUNS OFFLINE. `gh` is stubbed on PATH, which is what lets this suite
# run inside the gate on a machine with no credentials at all — the same shape
# `tests/checks-green.bats` uses for the same reason. The one thing not stubbed is
# `ready-lint`: the composition case runs the REAL gate over the REAL derived
# payload, because "the derived block is checkable by the same gate that checks a
# human's" is the claim that makes a mechanical row honest, and a stub would
# assert it rather than test it.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/bot-issue"
	STUB="$BATS_TEST_TMPDIR/stub"
	mkdir -p "$STUB"
	export PATH="$STUB:$PATH"
	export BOT_ISSUE_REPO="demo/repo"
	# The PR the stubs describe. Each case rewrites only the field it is about.
	PR_TITLE="build(deps): update cargo"
	PR_LOGIN="renovate[bot]"
	PR_BODY="This PR contains the following updates."
	PR_FILES=$'Cargo.toml\nCargo.lock'
	# The repository's issue list, as `mirror_for` reads it: `MIRROR=none` is a PR
	# with no mirror yet, `MIRROR=yes` is one already filed. `LINKBACK=none` is the
	# window after the issue exists and before the sync has run.
	MIRROR=none
	LINKBACK=yes
	CREATE_OK=yes
}

# `gh` dispatches on the endpoint and returns what `--jq` would have produced, so
# the stub answers the call rather than re-implementing the tool.
stub_gh() {
	cat >"$STUB/gh" <<-EOF
		#!/usr/bin/env bash
		args="\$*"
		case "\$args" in
		  *"-X POST"*"/issues"*)
		    if [ "$CREATE_OK" != yes ]; then echo "refused" >&2; exit 1; fi
		    for a in "\$@"; do
		      case "\$a" in body=@*) cp "\${a#body=@}" "$BATS_TEST_TMPDIR/issue-body" ;; esac
		    done
		    echo 41
		    ;;
		  *"-X PATCH"*)
		    for a in "\$@"; do
		      case "\$a" in body=@*) cp "\${a#body=@}" "$BATS_TEST_TMPDIR/patched-body" ;; esac
		    done
		    echo '{}'
		    ;;
		  *"/issues/"*"/comments"*)
		    if [ "$LINKBACK" = yes ]; then
		      printf '%s\n' '<!-- linear-linkback --> see https://linear.app/buttoninc/issue/CLOUD-700/x'
		    fi
		    ;;
		  *"issues?state=all"*)
		    if [ "$MIRROR" = yes ]; then printf '%s\n' 41; fi
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

stubs() { stub_gh; }

@test "a bump PR with no row gets one, and the PR is told which row it closes" {
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"#7 -> CLOUD-700"* ]]
	# The closing key is what makes the merge move the board — `closing-key-check`
	# refuses a body that names a key any other way.
	[[ "$(cat "$BATS_TEST_TMPDIR/patched-body")" == *"Closes CLOUD-700"* ]]
}

@test "the mirror issue carries the derived block and a marker naming its PR" {
	# The marker is what makes `ensure` idempotent across the window where the row
	# exists and the PR body does not yet name it. Hidden, so a reader never sees
	# it; last, so it is never in the way of the block above it.
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/issue-body")" == *"Refinement — Ready"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/issue-body")" == *"<!-- bot-lane pr=7 -->"* ]]
}

@test "THE PR CLOSES THE CLOUD KEY, never the mirror issue (CLOUD-750)" {
	# Measured on the probe: closing the GitHub issue moves the row to Done in
	# about a second, and Done here means RELEASED. Closing `#41` on merge would
	# assert a release that has not happened and skip In Review entirely.
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/patched-body")" == *"Closes CLOUD-700"* ]]
	[[ "$(cat "$BATS_TEST_TMPDIR/patched-body")" != *"Closes #41"* ]]
}

@test "a mirror that is not yet mirrored links nothing, and says so" {
	# The window between the issue existing and the sync having run. A tick that
	# cannot finish makes progress and returns 0; the next one links it. Nothing
	# polls: a wall-clock wait would be a guess about someone else's latency.
	LINKBACK=none
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[[ "$output" == *"not mirrored yet"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/patched-body" ]
}

@test "a second tick reuses the mirror it already filed rather than opening another" {
	# Idempotence in the window above, and the reason the marker is searched by
	# LISTING issues: the search API's indexing lag would let this file twice.
	MIRROR=yes
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 0 ]
	[ ! -e "$BATS_TEST_TMPDIR/issue-body" ]
	[[ "$(cat "$BATS_TEST_TMPDIR/patched-body")" == *"Closes CLOUD-700"* ]]
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

@test "a mirror that cannot be opened is exit 2, and no key is invented" {
	# A bot PR landing with no row is the board quietly stopping describing what
	# shipped. That is a defect to see, not one to route around.
	CREATE_OK=no
	stubs
	run "$TASK" ensure 7
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not open the mirror issue"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/patched-body" ]
}

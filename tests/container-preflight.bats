#!/usr/bin/env bats
# subject: mise-tasks/container-preflight.sh
# The container preflight (CLOUD-261): the gate that asks whether this container
# can do the work at all, as opposed to whether the toolchain installed.
#
# The GitHub half is driven through a stubbed `mise` on PATH — the same technique
# tests/doctor.bats uses — so every verdict is reachable without a real token,
# and so this suite tests the CODE rather than the machine it happens to run on.
# That separation is load-bearing: if `mise run test:bats` doubled as a
# container-health check, the fix for a broken container could not be landed from
# one.

setup() {
	PREFLIGHT="$BATS_TEST_DIRNAME/../mise-tasks/container-preflight.sh"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	# A fenced environment by default, so a test that is not about egress does
	# not accidentally assert on it.
	export NO_PROXY="api.github.com" no_proxy="api.github.com"
	export HTTPS_PROXY="http://proxy:8080"
}

# Stub `mise run gh-preflight` with a chosen exit code and output.
stub_mise() { # stub_mise <exit-code> [output]
	cat >"$STUB/mise" <<EOF
#!/usr/bin/env bash
echo "${2:-stubbed gh-preflight}"
exit $1
EOF
	chmod +x "$STUB/mise"
	PATH="$STUB:$PATH"
	export PATH
}

@test "the task is executable" {
	[ -x "$PREFLIGHT" ]
}

@test "a fenced container with every claim passes, quietly" {
	# THE ENVIRONMENT IS PINNED, and it has to be (CLOUD-1399). This case used to
	# run with whatever the box exported, so its verdict was a property of the
	# machine — and under `mise exec` the guard has already prepended the GitHub
	# hosts, which is now `partial` rather than `ok`. A case about the unproxied
	# container must state the unproxied container, the same way the unfenced
	# case below states its own.
	stub_mise 0
	run env NO_PROXY="" no_proxy="" HTTPS_PROXY="" https_proxy="" "$PREFLIGHT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"egress ok"* ]]
	# A passing preflight must not shout: the norm is passing, and a loud pass
	# trains the reader to skip the output that matters.
	[[ "$output" != *"CANNOT DO THE WORK"* ]]
}

@test "a partially fenced proxy is reported and does NOT halt" {
	# The state this repository's own container is in: the GitHub hosts are
	# fenced so the toolchain resolves, and the proxy still carries everything
	# else. It must not halt — `egress-is-unproxied` repairs what batten mediates
	# at every session start, and halting would brick every session over a state
	# a later row fixes. It must also not be silent, which is the false green the
	# three-verdict split exists to remove: before it, this input read `ok`.
	stub_mise 0
	run env NO_PROXY="api.github.com,pypi.org" no_proxy="api.github.com,pypi.org" \
		HTTPS_PROXY="http://proxy:8080" "$PREFLIGHT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"egress partial"* ]]
	[[ "$output" == *"EGRESS"* ]]
	[[ "$output" != *"CANNOT DO THE WORK"* ]]
}

@test "a missing read claim halts with exit 1" {
	stub_mise 1 "MISS checks=read"
	run "$PREFLIGHT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CANNOT DO THE WORK"* ]]
	[[ "$output" == *"CREDENTIAL"* ]]
	# The diagnosis must reach the reader, not just the verdict.
	[[ "$output" == *"MISS checks=read"* ]]
}

@test "the credential failure names land and ci-wait, the tasks that break" {
	# The measured cost: verify goes green, the PR is readied and pushed, and
	# only then does landing turn out to be impossible. A verdict that did not
	# name that is a verdict nobody acts on early enough.
	stub_mise 1
	run "$PREFLIGHT"
	[[ "$output" == *"ci-wait"* ]]
	[[ "$output" == *"land"* ]]
}

@test "an unreachable API is reported as a fork, never as a bad token" {
	# An Actions/API incident looks exactly like an absent token from here.
	# Sending someone to rotate a working credential mid-incident is its own
	# expensive mistake, so the status page must be named first.
	stub_mise 2
	run "$PREFLIGHT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"UNREACHABLE"* ]]
	[[ "$output" == *"githubstatus.com"* ]]
}

@test "an unfenced proxy halts, and names the ambient NO_PROXY as the repair" {
	stub_mise 0
	run env NO_PROXY="localhost" no_proxy="localhost" HTTPS_PROXY="http://proxy:8080" "$PREFLIGHT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"EGRESS"* ]]
	[[ "$output" == *"AMBIENT NO_PROXY"* ]]
	# The trap that makes this its own check: mise.toml's guard cannot fix it.
	[[ "$output" == *"CANNOT help here"* ]]
}

@test "both causes are reported together, not one at a time" {
	# A broken container is usually broken in more than one way. Reporting the
	# first and exiting costs a whole extra session to find the second.
	stub_mise 1
	run env NO_PROXY="localhost" no_proxy="localhost" HTTPS_PROXY="http://proxy:8080" "$PREFLIGHT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"EGRESS"* ]]
	[[ "$output" == *"CREDENTIAL"* ]]
}

@test "--degraded skips the GitHub probes — a missing gh is not a missing permission" {
	# The hook passes this when provisioning already failed. Probing with a
	# half-installed toolchain would stack a second wrong diagnosis on the first.
	stub_mise 1 "this must not be consulted"
	run "$PREFLIGHT" --degraded
	[ "$status" -eq 0 ]
	[[ "$output" == *"skipping the GitHub probes"* ]]
	[[ "$output" != *"this must not be consulted"* ]]
}

@test "it halts and never repairs — the opposite of doctor" {
	# doctor repairs because its failures have one correct outcome an agent can
	# reach. These need a human to change a token's scopes or an egress policy,
	# so the task must not mutate anything: an agent that "fixes" its way past
	# this produces work it cannot land.
	# Anchored at the start of a line, because the diagnostic text legitimately
	# NAMES `mise install` when explaining what the egress fault breaks — quoting
	# a command is not running one, and an unanchored grep cannot tell them apart.
	run bash -c "grep -vE '^[[:space:]]*#' '$PREFLIGHT' | grep -cE '^[[:space:]]*(rustup|rm -rf|git submodule|mise install|npm |pip )' || true"
	[ "$output" -eq 0 ]
}

@test "it tells the reader not to rewrite the repo around a broken container" {
	# The failure mode this exists to prevent, second only to the workaround:
	# concluding from one bad container that the tasks or memories are wrong.
	run env NO_PROXY="localhost" no_proxy="localhost" HTTPS_PROXY="http://proxy:8080" "$PREFLIGHT" --degraded
	[[ "$output" == *"a defect in this repository"* ]]
	[[ "$output" == *"memories"* ]]
}

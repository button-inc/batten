#!/usr/bin/env bats
# CLOUD-714. The shim exists to answer one question — did the client actually
# execute the configured command — so the suite's job is to prove the record is
# written, that it is written BEFORE the launch rather than after it, and that
# nothing about writing it can take the server down. The `exec` row is the one
# that keeps this from drifting into a supervisor.

setup() {
	SHIM="$BATS_TEST_DIRNAME/../mise-tasks/serena-mcp"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init -q
	LEDGER="$REPO/.git/batten-mcp-spawns"
	# A launcher standing in for `mise exec … -- serena start-mcp-server`: it
	# prints its own pid, which is the only thing that can distinguish exec from
	# fork from outside the process.
	LAUNCHER="$BATS_TEST_TMPDIR/launcher"
	printf '#!/usr/bin/env bash\nprintf "pid=%%s args=%%s\\n" "$$" "$*"\n' >"$LAUNCHER"
	chmod +x "$LAUNCHER"
	export BATTEN_MCP_LAUNCHER="$LAUNCHER"
}

shim() { (cd "$REPO" && "$SHIM" "$@"); }

@test "a launch appends one record naming the server, and execs the launch line" {
	run shim exec 'pipx:serena-agent@1.6.1' -- serena start-mcp-server
	[ "$status" -eq 0 ]
	[[ "$output" == *"args=exec pipx:serena-agent@1.6.1 -- serena start-mcp-server"* ]]
	[ "$(wc -l <"$LEDGER")" -eq 1 ]
	[[ "$(cut -f2 "$LEDGER")" == "serena" ]]
}

@test "THE SERVER'S PID IS THE SHIM'S — it execs rather than forks" {
	# Non-negotiable for this design: after `exec` there is no shell left, so the
	# shim structurally cannot become the supervisor or retry loop CLOUD-714
	# forbids. A fork would leave the recorded pid pointing at a process that is
	# not the server, which is also a wrong answer to the question being asked.
	run shim exec x -- y
	[ "$status" -eq 0 ]
	recorded=$(cut -f3 "$LEDGER")
	[[ "$output" == *"pid=$recorded"* ]]
}

@test "the record carries five fields: epoch, server, pid, load, siblings" {
	run shim exec x -- y
	[ "$(awk -F'\t' '{print NF}' "$LEDGER")" -eq 5 ]
	[[ "$(cut -f1 "$LEDGER")" =~ ^[0-9]+$ ]]
	[[ "$(cut -f5 "$LEDGER")" =~ ^[0-9]+$ ]]
}

@test "a launch inside the window counts the earlier one as a sibling" {
	# The burst hypothesis is the whole reason these fields exist: all three
	# measured failures were multi-server startup bursts and every success was a
	# lone launch. A sibling count that never moved would answer nothing.
	shim exec x -- y
	run shim exec x -- y
	[ "$status" -eq 0 ]
	[ "$(sed -n 1p "$LEDGER" | cut -f5)" -eq 0 ]
	[ "$(sed -n 2p "$LEDGER" | cut -f5)" -eq 1 ]
}

@test "a launch outside the window counts no sibling" {
	printf '%s\tserena\t999\t0.00\t0\n' "$(($(date +%s) - 600))" >"$LEDGER"
	run shim exec x -- y
	[ "$(sed -n 2p "$LEDGER" | cut -f5)" -eq 0 ]
}

@test "STDOUT CARRIES ONLY THE SERVER'S BYTES — stdout is the MCP transport" {
	# One stray byte here corrupts the JSON-RPC stream and takes the server down
	# in a way indistinguishable from the bug this is diagnosing.
	run shim exec x -- y
	[ "$(printf '%s\n' "$output" | wc -l)" -eq 1 ]
	[[ "$output" == pid=* ]]
}

@test "an unwritable ledger never stops the server from starting" {
	# The ledger is bookkeeping. A gate that could refuse a launch would be worse
	# than the defect it diagnoses.
	rm -rf "$REPO/.git"
	run shim exec x -- y
	[ "$status" -eq 0 ]
	[[ "$output" == pid=* ]]
}

@test "the server name comes from the shim's own basename, so a second server is a second name" {
	cp "$SHIM" "$BATS_TEST_TMPDIR/github-mcp"
	run env -u BATTEN_MCP_SERVER bash -c "cd '$REPO' && BATTEN_MCP_LAUNCHER='$LAUNCHER' '$BATS_TEST_TMPDIR/github-mcp' exec x -- y"
	[ "$status" -eq 0 ]
	[[ "$(cut -f2 "$LEDGER")" == "github" ]]
}

@test "the shim is what .mcp.json launches, so the ledger is populated in real sessions" {
	# Non-negotiable 2: a mechanism nothing invokes is half a change.
	run jq -r '.mcpServers.serena.command' "$BATS_TEST_DIRNAME/../.mcp.json"
	[ "$output" = "mise-tasks/serena-mcp" ]
}

@test "the launch args stay in .mcp.json, so the pin gate still reads them" {
	# The shim moved the COMMAND and deliberately not the args. If the pinned,
	# scoped `mise exec` argv migrated into this script, `mise-pin-agreement`
	# would report a clean pass over a file that no longer carries a pin.
	run jq -r '.mcpServers.serena.args | join(" ")' "$BATS_TEST_DIRNAME/../.mcp.json"
	[[ "$output" == "exec pipx:serena-agent@"*" -- serena start-mcp-server"* ]]
}

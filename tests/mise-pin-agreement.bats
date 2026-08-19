#!/usr/bin/env bats
# mise-pin-agreement (CLOUD-316). .mcp.json launches Serena through a scoped
# `mise exec`, which is the fix; the pin it must then repeat is the fix's cost.
# Both halves are gated here, and the SHAPE case is the load-bearing one: a
# revert to a bare `mise exec` removes every version reference, so a gate that
# only compared versions would report "nothing to check" and pass the defect.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/mise-pin-agreement"
	TOML="$BATS_TEST_TMPDIR/mise.toml"
	MCP="$BATS_TEST_TMPDIR/.mcp.json"
	cat >"$TOML" <<-'EOF'
		[tools]
		"pipx:serena-agent" = "1.6.1"
		uv = "0.8"
	EOF
}

scoped_mcp() { # scoped_mcp <version>
	cat >"$MCP" <<-EOF
		{"mcpServers":{"serena":{"command":"mise","args":[
		  "exec","pipx:serena-agent@$1","--","serena","start-mcp-server",
		  "--context","claude-code","--project","."]}}}
	EOF
}

@test "a scoped launch whose version matches mise.toml passes" {
	scoped_mcp 1.6.1
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 0 ]
	[[ "$output" == *"agree with"* ]]
}

@test "a version .mcp.json names that mise.toml does not pin fails, naming both" {
	scoped_mcp 9.9.9
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pipx:serena-agent@9.9.9"* ]]
	[[ "$output" == *"pins 1.6.1"* ]]
}

@test "a tool mise.toml does not carry at all fails" {
	cat >"$MCP" <<-'EOF'
		{"mcpServers":{"other":{"command":"mise","args":["exec","pipx:nothing@1.0","--","x"]}}}
	EOF
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no pin for pipx:nothing"* ]]
}

# The regression this gate exists for. It must NOT pass as "nothing to check".
@test "a bare \`mise exec\` fails even though it names no version to compare" {
	cat >"$MCP" <<-'EOF'
		{"mcpServers":{"serena":{"command":"mise","args":["exec","--","serena","start-mcp-server"]}}}
	EOF
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 1 ]
	[[ "$output" == *"names no tool"* ]]
}

@test "a server not launched through mise is left alone" {
	cat >"$MCP" <<-'EOF'
		{"mcpServers":{"thing":{"command":"npx","args":["-y","some-server"]}}}
	EOF
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 0 ]
}

@test "an unparseable .mcp.json is exit 2, never a clean pass" {
	echo 'not json' >"$MCP"
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not readable JSON"* ]]
}

@test "a missing .mcp.json is nothing to check" {
	run "$GATE" "$BATS_TEST_TMPDIR/absent.json" "$TOML"
	[ "$status" -eq 0 ]
}

@test "a missing mise.toml cannot be compared against — exit 2" {
	scoped_mcp 1.6.1
	run "$GATE" "$MCP" "$BATS_TEST_TMPDIR/absent.toml"
	[ "$status" -eq 2 ]
}

# CLOUD-714 interposes `mise-tasks/<server>-mcp`, a shim that records the spawn
# and execs `mise "$@"` with these same args. Keying the scoped-exec check on
# `command == "mise"` would have made every shimmed server exempt — the gate
# green while the property it exists for went unchecked.
@test "A SHIMMED LAUNCH IS STILL CHECKED — the selector is argv, not the command name" {
	cat >"$MCP" <<-'EOF'
		{"mcpServers":{"serena":{"command":"mise-tasks/serena-mcp","args":["exec","--","serena","start-mcp-server"]}}}
	EOF
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 1 ]
	[[ "$output" == *"names no tool"* ]]
}

@test "a shimmed launch that IS scoped passes, and its pin is still read" {
	cat >"$MCP" <<-'EOF'
		{"mcpServers":{"serena":{"command":"mise-tasks/serena-mcp","args":["exec","pipx:serena-agent@1.6.1","--","serena","start-mcp-server"]}}}
	EOF
	run "$GATE" "$MCP" "$TOML"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 tool reference(s)"* ]]
}

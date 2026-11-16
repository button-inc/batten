# A question that asks the owner to admit a finding, worded so the ledger can
# never record the answer (#1276, CLOUD-2775).
#
# An admission binds only when the recorded answer passes `asked::Entry::admits`
# (`crates/batten/src/asked.rs`): the question NAMES the exact `<verdict> <path>`
# pair, and the selected option's label starts with `Admit` (`asked::ADMIT`). A
# question that misses either conjunct is asked, answered, recorded — and admits
# nothing, so the gate refuses again and the owner is asked again. Measured on
# #1276: the same two findings were asked three times, twice with shortened
# paths and once with an option labelled "Yes, admit".
#
# SO THE QUESTION IS JUDGED BEFORE IT IS ASKED, on its own words: a question
# whose text asks to admit must offer an option labelled `Admit…`, and every
# path it names must be the full repository-relative one. A bare file name is
# never a finding's path, so it can never match.
#
# A REFUSAL NAMES THE TOOL OR THE SHORTENED TOKEN, never the question (rule 4).
#MUTANT-SUITE crates/batten/tests/it/admit_ask.rs
#MUTANT admit-label-unchecked|s@^\tnot labelled_admit\(question\)$@\tfalse@|an_admit_ask_without_the_exact_pair_is_refused

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.arguments` is the tool's own
#   input, its `questions` array for `AskUserQuestion`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.admit_ask

import rego.v1

rules contains "call ask loose"

# The ledger's own prefix (`asked::ADMIT`).
admit := "Admit"

# A path-shaped token: a file with an extension this repository's findings name,
# optionally followed by `::item` for a test or symbol.
path_token := `[A-Za-z0-9_./-]+\.(rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(::[A-Za-z0-9_:]+)?`

# Every question this call asks that asks to admit something.
admitting contains question if {
	input.call.tool == "AskUserQuestion"
	some question in input.call.arguments.questions
	regex.match(`(?i)\badmit(s|ted|ting)?\b`, question.question)
}

labelled_admit(question) if {
	some option in question.options
	startswith(option.label, admit)
}

paths(question) := {token | some token in regex.find_n(path_token, question.question, -1)}

# Asks to admit, and no option the owner can pick says it admits.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	some question in admitting
	not labelled_admit(question)
}

# Asks to admit, and names no repository-relative path at all.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	some question in admitting
	count({token | some token in paths(question); contains(token, "/")}) == 0
}

# Names a path, shortened: it can never equal a finding's pair.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"path": token}],
} if {
	some question in admitting
	some token in paths(question)
	not contains(token, "/")
}

# --- the module's own tier ----------------------------------------------------

ask(question, labels) := {"call": {
	"tool": "AskUserQuestion",
	"arguments": {"questions": [{
		"question": question,
		"options": [{"label": label} | some label in labels],
	}]},
}}

full := "Admit both? test-removed crates/batten/tests/it/session_provisioning.rs::a_local_release_build"

test_a_full_pair_with_an_admit_label_is_clean if {
	count(violation) == 0 with input as ask(full, ["Admit both", "Refuse"])
}

# The #1276 third round: "Yes, admit" admits nothing in the ledger.
test_an_option_not_labelled_admit_is_refused if {
	found := violation with input as ask(full, ["Yes, admit both", "No"])
	found == {{"rule": "call ask loose", "verdict": "call ask loose", "subjects": [{"artifact": "AskUserQuestion"}]}}
}

# The #1276 first round: a shortened path never matches the finding's pair.
test_a_shortened_path_is_refused if {
	found := violation with input as ask(
		"Admit? test-removed session_provisioning.rs::a_local_release_build and crates/batten/src/x.rs",
		["Admit", "Refuse"],
	)
	found == {{"rule": "call ask loose", "verdict": "call ask loose", "subjects": [{"path": "session_provisioning.rs::a_local_release_build"}]}}
}

test_an_admission_naming_no_path_is_refused if {
	count(violation) == 1 with input as ask("Admit the finding?", ["Admit", "Refuse"])
}

test_a_question_that_asks_nothing_about_admission_is_clean if {
	count(violation) == 0 with input as ask("Override the gate for this PR?", ["Yes, override", "No"])
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"tool": "Bash", "arguments": {"command": "echo admit"}}}
}

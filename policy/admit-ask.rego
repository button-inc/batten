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
# whose text asks to admit must offer an option labelled `Admit…`, must name a
# path, and every test finding it names (`<path>::<case>`) must carry the full
# repository-relative path. A test lives under a directory, so a `::` token with
# no `/` is a shortened one that can never match; a root-level file such as
# `clippy.toml` legitimately has no `/` and is a path as written.
#
# BOTH EXPRESSIONS ARE THE CONFIG'S: `admit-asked` and `finding-path` are
# `[[pattern]]` rows in `batten.toml`, read here from `data.batten.patterns`.
#
# A REFUSAL NAMES THE TOOL OR THE SHORTENED TOKEN, never the question (rule 4).
#MUTANT-SUITE crates/batten/tests/it/admit_ask.rs
#MUTANT admit-label-unchecked|s@^\tnot labelled_admit(question)$@\tfalse@|an_admit_ask_without_the_exact_pair_is_refused

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

# Every question this call asks that asks to admit something.
admitting contains question if {
	input.call.tool == "AskUserQuestion"
	some question in input.call.arguments.questions
	regex.match(data.batten.patterns["admit-asked"], question.question)
}

labelled_admit(question) if {
	some option in question.options
	startswith(option.label, admit)
}

paths(question) := {token |
	some token in regex.find_n(data.batten.patterns["finding-path"], question.question, -1)
}

# Asks to admit, and no option the owner can pick says it admits.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	some question in admitting
	not labelled_admit(question)
}

# Asks to admit, and names no path at all.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	some question in admitting
	count(paths(question)) == 0
}

# Names a test finding by a shortened path: it can never equal the pair.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"path": token}],
} if {
	some question in admitting
	some token in paths(question)
	contains(token, "::")
	not contains(token, "/")
}

# --- the module's own tier ----------------------------------------------------
#
# The two pattern keys are bound one by one, never the whole map: binding the
# map leaves any other key undefined, which `turn-ask.rego` measured as a
# silently passing suite.

asked_regex := `(?i)\badmit(s|ted|ting)?\b(?:[^.!?]|[.!?]\S)*\?`

path_regex := `[A-Za-z0-9_./-]+\.(rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(::[A-Za-z0-9_:]+)?`

ask(question, labels) := {"call": {
	"tool": "AskUserQuestion",
	"arguments": {"questions": [{
		"question": question,
		"options": [{"label": label} | some label in labels],
	}]},
}}

judged(question, labels) := v if {
	v := violation with input as ask(question, labels)
		with data.batten.patterns["admit-asked"] as asked_regex
		with data.batten.patterns["finding-path"] as path_regex
}

full := "Admit both? test-removed crates/batten/tests/it/session_provisioning.rs::a_local_release_build"

test_a_full_pair_with_an_admit_label_is_clean if {
	count(judged(full, ["Admit both", "Refuse"])) == 0
}

# The #1276 third round: "Yes, admit" admits nothing in the ledger.
test_an_option_not_labelled_admit_is_refused if {
	judged(full, ["Yes, admit both", "No"]) == {{"rule": "call ask loose", "verdict": "call ask loose", "subjects": [{"artifact": "AskUserQuestion"}]}}
}

# The #1276 first round: a shortened path never matches the finding's pair.
test_a_shortened_path_is_refused if {
	found := judged(
		"Admit? test-removed session_provisioning.rs::a_local_release_build and crates/batten/src/x.rs",
		["Admit", "Refuse"],
	)
	found == {{"rule": "call ask loose", "verdict": "call ask loose", "subjects": [{"path": "session_provisioning.rs::a_local_release_build"}]}}
}

# The #1276 false positive: a root-level file has no `/` and is a whole path.
test_a_root_level_file_is_a_path if {
	count(judged("Admit this smell? pattern-removed clippy.toml", ["Admit", "Refuse"])) == 0
}

test_an_admission_naming_no_path_is_refused if {
	count(judged("Admit the finding?", ["Admit", "Refuse"])) == 1
}

test_a_question_that_asks_nothing_about_admission_is_clean if {
	count(judged("Override the gate for this PR?", ["Yes, override", "No"])) == 0
}

# The #1276 false positive: the word in a statement, not in the sentence that asks.
test_the_word_outside_the_asking_sentence_asks_nothing if {
	count(judged(
		"Any failure still fails the lap, and nothing is admitted. Override the ruling for tier 3?",
		["Override", "Keep the ruling"],
	)) == 0
}

# ...and a path's `.` does not end the sentence that asks.
test_an_admit_over_a_path_still_asks if {
	count(judged(
		"Admit test-expectation-changed crates/batten/tests/it/cli.rs::every_format?",
		["Yes", "No"],
	)) == 1
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"tool": "Bash", "arguments": {"command": "cd /tmp && echo admit"}}}
		with data.batten.patterns["admit-asked"] as asked_regex
		with data.batten.patterns["finding-path"] as path_regex
}

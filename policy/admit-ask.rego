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
#MUTANT admit-pair-unchecked|s@^\tnot paired(question)$@\tfalse@|an_admit_ask_naming_no_ledger_pair_is_refused
#MUTANT single-answer-unchecked|s@^\tsettled(question)$@\tfalse@|a_question_with_one_useful_answer_is_refused
#MUTANT ledger-exemption-dropped|s@^\tnot ledger_question(question)$@\ttrue@|a_ledger_question_with_a_recommendation_is_asked
#MUTANT ledger-exemption-admitting-unchecked|s@^\tquestion in admitting$@\ttrue@|the_exemption_is_tied_to_the_admission
#MUTANT ledger-exemption-other-unchecked|s@^\tnot recommends_other(question)$@\ttrue@|the_exemption_is_tied_to_the_admission
#MUTANT recommendation-label-unread|s@^recommends(_, option) if marked(option.label)$@recommends(_, option) if false@|every_spelling_of_a_recommendation_is_refused
#MUTANT recommendation-description-unread|s@^recommends(_, option) if marked(option.description)$@recommends(_, option) if false@|every_spelling_of_a_recommendation_is_refused
#MUTANT recommendation-naming-unread|s@^recommends(question, option) if named_recommended(question, option)$@recommends(question, option) if false@|every_spelling_of_a_recommendation_is_refused
#MUTANT recommendation-tag-unread|s@^settled(question) if regex.*$@settled(question) if false@|every_spelling_of_a_recommendation_is_refused
#MUTANT recommendation-negation-dropped|s@^\tnot startswith(lower(found), "not")$@\ttrue@|every_spelling_of_a_recommendation_is_refused

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

# The ledger looks an answer up by `<smell-id> <key>` (`lint::admissions`), so
# a question binds only where those two sit side by side. Measured on #1276: a
# question naming `batten.toml` and a rule id in prose passed the path check and
# bound nothing, because no `rule-predicate-changed rule[<id>].<key>` stood in it.
paired(question) if regex.match(data.batten.patterns["ledger-pair"], question.question)

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

# Asks to admit, and names no `<smell-id> <key>` pair the ledger can look up.
violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	some question in admitting
	not paired(question)
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

# A QUESTION WITH ONE USEFUL ANSWER IS NOT A QUESTION (owner, 2026-11-23). On
# #1276 the owner was asked to approve a dispatch already approved, and to
# authorise an unsigned rewrite against "stay blocked", and answered both "why
# the fuck are you stopping to ask questions where there's only one useful
# answer". AGENTS.md already authorises the steps of agreed work; this refuses
# the question so the step is taken instead.
#
# A `(Recommended)` OPTION IS THE ASKER SAYING THE EVIDENCE SETTLES IT, so the
# question is refused whatever the other options say (CLOUD-2915). The first
# version judged the alternatives against a list of non-action words, and the
# list was the defect: "Keep fix 2 (Recommended)" / "Split fix 2 out" reached the
# owner on 2026-11-24 because "Split" was not on it, and every action verb
# escapes a list the same way. The remedy is the recommended action, its
# reasoning recorded where the decision lives, and the owner free to overrule.
#
# A RECOMMENDATION IS A MARK, NOT A SPELLING (CLOUD-2915 review): the harness's
# `(Recommended)` suffix is one way to say it; `Recommended: Keep fix 2`,
# `Keep fix 2 [Recommended]`, a description saying so, or the question text
# naming the option beside the word are the others, and each settles the
# question the same way. Matching is case-insensitive and both expressions are
# the config's (`recommendation-marked`, `recommendation-tagged`). "Not
# recommended" marks nothing.
marked(text) if {
	some found in regex.find_n(data.batten.patterns["recommendation-marked"], text, -1)
	not startswith(lower(found), "not")
}

recommends(_, option) if marked(option.label)

recommends(_, option) if marked(option.description)

recommends(question, option) if named_recommended(question, option)

# The question text names an option as the recommended one: its label beside
# the word, on either side.
named_after := [" (recommended)", " [recommended]", " is recommended", " - recommended", " — recommended", ", recommended"]

named_before := ["recommended: ", "recommend ", "recommended "]

named_recommended(question, option) if {
	label := trim_space(lower(option.label))
	label != ""
	some suffix in named_after
	contains(lower(question.question), concat("", [label, suffix]))
}

named_recommended(question, option) if {
	label := trim_space(lower(option.label))
	label != ""
	some prefix in named_before
	contains(lower(question.question), concat("", [prefix, label]))
}

settled(question) if {
	some option in question.options
	recommends(question, option)
}

# A `(Recommended)` tag in the text that names no option still says the asker
# settled it.
settled(question) if regex.match(data.batten.patterns["recommendation-tagged"], question.question)

# THE ONE QUESTION A HUMAN MUST ANSWER BY DESIGN: the ledger's own. It binds
# exactly when an option starts `Admit` and the text carries a `<smell-id> <key>`
# pair (`asked::Entry::admits`). The exemption is tied to the admission itself,
# not to those tokens appearing anywhere: the text asks to admit, and every
# option it recommends is an `Admit…` choice. A question recommending anything
# else over a pair it merely mentions is settled like any other (CLOUD-2915
# review). The label and the pair are NOT restated here: an admitting question
# lacking either is refused by the admission arms above whatever this says, so
# a conjunct for them decides nothing (the sweep measured both as survivors).
ledger_question(question) if {
	question in admitting
	not recommends_other(question)
}

recommends_other(question) if {
	some option in question.options
	recommends(question, option)
	not startswith(option.label, admit)
}

violation contains {
	"rule": "call ask loose",
	"verdict": "call ask loose",
	"subjects": [{"artifact": "AskUserQuestion"}],
} if {
	input.call.tool == "AskUserQuestion"
	some question in input.call.arguments.questions
	settled(question)
	not ledger_question(question)
}

test_a_question_with_one_useful_answer_is_refused if {
	some _ in violation with input as {"call": {"tool": "AskUserQuestion", "arguments": {"questions": [{
		"question": "Rewrite the range unsigned?",
		"options": [{"label": "Yes, rewrite unsigned (Recommended)"}, {"label": "No"}],
	}]}}}
}

test_an_approval_against_revise_is_refused if {
	some _ in violation with input as {"call": {"tool": "AskUserQuestion", "arguments": {"questions": [{
		"question": "Send the batch?",
		"options": [{"label": "Approve dispatch (Recommended)"}, {"label": "Revise first"}],
	}]}}}
}

# Two actions and no recommendation: a choice the asker could not settle.
test_two_real_choices_are_asked if {
	count(violation) == 0 with input as {"call": {"tool": "AskUserQuestion", "arguments": {"questions": [{
		"question": "Where should the shards run?",
		"options": [{"label": "Dispatched sessions"}, {"label": "CI matrix legs"}],
	}]}}}
}

# The 2026-11-24 question (CLOUD-2915): the alternative is an action, and the
# word list let it through.
test_the_measured_action_alternative_is_refused if {
	count(judged(
		"Keep fix 2 and close CLOUD-2904 with #1276?",
		["Keep fix 2 (Recommended)", "Split fix 2 out"],
	)) == 1
}

# The recommendation settles it, whatever the alternative is.
test_a_recommendation_between_two_actions_is_refused if {
	count(judged(
		"Where should the shards run?",
		["Dispatched sessions (Recommended)", "CI matrix legs"],
	)) == 1
}

test_a_lone_recommended_option_is_refused if {
	count(judged("Push the branch?", ["Push (Recommended)"])) == 1
}

# The ledger's own question is the exception: a human answers it by design.
test_a_ledger_question_with_a_recommendation_is_asked if {
	count(judged(
		"Admit test-expectation-changed crates/batten/tests/it/cli.rs::every_format?",
		["Admit the change (Recommended)", "Refuse"],
	)) == 0
}

# The text carries no "admit", so only the settled arm can fire: each half of
# the exception is required.
test_a_recommended_admit_label_without_the_pair_is_refused if {
	count(judged("Keep fix 2?", ["Admit it (Recommended)", "Split fix 2 out"])) == 1
}

test_a_recommended_pair_without_an_admit_label_is_refused if {
	count(judged(
		"Keep test-expectation-changed crates/batten/tests/it/cli.rs::every_format?",
		["Keep it (Recommended)", "Split it out"],
	)) == 1
}

test_a_question_with_no_recommendation_is_asked if {
	count(violation) == 0 with input as {"call": {"tool": "AskUserQuestion", "arguments": {"questions": [{
		"question": "Which crate goes first?",
		"options": [{"label": "batten-model"}, {"label": "No preference"}],
	}]}}}
}

# --- the module's own tier ----------------------------------------------------
#
# The two pattern keys are bound one by one, never the whole map: binding the
# map leaves any other key undefined, which `turn-ask.rego` measured as a
# silently passing suite.

asked_regex := `(?i)\badmit(s|ted|ting)?\b(?:[^.!?]|[.!?]\S)*\?`

path_regex := `[A-Za-z0-9_./-]+\.(rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(::[A-Za-z0-9_:]+)?`

pair_regex := `\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+ (?:[A-Za-z0-9_./-]+\.(?:rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(?:::[A-Za-z0-9_:]+)?|[A-Za-z_][A-Za-z0-9_.]*\[[^\]]+\](?:\.[A-Za-z0-9_]+)*)`

marked_regex := `(?i)(?:\bnot\s+)?\brecommended\b`

tagged_regex := `(?i)[(\[]\s*recommended\s*[)\]]`

ask(question, labels) := {"call": {
	"tool": "AskUserQuestion",
	"arguments": {"questions": [{
		"question": question,
		"options": [{"label": label} | some label in labels],
	}]},
}}

judged(question, labels) := described(question, [{"label": label} | some label in labels])

# Options as `{"label", "description"}` objects, for the spellings that sit in a
# description.
described(question, options) := v if {
	v := violation with input as {"call": {
		"tool": "AskUserQuestion",
		"arguments": {"questions": [{"question": question, "options": options}]},
	}}
		with data.batten.patterns["admit-asked"] as asked_regex
		with data.batten.patterns["finding-path"] as path_regex
		with data.batten.patterns["ledger-pair"] as pair_regex
		with data.batten.patterns["recommendation-marked"] as marked_regex
		with data.batten.patterns["recommendation-tagged"] as tagged_regex
}

# --- CLOUD-2915 review, item 2: every spelling of a recommendation ------------

test_a_recommended_prefix_is_refused if {
	count(judged("Keep fix 2?", ["Recommended: Keep fix 2", "Split fix 2 out"])) == 1
}

test_a_bracketed_recommendation_is_refused if {
	count(judged("Keep fix 2?", ["Keep fix 2 [Recommended]", "Split fix 2 out"])) == 1
}

test_a_lowercase_recommendation_is_refused if {
	count(judged("Keep fix 2?", ["Keep fix 2 (recommended)", "Split fix 2 out"])) == 1
}

test_a_recommendation_in_the_description_is_refused if {
	count(described("Keep fix 2?", [
		{"label": "Keep fix 2", "description": "Recommended: the evidence settles it"},
		{"label": "Split fix 2 out", "description": "a second PR"},
	])) == 1
}

test_the_text_naming_an_option_as_recommended_is_refused if {
	count(judged(
		"Keep fix 2 (Recommended) or split it out?",
		["Keep fix 2", "Split fix 2 out"],
	)) == 1
}

test_the_text_recommending_an_option_by_name_is_refused if {
	count(judged("I recommend keep fix 2. Which?", ["Keep fix 2", "Split fix 2 out"])) == 1
}

test_a_recommended_tag_in_the_text_is_refused if {
	count(judged("Keep fix 2? (Recommended)", ["Yes", "Split it out"])) == 1
}

# Saying an option is NOT recommended settles nothing on its own.
test_a_not_recommended_description_is_asked if {
	count(described("Which crate goes first?", [
		{"label": "batten-model", "description": "not recommended while #1276 is open"},
		{"label": "batten-base", "description": "the smaller cut"},
	])) == 0
}

# The owner asked for a view: a question about what is recommended marks no
# option.
test_asking_which_is_recommended_is_asked if {
	count(judged("Which runner do you recommend?", ["Dispatched sessions", "CI matrix legs"])) == 0
}

# --- CLOUD-2915 review, item 3: the exemption is the admission's -------------

# The review's own input: a pair mentioned, an `Admit…` alternative, and the
# recommendation on something else.
test_a_recommendation_over_a_mentioned_pair_is_refused if {
	count(judged(
		"Keep fix 2? It touches test-removed crates/a/b.rs::x",
		["Keep fix 2 (Recommended)", "Admit nothing, split it"],
	)) == 1
}

test_an_admission_recommending_a_non_admit_option_is_refused if {
	count(judged(
		"Admit test-removed crates/batten/tests/it/cli.rs::every_format?",
		["Keep it (Recommended)", "Admit"],
	)) == 1
}

test_a_recommended_admit_without_asking_to_admit_is_refused if {
	count(judged(
		"Keep fix 2? It touches test-removed crates/batten/tests/it/cli.rs::every_format",
		["Admit it (Recommended)", "Split it out"],
	)) == 1
}

# Every genuine admission shape stays asked, each spelling of the mark included.
test_a_genuine_admission_is_asked_however_it_recommends if {
	every options in [
		[{"label": "Admit the change (Recommended)"}, {"label": "Refuse"}],
		[{"label": "Admit the change [Recommended]"}, {"label": "Refuse"}],
		[{"label": "Admit the change", "description": "recommended"}, {"label": "Refuse"}],
		[{"label": "Admit the change"}, {"label": "Refuse"}],
	] {
		count(described(
			"Admit rule-predicate-changed rule[layer place wrong].use_sources?",
			options,
		)) == 0
	}
}

# A label the ledger cannot bind (it must START `Admit`) is refused whatever
# marks it.
test_a_recommended_prefix_before_admit_is_refused if {
	count(judged(
		"Admit rule-predicate-changed rule[layer place wrong].use_sources?",
		["Recommended: Admit the change", "Refuse"],
	)) > 0
}

test_a_genuine_admission_recommended_in_its_text_is_asked if {
	count(judged(
		"Admit test-removed crates/batten/tests/it/cli.rs::every_format? Recommended: admit",
		["Admit", "Refuse"],
	)) == 0
}

# The #1276 fourth round: a path and a rule id in prose, no pair side by side.
test_a_path_without_the_pair_is_refused if {
	count(judged(
		"Admit the change to layer place wrong's use_sources key in batten.toml?",
		["Admit the change", "Refuse"],
	)) == 1
}

# A dotted config key binds too: `mcp.permission_aliases[<alias>]` and
# `census.shell.generated[<path>]` are whole keys the ledger reads (#1276: a
# question naming only `mcp-permission-alias-removed mcp.permission_aliases[…]`
# was refused while it bound exactly).
test_a_dotted_key_pair_is_clean if {
	count(judged(
		"Admit mcp-permission-alias-removed mcp.permission_aliases[Claude_Code_Remote]?",
		["Admit the change", "Refuse"],
	)) == 0
	count(judged(
		"Admit shell-census-narrowed census.shell.generated[completions/batten.bash]?",
		["Admit", "Refuse"],
	)) == 0
}

# A config key's pair is `rule[<id>].<key>`, spaces inside the brackets.
test_a_rule_key_pair_is_clean if {
	count(judged(
		"Admit rule-predicate-changed rule[layer place wrong].use_sources?",
		["Admit the change", "Refuse"],
	)) == 0
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
	found = judged(
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
		with data.batten.patterns["ledger-pair"] as pair_regex
}

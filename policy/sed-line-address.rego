#MUTANT-SUITE crates/batten/tests/it/measure_and_edit_routes.rs
#MUTANT address-unread|s@^\tline_addressed(word)$@\tfalse@|a_line_addressed_in_place_edit_is_refused
#MUTANT script-unread|s@^\tscript_file(word)$@\tfalse@|an_in_place_edit_under_an_unread_script_is_refused
# `path edit unsafe`: an in-place `sed` aimed by line number at a repository
# file (CLOUD-2803).
#
# A line number names where text WAS. Every earlier edit to the file moves it,
# so a numeric address is a guess about the file's current shape, and a wrong
# guess edits the wrong line in silence. Measured on #1276: a `sed i\` script
# corrupted 93 files, and `51s/…/…/` on `verdict.rs` overwrote the import above
# the one it meant, after two earlier edits had shifted it. A text-matched edit
# (the Edit tool, or a regex address) fails loudly when its text is not there.
#
# Only an in-place run inside a repository is judged: `sed -n 5,9p` reads, and a
# scratch file outside every root is nobody's tree.

package batten.sed_line_address

import rego.v1

rules contains "path edit unsafe"

violation contains {
	"rule": "path edit unsafe",
	"verdict": "path edit unsafe",
	"subjects": [{"count": 1}],
} if {
	count(input.call.roots) > 0
	some program in input.call.programs
	program.name == "sed"
	in_place(program)
	some word in program.arguments
	line_addressed(word)
}

# `-i`, `-i.bak`, `-ni`, `--in-place`, `--in-place=.bak`.
in_place(program) if {
	some word in program.arguments
	regex.match(data.batten.patterns["sed-in-place-cluster"], word)
}

in_place(program) if {
	some word in program.arguments
	startswith(word, "--in-place")
}

# A script read from a file (`-f x.sed`, `--file=x.sed`) is text this module
# cannot see, so an in-place run under it is judged as if addressed: its
# addresses are unread, never cleared.
violation contains {
	"rule": "path edit unsafe",
	"verdict": "path edit unsafe",
	"subjects": [{"count": 1}],
} if {
	count(input.call.roots) > 0
	some program in input.call.programs
	program.name == "sed"
	in_place(program)
	some word in program.arguments
	script_file(word)
}

script_file(word) if word in {"-f", "--file"}

script_file(word) if startswith(word, "--file=")

# A script whose first address is a line number or a numeric range: `52s/a/b/`,
# `3,5d`, `1{/x/d}`, `7!d`. A file name such as `1.txt` is not one: an address
# is followed by a command letter or a brace, never a dot.
line_addressed(word) if {
	regex.match(data.batten.patterns["sed-line-address"], word)
}

call(argv, roots) := {"call": {
	"command": concat(" ", array.concat(["sed"], argv)),
	"segments": [],
	"programs": [{"program": "sed", "name": "sed", "arguments": argv, "subcommand": null, "global-options": [], "mediated": false}],
	"roots": roots,
}}

repo := ["/home/user/repo"]

test_a_line_numbered_in_place_substitution_is_refused if {
	some _ in violation with input as call(["-i", "52s/a/b/", "src/x.rs"], repo)
}

test_every_in_place_spelling_with_a_line_address_is_refused if {
	every argv in [
		["-i", "-e", "5d", "src/x.rs"],
		["-i.bak", "3,5d", "src/x.rs"],
		["-ni", "1{/x/d}", "src/x.rs"],
		["--in-place", "7,$d", "src/x.rs"],
		["--in-place=.orig", "7!d", "src/x.rs"],
	] {
		some _ in violation with input as call(argv, repo)
	}
}

test_a_line_address_after_the_first_command_is_refused if {
	every argv in [
		["-i", "-e", "s/a/b/;52d", "src/x.rs"],
		["-i", "s/a/b/\n7d", "src/x.rs"],
		["-i", "/x/{3d}", "src/x.rs"],
		["-i", "--expression=52d", "src/x.rs"],
		["-i", "0~3d", "src/x.rs"],
		["-i", "5,+2d", "src/x.rs"],
	] {
		some _ in violation with input as call(argv, repo)
	}
}

test_an_in_place_script_file_is_refused_unread if {
	every argv in [
		["-i", "-f", "x.sed", "src/x.rs"],
		["-i", "--file=x.sed", "src/x.rs"],
	] {
		some _ in violation with input as call(argv, repo)
	}
}

test_a_regex_address_is_allowed if {
	count(violation) == 0 with input as call(["-i", "/^use x;$/d", "src/x.rs"], repo)
}

test_a_read_only_line_range_is_allowed if {
	count(violation) == 0 with input as call(["-n", "5,9p", "src/x.rs"], repo)
}

test_a_file_named_like_a_number_is_not_an_address if {
	count(violation) == 0 with input as call(["-i", "s/a/b/", "1.txt"], repo)
}

test_outside_every_repository_is_allowed if {
	count(violation) == 0 with input as call(["-i", "52s/a/b/", "/tmp/x"], [])
}

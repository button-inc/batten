#MUTANT-SUITE crates/batten/tests/it/lock_complete.rs
#MUTANT residue-unread|s@not platform in known_platforms@false@|a_platform_key_mise_does_not_emit_is_reported
#MUTANT required-platform-unread|s@count(names) > 0@false@|a_required_platform_missing_entirely_is_reported
#MUTANT stale-pin-prefix-not-boundary|s@sprintf("%s.", \[pin\])@pin@|a_pin_its_entry_does_not_name_is_reported
#
# THE PREDECESSOR'S ROW, CARRIED RATHER THAN RETIRED.
# `policy/lock-entry-complete.rego` declared this mutation against
# `crates/batten/tests/it/staged_facts.rs`, and that module is subsumed here — so
# the row moves with the predicate it guards rather than dying with the file that
# used to hold it. Its suite is the one it always named: the case lives there
# because the ENGINE property it turns on (a declared `staged` path reaching a
# registered row at all) is `staged_facts.rs`' own subject.
#MUTANT-SUITE crates/batten/tests/it/staged_facts.rs
#MUTANT partial-entry-unread|s@^\tnot block.url$@\tfalse@|the_committed_lock_rule_refuses_a_partial_entry_over_the_binary

# METADATA
# description: |
#   The lockfile has no partial or bogus entry, and nothing in the tree can write
#   one — CLOUD-223/227/281/333/593, ported from `mise-tasks/lock-complete.sh`
#   under CLOUD-843.
#
#   THE COMMITTED BYTES, WHICH IS THE WHOLE DESIGN. `input.tree.staged` is `git
#   show :<path>` and `input.tree.tracked` explicitly is not: the working tree's
#   `mise.lock` differs from the index on any machine that has installed since
#   checkout, because a cold `mise install` writes the residue key this module
#   rejects. The predecessor read the worktree for its whole life under a header
#   claiming otherwise, so its verdict was a property of the machine — red in
#   every agent sandbox, green in the one CI job that runs it, for the same
#   commit. CLOUD-1203 landed `staged` for exactly this consumer, and
#   `git.rs::staged_facts` names it.
#
#   WHAT THIS DELIBERATELY DOES NOT ASK is whether regenerating would produce
#   something different. That is a question about UPSTREAM rather than about the
#   commit, it needs a network round trip, and it belongs on a clock —
#   `.github/workflows/lock-currency.yml`. Its predecessor `lock-check` asked it
#   and could not answer this one: regenerate-and-diff detects drift only, `mise
#   lock` never repairs an existing entry, and a stably wrong lockfile therefore
#   passes forever. One did, for its whole life.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.lockcomplete

import rego.v1

rules contains "lock-platform-residue"

rules contains "lock-platform-uninstallable"

rules contains "lock-tool-unlocked"

rules contains "lock-tool-missing"

rules contains "lock-pin-stale"

rules contains "lockfile-writes-enabled"

rules contains "workflow-installs-unlocked"

rules contains "lock-unreadable"

# --- the two committed authorities --------------------------------------------
#
# PARSED NODES RATHER THAN A LINE SCAN, and that is the largest single difference
# from the predecessor. `mise.lock`'s `[[tools.<name>]]` / `[tools.<name>.
# "platforms.<p>"` shape was read by a 38-line `awk` emitting a tab-separated
# record stream, with a second `awk` over `mise.toml`'s `[tools]` table beside it.
# Both are one map lookup here, and the quoted-versus-bare tool name that the awk
# needed a `gsub` for is simply a key.
lock := node if {
	node := input.tree.staged["mise.lock"]
	is_object(node)
}

manifest := node if {
	node := input.tree.staged["mise.toml"]
	is_object(node)
}

# The platform keys mise emits. Anything else in that position was written by an
# install on some contributor's machine, not by a lock.
known_platforms := {
	"linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl",
	"macos-x64", "macos-arm64", "windows-x64",
}

# Where this repo's tools actually get installed: CI runners are ubuntu-latest
# (linux-x64), agent sandboxes and arm runners are linux-arm64, contributors are
# on Apple silicon. musl, macos-x64 and windows are welcome but not demanded —
# upstream not shipping one of those is not this repo's defect.
#
# A LITERAL HERE RATHER THAN AN ENVIRONMENT VARIABLE, and the change is recorded
# rather than absorbed. The predecessor took `BATTEN_LOCK_PLATFORMS`, a knowable
# string anyone could spend to make the gate agree with them; a module reads no
# environment, and the set a repository installs on is committed config that
# belongs in a reviewed diff. Same reasoning CLOUD-1051 applied to two override
# passwords one campaign over.
required_platforms := {"linux-x64", "linux-arm64", "macos-arm64"}

# The backends that resolve a version through their own package manager and lock
# no URLs of their own. Written once because two clauses ask the same question of
# it — "this tool locks nothing" is the whole truth for these and a defect for
# everything else — and a second copy is exactly how the two would come to
# disagree about which tools are excused.
#
# It is an ALLOWLIST, so an unrecognised backend is required to lock: a backend
# added later is checked by default, and only a deliberate edit here excuses it.
locks_nothing(backend) if backend == "core:rust"

locks_nothing(backend) if {
	some prefix in {"npm:", "pipx:", "cargo:", "go:", "gem:"}
	startswith(backend, prefix)
}

# --- the lockfile's own entries -----------------------------------------------

# Tool name -> the entry the platform tables attach to.
#
# THE LAST ARRAY ELEMENT, because `[[tools.t]]` opens an array and a following
# `[tools.t."platforms.x"]` extends whichever element is open — so the last one is
# what TOML itself resolved the platform table into, not a choice made here.
lock_tools[name] := entry if {
	some name, entries in lock.tools
	is_array(entries)
	count(entries) > 0
	entry := entries[count(entries) - 1]
}

platform_keys[name] := keys if {
	some name, entry in lock_tools
	keys := {key |
		some key, _ in entry
		startswith(key, "platforms.")
	}
}

locked_platforms[name] := names if {
	some name, keys in platform_keys
	names := {trim_prefix(key, "platforms.") | some key in keys}
}

# The platforms this tool locked that mise could actually have emitted. Partiality
# below is only meaningful once a tool locks at least one REAL platform, which is
# what keeps a tool carrying nothing but residue from being reported twice.
real_platforms[name] := names if {
	some name, all in locked_platforms
	names := {found | some found in all; found in known_platforms}
}

has_url(name, platform) if {
	entry := lock_tools[name]
	block := entry[sprintf("platforms.%s", [platform])]
	is_string(block.url)
}

# --- pointers -----------------------------------------------------------------
#
# THE LINE SURFACE IS FOR POINTERS ONLY AND NEVER FOR A VERDICT, which is the one
# place this module reads the working tree. Every decision above comes off the
# index; a `path:line` a reader clicks is about the file they are going to edit,
# and the two differ only on a tree that is already dirty. A pointer that cannot
# be resolved degrades to the path rather than dropping the finding — an arm whose
# absence depends on a line lookup would be a gate switched off by its own
# cosmetics, which is CLOUD-1049's defect one layer out.
line_of(path, needles) := line if {
	hits := [found |
		some index, text in input.tree.lines[path]
		every needle in needles {
			contains(text, needle)
		}
		found := index + 1
	]
	count(hits) > 0
	line := min(hits)
}

pointer(path, needles) := {"path": path, "line": line_of(path, needles)}

pointer(path, needles) := {"path": path} if not line_of(path, needles)

# --- predicate 1: a platform key mise does not emit ---------------------------
#
# Install-time residue rather than a lock. The measured instance is
# `ubi:rust-cross/cargo-zigbuild`'s `linux-x64-cargo-zigbuild`, which carried a
# checksum and no url and which `lock-check` reported "complete and current" over
# on every run.
violation contains {
	"rule": "lock-platform-residue",
	"verdict": "V-LOCK-PLATFORM-RESIDUE",
	"subjects": [
		pointer("mise.lock", [sprintf("\"platforms.%s\"", [platform]), name]),
		{"artifact": name},
	],
} if {
	some name, names in locked_platforms
	some platform in names
	not platform in known_platforms
}

# --- predicate 2: a required platform that cannot be installed from -----------
#
# SCOPED TO REQUIRED PLATFORMS, and the scoping is the near-miss this gate was
# nearly built without. mise emits a provenance-only stub where upstream ships no
# artifact — zizmor's two musl entries are exactly that, and `mise lock`
# regenerates them — so failing on every url-less block would fail this repo for a
# decision upstream made. That is the defect of the gate being replaced, one level
# down.
violation contains {
	"rule": "lock-platform-uninstallable",
	"verdict": "V-LOCK-PLATFORM-UNINSTALLABLE",
	"subjects": [
		pointer("mise.lock", [sprintf("\"platforms.%s\"", [platform]), name]),
		{"artifact": name},
	],
} if {
	some name, names in locked_platforms
	some platform in names
	platform in required_platforms
	not has_url(name, platform)
}

# AND THE ONE THAT IS NOT THERE AT ALL. Guarded on the tool having locked at least
# one real platform: a tool that locks nothing is predicate 3's finding, and
# reporting it three times here as well would bury the one line a reader acts on.
violation contains {
	"rule": "lock-platform-uninstallable",
	"verdict": "V-LOCK-PLATFORM-UNINSTALLABLE",
	"subjects": [
		pointer("mise.lock", [sprintf("[[tools.%s]]", [name])]),
		{"artifact": name},
	],
} if {
	some name, names in real_platforms
	count(names) > 0
	some platform in required_platforms
	not platform in names
}

# AND A CHECKSUM WITH NOTHING TO FETCH, ON ANY PLATFORM. `policy/lock-entry-
# complete.rego` was a second row over this one question — CLOUD-1203's
# demonstration that a tree-scoped module can decide over the index — and it is
# SUBSUMED here rather than left beside this module, because two authorities over
# one object is what this repository refuses everywhere else. Its verdict token is
# raised here, so the registry row is conserved.
#
# THE PAIR IS THE POINT and it is why this is not the predicate above with the
# `required` conjunct dropped: an entry with NEITHER a checksum nor a url is
# simply unlocked, and one with both is complete. A checksum without a url is the
# partial shape that reads as locked and cannot be used, and it is partial
# wherever it appears — including on a platform this repository does not install
# on, where predicate 2 deliberately says nothing.
violation contains {
	"rule": "lock-platform-uninstallable",
	"verdict": "V-LOCK-ENTRY-PARTIAL",
	"subjects": [
		pointer("mise.lock", [sprintf("\"platforms.%s\"", [platform]), name]),
		{"artifact": name},
	],
} if {
	some name, entry in lock_tools
	some key, block in entry
	startswith(key, "platforms.")
	platform := trim_prefix(key, "platforms.")
	block.checksum
	not block.url
}

# --- predicate 3: a tool that locks no platform -------------------------------
#
# WHETHER THAT IS FINE DEPENDS ON THE BACKEND, NOT ON THE ABSENCE, and keying it
# on the absence is how the one tool here installed from an unverified download
# passed for its whole life with a bare version and no checksum (CLOUD-281). The
# exempt backends CANNOT lock a url; a fetch-an-asset backend can, so for one of
# those "locks nothing" means unlocked rather than exempt.
violation contains {
	"rule": "lock-tool-unlocked",
	"verdict": "V-LOCK-TOOL-UNLOCKED",
	"subjects": [
		pointer("mise.lock", [sprintf("[[tools.%s]]", [name])]),
		{"artifact": name},
	],
} if {
	some name, names in locked_platforms
	count(names) == 0
	backend := lock_tools[name].backend
	not locks_nothing(backend)
}

# A TOOL DECLARING NO BACKEND AT ALL, which is a different sentence and a
# different remedy: what it installs cannot be determined rather than can be and
# is unverified.
violation contains {
	"rule": "lock-tool-unlocked",
	"verdict": "V-LOCK-TOOL-UNDECLARED",
	"subjects": [
		pointer("mise.lock", [sprintf("[[tools.%s]]", [name])]),
		{"artifact": name},
	],
} if {
	some name, names in locked_platforms
	count(names) == 0
	not is_string(lock_tools[name].backend)
}

# --- predicate 4: a `[tools]` key with no lockfile entry at all ---------------
#
# CLOUD-333. Every predicate above judges an entry that is PRESENT, so the gate
# was blind to the omission — and the omission is the one failure a local run
# structurally cannot see. `[settings] lockfile = false` means nothing here ever
# installs `--locked`, so an unlocked tool installs fine on this machine forever;
# CI passes `--locked` and dies at the INSTALL step, before a single gate runs, in
# every job whose install list names the tool. Measured on PR #272, where `msrv`
# and `commit-lint` went red for a `cargo-msrv` pin neither of them owns, past a
# fully green `mise run verify`.
declared_tools[name] := value if {
	some name, value in manifest.tools
}

# There is no lockfile entry to read a `backend` from — that absence is the whole
# finding — so the backend comes from the KEY, which is how mise spells it: a
# `<backend>:` prefix is the backend itself, and a bare name is a registry name
# whose core form is `core:<name>`.
key_backend(name) := name if contains(name, ":")

key_backend(name) := sprintf("core:%s", [name]) if not contains(name, ":")

violation contains {
	"rule": "lock-tool-missing",
	"verdict": "V-LOCK-TOOL-MISSING",
	"subjects": [pointer("mise.toml", [name]), {"artifact": name}],
} if {
	lock_readable
	some name, _ in declared_tools
	not locks_nothing(key_backend(name))
	not lock_tools[name]
}

# --- predicate 5: a pin its lock entry does not name --------------------------
#
# CLOUD-593. Predicate 4 asks whether a row is THERE; this asks whether it says
# the same thing as the pin, which is the only question `mise install --locked`
# actually answers. The row being present is exactly what makes a stale one
# invisible. Measured: `[tools] rust` moved to 1.97.1, `mise.lock` still said
# 1.85.0, `mise run verify` was fully green, and all nine required checks went red
# at the install step in EVERY job, because `--locked` validates the whole file.
pinned_version(value) := value if is_string(value)

pinned_version(value) := version if {
	is_object(value)
	version := value.version
	is_string(version)
}

# SATISFACTION, NOT EQUALITY, and the difference is what most pins here are:
# `node = "24"` locks 24.19.0 and `"aqua:cli/cli" = "2.97"` locks 2.97.0, so a raw
# comparison would refuse this repo's own tree on the majority of its table.
#
# THE EXTENSION IS AT A COMPONENT BOUNDARY. `1.9` must not be satisfied by
# `1.97.1`: a plain prefix test is the plausible wrong spelling and it silently
# accepts exactly the pin the installer would reject, which is the whole failure
# this clause was added for.
satisfies(locked, pin) if locked == pin

satisfies(locked, pin) if startswith(locked, sprintf("%s.", [pin]))

# A pin that is not a plain dotted version — a range, a channel name — is skipped
# rather than guessed at. Refusing a spelling the gate does not understand is the
# larger of the two errors, and there is no such pin in this table today.
plain_version(pin) if regex.match(data.batten.patterns["plain-dotted-version"], pin)

violation contains {
	"rule": "lock-pin-stale",
	"verdict": "V-LOCK-PIN-STALE",
	"subjects": [pointer("mise.toml", [name]), {"artifact": name}],
} if {
	some name, value in declared_tools
	pin := pinned_version(value)
	plain_version(pin)
	locked := lock_tools[name].version
	is_string(locked)
	not satisfies(locked, pin)
}

# --- predicate 6: the setting that permits the write --------------------------
#
# CLOUD-223, and it is the other half of predicate 1 rather than a separate
# concern: every residue key this module rejects was written by an install, so the
# gate is half a mechanism while any `mise install` can produce one. The
# per-caller opt-out this repo tried first (`MISE_LOCKFILE=false` in the
# session-start hook) cannot reach a caller it does not own, which is exactly how
# a sandbox's own provisioning kept dirtying the tree afterwards.
writes_enabled if manifest.settings.lockfile == true

writes_enabled if manifest.settings.lockfile == 1

violation contains {
	"rule": "lockfile-writes-enabled",
	"verdict": "V-LOCKFILE-WRITES-ENABLED",
	"subjects": [pointer("mise.toml", ["lockfile"])],
} if {
	writes_enabled
}

# --- predicate 7: a workflow that installs unlocked ---------------------------
#
# The other half of that setting. `lockfile = false` turns off the whole lockfile
# feature rather than only the write, so `mise install --locked` fails outright
# with "locked mode requires lockfile to be enabled". A workflow therefore has to
# set `MISE_LOCKFILE` itself, and one that forgets does not fail loudly:
# mise-action only passes `--locked` when it detects a lockfile, so the job
# installs UNLOCKED and goes green. That is a checksum check silently dropped.
#
# THE LINE SURFACE RATHER THAN `staged`, AND IT IS THE ONE PLACE A VERDICT READS
# THE WORKTREE. `staged` takes literal paths — `git.rs::staged_facts` looks each
# one up in the index by name — so a workflow SET can only reach it as a
# hand-maintained inventory, and a workflow missing from that list is a silent
# hole in exactly the gate that exists to close one. A glob over the line surface
# has no such hole. What it costs is the index/worktree distinction, and the cost
# is measurably smaller here than for the lockfile: CLOUD-227's whole reason for
# reading the index is that `mise install` REWRITES `mise.lock` behind the
# author's back, and nothing writes a workflow file but a person.
workflows[path] := lines if {
	some path, lines in input.tree.lines
	startswith(path, ".github/workflows/")
	endswith(path, ".yml")
}

uses_mise_action(path) if {
	some text in workflows[path]
	contains(text, "mise-action")
}

sets_lockfile(path) if {
	some text in workflows[path]
	contains(text, "MISE_LOCKFILE")
}

violation contains {
	"rule": "workflow-installs-unlocked",
	"verdict": "V-WORKFLOW-INSTALLS-UNLOCKED",
	"subjects": [pointer(path, ["mise-action"])],
} if {
	some path, _ in workflows
	uses_mise_action(path)
	not sets_lockfile(path)
}

# --- could-not-look -----------------------------------------------------------
#
# SCOPED TO A REPOSITORY THAT CLAIMS TO LOCK SOMETHING, which is Finding 7's class
# from `tree-clean` avoided rather than survived. A `[[rule]]` has no call site —
# it runs wherever `batten check` runs — so an unconditional refusal over an
# absent `mise.lock` would speak in every fixture repository that inherits this
# config. A staged `mise.toml` carrying a `[tools]` table is the repository saying
# it locks tools; without one there is no subject and nothing to report.
lock_readable if lock

declares_tools if {
	some _, _ in declared_tools
}

violation contains {
	"rule": "lock-unreadable",
	"verdict": "V-LOCK-UNREADABLE",
	"subjects": [{"path": "mise.lock"}],
} if {
	declares_tools
	not lock_readable
}

# --- the load-time tier -------------------------------------------------------
#
# It pins each predicate. It CANNOT pin that the engine builds the input each one
# reads — `crates/batten/tests/it/lock_complete.rs` over the compiled binary is
# that tier, and it is the one that matters most here: `staged` is a fact whose
# whole point is which side of the index the bytes came from, and a `with input
# as` block fabricates it either way. A `.lock` extension is also one no `Format`
# owns, so the row declares the format to read it as, and only a real run says the
# declaration reaches the parser.

fixture_lock := {"tools": {"t": [{
	"version": "1.0.0",
	"backend": "aqua:x/t",
	"platforms.linux-x64": {"url": "https://e/x"},
	"platforms.linux-arm64": {"url": "https://e/x"},
	"platforms.macos-arm64": {"url": "https://e/x"},
}]}}

fixture_manifest := {"settings": {"lockfile": false}, "tools": {"t": "1.0.0"}}

fixture_input(lockfile, mise) := {"tree": {
	"staged": {"mise.lock": lockfile, "mise.toml": mise},
	"lines": {},
	"missing": [],
}}

test_a_complete_lockfile_is_clean if {
	count(violation) == 0 with input as fixture_input(fixture_lock, fixture_manifest)
		with data.batten.patterns as fixture_patterns
}

test_a_platform_key_mise_does_not_emit_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"t": [object.union(
			fixture_lock.tools.t[0],
			{"platforms.linux-x64-t": {"checksum": "blake3:abc"}},
		)]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-platform-residue"
}

# A LITERAL RATHER THAN `object.union`, and the difference is the reason this case
# was red on its first run: `object.union` merges RECURSIVELY, so overlaying
# `{"platforms.linux-x64": {"provenance": …}}` onto a block that already carries a
# `url` keeps the url and the fixture asserts nothing. It is the right tool for the
# cases that ADD a platform key and the wrong one for the cases that REPLACE a
# block, which is why the two are spelled differently below.
test_a_required_platform_with_no_url_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"t": [{
			"version": "1.0.0",
			"backend": "aqua:x/t",
			"platforms.linux-x64": {"provenance": "github-attestations"},
			"platforms.linux-arm64": {"url": "https://e/x"},
			"platforms.macos-arm64": {"url": "https://e/x"},
		}]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-platform-uninstallable"
}

# THE NEAR-MISS. A url-less stub on a NON-required platform is mise recording that
# upstream ships no artifact there, and `mise lock` regenerates it — so failing on
# it would fail this repo for a decision upstream made.
test_a_url_less_stub_on_a_non_required_platform_is_not if {
	count(violation) == 0 with input as fixture_input(
		{"tools": {"t": [object.union(
			fixture_lock.tools.t[0],
			{"platforms.linux-x64-musl": {"provenance": "github-attestations"}},
		)]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
}

test_a_checksum_with_nothing_to_fetch_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"t": [{
			"version": "1.0.0",
			"backend": "aqua:x/t",
			"platforms.linux-x64": {"url": "https://e/x"},
			"platforms.linux-arm64": {"url": "https://e/x"},
			"platforms.macos-arm64": {"url": "https://e/x"},
			"platforms.linux-x64-musl": {"checksum": "sha256:abc"},
		}]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
	v.verdict == "V-LOCK-ENTRY-PARTIAL"
}

# THE PAIR THE SUBSUMED MODULE TURNED ON: an entry with NEITHER is simply
# unlocked, not partial, so this must stay silent or the arm above degenerates
# into "any platform without a url", which is predicate 2 with its scoping thrown
# away.
test_an_unlocked_entry_is_not_a_partial_one if {
	count({v | some v in violation; v.verdict == "V-LOCK-ENTRY-PARTIAL"}) == 0 with input as fixture_input(
		{"tools": {"t": [{
			"version": "1.0.0",
			"backend": "aqua:x/t",
			"platforms.linux-x64": {"url": "https://e/x"},
			"platforms.linux-arm64": {"url": "https://e/x"},
			"platforms.macos-arm64": {"url": "https://e/x"},
			"platforms.linux-x64-musl": {"provenance": "github-attestations"},
		}]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
}

test_a_required_platform_missing_entirely_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"t": [{
			"version": "1.0.0",
			"backend": "aqua:x/t",
			"platforms.linux-x64": {"url": "https://e/x"},
			"platforms.linux-arm64": {"url": "https://e/x"},
		}]}},
		fixture_manifest,
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-platform-uninstallable"
}

test_a_backend_that_cannot_lock_is_exempt_from_locking_nothing if {
	count(violation) == 0 with input as fixture_input(
		{"tools": {"core:rust": [{"version": "1.85.0", "backend": "core:rust"}]}},
		{"settings": {"lockfile": false}, "tools": {"rust": "1.85.0"}},
	)
		with data.batten.patterns as fixture_patterns
}

# CLOUD-281 VERBATIM: the entry that passed for its whole life. An asset-fetching
# backend that locks no platform is unlocked, not exempt.
test_an_asset_backend_that_locks_nothing_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"ubi:rust-cross/cargo-zigbuild": [{
			"version": "0.23.0",
			"backend": "ubi:rust-cross/cargo-zigbuild",
		}]}},
		{"settings": {"lockfile": false}, "tools": {}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-tool-unlocked"
}

test_a_tool_declaring_no_backend_is_a_finding if {
	some v in violation with input as fixture_input(
		{"tools": {"mystery": [{"version": "1"}]}},
		{"settings": {"lockfile": false}, "tools": {}},
	)
		with data.batten.patterns as fixture_patterns
	v.verdict == "V-LOCK-TOOL-UNDECLARED"
}

test_a_declared_tool_with_no_lock_entry_is_a_finding if {
	some v in violation with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {
			"t": "1.0.0",
			"aqua:foresterre/cargo-msrv": "0.18.0",
		}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-tool-missing"
}

# THE ALLOWLIST IS FAIL-CLOSED, so a bare name other than `rust` must lock:
# `core:<name>` is not on the list, and node/pkl/zig/uv/hk/zizmor all lock today.
test_a_bare_name_other_than_rust_must_lock if {
	some v in violation with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {"t": "1.0.0", "node": "24"}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-tool-missing"
}

test_a_pin_its_entry_does_not_name_is_a_finding if {
	some v in violation with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {"t": "2.0.0"}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-pin-stale"
}

test_a_partial_pin_the_lock_extends_is_not if {
	count({v | some v in violation; v.rule == "lock-pin-stale"}) == 0 with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {"t": "1.0"}},
	)
		with data.batten.patterns as fixture_patterns
}

# THE MUTATION THE PREDECESSOR DECLARED, carried as a case: `1.9` must not be
# satisfied by `1.97.1`. A plain prefix test is what a reader writes by default and
# it accepts exactly the pin `mise install --locked` rejects.
test_the_extension_must_be_at_a_component_boundary if {
	some v in violation with input as fixture_input(
		{"tools": {"t": [{
			"version": "1.97.1",
			"backend": "aqua:x/t",
			"platforms.linux-x64": {"url": "https://e/x"},
			"platforms.linux-arm64": {"url": "https://e/x"},
			"platforms.macos-arm64": {"url": "https://e/x"},
		}]}},
		{"settings": {"lockfile": false}, "tools": {"t": "1.9"}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-pin-stale"
}

# The spelling the measured defect was written in, and the one a bare-string
# reader misses.
test_an_inline_table_pin_is_read if {
	some v in violation with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {"t": {
			"version": "2.0.0",
			"components": "clippy",
		}}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-pin-stale"
}

test_a_pin_that_is_not_a_dotted_version_is_skipped if {
	count({v | some v in violation; v.rule == "lock-pin-stale"}) == 0 with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": false}, "tools": {"t": "latest"}},
	)
		with data.batten.patterns as fixture_patterns
}

test_re_enabled_lockfile_writes_are_a_finding if {
	some v in violation with input as fixture_input(
		fixture_lock,
		{"settings": {"lockfile": true}, "tools": {"t": "1.0.0"}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "lockfile-writes-enabled"
}

# A `lockfile` key outside `[settings]` is not the setting. The predecessor needed
# an `awk` table-tracking reset for this; a parsed node has it by construction, and
# the case stays because the claim is worth pinning rather than because the
# spelling is still at risk.
test_a_lockfile_key_outside_settings_is_not_the_setting if {
	count(violation) == 0 with input as fixture_input(
		fixture_lock,
		{"env": {"lockfile": true}, "settings": {"lockfile": false}, "tools": {"t": "1.0.0"}},
	)
		with data.batten.patterns as fixture_patterns
}

test_a_workflow_installing_without_the_lockfile_env_is_a_finding if {
	some v in violation with input as object.union(
		fixture_input(fixture_lock, fixture_manifest),
		{"tree": {"lines": {".github/workflows/w.yml": ["      - uses: jdx/mise-action@abc"]}}},
	)
		with data.batten.patterns as fixture_patterns
	v.rule == "workflow-installs-unlocked"
}

test_the_same_workflow_setting_it_is_not if {
	count(violation) == 0 with input as object.union(
		fixture_input(fixture_lock, fixture_manifest),
		{"tree": {"lines": {".github/workflows/w.yml": [
			"      MISE_LOCKFILE: \"true\"",
			"      - uses: jdx/mise-action@abc",
		]}}},
	)
		with data.batten.patterns as fixture_patterns
}

test_a_workflow_that_does_not_install_needs_nothing if {
	count(violation) == 0 with input as object.union(
		fixture_input(fixture_lock, fixture_manifest),
		{"tree": {"lines": {".github/workflows/w.yml": ["      - run: echo hi"]}}},
	)
		with data.batten.patterns as fixture_patterns
}

# COULD-NOT-LOOK, and the scope mirror beside it. A repository declaring tools with
# no readable lockfile cannot be judged and says so; one declaring none has no
# subject, which is what keeps this row silent in every fixture repository that
# inherits the config.
test_an_unreadable_lockfile_a_manifest_depends_on_is_a_finding if {
	some v in violation with input as {"tree": {
		"staged": {"mise.toml": fixture_manifest},
		"lines": {},
		"missing": ["mise.lock"],
	}}
		with data.batten.patterns as fixture_patterns
	v.rule == "lock-unreadable"
}

test_an_unreadable_lockfile_no_manifest_depends_on_is_silent if {
	count(violation) == 0 with input as {"tree": {
		"staged": {},
		"lines": {},
		"missing": ["mise.lock"],
	}}
		with data.batten.patterns as fixture_patterns
}

fixture_patterns := {"plain-dotted-version": "^[0-9]+(\\.[0-9]+)*$"}

//! `manifest cover other` over the compiled binary and the REAL producer
//! (CLOUD-580, CLOUD-631, CLOUD-666, CLOUD-1717, CLOUD-843).
//!
//! `batten sbom --conformance` derives the document through stubbed `syft` and
//! `cargo` and asks a stubbed checker whose exit code and report are set
//! INDEPENDENTLY — the negative self-test needs a checker that disagrees with
//! itself, which no honest tool does. The engine then decides over what the
//! producer recorded. A finding is `check`'s exit 2; could-not-look is the
//! producer's exit 3. The producer was `[tasks.ntia-record]`'s inline body until
//! CLOUD-843 retired it onto the verb; the standards and the checker are
//! `[sbom.conformance]`'s now, where they were `NTIA_STANDARDS` and `SBOMCHECK`.
//! `[tasks.ntia-check]` — an argv sequence since CLOUD-1991 — is run too, for the
//! receipt half only it owns.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/ntia-check.sh policy/ntia.rego kind:mechanism crates/batten/tests/it/ntia.rs
// carried: tests/ntia-check.bats policy/ntia.rego kind:mechanism crates/batten/tests/it/ntia.rs
// carried: "a conformant document passes and records the SHA-keyed receipt" policy/ntia.rego kind:mechanism
// changed: "a receipt that cannot be written is reported, never a nonconformance" mise.toml `[tasks.ntia-check]` is an argv sequence since CLOUD-1991, so a refused write fails the task with the write's own `1`; the decision entry before it has already passed, so it is still never read as a nonconformance, and `receipt record` reports an unreadable transcript rather than refusing (CLOUD-819)
// carried: "a nonconformant document fails, and leaves NO receipt" policy/ntia.rego kind:mechanism
// carried: "THE NEGATIVE SELF-TEST: a conformant-looking report with a non-zero exit still fails" policy/ntia.rego kind:mechanism
// changed: "the failure carries counts, which are the message and not the decision" crates/batten/src/sbom.rs the counts are recorded on the standard's line of the `ntia` record, beside the exit code the module decides on; the finding carries the pointer alone, since only the first subject is a pointer
// changed: "a checker that writes no report still reports its exit code" crates/batten/src/sbom.rs the exit code is recorded whether or not a report was written, with `-` for the counts; the case asserts the refusal still lands
// carried: "output is pointer-only — no component name and no purl reach the log" policy/ntia.rego kind:mechanism
// changed: "the failure names the published asset, not a scratch path" policy/ntia.rego the pointer is `<asset>#<standard>`, where the program printed `<asset>:0`; still the asset name and never a scratch path
// carried: "one refusing standard of two fails the whole run" policy/ntia.rego kind:mechanism
// changed: "an absent checker exits 2 — could not look is not a verdict" crates/batten/src/sbom.rs refused at the producer and never recorded, at exit 3: 2 is `check`'s finding code now
// changed: "a checker that cannot answer --version exits 2 in precondition mode" crates/batten/src/sbom.rs the same move, and in every mode: the producer asks `--version` before any run it records
// changed: "a syft that cannot run exits 2 — the document, not the verdict, is missing" crates/batten/src/sbom.rs the same move: an underivable document is the producer's exit 3, nothing recorded
// changed: "THE SEVERITY SPLIT: the precondition passes over a nonconformant document" policy/ntia.rego the two command rows collapse into one policy row and both are `deny`; the split survives as two verdicts, and a nonconformant document raises `manifest cover partial` and never `manifest check unread`
// changed: "the precondition records no receipt — it attests the mechanism, not the SBOM" mise.toml there is no precondition mode left to call; the receipt is written only after `check` passes, which the nonconformant case asserts
// carried: "ntia-check.bats::the gate leaves the tree it judges unmodified" crates/batten/src/sbom.rs kind:verb
// changed: "the DEFAULT standards set is satisfiable: a conformant document exits 0" crates/batten/src/sbom.rs the set is `[sbom.conformance] standards` rather than an `NTIA_STANDARDS` default, and the committed table declares `ntia` alone; the case reads the committed authority's list
// carried: "dropping the unsatisfiable standard does not disarm the gate" policy/ntia.rego kind:mechanism
// changed: "THE DURABLE HALF: an spdx3-only standard over an spdx2 document is a PRECONDITION refusal" policy/ntia.rego `manifest check unread`, a finding through `check`, where the program exited 2; still never `manifest cover partial`
// carried: "the same standard over an spdx3 document is NOT refused" policy/ntia.rego kind:mechanism
// changed: "a document declaring no spdxVersion is could-not-look, never a pass" policy/ntia.rego recorded empty and raised as `manifest check unread`, never a pass
// changed: "an unclassifiable spdxVersion is could-not-look too" policy/ntia.rego the same move, as `<asset>#spdx-version-unknown`
// withdrawn: "the nonconformance summary names the standards that refused and asserts no cause" the summary line is gone: each refusing standard is its own finding, so there is no line left that could assert a cause on another's behalf
// withdrawn: "THE PROMOTION: the committed batten.toml declares deny on sbom-ntia-conformance" the row is one policy row whose severity `config-lint`'s weakening class holds; an awk slice over the authority restated a value the authority owns
// withdrawn: "the precondition row is STILL deny, and the two are not the same question" the two rows collapse into one `deny` row; that they are different questions is two verdicts, asserted by `an_spdx3_only_standard_over_an_spdx2_document_is_unread`
// carried: "a nonconformant document still exits 1 under the promoted row" policy/ntia.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

const RULE: &str = "manifest cover other";

fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    write(dir, name, body);
    let path = dir.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    path
}

/// A `syft` writing a one-package SPDX document with `STUB_SPDXVER` (`NONE`
/// omits the key) wherever `--output spdx-json=` says, and an empty `CycloneDX`.
const SYFT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[[ -z "${STUB_SBOM_FAILS:-}" ]] || exit 1
spdx="" cdx="" want=0
for arg in "$@"; do
	if [[ "$want" == 1 ]]; then
		case "$arg" in spdx-json=*) spdx="${arg#spdx-json=}" ;; cyclonedx-json=*) cdx="${arg#cyclonedx-json=}" ;; esac
		want=0
		continue
	fi
	[[ "$arg" != --output ]] || want=1
done
mkdir -p "$(dirname "$spdx")" "$(dirname "$cdx")"
ver="${STUB_SPDXVER:-SPDX-2.3}"
key="\"spdxVersion\":\"$ver\","
[[ "$ver" != NONE ]] || key=""
echo "{$key\"name\":\"batten\",\"packages\":[{\"SPDXID\":\"p\",\"name\":\"crate0\"}]}" >"$spdx"
echo '{"components":[]}' >"$cdx"
"#;

/// A `cargo` whose metadata lists nothing sourced, so the copyright pass reads no
/// cache.
const CARGO: &str = r#"#!/usr/bin/env bash
[[ "${1:-}" != fetch ]] || exit 0
[[ "${1:-}" == metadata ]] || exit 1
echo '{"packages":[]}'
"#;

/// A checker whose exit code (`STUB_FAIL` lists refusing standards) and report
/// (`STUB_LIES` writes a conformant one regardless) are set independently. It
/// prints a component name on stdout, so a leak has something to catch.
const CHECKER: &str = r#"#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then [[ -z "${STUB_NOVERSION:-}" ]] || exit 1; echo 5.0.3; exit 0; fi
standard=ntia out=""
while [[ $# -gt 0 ]]; do
	case "$1" in --comply) standard=$2; shift ;; --output-file) out=$2; shift ;; esac
	shift
done
fail=0
[[ " ${STUB_FAIL:-} " != *" $standard "* ]] || fail=1
if [[ -n "$out" && -z "${STUB_NOREPORT:-}" ]]; then
	if [[ "$fail" == 0 || -n "${STUB_LIES:-}" ]]; then
		echo '{"totalNumberComponents":3,"componentSuppliers":{"nonconformantComponents":[]}}' >"$out"
	else
		echo '{"totalNumberComponents":3,"componentSuppliers":{"nonconformantComponents":["crate0","crate1"]}}' >"$out"
	fi
fi
echo "crate0: no supplier; pkg:cargo/crate0@1.0.0"
exit "$fail"
"#;

/// The fixture's authority, asking `standards` of `checker`.
fn config(standards: &str, checker: &str) -> String {
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"batten sbom --conformance\"\n\n"
        )
    };
    format!(
        "version = 1\nscope = [\"**\"]\n\n{}{}\
         [[rule]]\nid = \"{RULE}\"\nkind = \"policy\"\nscope = \"tree\"\n\
         module = \"policy/ntia.rego\"\nseverity = \"deny\"\n\n\
         [[record]]\nrecord = \"ntia\"\nwriter = \"batten sbom --conformance\"\n\n\
         [sbom]\nsubject = \"batten\"\nout_dir = \"sbom\"\nbinary_out_dir = \"dist\"\n\n\
         [sbom.conformance]\nrecord = \"ntia\"\nchecker = \"{checker}\"\nstandards = [{standards}]\n",
        verdict("manifest cover partial"),
        verdict("manifest check unread"),
    )
}

fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("ntia-{name}"));
    let module = std::fs::read_to_string(at_root("policy/ntia.rego")).expect("the module");
    write(&dir, "policy/ntia.rego", &module);
    write(&dir, "batten.toml", &config("\"ntia\"", "sbomcheck"));
    write(&dir, "Cargo.toml", "version = \"9.9.9\"\n");
    write(&dir, ".gitignore", "bin/\n.receipts\n");
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    let stubs = dir.join("bin");
    executable(&stubs, "syft", SYFT);
    executable(&stubs, "cargo", CARGO);
    executable(&stubs, "sbomcheck", CHECKER);
    dir
}

/// Declare `standards` and `checker` in the fixture's authority.
fn declare(dir: &Path, standards: &str, checker: &str) {
    write(dir, "batten.toml", &config(standards, checker));
}

/// A `PATH` with the fixture's stubs first.
fn stubbed_path(dir: &Path) -> std::ffi::OsString {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::iter::once(dir.join("bin")).chain(std::env::split_paths(&inherited)))
        .expect("a PATH entry carries no separator")
}

/// The producer, in `dir`, with the stubs first and `knobs` set.
fn produce(dir: &Path, knobs: &[(&str, &str)]) -> Output {
    let mut command = common::batten();
    command
        .args(["sbom", "--conformance"])
        .current_dir(dir)
        .env("PATH", stubbed_path(dir))
        .stdin(Stdio::null());
    for (name, value) in knobs {
        command.env(name, value);
    }
    command.output().expect("run the producer")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce, assert it recorded, then decide: the exit code and what was said.
fn decide(dir: &Path, knobs: &[(&str, &str)]) -> (Option<i32>, String) {
    let produced = produce(dir, knobs);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = common::run(dir, &["check", "--json", "--rule", RULE]);
    (decided.status.code(), said(&decided))
}

fn verdict(name: &str, knobs: &[(&str, &str)]) -> (Option<i32>, String) {
    decide(&repo(name), knobs)
}

#[test]
fn a_conformant_document_passes() {
    let (code, text) = verdict("conformant", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_default_standards_set_is_satisfiable() {
    // The committed authority's list, read rather than restated: it must not ask
    // the SPDX-3-only standard a 2.3 document can never satisfy.
    let committed = std::fs::read_to_string(at_root("batten.toml")).expect("the authority");
    let parsed: toml::Value = toml::from_str(&committed).expect("batten.toml parses");
    let standards: Vec<String> = parsed["sbom"]["conformance"]["standards"]
        .as_array()
        .expect("[sbom.conformance] standards")
        .iter()
        .map(|s| format!("\"{}\"", s.as_str().unwrap()))
        .collect();
    let dir = repo("default");
    declare(&dir, &standards.join(", "), "sbomcheck");
    let (code, text) = decide(&dir, &[("STUB_FAIL", "fsct3-min")]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_nonconformant_document_fails() {
    let (code, text) = verdict("nonconformant", &[("STUB_FAIL", "ntia")]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.spdx.json#ntia"), "{text}");
    assert!(!text.contains("needs-spdx3"), "{text}");
}

#[test]
fn a_conformant_looking_report_with_a_nonzero_exit_still_fails() {
    let (code, text) = verdict("lies", &[("STUB_FAIL", "ntia"), ("STUB_LIES", "1")]);
    assert_eq!(code, Some(2), "{text}");
}

#[test]
fn a_checker_that_writes_no_report_still_refuses() {
    let (code, text) = verdict(
        "no-report",
        &[("STUB_FAIL", "ntia"), ("STUB_NOREPORT", "1")],
    );
    assert_eq!(code, Some(2), "{text}");
}

#[test]
fn the_failure_carries_counts_on_the_record_and_never_in_a_finding() {
    let dir = repo("counts");
    let produced = produce(&dir, &[("STUB_FAIL", "ntia")]);
    assert!(produced.status.success(), "{}", said(&produced));
    let decided = common::run(&dir, &["check", "--json", "--rule", RULE]);
    assert!(
        !said(&decided).contains("no-supplier"),
        "{}",
        said(&decided)
    );
    let text = recorded(&dir.join(".git")).expect("the named record");
    assert_eq!(
        text,
        "document\tbatten.spdx.json\nspdx-version\tSPDX-2.3\n\
         standard\tntia\t1\tcomponents=3 no-supplier=2 no-license=0 no-copyright=0\n"
    );
}

/// The one record under `dir` a conformance run wrote, found by its first line.
fn recorded(dir: &Path) -> Option<String> {
    for entry in std::fs::read_dir(dir).ok()?.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = recorded(&path) {
                return Some(found);
            }
        } else if let Ok(text) = std::fs::read_to_string(&path)
            && text.starts_with("document\t")
        {
            return Some(text);
        }
    }
    None
}

#[test]
fn output_is_pointer_only_and_never_a_scratch_path() {
    let dir = repo("pointer");
    let produced = produce(&dir, &[("STUB_FAIL", "ntia")]);
    let decided = common::run(&dir, &["check", "--rule", RULE]);
    for text in [said(&produced), said(&decided)] {
        assert!(!text.contains("crate0"), "{text}");
        assert!(!text.contains("pkg:cargo/"), "{text}");
        assert!(!text.contains("nonconformantComponents"), "{text}");
        assert!(!text.contains("/tmp/"), "{text}");
    }
}

#[test]
fn one_refusing_standard_of_two_fails_the_whole_run() {
    let dir = repo("two");
    declare(&dir, "\"ntia\", \"fsct3-min\"", "sbomcheck");
    let (code, text) = decide(
        &dir,
        &[("STUB_SPDXVER", "SPDX-3.0.1"), ("STUB_FAIL", "fsct3-min")],
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.spdx.json#fsct3-min"), "{text}");
    assert!(!text.contains("batten.spdx.json#ntia"), "{text}");
}

#[test]
fn an_spdx3_only_standard_over_an_spdx2_document_is_unread() {
    let dir = repo("durable");
    declare(&dir, "\"ntia\", \"fsct3-min\"", "sbomcheck");
    let (code, text) = decide(&dir, &[]);
    assert_eq!(code, Some(2), "{text}");
    // `manifest check unread`, never `manifest cover partial`: the checker passed.
    assert!(
        text.contains("batten.spdx.json#fsct3-min-needs-spdx3"),
        "{text}"
    );
    assert!(!text.contains("\"batten.spdx.json#fsct3-min\""), "{text}");
}

#[test]
fn the_same_standard_over_an_spdx3_document_is_askable() {
    let dir = repo("spdx3");
    declare(&dir, "\"ntia\", \"fsct3-min\"", "sbomcheck");
    let (code, text) = decide(&dir, &[("STUB_SPDXVER", "SPDX-3.0.1")]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_document_declaring_no_spdx_version_is_unread() {
    let (code, text) = verdict("no-version", &[("STUB_SPDXVER", "NONE")]);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten.spdx.json#spdx-version-absent"),
        "{text}"
    );
}

#[test]
fn an_unclassifiable_spdx_version_is_unread() {
    let (code, text) = verdict("unknown-version", &[("STUB_SPDXVER", "SPDX-9.9")]);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten.spdx.json#spdx-version-unknown"),
        "{text}"
    );
}

#[test]
fn every_mechanism_the_producer_cannot_use_is_exit_3_and_records_nothing() {
    for (name, checker, knobs) in [
        ("no-checker", "/nonexistent/sbomcheck", vec![]),
        ("no-version", "sbomcheck", vec![("STUB_NOVERSION", "1")]),
        ("no-sbom", "sbomcheck", vec![("STUB_SBOM_FAILS", "1")]),
    ] {
        let dir = repo(&format!("refuse-{name}"));
        declare(&dir, "\"ntia\"", checker);
        let produced = produce(&dir, &knobs);
        assert_eq!(
            produced.status.code(),
            Some(3),
            "{name}: {}",
            said(&produced)
        );
        assert!(said(&produced).contains("could not look"), "{name}: loud");
        let after = common::run(&dir, &["check", "--rule", RULE]);
        assert_eq!(after.status.code(), Some(0), "{name}: nothing recorded");
    }
}

#[test]
fn the_gate_leaves_the_tree_it_judges_unmodified() {
    let dir = repo("unmodified");
    let before = git_in(&dir, &["status", "--porcelain"]);
    let produced = produce(&dir, &[("STUB_FAIL", "ntia")]);
    assert!(produced.status.success(), "{}", said(&produced));
    assert_eq!(git_in(&dir, &["status", "--porcelain"]), before);
}

#[test]
fn a_record_missing_a_reading_is_torn() {
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "ntia"],
        "document\tbatten.spdx.json\nspdx-version\tSPDX-2.3\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--json", "--rule", RULE]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(said(&decided).contains("ntia#torn"));
}

// --- the sequence: record, decide, then the receipt ---------------------------

/// `[tasks.ntia-check]`'s argv sequence, read out of the committed manifest.
///
/// AN ARRAY SINCE CLOUD-1991, so there is no body to hand `bash`: mise runs the
/// entries in order and stops at the first that fails, with its code. The
/// wrapper below replays exactly that, which is the property these cases assert.
fn check_sequence() -> Vec<String> {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["ntia-check"]["run"]
        .as_array()
        .expect("[tasks.ntia-check] is an argv sequence")
        .iter()
        .map(|entry| entry.as_str().expect("a string entry").to_owned())
        .collect()
}

/// Run the sequence the way mise does, with `cargo run -p batten --` resolving the
/// engine under test and logging every receipt call, which can be made to fail —
/// the state of a store that refuses the write.
///
/// ONE `bin/cargo` ANSWERS BOTH CALLERS. The sequence reaches the engine through
/// `cargo run --quiet -p batten --`, and the producer it runs first (`batten sbom
/// --conformance`) spawns `cargo fetch` and `cargo metadata` from the same `PATH`.
/// So the stub dispatches on its first word: `run` drops the five words and hands
/// the rest to the real binary, and `fetch`/`metadata` answer as `CARGO` does.
fn wrapper(dir: &Path, knobs: &[(&str, &str)]) -> Output {
    let real = env!("CARGO_BIN_EXE_batten");
    executable(
        dir,
        "bin/cargo",
        &format!(
            "#!/usr/bin/env bash\nif [[ \"${{1:-}}\" == run ]]; then shift 5; \
             if [[ \"$1\" == receipt ]]; then echo \"$*\" >>\"{log}\"; \
             [[ -z \"${{STUB_RECEIPT_FAILS:-}}\" ]] || exit 1; exit 0; fi; exec \"{real}\" \"$@\"; fi\n\
             [[ \"${{1:-}}\" != fetch ]] || exit 0\n[[ \"${{1:-}}\" == metadata ]] || exit 1\n\
             echo '{{\"packages\":[]}}'\n",
            log = dir.join(".receipts").display(),
        ),
    );
    let mut last = None;
    for entry in check_sequence() {
        let mut command = common::task_bash(dir, &entry);
        command.stdin(Stdio::null());
        for (name, value) in knobs {
            command.env(name, value);
        }
        let out = command.output().expect("run one entry");
        let failed = !out.status.success();
        last = Some(out);
        if failed {
            break;
        }
    }
    last.expect("the sequence carries at least one entry")
}

#[test]
fn the_sequence_records_then_decides_then_writes_the_receipt() {
    assert_eq!(
        check_sequence(),
        [
            "cargo run --quiet -p batten -- sbom --conformance",
            "cargo run --quiet -p batten -- check --rule 'manifest cover other'",
            "cargo run --quiet -p batten -- receipt record sbom-ntia",
        ],
        "the receipt must follow the decision, so a refusal stops the array before it"
    );
}

#[test]
fn a_conformant_document_records_the_receipt() {
    let dir = repo("wrap-pass");
    let out = wrapper(&dir, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let log = std::fs::read_to_string(dir.join(".receipts")).expect("a receipt call");
    assert_eq!(log.trim(), "receipt record sbom-ntia");
}

#[test]
fn a_receipt_that_cannot_be_written_fails_the_task_and_is_not_a_nonconformance() {
    let dir = repo("wrap-receipt");
    let out = wrapper(&dir, &[("STUB_RECEIPT_FAILS", "1")]);
    // The write's own code, `1`, and never the policy verdict `2`: the document
    // conformed, and the decision entry before it said so.
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let decided = common::run(&dir, &["check", "--rule", RULE]);
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn a_nonconformant_document_leaves_no_receipt() {
    let dir = repo("wrap-fail");
    let out = wrapper(&dir, &[("STUB_FAIL", "ntia")]);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(!dir.join(".receipts").exists());
}

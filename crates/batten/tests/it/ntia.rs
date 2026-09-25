//! `manifest cover other` over the compiled binary and the REAL producer
//! (CLOUD-580, CLOUD-631, CLOUD-666, CLOUD-1717).
//!
//! `[tasks.ntia-record]` and `[tasks.ntia-check]` are read out of `mise.toml` and
//! run against a stubbed SBOM producer (`NTIA_SBOM`) and a stubbed checker
//! (`SBOMCHECK`) whose exit code and report are set INDEPENDENTLY — the negative
//! self-test needs a checker that disagrees with itself, which no honest tool
//! does. The engine then decides over what the producer recorded. A finding is
//! `check`'s exit 2 now, where the program used 1; could-not-look is the
//! producer's exit 3, where the program used 2.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/ntia-check.sh policy/ntia.rego kind:mechanism crates/batten/tests/it/ntia.rs
// carried: tests/ntia-check.bats policy/ntia.rego kind:mechanism crates/batten/tests/it/ntia.rs
// carried: "a conformant document passes and records the SHA-keyed receipt" policy/ntia.rego kind:mechanism
// carried: "a receipt that cannot be written is reported, never a nonconformance" mise.toml kind:mechanism
// carried: "a nonconformant document fails, and leaves NO receipt" policy/ntia.rego kind:mechanism
// carried: "THE NEGATIVE SELF-TEST: a conformant-looking report with a non-zero exit still fails" policy/ntia.rego kind:mechanism
// changed: "the failure carries counts, which are the message and not the decision" mise.toml the counts are recorded on the standard's line of the `ntia` record, beside the exit code the module decides on; the finding carries the pointer alone, since only the first subject is a pointer
// changed: "a checker that writes no report still reports its exit code" mise.toml the exit code is recorded whether or not a report was written, with `-` for the counts; the case asserts the refusal still lands
// carried: "output is pointer-only — no component name and no purl reach the log" policy/ntia.rego kind:mechanism
// changed: "the failure names the published asset, not a scratch path" policy/ntia.rego the pointer is `<asset>#<standard>`, where the program printed `<asset>:0`; still the asset name and never a scratch path
// carried: "one refusing standard of two fails the whole run" policy/ntia.rego kind:mechanism
// changed: "an absent checker exits 2 — could not look is not a verdict" mise.toml refused at the producer and never recorded, at exit 3: 2 is `check`'s finding code now
// changed: "a checker that cannot answer --version exits 2 in precondition mode" mise.toml the same move, and in every mode: the producer asks `--version` before any run it records
// changed: "a syft that cannot run exits 2 — the document, not the verdict, is missing" mise.toml the same move: an underivable document is the producer's exit 3, nothing recorded
// changed: "THE SEVERITY SPLIT: the precondition passes over a nonconformant document" policy/ntia.rego the two command rows collapse into one policy row and both are `deny`; the split survives as two verdicts, and a nonconformant document raises `manifest cover partial` and never `manifest check unread`
// changed: "the precondition records no receipt — it attests the mechanism, not the SBOM" mise.toml there is no precondition mode left to call; the receipt is written only after `check` passes, which the nonconformant case asserts
// carried: "ntia-check.bats::the gate leaves the tree it judges unmodified" mise.toml kind:mechanism
// carried: "the DEFAULT standards set is satisfiable: a conformant document exits 0" mise.toml kind:mechanism
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

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

const RULE: &str = "manifest cover other";

fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    write(dir, name, body);
    let path = dir.join(name);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// A producer writing `batten.spdx.json` with `STUB_SPDXVER` (`NONE` omits the
/// key), and printing `spdx=<path>` as `mise-tasks/sbom.sh` does.
const SBOM: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[[ -z "${STUB_SBOM_FAILS:-}" ]] || exit 1
mkdir -p "$SBOM_OUT_DIR"
ver="${STUB_SPDXVER:-SPDX-2.3}"
key="\"spdxVersion\":\"$ver\","
[[ "$ver" != NONE ]] || key=""
echo "{$key\"name\":\"batten\",\"packages\":[{\"name\":\"crate0\"}]}" >"$SBOM_OUT_DIR/batten.spdx.json"
echo "spdx=$SBOM_OUT_DIR/batten.spdx.json"
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

fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("ntia-{name}"));
    let module = std::fs::read_to_string(at_root("policy/ntia.rego")).expect("the module");
    write(&dir, "policy/ntia.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run ntia-record\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n{}{}\
             [[rule]]\nid = \"{RULE}\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/ntia.rego\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"ntia\"\nwriter = \"mise run ntia-record\"\n",
            verdict("manifest cover partial"),
            verdict("manifest check unread"),
        ),
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    let stubs = dir.join(".stubs");
    executable(&stubs, "sbom", SBOM);
    executable(&stubs, "sbomcheck", CHECKER);
    dir
}

/// Run one of the two task bodies in `dir` with the stubs injected.
fn run_task(dir: &Path, task: &str, knobs: &[(&str, &str)]) -> Output {
    let mut command = common::task_command(dir, task);
    let stubs = dir.join(".stubs");
    command
        .env("NTIA_SBOM", stubs.join("sbom"))
        .env("SBOMCHECK", stubs.join("sbomcheck"))
        .env("NTIA_STANDARDS", "ntia")
        .stdin(Stdio::null());
    for (name, value) in knobs {
        command.env(name, value);
    }
    command.output().expect("run the task")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce, assert it recorded, then decide: the exit code and what was said.
fn verdict(name: &str, knobs: &[(&str, &str)]) -> (Option<i32>, String) {
    let dir = repo(name);
    let produced = run_task(&dir, "ntia-record", knobs);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = common::run(&dir, &["check", "--json", "--rule", RULE]);
    (decided.status.code(), said(&decided))
}

#[test]
fn a_conformant_document_passes() {
    let (code, text) = verdict("conformant", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_default_standards_set_is_satisfiable() {
    let dir = repo("default");
    // Unset is the default, `ntia` alone: a refusing `fsct3-min` is never asked.
    let produced = common::task_command(&dir, "ntia-record")
        .env("NTIA_SBOM", dir.join(".stubs/sbom"))
        .env("SBOMCHECK", dir.join(".stubs/sbomcheck"))
        .env_remove("NTIA_STANDARDS")
        .env("STUB_FAIL", "fsct3-min")
        .stdin(Stdio::null())
        .output()
        .expect("run the producer");
    assert!(produced.status.success(), "{}", said(&produced));
    let decided = common::run(&dir, &["check", "--rule", RULE]);
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
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
fn output_is_pointer_only_and_never_a_scratch_path() {
    let dir = repo("pointer");
    let produced = run_task(&dir, "ntia-record", &[("STUB_FAIL", "ntia")]);
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
    let (code, text) = verdict(
        "two",
        &[
            ("NTIA_STANDARDS", "ntia fsct3-min"),
            ("STUB_SPDXVER", "SPDX-3.0.1"),
            ("STUB_FAIL", "fsct3-min"),
        ],
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.spdx.json#fsct3-min"), "{text}");
    assert!(!text.contains("batten.spdx.json#ntia"), "{text}");
}

#[test]
fn an_spdx3_only_standard_over_an_spdx2_document_is_unread() {
    let (code, text) = verdict("durable", &[("NTIA_STANDARDS", "ntia fsct3-min")]);
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
    let (code, text) = verdict(
        "spdx3",
        &[
            ("NTIA_STANDARDS", "ntia fsct3-min"),
            ("STUB_SPDXVER", "SPDX-3.0.1"),
        ],
    );
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
    for (name, knobs) in [
        ("no-checker", vec![("SBOMCHECK", "/nonexistent/sbomcheck")]),
        ("no-version", vec![("STUB_NOVERSION", "1")]),
        ("no-sbom", vec![("STUB_SBOM_FAILS", "1")]),
        ("no-producer", vec![("NTIA_SBOM", "/nonexistent/sbom")]),
    ] {
        let dir = repo(&format!("refuse-{name}"));
        let produced = run_task(&dir, "ntia-record", &knobs);
        assert_eq!(
            produced.status.code(),
            Some(3),
            "{name}: {}",
            said(&produced)
        );
        assert!(said(&produced).contains("::error::"), "{name}: loud");
        let after = common::run(&dir, &["check", "--rule", RULE]);
        assert_eq!(after.status.code(), Some(0), "{name}: nothing recorded");
    }
}

#[test]
fn the_gate_leaves_the_tree_it_judges_unmodified() {
    let dir = repo("unmodified");
    let before = git_in(&dir, &["status", "--porcelain"]);
    let produced = run_task(&dir, "ntia-record", &[("STUB_FAIL", "ntia")]);
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

// --- the wrapper: record, decide, then the receipt that is never a verdict ----

/// A `batten` that delegates to the real binary, logs every receipt call, and can
/// refuse one — the state of a runner with no readable transcript.
fn wrapper(dir: &Path, knobs: &[(&str, &str)]) -> Output {
    let stubs = dir.join(".stubs");
    let real = env!("CARGO_BIN_EXE_batten");
    executable(
        &stubs,
        "batten",
        &format!(
            "#!/usr/bin/env bash\nif [[ \"$1\" == receipt ]]; then echo \"$*\" >>\"{log}\"; \
             [[ -z \"${{STUB_RECEIPT_FAILS:-}}\" ]] || exit 1; exit 0; fi\nexec \"{real}\" \"$@\"\n",
            log = dir.join(".receipts").display(),
        ),
    );
    // `mise run ntia-record` is the producer the cases above already run.
    executable(&stubs, "mise", "#!/usr/bin/env bash\nexit 0\n");
    let produced = run_task(dir, "ntia-record", knobs);
    assert!(produced.status.success(), "{}", said(&produced));
    let path = format!(
        "{}:{}",
        stubs.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut all: Vec<(&str, &str)> = knobs.to_vec();
    let batten = stubs.join("batten");
    let batten = batten.to_str().unwrap();
    all.push(("BATTEN_BIN", batten));
    all.push(("PATH", &path));
    run_task(dir, "ntia-check", &all)
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
fn a_receipt_that_cannot_be_written_is_reported_never_a_nonconformance() {
    let dir = repo("wrap-receipt");
    let out = wrapper(&dir, &[("STUB_RECEIPT_FAILS", "1")]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        said(&out).contains("not a verdict about the document"),
        "{}",
        said(&out)
    );
}

#[test]
fn a_nonconformant_document_leaves_no_receipt() {
    let dir = repo("wrap-fail");
    let out = wrapper(&dir, &[("STUB_FAIL", "ntia")]);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(!dir.join(".receipts").exists());
}

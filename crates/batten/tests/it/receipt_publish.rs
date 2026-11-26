//! Published receipts (CLOUD-1544): publish from one clone to a state
//! repository, pull into a second, and the second answers `Valid`.
//!
//! # The remote is a real bare repository, behind the transport's one door
//!
//! `land::receipts` speaks smart-HTTP through `lease`, and every exchange goes
//! through `fetch::spend`. The stand-in below answers those exchanges by running
//! `git upload-pack` and `git receive-pack --stateless-rpc` over a local bare
//! repository — what `git http-backend` does — so the ref, the commit and the
//! compare-and-swap are git's own, and no case reaches the network. The verdicts
//! are read off the COMPILED binary's `receipt status`, so the reader under test
//! is the one a gate runs.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common::{Fixture, StateHome as _, batten, git_in, scratch, stdout};
use batten::capture::StreamedChild as _;
use batten::land::receipts;

/// Any URL: the stand-in answers every call, so the host is never resolved.
const REMOTE: &str = "https://state.invalid/owner/state";

/// The fixture's committed config: the receipt check, and an `[attribution]`
/// table so a publish can name its producer (row §5).
const CONFIG: &str = "version = 1\n\n[receipt]\nverified_by = [\"verify\"]\n\n\
                      [attribution]\nidentity_deny = ['@noreply\\.example>$']\n\
                      trailer_deny = ['^Fixture-Vendor:']\nbody_deny = ['fixture advert']\n";

/// The producer every library-level publish names.
const PRODUCER: &str = "Fixture Producer <producer@example.com>";

/// The branch every library-level case keys its ref and its claim on.
const BRANCH: &str = "work";

/// Run git in `dir` with `input` on stdin, returning stdout.
#[expect(
    clippy::disallowed_types,
    reason = "test-only: the stand-in IS git's own server half over a local bare repository, which is what makes the CAS under test git's rather than a mock's"
)]
fn git_with(dir: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start git");
    // Taken and dropped, so git reads EOF: both services read the whole request
    // before they answer, so writing it first cannot deadlock.
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.streamed_wait().unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// One pkt-line.
fn pkt(line: &str) -> Vec<u8> {
    format!("{:04x}{line}", line.len() + 4).into_bytes()
}

/// Answer one smart-HTTP call from the bare repository at `bare`.
fn serve(bare: &Path, call: &batten::fetch::Call<'_>) -> batten::fetch::Response {
    batten::fetch::Response {
        status: 200,
        body: answer(bare, call.url, call.body.unwrap_or_default()),
        headers: Vec::new(),
    }
}

/// The body a smart-HTTP exchange at `url` with request `input` answers, from
/// the bare repository at `bare` — what `git http-backend` does.
fn answer(bare: &Path, url: &str, input: &[u8]) -> Vec<u8> {
    if let Some((_, service)) = url.split_once("/info/refs?service=") {
        let verb = service.trim_start_matches("git-");
        let mut body = pkt(&format!("# service={service}\n"));
        body.extend_from_slice(b"0000");
        body.extend(git_with(
            bare,
            &[verb, "--stateless-rpc", "--advertise-refs", "."],
            b"",
        ));
        body
    } else {
        let service = url.rsplit('/').next().unwrap();
        let verb = service.trim_start_matches("git-");
        git_with(bare, &[verb, "--stateless-rpc", "."], input)
    }
}

/// Stand the bare repository at `bare` up as this thread's remote, calling
/// `before` with each call first.
fn stand_up(bare: PathBuf, before: impl Fn(&batten::fetch::Call<'_>) + 'static) {
    batten::fetch::stand_in(Box::new(move |calls| {
        Ok(calls
            .iter()
            .map(|call| {
                before(call);
                serve(&bare, call)
            })
            .collect())
    }));
}

/// An empty bare repository standing in for the state repository.
fn state_repo(case: &str) -> PathBuf {
    let bare = scratch(&format!("{case}-state-git")).join("state.git");
    std::fs::create_dir_all(&bare).unwrap();
    git_in(&bare, &["init", "--bare", "-q"]);
    bare
}

/// The first clone: a committed config, one commit, `origin/main` at it.
fn first_clone(case: &str) -> PathBuf {
    let dir = Fixture::at(scratch(&format!("{case}-one")).join("one"))
        .config(CONFIG)
        .file("src.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// A second clone of `first` at the same HEAD, with its own `origin/main`.
fn second_clone(case: &str, first: &Path) -> PathBuf {
    let dir = scratch(&format!("{case}-two")).join("two");
    git_in(
        first,
        &[
            "clone",
            "-q",
            first.to_str().unwrap(),
            dir.to_str().unwrap(),
        ],
    );
    dir
}

/// This clone's canonical receipt store under `state`.
fn receipts_dir(state: &Path, repo: &Path) -> PathBuf {
    batten::state::repo_state_dir_under(state, repo)
        .unwrap()
        .join("receipts")
}

/// This clone's carried stores under `state`.
fn stores(state: &Path, repo: &Path) -> receipts::Stores {
    receipts::Stores::at(
        &batten::state::repo_state_dir_under(state, repo).unwrap(),
        &repo.join(".git"),
    )
}

fn record(repo: &Path, state: &Path, check: &str) {
    let output = batten()
        .args(["receipt", "record", check])
        .current_dir(repo)
        .state_dir(state)
        .streamed_output()
        .expect("run batten receipt record");
    assert!(output.status.success(), "record {check}: {output:?}");
}

/// `receipt status <check>`'s exit and line, from the compiled binary.
fn status(repo: &Path, state: &Path, check: &str) -> (Option<i32>, String) {
    let output = batten()
        .args(["receipt", "status", check])
        .current_dir(repo)
        .state_dir(state)
        .streamed_output()
        .expect("run batten receipt status");
    (output.status.code(), stdout(&output))
}

/// Publish `repo`'s local set to `name`.
fn publish(repo: &Path, state: &Path, name: &str, seconds: i64) -> receipts::Moved {
    let local = receipts::local_set(&stores(state, repo), BRANCH);
    let local = receipts::produced_by(&local, PRODUCER).expect("a producer");
    receipts::publish(REMOTE, &repo.join(".git"), name, BRANCH, &local, seconds).expect("publish")
}

/// Pull `name` into `repo`.
fn pull(repo: &Path, state: &Path, name: &str) -> receipts::Moved {
    let head = git_in(repo, &["rev-parse", "HEAD"]).trim().to_owned();
    receipts::pull(
        REMOTE,
        &repo.join(".git"),
        name,
        BRANCH,
        &stores(state, repo),
        &head,
    )
    .expect("pull")
}

/// Fails by: the published class keeping the git-dir conjunct
/// (`published-receipt-gitdir-required`), so a receipt pulled into a second
/// clone still reads `missing`.
#[test]
fn a_published_receipt_pulled_into_a_second_clone_is_valid() {
    let case = "receipt-publish-second-clone";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let two = second_clone(case, &one);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    let name = receipts::reference("work").unwrap();

    record(&one, &state_one, "verify");
    assert_eq!(status(&one, &state_one, "verify").0, Some(0));
    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(2), "nothing pulled yet: {line}");
    assert!(line.ends_with(" missing\n"), "{line}");

    let published = publish(&one, &state_one, &name, 1_700_000_000);
    assert!(
        published.count >= 2,
        "the statement and its compat file: {published:?}"
    );
    let pulled = pull(&two, &state_two, &name);
    assert_eq!(pulled.commit, published.commit);
    assert!(pulled.count >= 1, "{pulled:?}");

    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(0), "the pulled receipt answers: {line}");
    assert!(line.ends_with(" valid\n"), "{line}");
    // The verb that reads the compatibility layout agrees, from the same pull.
    let verified = batten()
        .args(["receipt", "verified"])
        .current_dir(&two)
        .state_dir(&state_two)
        .streamed_output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");
}

/// Fails by: a publish setting the observed head as the new commit's parent
/// (`publish-chains-parent`), so the ref grows a history.
#[test]
fn every_publish_mints_a_parentless_commit() {
    let case = "receipt-publish-parentless";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    let name = receipts::reference("work").unwrap();

    record(&one, &state, "verify");
    let first = publish(&one, &state, &name, 1_700_000_000);
    record(&one, &state, "linear-check");
    let second = publish(&one, &state, &name, 1_700_000_100);
    assert_ne!(first.commit, second.commit, "a new receipt moves the ref");

    for commit in [&first.commit, &second.commit] {
        let parents = git_in(&bare, &["rev-list", "--parents", "-n", "1", commit]);
        assert_eq!(
            parents.split_whitespace().count(),
            1,
            "{commit} has a parent: {parents}"
        );
    }
    assert_eq!(
        git_in(&bare, &["rev-parse", &name]).trim(),
        second.commit,
        "the ref reads the last publish"
    );
    let listed = git_in(&bare, &["ls-tree", "-r", "--name-only", &name]);
    let statements = listed
        .lines()
        .filter(|path| path.starts_with("statement/"))
        .count();
    assert_eq!(statements, 2, "the union kept both checks: {listed}");
}

/// The anti-vacuity control: a published receipt minted under another
/// governing surface answers `missing`, so the published arm is not "any
/// pulled file is valid".
#[test]
fn a_published_receipt_under_another_epoch_is_missing() {
    let case = "receipt-publish-other-epoch";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let two = second_clone(case, &one);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    let name = receipts::reference("work").unwrap();

    record(&one, &state_one, "verify");
    // The epoch a different governing surface would have bound.
    for entry in std::fs::read_dir(receipts_dir(&state_one, &one)).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let mut statement: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            statement["predicate"]["configEpoch"] = "0".repeat(64).into();
            std::fs::write(&path, serde_json::to_vec_pretty(&statement).unwrap()).unwrap();
        }
    }
    publish(&one, &state_one, &name, 1_700_000_000);
    pull(&two, &state_two, &name);

    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(2), "{line}");
    assert!(line.ends_with(" missing\n"), "{line}");
}

/// A rival publish landing between this publish's fetch and its swap: the swap
/// loses, the publish re-fetches, and the final tree is the union.
#[test]
fn a_lost_swap_retries_and_keeps_the_rivals_receipts() {
    let case = "receipt-publish-cas-loss";
    let bare = state_repo(case);
    let name = receipts::reference("work").unwrap();
    let rival = std::cell::Cell::new(false);
    let (bare_for_rival, name_for_rival) = (bare.clone(), name.clone());
    stand_up(bare.clone(), move |call| {
        if call.url.ends_with("/git-receive-pack") && !rival.replace(true) {
            // Another session's set, swapped in by git itself: a step receipt
            // and the producer entry every published blob carries (row §5).
            let hash = |bytes: &[u8]| {
                String::from_utf8(git_with(
                    &bare_for_rival,
                    &["hash-object", "-w", "--stdin"],
                    bytes,
                ))
                .unwrap()
                .trim()
                .to_owned()
            };
            let mktree = |entries: String| {
                String::from_utf8(git_with(&bare_for_rival, &["mktree"], entries.as_bytes()))
                    .unwrap()
                    .trim()
                    .to_owned()
            };
            let blob = hash(b"base x\n");
            let producer = hash(b"Rival Producer <rival@example.com>\n");
            let kind = mktree(format!("100644 blob {blob}\tstep.rival.x\n"));
            let producers = mktree(format!("100644 blob {producer}\tcompat.step.rival.x\n"));
            let root = mktree(format!(
                "040000 tree {kind}\tcompat\n040000 tree {producers}\tproducer\n"
            ));
            let commit = git_with(
                &bare_for_rival,
                &[
                    "-c",
                    "user.name=rival",
                    "-c",
                    "user.email=rival@localhost",
                    "commit-tree",
                    &root,
                    "-m",
                    "rival",
                ],
                b"",
            );
            let commit = String::from_utf8(commit).unwrap();
            git_in(
                &bare_for_rival,
                &["update-ref", &name_for_rival, commit.trim()],
            );
        }
    });
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    record(&one, &state, "verify");

    let published = publish(&one, &state, &name, 1_700_000_000);
    assert_eq!(
        git_in(&bare, &["rev-parse", &name]).trim(),
        published.commit
    );
    let listed = git_in(&bare, &["ls-tree", "-r", "--name-only", &name]);
    assert!(
        listed.contains("compat/step.rival.x") && listed.contains("producer/compat.step.rival.x"),
        "the rival's receipt: {listed}"
    );
    assert!(
        listed.lines().any(|path| path.starts_with("statement/")),
        "this clone's receipt: {listed}"
    );
}

/// Fails by: an unset variable deriving, calling or writing anything.
#[test]
fn unset_is_off_and_writes_nothing() {
    let case = "receipt-publish-unset";
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    for verb in ["publish", "pull"] {
        let output = batten()
            .args(["receipt", verb])
            .current_dir(&one)
            .state_dir(&state)
            .streamed_output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{verb}: {output:?}");
        assert_eq!(stdout(&output), "off\n", "{verb}");
    }
    assert!(!state.exists(), "off must leave no trace");
}

/// Fails by: a project with no `http(s)` origin being taken as a remote.
#[test]
fn a_local_path_origin_is_refused_never_a_verdict() {
    let case = "receipt-publish-local-origin";
    let one = first_clone(case);
    git_in(&one, &["remote", "add", "origin", "/srv/git/widgets.git"]);
    let output = batten()
        .args(["receipt", "publish"])
        .current_dir(&one)
        .env(batten::session::STATE_REPO_ENV, "owner/state")
        .state_dir(&scratch(&format!("{case}-state")).join("state"))
        .streamed_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "no-http-origin\n");
}

// ---------------------------------------------------------------------------
// The compiled verbs against a real remote (CLOUD-1544 §7, review finding 3).
//
// The cases above drive the library in-process, because `fetch::stand_in` is a
// thread-local seam the compiled binary cannot see. These drive `batten receipt
// publish` and `pull` themselves: a loopback HTTPS host whose certificate only a
// fixture CA signs (named to the binary by `SSL_CERT_FILE`) answers smart-HTTP
// by running git's own `upload-pack` and `receive-pack --stateless-rpc` over
// local bare repositories. So the environment read, the branch-derived ref, the
// producer read off `[attribution]` and the publish/pull dispatch are all the
// binary's, and swapping the two dispatch arms turns the first case red.
// ---------------------------------------------------------------------------

/// The repository path origin names on the loopback host.
const ORIGIN_PATH: &str = "owner/repo";
/// The repository path `BATTEN_STATE_REPO` names on the loopback host.
const STATE_PATH: &str = "owner/state";

/// A loopback smart-HTTP host: its base URL, the CA bundle that trusts it, and
/// every request path it answered.
struct Host {
    base: String,
    ca: PathBuf,
    log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Host {
    /// Every request path this host has answered so far.
    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// Read one HTTP/1.1 request off `stream`: its target and its body, by
/// `Content-Length` or chunked transfer.
fn read_request(stream: &mut impl std::io::BufRead) -> Option<(String, Vec<u8>)> {
    let mut line = String::new();
    stream.read_line(&mut line).ok()?;
    let target = line.split_whitespace().nth(1)?.to_owned();
    let (mut length, mut chunked) = (0usize, false);
    loop {
        let mut header = String::new();
        if stream.read_line(&mut header).ok()? == 0 || header.trim().is_empty() {
            break;
        }
        let (key, value) = header.split_once(':')?;
        let value = value.trim();
        if key.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok()?;
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            stream.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
            let mut chunk = vec![0; size + 2];
            stream.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        body.resize(length, 0);
        stream.read_exact(&mut body).ok()?;
    }
    Some((target, body))
}

/// Serve `repos` (URL path to bare repository) over loopback HTTPS.
fn https_host(case: &str, repos: Vec<(&'static str, PathBuf)>) -> Host {
    use rustls_pki_types::pem::PemObject as _;
    use std::io::Write as _;

    let tls = scratch(&format!("{case}-tls")).join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    crate::common::mint_ca_and_server_certificate(&tls);
    let chain: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_file_iter(tls.join("cert.pem"))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls.join("key.pem")).unwrap();
    let config = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls_graviola::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = std::sync::Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(connection) = rustls::ServerConnection::new(std::sync::Arc::clone(&config))
            else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(connection, stream);
            let Some((target, body)) = read_request(&mut std::io::BufReader::new(&mut tls)) else {
                continue;
            };
            seen.lock().unwrap().push(target.clone());
            let path = target.trim_start_matches('/');
            let answer = repos
                .iter()
                .find(|(prefix, _)| path.starts_with(&format!("{prefix}/")))
                .map(|(prefix, bare)| answer(bare, &path[prefix.len()..], &body));
            let head = match &answer {
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
            };
            let _ = tls.write_all(head.as_bytes());
            if let Some(body) = answer {
                let _ = tls.write_all(&body);
            }
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    Host {
        base,
        ca: tls.join("ca.pem"),
        log,
    }
}

/// A clone on branch `work` whose origin is `host`'s `owner/repo`.
fn wired_clone(case: &str, host: &Host) -> PathBuf {
    let dir = first_clone(case);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(
        &dir,
        &[
            "remote",
            "add",
            "origin",
            &format!("{}/{ORIGIN_PATH}", host.base),
        ],
    );
    dir
}

/// A second clone of `first`, rewired to `host`'s origin.
fn wired_second(case: &str, first: &Path, host: &Host) -> PathBuf {
    let dir = second_clone(case, first);
    git_in(
        &dir,
        &[
            "remote",
            "set-url",
            "origin",
            &format!("{}/{ORIGIN_PATH}", host.base),
        ],
    );
    dir
}

/// `batten receipt <verb>` in `repo`, the compiled binary, against `host` with
/// `BATTEN_STATE_REPO` set to `state_repo`.
fn verb(
    repo: &Path,
    state: &Path,
    host: &Host,
    state_repo: &str,
    verb: &str,
) -> std::process::Output {
    let mut command = batten();
    command
        .args(["receipt", verb])
        .current_dir(repo)
        .env(batten::session::STATE_REPO_ENV, state_repo)
        .env("SSL_CERT_FILE", &host.ca)
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .env("GIT_AUTHOR_NAME", "Fixture Producer")
        .env("GIT_AUTHOR_EMAIL", "producer@example.com")
        .env("GIT_COMMITTER_NAME", "Fixture Producer")
        .env("GIT_COMMITTER_EMAIL", "producer@example.com");
    command
        .state_dir(state)
        .streamed_output()
        .expect("run batten receipt")
}

/// Fails by: the dispatch arms swapped (`Publish => …(false…)`), the branch
/// ref derived from anything but HEAD's branch, or the producer missing from
/// the published tree. The compiled `publish` puts the ref in the STATE
/// repository and nowhere else; the compiled `pull` makes the second clone's
/// `receipt status` answer `valid`.
#[test]
fn the_compiled_verbs_publish_and_pull_through_a_real_remote() {
    let case = "receipt-publish-binary";
    let (origin, state_git) = (state_repo(&format!("{case}-origin")), state_repo(case));
    let host = https_host(
        case,
        vec![
            (ORIGIN_PATH, origin.clone()),
            (STATE_PATH, state_git.clone()),
        ],
    );
    let one = wired_clone(case, &host);
    let two = wired_second(case, &one, &host);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    record(&one, &state_one, "verify");
    assert_eq!(
        status(&two, &state_two, "verify").0,
        Some(2),
        "nothing pulled yet"
    );

    let published = verb(&one, &state_one, &host, STATE_PATH, "publish");
    assert_eq!(published.status.code(), Some(0), "{published:?}");
    let name = receipts::reference("work").unwrap();
    let line = stdout(&published);
    let head = git_in(&state_git, &["rev-parse", &name]).trim().to_owned();
    let mutate = receipts::mutate_reference("work").unwrap();
    assert_eq!(
        line,
        format!("{name} {head} 2\n{mutate} {} 0\n", "0".repeat(40)),
        "statement + compat, and no mutate state to carry"
    );
    let listed = git_in(&state_git, &["ls-tree", "-r", "--name-only", &name]);
    let receipts_listed: Vec<&str> = listed
        .lines()
        .filter(|path| !path.starts_with("producer/"))
        .collect();
    assert_eq!(receipts_listed.len(), 2, "{listed}");
    for path in receipts_listed {
        let (kind, file) = path.split_once('/').unwrap();
        let producer = git_in(
            &state_git,
            &["show", &format!("{name}:producer/{kind}.{file}")],
        );
        assert_eq!(
            producer.trim_end(),
            "Fixture Producer <producer@example.com>",
            "{path}"
        );
    }
    assert!(
        git_in(&origin, &["for-each-ref"]).trim().is_empty(),
        "origin received nothing"
    );

    let pulled = verb(&two, &state_two, &host, STATE_PATH, "pull");
    assert_eq!(pulled.status.code(), Some(0), "{pulled:?}");
    assert!(
        stdout(&pulled).starts_with(&format!("{name} {head} ")),
        "{pulled:?}"
    );
    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(0), "the pulled receipt answers: {line}");
    assert!(line.ends_with(" valid\n"), "{line}");
}

/// Fails by: a state repository naming origin's own repository in any
/// spelling reaching the transport (review finding 1). Every spelling exits
/// `1` with `state-repo-is-origin`, the host sees no request, and origin holds
/// no ref.
#[test]
fn the_compiled_publish_refuses_a_state_repo_that_is_origin() {
    let case = "receipt-publish-binary-is-origin";
    let origin = state_repo(&format!("{case}-origin"));
    let host = https_host(case, vec![(ORIGIN_PATH, origin.clone())]);
    let one = wired_clone(case, &host);
    let state = scratch(&format!("{case}-state")).join("state");
    record(&one, &state, "verify");
    let port_host = host.base.trim_start_matches("https://").to_owned();
    for spelling in [
        ORIGIN_PATH.to_owned(),
        "Owner/Repo".to_owned(),
        format!("{ORIGIN_PATH}.git"),
        format!("/{ORIGIN_PATH}/"),
        format!("{}/{ORIGIN_PATH}", host.base),
        format!("{}/Owner/Repo.git", host.base),
        format!("{port_host}/{ORIGIN_PATH}"),
    ] {
        for which in ["publish", "pull"] {
            let output = verb(&one, &state, &host, &spelling, which);
            assert_eq!(
                output.status.code(),
                Some(1),
                "{spelling} {which}: {output:?}"
            );
            assert_eq!(
                stdout(&output),
                "state-repo-is-origin\n",
                "{spelling} {which}"
            );
        }
    }
    assert!(host.requests().is_empty(), "{:?}", host.requests());
    assert!(git_in(&origin, &["for-each-ref"]).trim().is_empty());
}

/// Fails by: another branch's claim travelling on this branch's ref (review
/// finding 2). A claim `claim --adopt-from` deleted is never written back by a
/// pull — not even one an older engine already published, with its producer —
/// and the next publish prunes it from the ref.
#[test]
fn a_deleted_claim_stays_deleted() {
    let case = "receipt-publish-binary-claims";
    let (origin, state_git) = (state_repo(&format!("{case}-origin")), state_repo(case));
    let host = https_host(
        case,
        vec![(ORIGIN_PATH, origin), (STATE_PATH, state_git.clone())],
    );
    let one = wired_clone(case, &host);
    let two = wired_second(case, &one, &host);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    let name = receipts::reference("work").unwrap();

    // What an older engine published: another branch's claim, with a producer.
    let blob = |bytes: &[u8]| {
        String::from_utf8(git_with(
            &state_git,
            &["hash-object", "-w", "--stdin"],
            bytes,
        ))
        .unwrap()
        .trim()
        .to_owned()
    };
    let mktree = |entries: String| {
        String::from_utf8(git_with(&state_git, &["mktree"], entries.as_bytes()))
            .unwrap()
            .trim()
            .to_owned()
    };
    let claim = blob(b"branch other\n");
    let producer = blob(b"Fixture Producer <producer@example.com>\n");
    let compat = mktree(format!("100644 blob {claim}\tclaim.other\n"));
    let producers = mktree(format!("100644 blob {producer}\tcompat.claim.other\n"));
    let root = mktree(format!(
        "040000 tree {compat}\tcompat\n040000 tree {producers}\tproducer\n"
    ));
    let commit = String::from_utf8(git_with(
        &state_git,
        &[
            "-c",
            "user.name=old",
            "-c",
            "user.email=old@localhost",
            "commit-tree",
            &root,
            "-m",
            "older engine",
        ],
        b"",
    ))
    .unwrap();
    git_in(&state_git, &["update-ref", &name, commit.trim()]);

    let compat_two = two.join(".git").join("batten-receipts");
    let pulled = verb(&two, &state_two, &host, STATE_PATH, "pull");
    assert_eq!(pulled.status.code(), Some(0), "{pulled:?}");
    assert!(
        !compat_two.join("claim.other").exists(),
        "another branch's claim was written back"
    );

    // This clone holds its own claim and another branch's; only its own travels,
    // and the older engine's entry is pruned.
    let compat_one = one.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&compat_one).unwrap();
    std::fs::write(compat_one.join("claim.work"), "branch work\n").unwrap();
    std::fs::write(compat_one.join("claim.other"), "branch other\n").unwrap();
    let published = verb(&one, &state_one, &host, STATE_PATH, "publish");
    assert_eq!(published.status.code(), Some(0), "{published:?}");
    let listed = git_in(&state_git, &["ls-tree", "-r", "--name-only", &name]);
    assert!(listed.contains("compat/claim.work"), "{listed}");
    assert!(!listed.contains("claim.other"), "{listed}");

    let pulled = verb(&two, &state_two, &host, STATE_PATH, "pull");
    assert_eq!(pulled.status.code(), Some(0), "{pulled:?}");
    assert!(compat_two.join("claim.work").exists());
    assert!(!compat_two.join("claim.other").exists());
}

// ---------------------------------------------------------------------------
// The session-start row, withheld until a release ships the verb (CLOUD-2840).
// ---------------------------------------------------------------------------

/// Fails by: a session-start row or task reaching `receipt pull` while the
/// pinned engine has no such verb, so every session start runs a call the
/// installed engine cannot parse. The row and its task are withheld until the
/// pin names a release that carries it (step 14, CLOUD-2821), and `batten.toml`
/// keeps both verbatim for that commit to restore. Restoring them early turns
/// this red; restoring them with the pin bump is the moment to delete this case.
#[test]
fn the_session_row_is_withheld_until_a_release_ships_the_verb() {
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(crate::common::at_root("batten.toml")).unwrap())
            .unwrap();
    let handlers = config["hook"]["handler"].as_array().unwrap();
    assert!(
        !handlers
            .iter()
            .any(|row| row["id"].as_str() == Some("session-receipts")),
        "the session-receipts row is withheld"
    );
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(crate::common::at_root("mise.toml")).unwrap())
            .unwrap();
    assert!(
        manifest["tasks"].get("session:receipts").is_none(),
        "the session:receipts task is withheld with its row"
    );
    let authority = std::fs::read_to_string(crate::common::at_root("batten.toml")).unwrap();
    assert!(
        authority.contains("# id = \"session-receipts\"")
            && authority.contains("# [tasks.\"session:receipts\"]"),
        "batten.toml keeps the row and the task verbatim for the restore"
    );
}

// ---------------------------------------------------------------------------
// THE CARRY IN THE LAND LOOP (CLOUD-1544 for #1276): a second container of the
// branch gains what the first proved, with no command of its own but the pull
// every lap and session start makes.
// ---------------------------------------------------------------------------

/// One step row over `input.txt`, keyed on the stub tool's version.
const STEP_ROW: &str =
    "\n[[step]]\nid = \"carried\"\ninputs = [\"input.txt\"]\ntools = [[\"toolv\"]]\n";

/// Write the step stubs into `dir/bin`: the tool the key reads and a command
/// that leaves a mark when it runs.
fn step_stubs(dir: &Path) {
    for (file, body) in [
        ("bin/toolv", "#!/bin/sh\necho tool-1.0\n"),
        ("bin/mark", "#!/bin/sh\necho ran >>bin/ran.log\n"),
    ] {
        crate::common::write(dir, file, body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }
}

/// `batten <args>` in `repo` as a container of the branch runs it: the state
/// repository set, `host` trusted, the step stubs first on `PATH`, and no CI.
fn in_container(repo: &Path, state: &Path, host: &Host, args: &[&str]) -> std::process::Output {
    in_container_naming(repo, state, host, STATE_PATH, args)
}

/// [`in_container`], with `BATTEN_STATE_REPO` set to `state_repo`.
fn in_container_naming(
    repo: &Path,
    state: &Path,
    host: &Host,
    state_repo: &str,
    args: &[&str],
) -> std::process::Output {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(repo.join("bin")).chain(std::env::split_paths(&inherited)),
    )
    .unwrap();
    let mut command = batten();
    command
        .args(args)
        .current_dir(repo)
        .env("PATH", path)
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .env_remove("BATTEN_TASK_PID")
        .env(batten::session::STATE_REPO_ENV, state_repo)
        .env("SSL_CERT_FILE", &host.ca)
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .env("GIT_AUTHOR_NAME", "Fixture Producer")
        .env("GIT_AUTHOR_EMAIL", "producer@example.com")
        .env("GIT_COMMITTER_NAME", "Fixture Producer")
        .env("GIT_COMMITTER_EMAIL", "producer@example.com");
    command.state_dir(state).streamed_output().unwrap()
}

/// Fails by: step receipts (`batten-records/step-receipts`) left out of the
/// carried set, `step run` not publishing when the step ends, or the pull not
/// materialising them. Container A runs a step, which publishes as it ends; a
/// fresh container B pulls and runs the same step: a HIT, its command never
/// run. A's claim travels with it and another branch's does not.
#[test]
fn a_second_container_hits_the_step_the_first_ran() {
    let case = "receipt-carry-step";
    let (origin, state_git) = (state_repo(&format!("{case}-origin")), state_repo(case));
    let host = https_host(
        case,
        vec![
            (ORIGIN_PATH, origin.clone()),
            (STATE_PATH, state_git.clone()),
        ],
    );
    let one = wired_clone(case, &host);
    crate::common::write(&one, "batten.toml", &format!("{CONFIG}{STEP_ROW}"));
    crate::common::write(&one, "input.txt", "one\n");
    crate::common::write(&one, ".gitignore", "bin/\n");
    git_in(&one, &["add", "-A"]);
    git_in(&one, &["commit", "-qm", "a step"]);
    step_stubs(&one);
    let claims = one.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&claims).unwrap();
    let claim = batten::claim::receipt_name("work");
    std::fs::write(claims.join(&claim), "CLOUD-1\nready-lint pass\n").unwrap();
    let other = batten::claim::receipt_name("elsewhere");
    std::fs::write(claims.join(&other), "CLOUD-2\nready-lint pass\n").unwrap();
    let two = wired_second(case, &one, &host);
    step_stubs(&two);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );

    let ran = in_container(
        &one,
        &state_one,
        &host,
        &["step", "run", "carried", "--", "mark"],
    );
    assert_eq!(ran.status.code(), Some(0), "{ran:?}");
    assert_eq!(
        std::fs::read_to_string(one.join("bin/ran.log"))
            .unwrap_or_default()
            .lines()
            .count(),
        1,
        "A ran the step"
    );
    let name = receipts::reference("work").unwrap();
    let listed = git_in(&state_git, &["ls-tree", "-r", "--name-only", &name]);
    assert_eq!(
        listed
            .lines()
            .filter(|path| path.starts_with("step/"))
            .count(),
        1,
        "the step's receipt was published as the step ended: {listed}"
    );

    let pulled = in_container(&two, &state_two, &host, &["receipt", "pull"]);
    assert_eq!(pulled.status.code(), Some(0), "{pulled:?}");
    let hit = in_container(
        &two,
        &state_two,
        &host,
        &["step", "run", "carried", "--", "mark"],
    );
    assert_eq!(hit.status.code(), Some(0), "{hit:?}");
    assert!(
        String::from_utf8_lossy(&hit.stderr).starts_with("hit "),
        "B hits: {hit:?}"
    );
    assert!(!two.join("bin/ran.log").exists(), "B never ran the command");
    let carried = two.join(".git").join("batten-receipts");
    assert_eq!(
        std::fs::read(carried.join(&claim)).ok(),
        std::fs::read(claims.join(&claim)).ok(),
        "the branch's claim is honoured in B"
    );
    assert!(
        !carried.join(&other).exists(),
        "another branch's claim stays home"
    );
    assert!(
        git_in(&origin, &["for-each-ref"]).trim().is_empty(),
        "origin received nothing"
    );
}

/// A schema state directory holding `journal` and, when `sealed` is given, a
/// reach record sealed over it.
fn mutate_state(case: &str, journal: &str, sealed: Option<&str>) -> PathBuf {
    let dir = scratch(&format!("{case}-mutate")).join("schema");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("verdicts"), journal).unwrap();
    if let Some(sealed) = sealed {
        let reach = dir.join("reach");
        std::fs::create_dir_all(reach.join("cases/one")).unwrap();
        std::fs::write(reach.join("cases/one/depends"), "Ffn_a\nT12\n").unwrap();
        std::fs::write(reach.join("context.json"), "{}\n").unwrap();
        std::fs::write(reach.join("sealed"), sealed).unwrap();
    }
    dir
}

/// Fails by: the journal or the reach record left out of the mutate carry, a
/// pull that rewrites the journal rather than appending, or one that unpacks
/// over a reach record already here. A's verdicts and its sealed reach record
/// reach B whole; a second publish of the same seal sends no second archive.
#[test]
fn the_verdict_journal_and_reach_record_reach_a_second_container() {
    let case = "receipt-carry-mutate";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let name = receipts::mutate_reference(BRANCH).unwrap();
    let sealed = "a".repeat(64);
    let one = first_clone(case);
    let a = mutate_state(
        &format!("{case}-a"),
        "k1\tcaught\tm1\nk2\tmissed\tm2\n",
        Some(&sealed),
    );
    let first = receipts::publish_mutate(REMOTE, &one.join(".git"), &name, &a, PRODUCER, 10)
        .expect("publish");
    assert_eq!(
        first.count, 3,
        "one chunk, one archive part, its stamp: {first:?}"
    );
    let again = receipts::publish_mutate(REMOTE, &one.join(".git"), &name, &a, PRODUCER, 11)
        .expect("publish again");
    assert_eq!(again.commit, first.commit, "nothing new moves nothing");

    let two = second_clone(case, &one);
    let b = mutate_state(
        &format!("{case}-b"),
        "k3\tcaught\tm3\nk1\tcaught\tm1\n",
        None,
    );
    let pulled = receipts::pull_mutate(REMOTE, &two.join(".git"), &name, &b).expect("pull");
    assert_eq!(
        pulled.count, 2,
        "one line appended, one archive: {pulled:?}"
    );
    assert_eq!(
        std::fs::read_to_string(b.join("verdicts")).unwrap(),
        "k3\tcaught\tm3\nk1\tcaught\tm1\nk2\tmissed\tm2\n",
        "appended, never rewritten"
    );
    for file in ["sealed", "context.json", "cases/one/depends"] {
        assert_eq!(
            std::fs::read(b.join("reach").join(file)).ok(),
            std::fs::read(a.join("reach").join(file)).ok(),
            "{file}"
        );
    }

    let c = mutate_state(&format!("{case}-c"), "", Some(&"b".repeat(64)));
    receipts::pull_mutate(REMOTE, &two.join(".git"), &name, &c).expect("pull over a record");
    assert_eq!(
        std::fs::read_to_string(c.join("reach/sealed")).unwrap(),
        "b".repeat(64),
        "a reach record already here is never displaced"
    );
}

/// Fails by: a publish that does not re-read and re-union after a lost swap,
/// or additions computed once rather than against the ref it swaps. A second
/// container's publish lands between A's fetch and A's swap — a real publish
/// through the same transport — and both containers' verdicts are on the ref.
#[test]
fn two_concurrent_mutate_publishers_lose_nothing() {
    let case = "receipt-carry-concurrent";
    let bare = state_repo(case);
    let name = receipts::mutate_reference(BRANCH).unwrap();
    let one = first_clone(case);
    let two = second_clone(case, &one);
    let a = mutate_state(&format!("{case}-a"), "ka\tcaught\tma\n", None);
    let b = mutate_state(&format!("{case}-b"), "kb\tmissed\tmb\n", None);
    let rival = std::cell::Cell::new(false);
    let (bare_for_rival, name_for_rival) = (bare.clone(), name.clone());
    stand_up(bare.clone(), move |call| {
        if call.url.ends_with("/git-receive-pack") && !rival.replace(true) {
            let (bare, name, two, b) = (
                bare_for_rival.clone(),
                name_for_rival.clone(),
                two.clone(),
                b.clone(),
            );
            std::thread::spawn(move || {
                stand_up(bare, |_| {});
                receipts::publish_mutate(REMOTE, &two.join(".git"), &name, &b, PRODUCER, 2)
                    .expect("the rival publishes")
            })
            .join()
            .unwrap();
        }
    });
    receipts::publish_mutate(REMOTE, &one.join(".git"), &name, &a, PRODUCER, 1).expect("publish");

    let fresh = mutate_state(&format!("{case}-fresh"), "", None);
    let pulled = receipts::pull_mutate(REMOTE, &one.join(".git"), &name, &fresh).expect("pull");
    let journal = std::fs::read_to_string(fresh.join("verdicts")).unwrap();
    assert!(
        journal.contains("ka\tcaught\tma\n"),
        "A's verdict: {journal}"
    );
    assert!(
        journal.contains("kb\tmissed\tmb\n"),
        "the rival's verdict: {journal}"
    );
    assert_eq!(pulled.count, 2, "{pulled:?}");
}

/// Fails by: any publish — the receipt set's, the claim it carries, or the
/// mutate carry's — resolving to origin. The step-end publish runs with a
/// step receipt, a claim AND mutate state to carry, under every spelling of
/// origin's own repository; each says `state-repo-is-origin`, the step's own
/// verdict stands, and origin holds no ref of any kind afterwards. Origin is a
/// real repository on the same host, so a publish that resolved to it would
/// land there.
#[test]
fn no_publish_of_any_ref_reaches_origin() {
    let case = "receipt-carry-never-origin";
    let origin = state_repo(&format!("{case}-origin"));
    let host = https_host(case, vec![(ORIGIN_PATH, origin.clone())]);
    let one = wired_clone(case, &host);
    crate::common::write(&one, "batten.toml", &format!("{CONFIG}{STEP_ROW}"));
    crate::common::write(&one, "input.txt", "one\n");
    crate::common::write(&one, ".gitignore", "bin/\n");
    git_in(&one, &["add", "-A"]);
    git_in(&one, &["commit", "-qm", "a step"]);
    step_stubs(&one);
    let claims = one.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&claims).unwrap();
    std::fs::write(
        claims.join(batten::claim::receipt_name("work")),
        "CLOUD-1\nready-lint pass\n",
    )
    .unwrap();
    let state = scratch(&format!("{case}-state")).join("state");
    let schema = batten::state::repo_state_dir_under(&state, &one)
        .unwrap()
        .join("mutate")
        .join("schema");
    std::fs::create_dir_all(schema.join("reach")).unwrap();
    std::fs::write(schema.join("verdicts"), "k\tcaught\tm\n").unwrap();
    std::fs::write(schema.join("reach/sealed"), "a".repeat(64)).unwrap();
    let port_host = host.base.trim_start_matches("https://").to_owned();
    let bare_host = port_host.split(':').next().unwrap().to_owned();
    for spelling in [
        ORIGIN_PATH.to_owned(),
        ORIGIN_PATH.to_uppercase(),
        format!("{ORIGIN_PATH}.git"),
        format!("/{ORIGIN_PATH}/"),
        format!("{}/{ORIGIN_PATH}", host.base),
        format!("{port_host}/{ORIGIN_PATH}"),
        format!("{bare_host}/{ORIGIN_PATH}"),
    ] {
        let ran = in_container_naming(
            &one,
            &state,
            &host,
            &spelling,
            &["step", "run", "carried", "--", "mark"],
        );
        assert_eq!(
            ran.status.code(),
            Some(0),
            "the step's verdict stands: {spelling}"
        );
        assert!(
            String::from_utf8_lossy(&ran.stderr).contains("receipt publish: state-repo-is-origin"),
            "{spelling}: {ran:?}"
        );
        let published =
            in_container_naming(&one, &state, &host, &spelling, &["receipt", "publish"]);
        assert_eq!(
            published.status.code(),
            Some(1),
            "{spelling}: {published:?}"
        );
        assert_eq!(stdout(&published), "state-repo-is-origin\n", "{spelling}");
        assert!(
            git_in(&origin, &["for-each-ref"]).trim().is_empty(),
            "{spelling}: origin holds no receipt, claim or mutate ref"
        );
    }
    assert!(
        host.requests()
            .iter()
            .all(|path| !path.contains("receive-pack")),
        "no push of any ref was attempted: {:?}",
        host.requests()
    );
}

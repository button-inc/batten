//! One HTTPS request, in process (CLOUD-745).
//!
//! The client this crate uses is **hyper plus hyper-rustls**, not `reqwest`
//! which CLOUD-745 names. That substitution is a measurement rather than a
//! preference, and the numbers are in `Cargo.toml` beside the dependency: every
//! `reqwest` configuration hits one of the two chokepoints CLOUD-320 died at,
//! because it selects the verifier and the crypto provider through FEATURES,
//! and feature unification then puts `ring` or `security-framework` in the
//! graph from a crate this workspace does not control. Below `reqwest` both are
//! constructor arguments, which is the whole of why this links on a macOS build
//! with no SDK.
//!
//! ## What a link gate cannot ask, and this module therefore states
//!
//! With no provider in the graph the binary links perfectly and fails at the
//! first handshake. [`provider`] is what makes the provider a compile-time fact
//! rather than a hope — and the measurement that made this paragraph necessary
//! is recorded on CLOUD-745: three of four false passes on the way here were
//! invisible to `cargo metadata`, and the fourth resolved and did not compile.
//!
//! ## Bounds this module keeps, from CLOUD-745's hardening items
//!
//! * **Explicit connect AND total timeouts.** The `curl` invocation being
//!   replaced sets neither, so a hung server hangs the caller forever today. In
//!   process that sharpens, because a hung future is harder to interrupt than a
//!   hung child.
//! * **Buffer, then hand back.** The body is read to a `Vec` and returned; this
//!   module never writes a file. That keeps `provision`'s verify-before-write
//!   order available to its caller, which the obvious streaming idiom destroys
//!   silently.
//! * **A scoped runtime, never `#[tokio::main]`.** One current-thread runtime is
//!   built for the request and dropped with it, so no verb carries a runtime it
//!   did not ask for and the mediated path constructs none at all — CLOUD-689's
//!   100 ms per-call ceiling is untouched because `hook` never reaches here.
//! * **A status is a typed value.** `curl` reports a 404 body as a successful
//!   fetch, which then digests as a checksum *mismatch* — reporting a tampered
//!   artifact for a missing one. A status code that travels as a number cannot
//!   make that mistake.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::Result;
use crate::error::UsageError;

/// How long to wait for the whole exchange, connect included.
///
/// A constant rather than a caller's choice, because every caller in this crate
/// wants the same thing — a bound that is generous for a release artifact and
/// finite for a server that accepts and never answers.
const TOTAL_TIMEOUT: Duration = Duration::from_mins(1);

/// How long to wait for the connection alone.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the runtime is given to wind down once the verdict is in.
///
/// Short on purpose: by the time this runs the answer is already decided, and
/// what is being waited on is a connection pool tidying up after a request
/// nobody is reading any more.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// The one variable that moves the two bounds above, and what it is for.
///
/// **It exists so the total bound is testable over the compiled binary**, which
/// is the shape CLOUD-745's §7 asks for. The bound fires on a server that
/// accepts and never answers, and the only hermetic fixture for that is a
/// listener which never completes the TLS handshake — a *trusted* local
/// certificate is unreachable by construction, because the roots are vendored
/// and nothing signs a loopback CA. At the default the case would cost a minute
/// of every run.
///
/// **It is not a bypass, and the distinction is the whole reason it is
/// admissible.** CLOUD-1051 removed two environment variables because they let
/// anyone spend a refusal without articulating anything. This one cannot reach
/// a verdict at all: it changes how long a wait waits, so every value still
/// ends in the same three answers, and the shortest value is the *strictest*.
/// Nothing it can be set to admits a fetch that would otherwise be refused.
const TIMEOUT_OVERRIDE: &str = "BATTEN_FETCH_TIMEOUT_MS";

/// The bounds this run uses.
///
/// An unparseable or zero value is IGNORED rather than refused: this reads the
/// ambient environment on a path whose job is to fetch one artifact, and a
/// usage error about a timeout knob would turn a typo somewhere in an
/// operator's shell into a failed provision.
fn bounds() -> (Duration, Duration) {
    bounds_from(std::env::var(TIMEOUT_OVERRIDE).ok().as_deref())
}

/// The decision [`bounds`] makes, over a value rather than over the process
/// environment — so the cases below pin the reading without a test mutating
/// state every other case in the binary shares.
fn bounds_from(raw: Option<&str>) -> (Duration, Duration) {
    let Some(millis) = raw
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
    else {
        return (CONNECT_TIMEOUT, TOTAL_TIMEOUT);
    };
    let bound = Duration::from_millis(millis);
    // The same value for both: a caller shrinking the total bound to make a
    // hang observable wants the connect bound shrunk with it, and two knobs
    // would be two things to keep consistent for one question.
    (bound, bound)
}

/// What a fetch returned: the status, and the body it buffered.
///
/// The status is a number rather than a success boolean, which is the
/// distinction `--fail` existed to protect: a missing artifact and a tampered
/// one are different answers and must reach different exit codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The buffered body.
    pub body: Vec<u8>,
}

/// The crypto provider, installed explicitly.
///
/// Pure Rust and links-free, which is what keeps `ring` and `aws-lc-rs` — both
/// of which declare a `links` key — out of a graph that has to link on a macOS
/// build with no SDK.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_graviola::default_provider())
}

/// The TLS configuration: vendored roots, explicit provider, no platform store.
///
/// # Errors
///
/// An internal error (→ exit `3`) when the provider cannot supply the default
/// protocol versions. That is a build-configuration failure rather than
/// anything a caller can cause, which is why it is not a [`UsageError`] —
/// reported rather than panicked, because the workspace forbids `expect` on a
/// reachable path.
fn tls_config() -> Result<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            anyhow::anyhow!(
                "fetch: the vendored crypto provider does not support the default TLS \
                 versions — the build is misconfigured"
            )
        })
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

/// Fetch one URL, returning its status and buffered body.
///
/// **HTTPS only**, by construction rather than by checking the scheme: the
/// connector is built `https_only`, so a plain-HTTP URL is refused by the
/// transport instead of by a predicate somebody could forget.
///
/// # Errors
///
/// **Two classes, and the split is the exit contract rather than tidiness.** A
/// URL that will not parse is a [`UsageError`] (→ exit `1`): the caller asked
/// for something malformed, which is the same answer `provision` gives an
/// unsupported scheme. Everything else — the TLS stack, the exchange, a
/// timeout — is an internal error (→ exit `3`), because the fetch could not
/// COMPLETE, which is a different claim from one it made and refused.
///
/// Collapsing the two is not cosmetic: a server that accepts and never answers
/// would report as a usage error, telling an operator to fix their manifest
/// about a network that hung.
///
/// A non-2xx **status is not an error** at all — it travels in
/// [`Response::status`], because the caller is the one that knows whether a 404
/// is fatal.
pub fn get(url: &str, headers: &[(String, String)]) -> Result<Response> {
    // ONE runtime, current-thread, built here and dropped with the request.
    // `clippy.toml` refuses the multi-thread builder outright (CLOUD-747), and
    // an async `main` would put a runtime under every verb in the binary.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| anyhow::anyhow!("fetch: cannot start a runtime: {err}"))?;
    let answer = runtime.block_on(exchange(url, headers));
    // BOUNDED TEARDOWN, never a bare drop (CLOUD-745 item 4). `Runtime::drop`
    // blocks until blocking tasks finish, and a client's connection pool holds
    // background work — so a fetch abandoned by the total bound above could
    // otherwise hang the process at exit, after the verdict was already
    // decided. What licenses cutting it short is `provision`'s own invariant:
    // this module writes no file and takes no lock, so there is nothing a
    // half-finished task could leave behind.
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    answer
}

/// The request itself, on the runtime [`get`] built.
async fn exchange(url: &str, headers: &[(String, String)]) -> Result<Response> {
    let (connect_timeout, total_timeout) = bounds();
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| UsageError::raise("fetch: the URL will not parse".to_owned()))?;
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.enforce_http(false);
    connector.set_connect_timeout(Some(connect_timeout));
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config()?)
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let client: Client<_, http_body_util::Empty<hyper::body::Bytes>> =
        Client::builder(TokioExecutor::new()).build(https);

    let mut request = hyper::Request::builder()
        .uri(uri)
        .method(hyper::Method::GET);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let request = request
        .body(http_body_util::Empty::new())
        .map_err(|_| anyhow::anyhow!("fetch: the request will not build"))?;

    // The TOTAL bound, over connect plus exchange plus body. The connect timeout
    // above bounds only the first of the three, and a server that accepts and
    // then says nothing is exactly the case this one exists for.
    let answer = tokio::time::timeout(total_timeout, client.request(request))
        .await
        .map_err(|_| anyhow::anyhow!("fetch: timed out"))?
        .map_err(|err| anyhow::anyhow!("fetch: the request failed: {err}"))?;

    let status = answer.status().as_u16();
    let body = tokio::time::timeout(total_timeout, answer.into_body().collect())
        .await
        .map_err(|_| anyhow::anyhow!("fetch: timed out reading the body"))?
        .map_err(|err| anyhow::anyhow!("fetch: the body failed: {err}"))?
        .to_bytes()
        .to_vec();
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendored_provider_supports_the_default_protocol_versions() {
        // THE ASSERTION A LINK GATE CANNOT MAKE. With no provider in the graph
        // the binary links clean and fails at the first handshake, which is one
        // of the four false passes CLOUD-745's probe recorded. This is the
        // cheapest thing that would go red if the provider were dropped or
        // swapped for one that cannot serve TLS 1.2 and 1.3.
        assert!(
            tls_config().is_ok(),
            "the vendored provider must serve the default TLS versions"
        );
    }

    #[test]
    fn a_url_that_will_not_parse_is_a_usage_error_rather_than_a_panic() {
        let answer = get("not a url", &[]);
        assert!(answer.is_err(), "an unparseable URL must be reported");
    }

    #[test]
    fn a_malformed_url_is_the_only_class_that_reaches_exit_1() {
        // THE SPLIT, asserted rather than described. A malformed URL is the
        // caller's mistake and exits 1; everything else here is "could not
        // complete" and exits 3, which is a different claim. Collapsing them
        // would tell an operator to fix their manifest about a network that
        // hung — and it did, until this case was written: every arm of this
        // module raised `UsageError`, so a timed-out fetch reported as usage.
        let malformed = get("not a url", &[]).expect_err("an unparseable URL is refused");
        assert!(
            malformed.downcast_ref::<UsageError>().is_some(),
            "a malformed URL is the caller's, so it is a UsageError"
        );

        // The other side of the split, over the one non-transport arm a unit
        // test can reach without a listener. A build whose provider cannot
        // serve TLS is not the caller's mistake.
        let scheme = get("ftp://example.invalid/x", &[]).expect_err("a non-HTTPS URL is refused");
        assert!(
            scheme.downcast_ref::<UsageError>().is_none(),
            "a transport refusal is could-not-complete, never a usage error"
        );
    }

    #[test]
    fn an_unset_override_leaves_the_declared_bounds_in_place() {
        // The default arm, asserted rather than assumed: the seam exists for a
        // test fixture, so the case that matters most is the one where no
        // fixture set it. Read through a guard rather than by mutating the
        // process environment, which every other case in this binary shares.
        assert_eq!(
            bounds_from(None),
            (CONNECT_TIMEOUT, TOTAL_TIMEOUT),
            "with nothing set, the constants are the bounds"
        );
    }

    #[test]
    fn a_shorter_override_is_the_only_direction_that_matters() {
        assert_eq!(
            bounds_from(Some("250")),
            (Duration::from_millis(250), Duration::from_millis(250)),
            "a numeric override moves both bounds together"
        );
    }

    #[test]
    fn an_unusable_override_is_ignored_rather_than_refused() {
        // Three shapes, one answer. This reads the ambient environment on a
        // path whose job is to fetch an artifact, so a typo in an operator's
        // shell must not become a failed provision — and zero is refused with
        // the rest, because a zero bound would time every fetch out instantly
        // and read as the network being down.
        for raw in ["", "soon", "0"] {
            assert_eq!(
                bounds_from(Some(raw)),
                (CONNECT_TIMEOUT, TOTAL_TIMEOUT),
                "{raw:?} must fall back to the declared bounds"
            );
        }
    }
}

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
/// [`UsageError`] when the provider cannot supply the default protocol
/// versions, which is a build-configuration failure rather than anything a
/// caller can cause — reported rather than panicked, because the workspace
/// forbids `expect` on a reachable path.
fn tls_config() -> Result<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            UsageError::raise(
                "fetch: the vendored crypto provider does not support the default TLS \
                 versions — the build is misconfigured"
                    .to_owned(),
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
/// [`UsageError`] when the URL will not parse, when the TLS stack cannot be
/// built, or when the exchange fails or times out. A non-2xx **status is not an
/// error** — it travels in [`Response::status`], because the caller is the one
/// that knows whether a 404 is fatal.
pub fn get(url: &str, headers: &[(String, String)]) -> Result<Response> {
    // ONE runtime, current-thread, built here and dropped with the request.
    // `clippy.toml` refuses the multi-thread builder outright (CLOUD-747), and
    // an async `main` would put a runtime under every verb in the binary.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| UsageError::raise(format!("fetch: cannot start a runtime: {err}")))?;
    runtime.block_on(async { exchange(url, headers).await })
}

/// The request itself, on the runtime [`get`] built.
async fn exchange(url: &str, headers: &[(String, String)]) -> Result<Response> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|_| UsageError::raise("fetch: the URL will not parse".to_owned()))?;
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.enforce_http(false);
    connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
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
        .map_err(|_| UsageError::raise("fetch: the request will not build".to_owned()))?;

    // The TOTAL bound, over connect plus exchange plus body. The connect timeout
    // above bounds only the first of the three, and a server that accepts and
    // then says nothing is exactly the case this one exists for.
    let answer = tokio::time::timeout(TOTAL_TIMEOUT, client.request(request))
        .await
        .map_err(|_| UsageError::raise("fetch: timed out".to_owned()))?
        .map_err(|err| UsageError::raise(format!("fetch: the request failed: {err}")))?;

    let status = answer.status().as_u16();
    let body = tokio::time::timeout(TOTAL_TIMEOUT, answer.into_body().collect())
        .await
        .map_err(|_| UsageError::raise("fetch: timed out reading the body".to_owned()))?
        .map_err(|err| UsageError::raise(format!("fetch: the body failed: {err}")))?
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
}

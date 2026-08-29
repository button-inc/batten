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

/// Where an operator names a CA this build would otherwise not trust.
///
/// **This is the acceptance clause `curl` used to satisfy**, and dropping it was
/// the defect that made `batten check` unable to provision at all: a
/// re-terminating proxy presents a certificate signed by a CA only the host
/// knows about, so a build whose roots are purely vendored cannot reach
/// anything through one. `curl` read `CURL_CA_BUNDLE`; the generic spelling of
/// the same thing is OpenSSL's, and it is what a proxied environment sets
/// beside every other tool's variable.
///
/// It **adds** to the vendored roots and never replaces them, so naming a
/// bundle cannot quietly narrow what is trusted to one certificate.
const CA_BUNDLE: &str = "SSL_CERT_FILE";

/// The TLS configuration: vendored roots, the host's extra CA, explicit
/// provider, no platform store.
///
/// The platform store is still absent, and that is the distinction worth
/// keeping: the roots are a compiled-in bundle plus whatever an operator names
/// on purpose, which is reproducible across hosts in a way the platform store
/// is not — and it is the reason this graph links with no macOS SDK.
///
/// # Errors
///
/// An internal error (→ exit `3`) when the provider cannot supply the default
/// protocol versions, or when [`CA_BUNDLE`] names a file that will not read or
/// parse. That last one is deliberately fatal rather than ignored: an operator
/// who named a bundle is telling us the fetch needs it, and carrying on with
/// the vendored roots alone would fail later with a certificate error that says
/// nothing about the typo.
fn tls_config() -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = std::env::var(CA_BUNDLE)
        .ok()
        .filter(|at| !at.trim().is_empty())
    {
        use rustls_pki_types::pem::PemObject as _;

        for certificate in
            rustls_pki_types::CertificateDer::pem_file_iter(&path).map_err(|err| {
                anyhow::anyhow!("fetch: cannot read the CA bundle {CA_BUNDLE} names: {err}")
            })?
        {
            let certificate = certificate.map_err(|err| {
                anyhow::anyhow!("fetch: the CA bundle {CA_BUNDLE} names will not parse: {err}")
            })?;
            roots.add(certificate).map_err(|err| {
                anyhow::anyhow!("fetch: the CA bundle {CA_BUNDLE} names is not usable: {err}")
            })?;
        }
    }
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

/// How many redirects are followed before the fetch gives up.
///
/// A bound rather than a count somebody tunes: a release URL redirects once or
/// twice, and a chain longer than this is a loop or a misconfiguration.
const MAX_REDIRECTS: u8 = 10;

/// The proxy this fetch goes through, if any.
///
/// **Dropping this was the defect that made `batten check` unable to
/// provision.** `curl` reads these variables, so the shell-out honoured a
/// proxied environment for free, and an in-process client that ignores them
/// cannot reach anything at all where one is required — which is not a corner
/// case: it is how this repository's own CI sandbox is wired.
///
/// Lower case first, then upper, which is the order every other client in this
/// class resolves them in.
fn proxy_for(host: &str) -> Option<hyper::Uri> {
    let no_proxy = ["no_proxy", "NO_PROXY"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok());
    if bypassed(host, no_proxy.as_deref()) {
        return None;
    }
    ["https_proxy", "HTTPS_PROXY"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|raw| !raw.trim().is_empty())
        .and_then(|raw| raw.trim().parse().ok())
}

/// Whether `host` is reached directly rather than through a proxy.
///
/// Two rules, and the first is not read from the environment at all: a loopback
/// destination is **always** direct. That is what keeps this module's own
/// fixtures hermetic — a suite standing up a listener on `127.0.0.1` must not
/// have its connection routed through whatever the ambient environment names,
/// and relying on `NO_PROXY` to say so makes the suite a function of the box it
/// runs on.
///
/// The second is the `NO_PROXY` list, matched the way it is conventionally
/// written: `*` for everything, an exact host, or a `.suffix`/`suffix` domain
/// match. CIDR entries are **not** matched, and that is a stated bound rather
/// than an oversight — a literal address that needs bypassing is either
/// loopback, which rule one already covers, or something this fetch has no
/// business reaching.
///
/// The list arrives as a VALUE rather than being read here, for `bounds_from`'s
/// reason and one more: the workspace forbids `unsafe`, and mutating the
/// process environment is `unsafe` since the 2024 edition — so a case that set
/// `NO_PROXY` to test this could not be written at all.
fn bypassed(host: &str, no_proxy: Option<&str>) -> bool {
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|at| at.is_loopback())
        || host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|at| at.is_loopback())
    {
        return true;
    }
    let Some(list) = no_proxy else {
        return false;
    };
    list.split(',').map(str::trim).any(|entry| {
        if entry == "*" {
            return true;
        }
        let entry = entry.trim_start_matches('.');
        !entry.is_empty()
            && (host.eq_ignore_ascii_case(entry)
                || host
                    .len()
                    .checked_sub(entry.len())
                    .and_then(|at| at.checked_sub(1))
                    .is_some_and(|at| {
                        host.as_bytes()[at] == b'.' && host[at + 1..].eq_ignore_ascii_case(entry)
                    }))
    })
}

/// A TCP connector that opens a `CONNECT` tunnel when a proxy applies.
///
/// **A tunnel, never a rewrite**, and that distinction is the security
/// property: the proxy is asked to carry bytes to `host:port` and the TLS
/// handshake then happens end to end inside it, so the transport above this is
/// unchanged and `https_only` still means what it says. Where the proxy
/// re-terminates anyway, it presents its own certificate and [`CA_BUNDLE`] is
/// what makes that verifiable — an operator's explicit decision rather than
/// something this connector waves through.
#[derive(Clone)]
struct Tunnelled {
    inner: hyper_util::client::legacy::connect::HttpConnector,
    proxy: Option<hyper::Uri>,
}

impl tower_service::Service<hyper::Uri> for Tunnelled {
    type Response = hyper_util::rt::TokioIo<tokio::net::TcpStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<Self::Response, Self::Error>>
                + Send,
        >,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        tower_service::Service::poll_ready(&mut self.inner, cx).map_err(Into::into)
    }

    fn call(&mut self, destination: hyper::Uri) -> Self::Future {
        let Some(proxy) = self.proxy.clone() else {
            let connecting = tower_service::Service::call(&mut self.inner, destination);
            return Box::pin(async move { connecting.await.map_err(Into::into) });
        };
        // Read the destination BEFORE dialing, so a URL with no host fails as a
        // request rather than as a tunnel the proxy refuses.
        let authority = destination
            .host()
            .map(|host| format!("{host}:{}", destination.port_u16().unwrap_or(443)));
        let connecting = tower_service::Service::call(&mut self.inner, proxy);
        Box::pin(async move {
            let authority = authority
                .ok_or_else(|| -> Self::Error { "fetch: the URL names no host".into() })?;
            let stream = connecting.await?;
            tunnel(stream.into_inner(), &authority).await
        })
    }
}

/// Ask an open proxy connection to carry bytes to `authority`.
async fn tunnel(
    mut stream: tokio::net::TcpStream,
    authority: &str,
) -> std::result::Result<
    hyper_util::rt::TokioIo<tokio::net::TcpStream>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;

    // ONE BYTE AT A TIME, and it is not an oversight. The bytes after the blank
    // line belong to the TLS handshake above this, so a buffered read that
    // over-ran the header would swallow the first record and the handshake would
    // fail with something that looks nothing like its cause.
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > PROXY_HEAD_LIMIT {
            return Err("fetch: the proxy sent no usable CONNECT response".into());
        }
        if stream.read(&mut byte).await? == 0 {
            return Err("fetch: the proxy closed the connection during CONNECT".into());
        }
        head.push(byte[0]);
    }

    // Pointer-only: the status the proxy gave, never its body. A proxy refusal
    // page is content from something the operator did not choose.
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned));
    if status.as_deref() != Some("200") {
        return Err(format!(
            "fetch: the proxy refused CONNECT with status {}",
            status.as_deref().unwrap_or("(unreadable)")
        )
        .into());
    }
    Ok(hyper_util::rt::TokioIo::new(stream))
}

/// How much of a proxy's CONNECT response is read before giving up on it.
const PROXY_HEAD_LIMIT: usize = 8192;

/// Follow the request to its answer, through at most [`MAX_REDIRECTS`] hops.
///
/// `--location` was a load-bearing `curl` flag with a one-line reason —
/// *"release URLs redirect, routinely"* — and `--proto-redir '=https'` was the
/// bound on it. Both are here rather than in the transport, because a redirect
/// is the one place the transport's `https_only` cannot speak: it refuses the
/// URL it is HANDED, and a 302 hands it a new one.
async fn exchange(url: &str, headers: &[(String, String)]) -> Result<Response> {
    let mut target = url.to_owned();
    for _hop in 0..=MAX_REDIRECTS {
        let (answer, location) = one_exchange(&target, headers).await?;
        let Some(next) = redirect_target(&target, answer.status, location.as_deref())? else {
            return Ok(answer);
        };
        target = next;
    }
    Err(anyhow::anyhow!(
        "fetch: more than {MAX_REDIRECTS} redirects"
    ))
}

/// Where a redirect points, or `None` when the answer is the answer.
///
/// # Errors
///
/// An internal error when a 3xx carries no usable `Location`, or when it points
/// somewhere that is not HTTPS. **That refusal is `--proto-redir '=https'`**: a
/// redirect must not downgrade the transport that was the whole point of
/// choosing the scheme, and the connector cannot catch it because by then the
/// scheme is the server's choice rather than the caller's.
fn redirect_target(from: &str, status: u16, location: Option<&str>) -> Result<Option<String>> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(location) = location else {
        return Err(anyhow::anyhow!(
            "fetch: HTTP {status} with no Location to follow"
        ));
    };
    let base: hyper::Uri = from
        .parse()
        .map_err(|_| anyhow::anyhow!("fetch: the URL being redirected will not parse"))?;
    let next = resolve(&base, location)?;
    if !next.starts_with("https://") {
        // Pointer-only: the status and the scheme decision, never the location,
        // which is a string a server chose.
        return Err(anyhow::anyhow!(
            "fetch: HTTP {status} redirects away from https, which is refused"
        ));
    }
    Ok(Some(next))
}

/// A `Location` resolved against the URL that produced it.
///
/// Absolute, root-relative and path-relative are the three shapes a server
/// actually sends; anything else parses as absolute or fails.
fn resolve(base: &hyper::Uri, location: &str) -> Result<String> {
    if location.contains("://") {
        return Ok(location.to_owned());
    }
    let authority = base
        .authority()
        .ok_or_else(|| anyhow::anyhow!("fetch: the URL being redirected names no host"))?;
    let scheme = base.scheme_str().unwrap_or("https");
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{location}"));
    }
    let path = base.path();
    let dir = path.rfind('/').map_or("/", |at| &path[..=at]);
    Ok(format!("{scheme}://{authority}{dir}{location}"))
}

/// One request, with no redirect following: the status, the buffered body, and
/// the `Location` header if there was one.
async fn one_exchange(
    url: &str,
    headers: &[(String, String)],
) -> Result<(Response, Option<String>)> {
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
        .wrap_connector(Tunnelled {
            inner: connector,
            proxy: proxy_for(uri.host().unwrap_or_default()),
        });
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

    let location = answer
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let status = answer.status().as_u16();
    let body = tokio::time::timeout(total_timeout, answer.into_body().collect())
        .await
        .map_err(|_| anyhow::anyhow!("fetch: timed out reading the body"))?
        .map_err(|err| anyhow::anyhow!("fetch: the body failed: {err}"))?
        .to_bytes()
        .to_vec();
    Ok((Response { status, body }, location))
}

#[cfg(test)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly —
// the same carve-out `provision::tests` takes, at the same scope.
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn a_loopback_destination_never_goes_through_a_proxy() {
        // NOT read from the environment, and that is the point: this module's
        // own fixtures stand up a listener on 127.0.0.1, and routing those
        // through whatever the ambient environment names would make the suite a
        // function of the box it runs on. `NO_PROXY` happens to list loopback
        // in this container; a case relying on that would pass here and fail in
        // CI for a reason nobody would connect to this line.
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.9.9.9",
            "::1",
            "[::1]",
        ] {
            assert!(
                bypassed(host, None),
                "{host} must be reached directly with no list at all"
            );
            assert!(
                bypassed(host, Some("github.com")),
                "{host} must be reached directly whatever the list says"
            );
        }
    }

    #[test]
    fn a_no_proxy_entry_matches_a_host_or_its_subdomains_and_not_a_lookalike() {
        // The allow half is what makes this discriminate: a matcher that
        // returned true for everything would satisfy the case above and every
        // bypass assertion here, and would silently stop proxying entirely.
        assert!(!bypassed("github.com", None), "an unlisted host is proxied");

        // The suffix rule must be anchored on a dot. `notgithub.com` ends with
        // `github.com` as a STRING, and a naive `ends_with` would bypass it —
        // sending a request meant for the proxy straight out instead.
        for (list, host, expected) in [
            ("github.com", "github.com", true),
            ("github.com", "api.github.com", true),
            ("github.com", "notgithub.com", false),
            (".github.com", "api.github.com", true),
            ("example.org,github.com", "github.com", true),
            ("example.org, github.com", "github.com", true),
            ("*", "anything.invalid", true),
            ("", "github.com", false),
            ("github.com", "github.com.evil.invalid", false),
        ] {
            assert_eq!(
                bypassed(host, Some(list)),
                expected,
                "NO_PROXY={list:?} against {host:?}"
            );
        }
    }

    #[test]
    fn a_redirect_is_followed_only_while_it_stays_on_https() {
        // `--location` and `--proto-redir '=https'`, which were two curl flags
        // and are one decision here. The transport cannot make it: `https_only`
        // refuses the URL it is HANDED, and a 302 hands it a new one.
        let base = "https://example.invalid/a/b";
        assert_eq!(
            redirect_target(base, 302, Some("https://cdn.invalid/x")).unwrap(),
            Some("https://cdn.invalid/x".to_owned())
        );
        assert_eq!(
            redirect_target(base, 302, Some("/root")).unwrap(),
            Some("https://example.invalid/root".to_owned()),
            "a root-relative Location resolves against the authority"
        );
        assert_eq!(
            redirect_target(base, 302, Some("c")).unwrap(),
            Some("https://example.invalid/a/c".to_owned()),
            "a path-relative Location resolves against the directory"
        );

        // A DOWNGRADE IS REFUSED, which is the half that is a security property
        // rather than a convenience.
        assert!(
            redirect_target(base, 302, Some("http://example.invalid/x")).is_err(),
            "a redirect must not downgrade the transport"
        );
        // And a 3xx with nowhere to go is a failure, never a silent 302 body
        // handed back to a caller that would digest it.
        assert!(redirect_target(base, 302, None).is_err());
        // The stop condition: a real answer is not a redirect.
        assert_eq!(redirect_target(base, 200, None).unwrap(), None);
        assert_eq!(
            redirect_target(base, 404, Some("https://elsewhere.invalid/")).unwrap(),
            None,
            "only a 3xx follows a Location, whatever else carries the header"
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

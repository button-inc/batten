//! Parallel-session dispatch: which calls carry a dispatch message, and where
//! (CLOUD-1978, CLOUD-2858).
//!
//! # The owner's ruling this implements
//!
//! The gate decides, never a human (2026-11-23). A dispatch whose message
//! passes `batten lint brief` is granted like any call the engine allows, and
//! one whose message fails it is refused with its findings
//! (`dispatch-brief-is-linted`, a vendored `claude-code-cloud` module). The
//! owner-approval receipt that once cleared a dispatch, and the question-tool
//! reader that wrote it, are retired: an approval on top of the engine's own
//! Allow contradicted the ruling that every allowed call is granted.
//!
//! # What never leaves here
//!
//! A borrowed slice of the call's own arguments, for the caller to lint in
//! process. Nothing here writes a receipt or reads one.

/// The session-management methods that carry a dispatch message, and the
/// argument each carries it in.
const METHODS: &[(&str, &str)] = &[("create_session", "prompt"), ("send_message", "message")];

/// The message a session-management call carries, if the call is one.
///
/// Matched on the method after the last `__`, so the server's name — which a
/// host may alias — decides nothing.
#[must_use]
pub fn prompt_of<'a>(tool: &str, arguments: &'a serde_json::Value) -> Option<&'a str> {
    if !tool.starts_with("mcp__") {
        return None;
    }
    let method = tool.rsplit("__").next()?;
    let (_, field) = METHODS.iter().find(|(name, _)| *name == method)?;
    arguments.get(*field).and_then(serde_json::Value::as_str)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_method_decides_and_the_server_alias_does_not() {
        let args = serde_json::json!({ "prompt": "p", "message": "m" });
        assert_eq!(
            prompt_of("mcp__Claude_Code_Remote__create_session", &args),
            Some("p")
        );
        assert_eq!(prompt_of("mcp__x__send_message", &args), Some("m"));
        assert_eq!(prompt_of("mcp__x__get_session", &args), None);
        assert_eq!(prompt_of("create_session", &args), None);
    }
}

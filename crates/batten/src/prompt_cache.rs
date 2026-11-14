//! When a waiting session's cached context is evicted, and whether waking it
//! first is worth a read (CLOUD-2763).
//!
//! # The rule
//!
//! Waking before eviction costs one read of the context; not waking costs one
//! write of it when the wait ends; how long the wait runs is not known in
//! advance. That is the rent-or-buy problem, and its answer is the break-even
//! rule: keep paying the small cost until the payments would exceed the large
//! one, then stop. No deterministic rule that does not know the duration does
//! better than twice the cost of one that does (Karlin, Manasse, Rudolph and
//! Sleator, "Competitive Snoopy Caching", Algorithmica 3, 1988).
//!
//! # Integers, and why
//!
//! Prices are thousandths of the base input price, because 0.025 is not a whole
//! number of hundredths, and the division is integer division. In floating point
//! four cells of the published table come out one low.
//!
//! # What it ignores
//!
//! The context size cancels only if a wake adds nothing to the context. Each
//! wake adds a few hundred tokens, written at the write price; that is ignored
//! while the addition is small against the context.
//!
//! Not `cache.rs`, which is the cross-process cache: this module is about a
//! model host's prompt cache.

use std::path::Path;

/// The seconds between a task's exit and the request that follows it, taken
/// off a limit before a waiter exits.
///
/// Chosen, not published and not measured: a measurement of the gap from exit
/// to request would replace it here, in this one place.
pub const BUFFER_SECS: u64 = 60;

/// Requests one wake by a waiter costs: the wake itself, and the turn after the
/// relaunch's tool result. Counted from the shape of the turn, not measured.
pub const REQUESTS_PER_WAKE: u64 = 2;

/// One prompt-cache bucket a host publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Bucket {
    /// Seconds an unread cache entry lives.
    pub lifetime_secs: u64,
    /// The write price, in thousandths of the base input price.
    pub write_milli: u64,
}

/// A host's published eviction limits and prices (CLOUD-2763).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Eviction {
    /// Every bucket the host publishes.
    pub buckets: &'static [Bucket],
    /// Read prices in thousandths, keyed by model-id prefix, most specific
    /// first: the first prefix a model id starts with is its price.
    pub reads: &'static [(&'static str, u64)],
}

impl Eviction {
    /// The bucket with this lifetime, if the host publishes one.
    #[must_use]
    pub fn bucket(&self, lifetime_secs: u64) -> Option<Bucket> {
        self.buckets
            .iter()
            .copied()
            .find(|bucket| bucket.lifetime_secs == lifetime_secs)
    }

    /// The read price of `model`, or `None` for a model the host publishes no
    /// price for: no price, no wake.
    #[must_use]
    pub fn read_milli(&self, model: &str) -> Option<u64> {
        self.reads
            .iter()
            .find(|(prefix, _)| model.starts_with(prefix))
            .map(|(_, price)| *price)
    }
}

/// Claude Code's published figures, read 2026-11-14 from
/// code.claude.com/docs/en/prompt-caching.md and
/// platform.claude.com/docs/en/build-with-claude/prompt-caching: a five-minute
/// bucket written at 1.25 times and a one-hour bucket at 2 times; reads at 0.025
/// times on Fable 5.2, 0.05 on Opus 5.5 and Sonnet 5.5, 0.1 on any other Claude
/// model.
//MUTANT-SUITE crates/batten/src/hook.rs
//MUTANT eviction-figures-drift|s@^            write_milli: 2000,$@            write_milli: 1999,@|only_claude_code_declares_an_eviction_limit
pub const CLAUDE_CODE: Eviction = Eviction {
    buckets: &[
        Bucket {
            lifetime_secs: 300,
            write_milli: 1250,
        },
        Bucket {
            lifetime_secs: 3600,
            write_milli: 2000,
        },
    ],
    reads: &[
        ("claude-fable-5-2", 25),
        ("claude-opus-5-5", 50),
        ("claude-sonnet-5-5", 50),
        ("claude-", 100),
    ],
};

/// How many warm wakes one wait may spend: `(w - n*r) / (n*r)`, in integer
/// thousandths, zero where one wake already costs a write.
//MUTANT-SUITE crates/batten/src/prompt_cache.rs
//MUTANT break-even-off-by-one|s@^    (write_milli - spent) / spent$@    (write_milli - spent) / spent + 1@|keep_warm_matches_the_published_table
//MUTANT break-even-ignores-read-price|s@^    let spent = read_milli \* requests_per_wake;$@    let spent = 100 * requests_per_wake;@|keep_warm_matches_the_published_table
//MUTANT break-even-in-floats|s@^    (write_milli - spent) / spent$@    ((write_milli as f64 / 1000.0 - spent as f64 / 1000.0) / (spent as f64 / 1000.0)).floor() as u64@|keep_warm_matches_the_published_table
#[must_use]
pub fn wakes_allowed(write_milli: u64, read_milli: u64, requests_per_wake: u64) -> u64 {
    let spent = read_milli * requests_per_wake;
    if spent == 0 || spent >= write_milli {
        return 0;
    }
    (write_milli - spent) / spent
}

/// Whether one more wake is worth its read: true while the wakes already spent
/// are under [`wakes_allowed`].
#[must_use]
pub fn keep_warm(
    write_milli: u64,
    read_milli: u64,
    requests_per_wake: u64,
    wakes_so_far: u64,
) -> bool {
    wakes_so_far < wakes_allowed(write_milli, read_milli, requests_per_wake)
}

/// The limit in force for a session, as the Stop path writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InForce {
    /// Seconds the bucket of the last cache write lives.
    pub lifetime_secs: u64,
    /// That bucket's write price, in thousandths.
    pub write_milli: u64,
    /// The last write's model's read price, in thousandths.
    pub read_milli: u64,
}

/// The receipt the limit in force is written to, under the authority's git
/// directory's receipt store.
pub const RECEIPT: &str = "cache-evicts-after";

impl InForce {
    /// The receipt's one line: lifetime, write price, read price.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{} {} {}",
            self.lifetime_secs, self.write_milli, self.read_milli
        )
    }

    /// Read a receipt line back, or `None` where it is not one.
    #[must_use]
    pub fn parse(line: &str) -> Option<InForce> {
        let mut fields = line.split_whitespace().map(str::parse::<u64>);
        let in_force = InForce {
            lifetime_secs: fields.next()?.ok()?,
            write_milli: fields.next()?.ok()?,
            read_milli: fields.next()?.ok()?,
        };
        fields.next().is_none().then_some(in_force)
    }

    /// The receipt at `store`, if it reads.
    #[must_use]
    pub fn read(store: &Path) -> Option<InForce> {
        let text = std::fs::read_to_string(store.join(RECEIPT)).ok()?;
        InForce::parse(text.trim())
    }
}

/// The bucket lifetime and model of the LAST cache write in a transcript: the
/// last main-stream assistant record whose usage names a write in a bucket.
///
/// The bucket is the host's own field (`cache_creation.ephemeral_1h_input_tokens`
/// against `ephemeral_5m_input_tokens`), never inferred from billing, which
/// the engine does not see.
//MUTANT-SUITE crates/batten/src/prompt_cache.rs
//MUTANT limit-from-first-write|s@^    for line in transcript.lines().rev() {$@    for line in transcript.lines() {@|the_limit_in_force_follows_the_last_write
#[must_use]
pub fn last_write(transcript: &str) -> Option<(u64, String)> {
    for line in transcript.lines().rev() {
        let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if record.get("isSidechain") == Some(&serde_json::Value::Bool(true)) {
            continue;
        }
        let message = &record["message"];
        if message["role"] != "assistant" {
            continue;
        }
        let creation = &message["usage"]["cache_creation"];
        let written = |key: &str| creation[key].as_u64().is_some_and(|tokens| tokens > 0);
        let lifetime = if written("ephemeral_1h_input_tokens") {
            3600
        } else if written("ephemeral_5m_input_tokens") {
            300
        } else {
            continue;
        };
        let model = message["model"].as_str().unwrap_or_default().to_owned();
        return Some((lifetime, model));
    }
    None
}

/// The limit in force for `transcript` under a host's published figures, or
/// `None` where there is no write, no published bucket, or no read price.
#[must_use]
pub fn in_force(eviction: &Eviction, transcript: &str) -> Option<InForce> {
    let (lifetime, model) = last_write(transcript)?;
    let bucket = eviction.bucket(lifetime)?;
    Some(InForce {
        lifetime_secs: bucket.lifetime_secs,
        write_milli: bucket.write_milli,
        read_milli: eviction.read_milli(&model)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn keep_warm_matches_the_published_table() {
        let rows = [
            (1250, 100),
            (1250, 50),
            (1250, 25),
            (2000, 100),
            (2000, 50),
            (2000, 25),
        ];
        let one: Vec<u64> = rows.iter().map(|(w, r)| wakes_allowed(*w, *r, 1)).collect();
        let two: Vec<u64> = rows.iter().map(|(w, r)| wakes_allowed(*w, *r, 2)).collect();
        assert_eq!(one, vec![11, 24, 49, 19, 39, 79]);
        assert_eq!(two, vec![5, 11, 24, 9, 19, 39]);
        assert!(keep_warm(2000, 25, 2, 38));
        assert!(!keep_warm(2000, 25, 2, 39));
    }

    /// One main-stream assistant record writing `tokens` to the `bucket`.
    fn write(bucket: &str, model: &str) -> String {
        let mut creation = serde_json::Map::new();
        creation.insert(bucket.to_owned(), serde_json::json!(500));
        serde_json::json!({
            "type": "assistant",
            "message": {
                "role": "assistant",
                "model": model,
                "content": [],
                "usage": {"input_tokens": 1, "output_tokens": 1,
                          "cache_creation": creation},
            },
        })
        .to_string()
    }

    fn stop(transcript: &Path, agent: bool, event: &str) -> crate::hook::Envelope {
        let mut payload = serde_json::json!({
            "hook_event_name": event,
            "session_id": "s-1",
            "transcript_path": transcript.display().to_string(),
            "tool_name": "Bash",
            "tool_input": {"command": "true"},
        });
        if agent {
            payload["agent_id"] = serde_json::json!("sub-1");
        }
        crate::hook::decode(crate::hook::Harness::ClaudeCode, &payload.to_string())
            .expect("decodes")
    }

    #[test]
    fn the_limit_in_force_follows_the_last_write() {
        let dir = crate::scratch::scratch("prompt-cache-limit");
        let store = dir.join("receipts");
        let transcript = dir.join("session.jsonl");
        let claude = crate::hook::Harness::ClaudeCode;
        let one_hour = write("ephemeral_1h_input_tokens", "claude-fable-5-2");
        let five_minutes = write("ephemeral_5m_input_tokens", "claude-fable-5-2");
        std::fs::write(&transcript, format!("{five_minutes}\n{one_hour}\n")).expect("t");
        crate::record_cache_limit(&store, claude, &stop(&transcript, false, "Stop"));
        assert_eq!(InForce::read(&store).map(|it| it.lifetime_secs), Some(3600));
        std::fs::write(&transcript, format!("{one_hour}\n{five_minutes}\n")).expect("t");
        crate::record_cache_limit(&store, claude, &stop(&transcript, false, "Stop"));
        assert_eq!(
            InForce::read(&store),
            Some(InForce {
                lifetime_secs: 300,
                write_milli: 1250,
                read_milli: 25
            }),
            "the later write replaces it"
        );
        // A SUBAGENT'S STOP, and a post-tool call, leave it as it was.
        std::fs::write(&transcript, format!("{one_hour}\n")).expect("t");
        crate::record_cache_limit(&store, claude, &stop(&transcript, true, "Stop"));
        crate::record_cache_limit(&store, claude, &stop(&transcript, false, "PostToolUse"));
        assert_eq!(InForce::read(&store).map(|it| it.lifetime_secs), Some(300));
        // NO USAGE, and a host with no table, remove it.
        std::fs::write(&transcript, "{\"type\":\"user\"}\n").expect("t");
        crate::record_cache_limit(&store, claude, &stop(&transcript, false, "Stop"));
        assert_eq!(InForce::read(&store), None, "no usage removes the file");
        std::fs::write(&transcript, format!("{one_hour}\n")).expect("t");
        crate::record_cache_limit(&store, claude, &stop(&transcript, false, "Stop"));
        assert!(InForce::read(&store).is_some(), "the premise");
        crate::record_cache_limit(
            &store,
            crate::hook::Harness::CodexCli,
            &stop(&transcript, false, "Stop"),
        );
        assert_eq!(
            InForce::read(&store),
            None,
            "a host with no table removes it"
        );
    }

    #[test]
    fn a_receipt_line_round_trips() {
        let in_force = InForce {
            lifetime_secs: 3600,
            write_milli: 2000,
            read_milli: 25,
        };
        assert_eq!(InForce::parse(&in_force.line()), Some(in_force));
        assert_eq!(InForce::parse("3600 2000"), None);
    }
}

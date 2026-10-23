//! The hook's stdin, read streaming (CLOUD-2224).
//!
//! **One pass, memory bounded by the token bound rather than by the payload.**
//! Every byte read is teed into a spool file, so a handler is handed the exact
//! document the host sent (streamed from that file, never re-serialized) and
//! the capture store gets the host's own bytes. The same bytes are parsed by a
//! pull reader ([`struson`]) whose string values are themselves readers, so the
//! one member that can be enormous — a tool result's text — never has to be held
//! whole:
//!
//! * a result string leaf is read in chunks and counted in `o200k` tokens as it
//!   arrives; while the RESULT's running total is within the bound the leaf is
//!   kept, so a result under the bound reaches the model verbatim;
//! * past the bound, what was buffered and everything after it streams to a
//!   leaf file, and the parsed value carries a marker in its place, so nothing
//!   downstream holds the bulk either.
//!
//! Measured before the switch (`examples/hook-read-bench.rs`, recorded on
//! CLOUD-2224): reading a 50 MB payload whole peaked at 150 MiB and 248-284 ms;
//! streamed, 2.4 MiB (the process baseline) and 179-210 ms.

//MUTANT-SUITE crates/batten/src/stream_input.rs
//MUTANT tee-drops-bytes|s@^        self.sink.write_all(buf.get(..read).unwrap_or_default())?;$@@|the_spool_holds_the_exact_bytes_the_host_sent

use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use struson::reader::{JsonReader, JsonStreamReader, ValueType};

/// The top-level members a host puts a tool's result under — the same alias
/// walk [`crate::hook::decode`] reads `result` through.
pub const RESULT_KEYS: [&str; 3] = ["tool_response", "toolResponse", "tool_result"];

/// The chunk a string leaf is read in, 16 KiB, written as the literal: only the
/// read granularity rides on it, so no case can tell a product from a sum.
const CHUNK: usize = 16_384;

/// One result leaf too large to keep: where its text went and what stands in
/// its place in the parsed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spilled {
    /// The leaf's RFC 6901 pointer within the result.
    pub pointer: String,
    /// The file holding the leaf's whole text.
    pub path: PathBuf,
    /// How many bytes the text is.
    pub bytes: u64,
}

/// What one streamed read produced.
#[derive(Debug)]
pub struct Streamed {
    /// The document, with every spilled leaf replaced by [`marker`] text.
    pub value: Value,
    /// The exact bytes the host sent, spooled.
    pub raw: PathBuf,
    /// The leaves that went to files, in document order.
    pub spilled: Vec<Spilled>,
}

/// The text a spilled leaf's place holds until the caller replaces it with its
/// pointer line — distinct enough that no tool output is mistaken for one.
#[must_use]
pub fn marker(pointer: &str) -> String {
    format!("\u{0}batten-spilled:{pointer}\u{0}")
}

/// The largest spilled leaf [`restore`] reads back, in bytes.
///
/// The recorders that judge a call's response (the board's write record above
/// all) read the tracker's own JSON, which is kilobytes; a leaf past this stays
/// a marker, so the memory bound CLOUD-2224 bought still holds for the bulk.
pub const RESTORE_MAX_BYTES: u64 = 1 << 20;

/// `value` with each spilled leaf at or under [`RESTORE_MAX_BYTES`] put back
/// from its file, for the recorders.
///
/// A recorder reading the marker recorded the call as answering nothing: on
/// #1132 every `save_issue` whose response spilled was written to the board
/// record as `unready`, and the filed-row guard then refused every edit
/// (CLOUD-2224's regression). What reaches the MODEL is still the pointer.
#[must_use]
pub fn restore(value: &Value, spilled: &[Spilled]) -> Value {
    fn put(value: &mut Value, marker: &str, text: &str) {
        match value {
            Value::String(leaf) if leaf == marker => text.clone_into(leaf),
            Value::Array(items) => items.iter_mut().for_each(|item| put(item, marker, text)),
            Value::Object(fields) => fields
                .values_mut()
                .for_each(|field| put(field, marker, text)),
            _ => {}
        }
    }
    let mut restored = value.clone();
    for spill in spilled
        .iter()
        .filter(|spill| spill.bytes <= RESTORE_MAX_BYTES)
    {
        if let Ok(text) = std::fs::read_to_string(&spill.path) {
            put(&mut restored, &marker(&spill.pointer), &text);
        }
    }
    restored
}

/// Every byte the parser pulls is also written to the spool.
struct Tee<R, W> {
    inner: R,
    sink: W,
}

impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.sink.write_all(buf.get(..read).unwrap_or_default())?;
        Ok(read)
    }
}

/// The parse state the walk threads through: where spills go, the bound, the
/// running token total of the result, and the counter.
struct Walk<'a, C: FnMut(&str) -> u64> {
    spill_dir: &'a Path,
    bound: u64,
    counted: u64,
    over: bool,
    count: C,
    spilled: Vec<Spilled>,
}

/// Read one hook payload from `input`, streaming.
///
/// `spool_dir` receives the raw spool and any leaf files; `bound` is the
/// result's `o200k` token bound and `count` the tokenizer, injected so a case
/// can count what it was asked to encode.
///
/// # Errors
///
/// When the input is not one JSON document or a spool file cannot be written:
/// the caller's could-not-look, exactly as an undecodable buffered payload was.
pub fn read(
    input: impl Read,
    spool_dir: &Path,
    bound: u64,
    count: impl FnMut(&str) -> u64,
) -> Result<Streamed> {
    std::fs::create_dir_all(spool_dir)
        .with_context(|| format!("create the hook spool {}", spool_dir.display()))?;
    let raw = spool_dir.join(format!("payload-{}.json", std::process::id()));
    let spool = std::io::BufWriter::new(
        // The host's bytes, teed as they are parsed and read back by this
        // process alone: committed when the parse returns.
        std::fs::File::create(&raw) // stream: the hook spool
            .with_context(|| format!("spool {}", raw.display()))?,
    );
    let mut bom = [0_u8; 3];
    let mut input = BufReader::with_capacity(CHUNK, input);
    // A LEADING BOM IS DROPPED, on every host, as `decode` did: Cursor's Windows
    // stdin prefixes one, and it is never meaningful in these payloads.
    let peeked = std::io::BufRead::fill_buf(&mut input)?;
    let skip = usize::from(peeked.starts_with(&[0xEF, 0xBB, 0xBF])) * 3;
    if skip > 0 {
        input.read_exact(&mut bom)?;
    }
    let tee = Tee {
        inner: input,
        sink: spool,
    };
    let mut json = JsonStreamReader::new(tee);
    let mut walk = Walk {
        spill_dir: spool_dir,
        bound,
        counted: 0,
        over: false,
        count,
        spilled: Vec::new(),
    };
    let value = walk.document(&mut json)?;
    json.consume_trailing_whitespace()
        .context("the payload is more than one JSON document")?;
    Ok(Streamed {
        value,
        raw,
        spilled: walk.spilled,
    })
}

//MUTANT leaf-never-spills|s@^                if self.counted > self.bound {$@                if false {@|a_result_over_the_bound_spills_and_one_under_it_is_kept
impl<C: FnMut(&str) -> u64> Walk<'_, C> {
    /// The top level: an object whose result members are walked as results.
    fn document<R: Read>(&mut self, json: &mut JsonStreamReader<R>) -> Result<Value> {
        if json.peek()? != ValueType::Object {
            return Self::plain(json);
        }
        json.begin_object()?;
        let mut map = serde_json::Map::new();
        while json.has_next()? {
            let name = json.next_name_owned()?;
            let value = if RESULT_KEYS.contains(&name.as_str()) {
                self.result(json, "")?
            } else {
                Self::plain(json)?
            };
            map.insert(name, value);
        }
        json.end_object()?;
        Ok(Value::Object(map))
    }

    /// Any value outside a result, parsed as it is.
    fn plain<R: Read>(json: &mut JsonStreamReader<R>) -> Result<Value> {
        Ok(match json.peek()? {
            ValueType::Object => {
                json.begin_object()?;
                let mut map = serde_json::Map::new();
                while json.has_next()? {
                    let name = json.next_name_owned()?;
                    let value = Self::plain(json)?;
                    map.insert(name, value);
                }
                json.end_object()?;
                Value::Object(map)
            }
            ValueType::Array => {
                json.begin_array()?;
                let mut items = Vec::new();
                while json.has_next()? {
                    items.push(Self::plain(json)?);
                }
                json.end_array()?;
                Value::Array(items)
            }
            ValueType::String => Value::String(json.next_string()?),
            ValueType::Number => {
                let number = json.next_number_as_string()?;
                serde_json::from_str(&number).context("a JSON number")?
            }
            ValueType::Boolean => Value::Bool(json.next_bool()?),
            ValueType::Null => {
                json.next_null()?;
                Value::Null
            }
        })
    }

    /// A value inside a result: containers walked, string leaves streamed.
    fn result<R: Read>(&mut self, json: &mut JsonStreamReader<R>, pointer: &str) -> Result<Value> {
        Ok(match json.peek()? {
            ValueType::Object => {
                json.begin_object()?;
                let mut map = serde_json::Map::new();
                while json.has_next()? {
                    let name = json.next_name_owned()?;
                    let escaped = name.replace('~', "~0").replace('/', "~1");
                    let value = self.result(json, &format!("{pointer}/{escaped}"))?;
                    map.insert(name, value);
                }
                json.end_object()?;
                Value::Object(map)
            }
            ValueType::Array => {
                json.begin_array()?;
                let mut items = Vec::new();
                let mut index = 0usize;
                while json.has_next()? {
                    items.push(self.result(json, &format!("{pointer}/{index}"))?);
                    index += 1;
                }
                json.end_array()?;
                Value::Array(items)
            }
            ValueType::String => self.leaf(json, pointer)?,
            _ => Self::plain(json)?,
        })
    }

    /// One result string, read in chunks: kept while the result is within the
    /// bound, spilled to a file from the chunk that passes it.
    fn leaf<R: Read>(&mut self, json: &mut JsonStreamReader<R>, pointer: &str) -> Result<Value> {
        let mut text = json.next_string_reader()?;
        let mut kept = String::new();
        let mut file: Option<(std::io::BufWriter<std::fs::File>, PathBuf)> = None;
        let mut bytes: u64 = 0;
        let mut chunk = vec![0_u8; CHUNK];
        let mut carry: Vec<u8> = Vec::new();
        loop {
            let read = text.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            bytes += read as u64;
            if let Some((out, _)) = file.as_mut() {
                out.write_all(chunk.get(..read).unwrap_or_default())?;
                continue;
            }
            // A chunk can end inside a UTF-8 sequence; the remainder carries.
            carry.extend_from_slice(chunk.get(..read).unwrap_or_default());
            let valid = match std::str::from_utf8(&carry) {
                Ok(all) => all.len(),
                Err(cut) => cut.valid_up_to(),
            };
            let piece = std::str::from_utf8(carry.get(..valid).unwrap_or_default())
                .unwrap_or_default()
                .to_owned();
            carry.drain(..valid);
            if !self.over {
                self.counted += (self.count)(&piece);
                if self.counted > self.bound {
                    self.over = true;
                }
            }
            kept.push_str(&piece);
            if self.over && kept.len() > crate::capture::LEAF_KEEP_BYTES {
                let path = self.spill_dir.join(format!(
                    "leaf-{}-{}.txt",
                    std::process::id(),
                    self.spilled.len()
                ));
                let mut out = std::io::BufWriter::new(
                    // One leaf's bulk, committed by the flush that records it
                    // in `Spilled`.
                    std::fs::File::create(&path) // stream: a spilled leaf
                        .with_context(|| format!("spill {}", path.display()))?,
                );
                out.write_all(kept.as_bytes())?;
                out.write_all(&carry)?;
                carry.clear();
                kept.clear();
                file = Some((out, path));
            }
        }
        drop(text);
        if let Some((mut out, path)) = file {
            out.flush()?;
            self.spilled.push(Spilled {
                pointer: pointer.to_owned(),
                path,
                bytes,
            });
            return Ok(Value::String(marker(pointer)));
        }
        kept.push_str(&String::from_utf8_lossy(&carry));
        Ok(Value::String(kept))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-stream-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn payload(text: &str) -> String {
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "x"},
            "tool_response": {"type": "text", "file": {"content": text, "numLines": 2}},
        })
        .to_string()
    }

    #[test]
    fn a_result_over_the_bound_spills_and_one_under_it_is_kept() {
        let dir = scratch("bound");
        let big = "word ".repeat(40_000);
        let read = super::read(payload(&big).as_bytes(), &dir, 1000, |text| {
            text.split_whitespace().count() as u64
        })
        .expect("reads");
        assert_eq!(read.spilled.len(), 1, "{:?}", read.spilled);
        assert_eq!(read.spilled[0].pointer, "/file/content");
        assert_eq!(
            std::fs::read_to_string(&read.spilled[0].path).expect("leaf"),
            big,
            "the leaf file holds the whole text"
        );
        assert_eq!(
            read.value["tool_response"]["file"]["content"],
            marker("/file/content")
        );
        assert_eq!(read.value["tool_response"]["file"]["numLines"], 2);

        let small = "word ".repeat(100);
        let kept = super::read(payload(&small).as_bytes(), &dir, 1000, |text| {
            text.split_whitespace().count() as u64
        })
        .expect("reads");
        assert!(kept.spilled.is_empty());
        assert_eq!(
            kept.value["tool_response"]["file"]["content"],
            small.as_str()
        );
    }

    #[test]
    fn the_spool_holds_the_exact_bytes_the_host_sent() {
        let dir = scratch("raw");
        let sent = format!("\u{feff}{}", payload("é and \\\"quoted\\\" text"));
        let read =
            super::read(sent.as_bytes(), &dir, 1000, |text| text.len() as u64).expect("reads");
        let spooled = std::fs::read_to_string(&read.raw).expect("raw");
        assert_eq!(
            spooled,
            sent.trim_start_matches('\u{feff}'),
            "byte for byte, BOM aside"
        );
    }

    /// A recorder sees the response the tracker sent, not the marker that
    /// stands in for it on the way to the model; a leaf past the cap stays a
    /// marker (CLOUD-2224's regression, task #31 on #1132).
    #[test]
    fn a_spilled_leaf_is_restored_for_the_recorders_up_to_the_cap() {
        let dir = scratch("restore");
        let big = "word ".repeat(40_000);
        let read = super::read(payload(&big).as_bytes(), &dir, 1000, |text| {
            text.split_whitespace().count() as u64
        })
        .expect("reads");
        let restored = restore(&read.value, &read.spilled);
        assert_eq!(
            restored["tool_response"]["file"]["content"],
            big.as_str(),
            "the recorder reads the whole leaf"
        );
        assert_eq!(
            read.value["tool_response"]["file"]["content"],
            marker("/file/content"),
            "the model-facing value keeps its marker"
        );
        let mut huge = read.spilled.clone();
        huge[0].bytes = RESTORE_MAX_BYTES + 1;
        assert_eq!(
            restore(&read.value, &huge)["tool_response"]["file"]["content"],
            marker("/file/content"),
            "a leaf past the cap is never read back"
        );
    }

    /// Fails by: a marker inside an array left in place, or a string that is not
    /// the marker overwritten with the leaf.
    #[test]
    fn only_the_marker_is_restored_wherever_it_sits() {
        let dir = scratch("restore-array");
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("leaf.txt");
        std::fs::write(&path, "restored").expect("leaf");
        let value = serde_json::json!({"a": [marker("/p"), "kept"]});
        let spilled = [Spilled {
            pointer: "/p".to_owned(),
            path,
            bytes: 8,
        }];
        assert_eq!(
            restore(&value, &spilled),
            serde_json::json!({"a": ["restored", "kept"]})
        );
    }

    /// Fails by: a result array's leaves not streamed, or a spilled leaf filed
    /// under the wrong index or with the wrong length.
    #[test]
    fn a_leaf_inside_a_result_array_spills_under_its_index() {
        let dir = scratch("array");
        let big = "q".repeat(40_000);
        let sent = serde_json::json!({"tool_response": ["small", big]}).to_string();
        let read = super::read(sent.as_bytes(), &dir, 1000, q_count).expect("reads");
        assert_eq!(read.spilled.len(), 1, "{:?}", read.spilled);
        assert_eq!(read.spilled[0].pointer, "/1");
        assert_eq!(read.spilled[0].bytes, 40_000);
        assert_eq!(
            read.value["tool_response"],
            serde_json::json!(["small", marker("/1")])
        );
        assert_eq!(marker("/1"), "\u{0}batten-spilled:/1\u{0}");
    }

    /// Fails by: a leaf of exactly the kept length spilled once the bound is
    /// passed — a leaf that short is kept whole whatever the result's total.
    #[test]
    fn a_leaf_no_longer_than_the_kept_length_is_never_spilled() {
        let dir = scratch("keep");
        let at = "q".repeat(crate::capture::LEAF_KEEP_BYTES);
        let kept = super::read(payload(&at).as_bytes(), &dir, 0, q_count).expect("reads");
        assert!(kept.spilled.is_empty(), "{:?}", kept.spilled);
        let past = "q".repeat(crate::capture::LEAF_KEEP_BYTES + 1);
        let over = super::read(payload(&past).as_bytes(), &dir, 0, q_count).expect("reads");
        assert_eq!(over.spilled.len(), 1);
    }

    /// Fails by: a result whose count reaches the bound exactly treated as past
    /// it — the bound is the most a kept result may count.
    #[test]
    fn a_result_counting_exactly_the_bound_is_kept() {
        let dir = scratch("at-bound");
        let sent = payload(&"q".repeat(40_000));
        let kept = super::read(sent.as_bytes(), &dir, 40_000, q_count).expect("reads");
        assert!(kept.spilled.is_empty(), "{:?}", kept.spilled);
        let over = super::read(sent.as_bytes(), &dir, 39_999, q_count).expect("reads");
        assert_eq!(over.spilled.len(), 1);
    }

    /// A counter that charges one token per `q`, so a fixture's count is its
    /// length in `q`s.
    fn q_count(text: &str) -> u64 {
        u64::try_from(text.matches('q').count()).unwrap_or(u64::MAX)
    }
}

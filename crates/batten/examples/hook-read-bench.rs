//! Peak memory and wall time of reading one hook payload three ways (CLOUD-2224).
//!
//! `hook-read-bench <mode> <payload.json>`, one mode per process so the peak
//! resident set (`VmHWM`) is that mode's alone:
//!
//! * `current` — the hook's path today: read stdin to a string, parse into a
//!   `serde_json::Value`, serialize it again for the capture store, digest it.
//! * `reader` — `serde_json::from_reader` into a `Value`: no string copy of the
//!   input, but still a whole tree, and each string leaf held whole.
//! * `struson` — a pull parse that streams every string leaf through its own
//!   reader in fixed chunks into the digest; nothing is held whole.
//!
//! `gen <bytes> <path>` writes a `PostToolUse` `Read` payload of about that size.
//! Prints one line: mode, input bytes, wall ms, peak RSS KiB, digest prefix.

// A measurement program: a failed read is the run's answer, printed and fatal.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used)]

use std::io::{BufReader, Read, Write};

const CHUNK: usize = 16 * 1024;

#[expect(
    clippy::disallowed_methods,
    reason = "bounded: `peak_rss_kib` reads a kernel-sized /proc record"
)]
fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|rest| rest.trim().trim_end_matches(" kB").trim().parse().ok())
        })
        .unwrap_or(0)
}

fn generate(bytes: usize, path: &str) -> std::io::Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    out.write_all(
        br#"{"hook_event_name":"PostToolUse","session_id":"bench","tool_name":"Read","tool_input":{"file_path":"big.log"},"tool_response":{"type":"text","file":{"filePath":"/repo/big.log","content":""#,
    )?;
    let line = "payload line of a large log, with some \\\"quoted\\\" text and a tab\\t here\\n";
    let mut written = 0;
    while written < bytes {
        out.write_all(line.as_bytes())?;
        written += line.len();
    }
    out.write_all(br#"","numLines":1,"startLine":1,"totalLines":1}}}"#)?;
    out.flush()
}

fn current(path: &str) -> (u64, String) {
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|mut file| file.read_to_string(&mut text))
        .expect("read");
    let value: serde_json::Value = serde_json::from_str(&text).expect("parse");
    let bytes = serde_json::to_vec(&value["tool_response"]).expect("serialize");
    (
        text.len() as u64,
        blake3::hash(&bytes).to_hex()[..12].to_owned(),
    )
}

fn reader(path: &str) -> (u64, String) {
    let file = std::fs::File::open(path).expect("open");
    let len = file.metadata().map_or(0, |meta| meta.len());
    let value: serde_json::Value = serde_json::from_reader(BufReader::new(file)).expect("parse");
    let bytes = serde_json::to_vec(&value["tool_response"]).expect("serialize");
    (len, blake3::hash(&bytes).to_hex()[..12].to_owned())
}

fn streamed(path: &str) -> (u64, String) {
    use struson::reader::{JsonReader, JsonStreamReader, ValueType};
    fn walk(
        json: &mut JsonStreamReader<BufReader<std::fs::File>>,
        hasher: &mut blake3::Hasher,
        chunk: &mut [u8],
    ) {
        match json.peek().expect("peek") {
            ValueType::Object => {
                json.begin_object().expect("object");
                while json.has_next().expect("next") {
                    let _ = json.next_name().expect("name");
                    walk(json, hasher, chunk);
                }
                json.end_object().expect("end object");
            }
            ValueType::Array => {
                json.begin_array().expect("array");
                while json.has_next().expect("next") {
                    walk(json, hasher, chunk);
                }
                json.end_array().expect("end array");
            }
            ValueType::String => {
                let mut leaf = json.next_string_reader().expect("string reader");
                loop {
                    let read = leaf.read(chunk).expect("read leaf");
                    if read == 0 {
                        break;
                    }
                    hasher.update(&chunk[..read]);
                }
                drop(leaf);
            }
            _ => json.skip_value().expect("skip"),
        }
    }
    let file = std::fs::File::open(path).expect("open");
    let len = file.metadata().map_or(0, |meta| meta.len());
    let mut json = JsonStreamReader::new(BufReader::with_capacity(CHUNK, file));
    let mut hasher = blake3::Hasher::new();
    let mut chunk = vec![0_u8; CHUNK];
    walk(&mut json, &mut hasher, &mut chunk);
    json.consume_trailing_whitespace().expect("trailing");
    (len, hasher.finalize().to_hex()[..12].to_owned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("", String::as_str);
    if mode == "gen" {
        let bytes: usize = args[2].parse().expect("bytes");
        generate(bytes, &args[3]).expect("generate");
        return;
    }
    if mode == "o200k-longest" {
        // The longest token's byte length: a result over `bound * longest`
        // bytes is over the bound with no count at all.
        let bpe = tiktoken_rs::o200k_base().expect("table");
        let longest = (0..200_019_u32)
            .filter_map(|rank| bpe.decode_bytes(&[rank]).ok())
            .map(|bytes| bytes.len())
            .max()
            .unwrap_or(0);
        println!("o200k-longest\t{longest} bytes");
        return;
    }
    if mode == "bpe-load" {
        // GitHub's prebuilt encoder: the same two numbers as `o200k-load`, plus
        // whether its count agrees with tiktoken-rs on the same text.
        let text = "payload line of a large log, with some text\n".repeat(93);
        let started = std::time::Instant::now();
        let tokenizer = bpe_openai::o200k_base();
        let first = tokenizer.count(&text);
        let loaded = started.elapsed().as_secs_f64() * 1000.0;
        let counted_at = std::time::Instant::now();
        let tokens = tokenizer.count(&text);
        let counted = counted_at.elapsed().as_secs_f64() * 1000.0;
        println!(
            "bpe-load\t{loaded:.1}ms load+first count\t{counted:.2}ms for {tokens} tokens\t{}KiB\tfirst={first}",
            peak_rss_kib()
        );
        return;
    }
    if mode == "o200k-regex" {
        // The pre-tokenizer alone: o200k's split pattern compiled and run once,
        // so the table load splits into regex compile and vocabulary build.
        const PATTERN: &str = concat!(
            r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
            r"|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
            r"|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+",
        );
        let started = std::time::Instant::now();
        let regex = fancy_regex::Regex::new(PATTERN).expect("pattern");
        let compiled = started.elapsed().as_secs_f64() * 1000.0;
        let text = "payload line of a large log, with some text\n".repeat(93);
        let split_at = std::time::Instant::now();
        let pieces = regex.find_iter(&text).count();
        let split = split_at.elapsed().as_secs_f64() * 1000.0;
        println!(
            "o200k-regex\t{compiled:.1}ms compile\t{split:.2}ms for {pieces} pieces\t{}KiB",
            peak_rss_kib()
        );
        return;
    }
    if mode == "static-load" {
        // The compile-time table (CLOUD-2224): nothing to build, so the first
        // call is the regex compile plus the count itself.
        let text = "payload line of a large log, with some text\n".repeat(93);
        let started = std::time::Instant::now();
        let first = batten::o200k::tokens(&text);
        let loaded = started.elapsed().as_secs_f64() * 1000.0;
        let counted_at = std::time::Instant::now();
        let tokens = batten::o200k::tokens(&text);
        let counted = counted_at.elapsed().as_secs_f64() * 1000.0;
        println!(
            "static-load\t{loaded:.2}ms first call\t{counted:.2}ms for {tokens} tokens\t{}KiB\tfirst={first}",
            peak_rss_kib()
        );
        return;
    }
    if mode == "o200k-load" {
        // The one-off cost a hook process pays to load the table, and then to
        // count one ordinary 4 KiB result, which is what a lazy load buys back.
        let started = std::time::Instant::now();
        let bpe = tiktoken_rs::o200k_base().expect("table");
        let loaded = started.elapsed().as_secs_f64() * 1000.0;
        let text = "payload line of a large log, with some text\n".repeat(93);
        let counted_at = std::time::Instant::now();
        let tokens = bpe.encode_ordinary(&text).len();
        let counted = counted_at.elapsed().as_secs_f64() * 1000.0;
        println!(
            "o200k-load\t{loaded:.1}ms load\t{counted:.2}ms for {tokens} tokens\t{}KiB",
            peak_rss_kib()
        );
        return;
    }
    let path = args.get(2).expect("payload path");
    let started = std::time::Instant::now();
    let (len, digest) = match mode {
        "current" => current(path),
        "reader" => reader(path),
        "struson" => streamed(path),
        other => panic!("unknown mode {other}"),
    };
    let wall = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{mode}\t{len}\t{wall:.1}ms\t{}KiB\t{digest}",
        peak_rss_kib()
    );
}

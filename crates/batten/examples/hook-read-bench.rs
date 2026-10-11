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
//! `gen <bytes> <path>` writes a PostToolUse `Read` payload of about that size.
//! Prints one line: mode, input bytes, wall ms, peak RSS KiB, digest prefix.

use std::io::{BufReader, Read, Write};

const CHUNK: usize = 16 * 1024;

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
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
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
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
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

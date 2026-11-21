//! Query a sampling profile the way an agent reads, not the way a person looks.
//!
//! `samply record --save-only --unstable-presymbolicate -o P.json` writes the
//! Firefox Profiler's processed format plus a `P.syms.json` symbol sidecar. A
//! flame graph of it is for eyes; dumping its stacks floods a context window
//! (PerfAgent, arXiv 2607.19653: a curated hotspot report beat profiler
//! instructions 44.1 to 17.6 Opt@1). So this answers three narrow questions,
//! each as a handful of one-line rows — a share, a name, a `file:line`:
//!
//! * `hot P.json [--top N] [--min PCT] [--all]` — the heaviest frames by
//!   inclusive and by self share. Runtime and libc frames are hidden unless
//!   `--all` (v8-cpu-profile-decoder-mcp's default filter); generic arguments
//!   are stripped from names, which is most of a Rust symbol's length.
//! * `callers P.json NAME [--top N]` — the distinct paths into frames whose name
//!   contains NAME, three frames deep, with their share.
//! * `diff A.json B.json [--top N]` — inclusive share per frame, B minus A,
//!   largest movement first: the re-profile after a patch.
//!
//! Inline frames come from the sidecar's per-address frame lists, so a function
//! LTO folded into its caller still has its own row. Call COUNTS are not a
//! sampler's to give; `callgrind_annotate --tree=caller` gives them
//! (`skills/profile`).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;

/// One frame as an agent reads it: a short name and where it is.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Frame {
    name: String,
    at: String,
}

/// A profile reduced to weighted stacks of frames, outermost first.
struct Stacks {
    total: u64,
    stacks: Vec<(Vec<Frame>, u64)>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("batten-profile: {message}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str = "usage: batten-profile record ARM [--rate HZ] [--iterations N] [--out P.json] \
                     | hot P.json [--top N] [--min PCT] [--all] \
                     | callers P.json NAME [--top N] | diff A.json B.json [--top N] \
                     | calls CALLGRIND.out NAME";

/// The arms `batten perf measure` times, as (payload under the hook fixtures,
/// arguments after the binary, whether it runs in the staged `check-repo`).
/// The same commands, so a profile describes what the gate measured.
const ARMS: [(&str, Option<&str>, &[&str], bool); 6] = [
    ("noop", None, &["--help"], false),
    ("check", None, &["check"], true),
    (
        "hook",
        Some("claude-code.json"),
        &["adjudicate", "--harness", "claude-code"],
        false,
    ),
    (
        "passthrough",
        Some("claude-code-passthrough.json"),
        &["adjudicate", "--harness", "claude-code"],
        false,
    ),
    (
        "posttool",
        Some("claude-code-posttool.json"),
        &["adjudicate", "--harness", "claude-code"],
        false,
    ),
    (
        "stop",
        Some("claude-code-stop.json"),
        &["adjudicate", "--harness", "claude-code"],
        true,
    ),
];

fn flag<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn run(args: &[String]) -> Result<String, String> {
    let top = flag(args, "--top", 15_usize);
    let all = args.iter().any(|a| a == "--all");
    match (args.first().map(String::as_str), args.get(1), args.get(2)) {
        (Some("hot"), Some(path), _) => Ok(hot(
            &load(Path::new(path), all)?,
            top,
            flag(args, "--min", 1.0),
        )),
        (Some("callers"), Some(path), Some(name)) => callers(
            &load(Path::new(path), all)?,
            name,
            top,
            flag(args, "--depth", 3_usize),
        ),
        (Some("diff"), Some(a), Some(b)) => Ok(diff(
            &load(Path::new(a), all)?,
            &load(Path::new(b), all)?,
            top,
        )),
        (Some("calls"), Some(path), Some(name)) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            calls(&text, name)
        }
        (Some("record"), Some(arm), _) => {
            let out = args
                .iter()
                .position(|a| a == "--out")
                .and_then(|i| args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| format!("target/profile/{arm}.json"));
            record(
                arm,
                flag(args, "--rate", 10_000_u32),
                flag(args, "--iterations", 10_u32),
                Path::new(&out),
            )?;
            Ok(format!(
                "{out}\n{}",
                hot(&load(Path::new(&out), all)?, top, flag(args, "--min", 1.0))
            ))
        }
        _ => Err(USAGE.to_owned()),
    }
}

/// Exact call counts into frames whose name contains `needle`, per caller, from
/// a callgrind output file: what a sampler cannot give and what proves a claim
/// like "computed three times per call".
///
/// The format names a function once as `(id) name` and by `(id)` after; a
/// `calls=N …` line counts calls into the preceding `cfn=`, made from the
/// current `fn=`.
fn calls(text: &str, needle: &str) -> Result<String, String> {
    let mut names: HashMap<String, String> = HashMap::new();
    let mut resolve = |spec: &str| -> String {
        let spec = spec.trim();
        match spec.strip_prefix('(').and_then(|rest| rest.split_once(')')) {
            Some((id, "")) => names.get(id).cloned().unwrap_or_else(|| format!("({id})")),
            Some((id, name)) => {
                let name = short(name.trim());
                names.insert(id.to_owned(), name.clone());
                name
            }
            None => short(spec),
        }
    };
    let (mut current, mut callee) = (String::new(), None::<String>);
    let mut counted: HashMap<(String, String), u64> = HashMap::new();
    for line in text.lines() {
        if let Some(spec) = line.strip_prefix("fn=") {
            current = resolve(spec);
        } else if let Some(spec) = line.strip_prefix("cfn=") {
            callee = Some(resolve(spec));
        } else if let Some(rest) = line.strip_prefix("calls=") {
            if let Some(called) = callee.take().filter(|c| c.contains(needle)) {
                let n: u64 = rest
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                *counted.entry((called, current.clone())).or_default() += n;
            }
        }
    }
    if counted.is_empty() {
        return Err(format!(
            "no call into a function containing `{needle}`; record with --toggle-collect unset or wider"
        ));
    }
    let mut rows: Vec<((String, String), u64)> = counted.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let total: u64 = rows.iter().map(|(_, n)| n).sum();
    let mut out = format!("{total} calls into `{needle}`\n");
    for ((called, caller), n) in rows {
        let _ = writeln!(out, "{n:>8}  {caller} -> {called}");
    }
    Ok(out)
}

/// Restores `kernel.perf_event_paranoid` when dropped, so an error or a panic
/// mid-recording cannot leave the host's setting lowered.
struct Paranoid(Option<String>);

const PARANOID: &str = "/proc/sys/kernel/perf_event_paranoid";

impl Paranoid {
    /// Lower the setting to 1 only if it is above, remembering the original.
    /// samply needs `<= 1`; an unwritable setting is reported, not worked around.
    fn lower() -> Result<Self, String> {
        let now = std::fs::read_to_string(PARANOID).map_err(|e| format!("{PARANOID}: {e}"))?;
        if now.trim().parse::<i32>().map_or(true, |level| level <= 1) {
            return Ok(Self(None));
        }
        std::fs::write(PARANOID, "1")
            .map_err(|e| format!("samply needs {PARANOID} <= 1 and it is {}: {e}", now.trim()))?;
        Ok(Self(Some(now)))
    }
}

impl Drop for Paranoid {
    fn drop(&mut self) {
        if let Some(original) = self.0.take() {
            let _ = std::fs::write(PARANOID, original.trim());
        }
    }
}

/// `'…'`-quote a word for `sh -c`.
fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// The iteration's shell script. NOT `exec`, and the status is discarded:
/// samply skips every remaining iteration after a non-zero exit, and `stop`
/// and every refusing arm exit 2 by design — the deny channel — so an
/// `exec`'d run recorded one cold iteration of ten.
fn wrapped(command: &[String]) -> String {
    format!("{}; exit 0", command.join(" "))
}

/// Build the `profiling` binary and sample `arm` with the pinned samply,
/// writing `out` and its `.syms.json` sidecar. Every iteration gets its own
/// stdin through `sh -c '… < payload'`: a bare redirect would be consumed by
/// the first and leave the rest adjudicating nothing.
fn record(arm: &str, rate: u32, iterations: u32, out: &Path) -> Result<(), String> {
    let repo = std::env::current_dir().map_err(|e| e.to_string())?;
    let (_, payload, argv, staged) =
        ARMS.iter().find(|(name, ..)| *name == arm).ok_or_else(|| {
            let names: Vec<&str> = ARMS.iter().map(|(name, ..)| *name).collect();
            format!("unknown arm `{arm}`; one of {}", names.join(", "))
        })?;
    let dir = if *staged {
        repo.join("target/perf/check-repo")
    } else {
        repo.clone()
    };
    if !dir.is_dir() {
        return Err(format!(
            "{} is missing: run `mise run perf` once to stage it",
            dir.display()
        ));
    }
    let status = std::process::Command::new("mise")
        .args([
            "exec",
            "--",
            "cargo",
            "build",
            "--profile",
            "profiling",
            "-q",
            "-p",
            "batten",
            "--bin",
            "batten",
        ])
        .current_dir(&repo)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !status.success() {
        return Err("the profiling build failed".to_owned());
    }
    let binary = repo.join("target/profiling/batten");
    let mut command: Vec<String> = vec![quote(&binary.to_string_lossy())];
    command.extend(argv.iter().map(|word| quote(word)));
    if let Some(payload) = payload {
        let file = repo
            .join("crates/batten/tests/fixtures/hooks")
            .join(payload);
        command.push(format!("< {}", quote(&file.to_string_lossy())));
    }
    let out = repo.join(out);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let _restore = Paranoid::lower()?;
    let status = std::process::Command::new("mise")
        .args([
            "exec",
            "--",
            "samply",
            "record",
            "--save-only",
            "--unstable-presymbolicate",
        ])
        .args([
            "--rate",
            &rate.to_string(),
            "--iteration-count",
            &iterations.to_string(),
        ])
        .arg("-o")
        .arg(&out)
        .args(["--", "sh", "-c", &wrapped(&command)])
        .current_dir(&dir)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("samply: {e}"))?;
    if !status.success() {
        return Err(format!("samply exited {status}"));
    }
    Ok(())
}

/// Frames a reader of batten's own code does not act on: the runtime, libc,
/// the allocator, and std's iterator and pointer plumbing.
fn is_noise(frame: &Frame) -> bool {
    const PREFIXES: [&str; 6] = [
        "/rustc/",
        "./",
        "/usr/",
        "/root/.rustup/",
        "../sysdeps",
        "glibc",
    ];
    const NAMES: [&str; 7] = [
        "_start",
        "main",
        "__libc",
        "_GI_",
        "mi_",
        "_mem",
        "lang_start",
    ];
    PREFIXES.iter().any(|p| frame.at.starts_with(p))
        || NAMES.iter().any(|n| frame.name.starts_with(n))
        || frame.at.is_empty() && frame.name.contains('+')
}

/// `foo<alloc::vec::Vec<u8>, Bar>` → `foo<…>`: the generic arguments are most
/// of a Rust symbol and almost never what tells two hot frames apart.
fn short(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0_usize;
    for c in name.chars() {
        match c {
            '<' => {
                if depth == 0 {
                    out.push_str("<…>");
                }
                depth += 1;
            }
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// `/home/u/repo/crates/batten/src/store.rs:363` → `crates/batten/src/store.rs:363`;
/// a registry path keeps only `crate-ver/src/…`.
fn short_path(file: &str, line: u64) -> String {
    let trimmed = file
        .find("/crates/")
        .map(|i| &file[i + 1..])
        .or_else(|| {
            file.find("/registry/src/")
                .and_then(|i| file[i..].splitn(5, '/').nth(4))
        })
        .unwrap_or(file);
    if line == 0 {
        trimmed.to_owned()
    } else {
        format!("{trimmed}:{line}")
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// One library's symbols: sorted starts, and per entry its size and inline
/// frames innermost-first.
struct Table {
    starts: Vec<u64>,
    entries: Vec<(u64, Vec<Frame>)>,
}

impl Table {
    fn frames(&self, rva: u64) -> Option<Vec<Frame>> {
        let index = self
            .starts
            .partition_point(|start| *start <= rva)
            .checked_sub(1)?;
        let (size, frames) = &self.entries[index];
        (rva < self.starts[index] + size).then(|| frames.iter().rev().cloned().collect())
    }
}

fn symbol_tables(sidecar: &Value) -> Result<HashMap<String, Table>, String> {
    let strings: Vec<&str> = sidecar["string_table"]
        .as_array()
        .ok_or("the .syms.json sidecar has no string_table: record with --unstable-presymbolicate")?
        .iter()
        .map(|s| s.as_str().unwrap_or("?"))
        .collect();
    let text = |v: &Value| {
        v.as_u64()
            .and_then(|i| strings.get(i as usize))
            .copied()
            .unwrap_or("")
    };
    let mut tables = HashMap::new();
    for lib in sidecar["data"]
        .as_array()
        .ok_or("the sidecar has no data")?
    {
        let mut rows: Vec<(u64, u64, Vec<Frame>)> = Vec::new();
        for entry in lib["symbol_table"].as_array().into_iter().flatten() {
            let mut frames: Vec<Frame> = entry["frames"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| Frame {
                    name: short(text(&f["function"])),
                    at: short_path(text(&f["file"]), f["line"].as_u64().unwrap_or(0)),
                })
                .collect();
            if frames.is_empty() {
                frames.push(Frame {
                    name: short(text(&entry["symbol"])),
                    at: String::new(),
                });
            }
            rows.push((
                entry["rva"].as_u64().unwrap_or(0),
                entry["size"].as_u64().unwrap_or(0),
                frames,
            ));
        }
        rows.sort_by_key(|row| row.0);
        tables.insert(
            lib["debug_name"].as_str().unwrap_or("?").to_owned(),
            Table {
                starts: rows.iter().map(|row| row.0).collect(),
                entries: rows
                    .into_iter()
                    .map(|(_, size, frames)| (size, frames))
                    .collect(),
            },
        );
    }
    Ok(tables)
}

fn at(v: &Value, i: usize) -> Option<usize> {
    v.get(i)?.as_u64().map(|n| n as usize)
}

/// Every sampled stack of the profiled process, symbolized, noise removed
/// unless `all`. The process is the most-sampled one: `samply` records its own
/// launcher and any `sh -c` wrapper too.
fn load(path: &Path, all: bool) -> Result<Stacks, String> {
    let profile = read_json(path)?;
    let stem = path.to_string_lossy();
    let sidecar = format!("{}.syms.json", stem.strip_suffix(".json").unwrap_or(&stem));
    let tables = symbol_tables(&read_json(Path::new(&sidecar))?)?;
    let libs: Vec<&str> = profile["libs"]
        .as_array()
        .ok_or("not a samply profile: no libs")?
        .iter()
        .map(|lib| lib["debugName"].as_str().unwrap_or("?"))
        .collect();
    let threads = profile["threads"]
        .as_array()
        .ok_or("not a samply profile: no threads")?;
    let mut by_process: HashMap<&str, u64> = HashMap::new();
    for thread in threads {
        *by_process
            .entry(thread["processName"].as_str().unwrap_or("?"))
            .or_default() += thread["samples"]["length"].as_u64().unwrap_or(0);
    }
    let process = by_process
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(p, _)| p)
        .unwrap_or("?");
    let mut out = Stacks {
        total: 0,
        stacks: Vec::new(),
    };
    for thread in threads
        .iter()
        .filter(|t| t["processName"].as_str() == Some(process))
    {
        let (frames, funcs, resources, stack_table) = (
            &thread["frameTable"],
            &thread["funcTable"],
            &thread["resourceTable"],
            &thread["stackTable"],
        );
        let mut memo: HashMap<usize, Vec<Frame>> = HashMap::new();
        let mut frame_of = |fi: usize| -> Vec<Frame> {
            memo.entry(fi)
                .or_insert_with(|| {
                    let func = at(&frames["func"], fi).unwrap_or(0);
                    at(&funcs["resource"], func)
                        .and_then(|res| at(&resources["lib"], res))
                        .and_then(|lib| libs.get(lib))
                        .zip(frames["address"].get(fi).and_then(Value::as_u64))
                        .map(|(lib, rva)| {
                            tables
                                .get(*lib)
                                .and_then(|t| t.frames(rva))
                                .unwrap_or_else(|| {
                                    vec![Frame {
                                        name: format!("{lib}+{rva:#x}"),
                                        at: String::new(),
                                    }]
                                })
                        })
                        .unwrap_or_else(|| {
                            let name = at(&funcs["name"], func)
                                .and_then(|s| thread["stringArray"].get(s))
                                .and_then(Value::as_str)
                                .unwrap_or("?");
                            vec![Frame {
                                name: short(name),
                                at: String::new(),
                            }]
                        })
                })
                .clone()
        };
        let samples = &thread["samples"];
        let weights = samples["weight"].as_array();
        for (n, top) in samples["stack"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(top) = top.as_u64().map(|s| s as usize) else {
                continue;
            };
            let mut chain = Vec::new();
            let mut cursor = Some(top);
            while let Some(s) = cursor {
                chain.push(s);
                cursor = at(&stack_table["prefix"], s);
            }
            let stack: Vec<Frame> = chain
                .iter()
                .rev()
                .filter_map(|s| at(&stack_table["frame"], *s))
                .flat_map(&mut frame_of)
                .filter(|f| all || !is_noise(f))
                .collect();
            let weight = weights
                .and_then(|w| w.get(n))
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1);
            out.total += weight;
            out.stacks.push((stack, weight));
        }
    }
    if out.total == 0 {
        return Err(format!(
            "{}: no samples for process {process}",
            path.display()
        ));
    }
    Ok(out)
}

/// Inclusive (each frame once per stack) and self (the leaf) weights.
fn shares(stacks: &Stacks) -> (HashMap<Frame, u64>, HashMap<Frame, u64>) {
    let (mut inclusive, mut own) = (HashMap::new(), HashMap::new());
    for (stack, weight) in &stacks.stacks {
        let mut seen = HashSet::new();
        for frame in stack {
            if seen.insert(frame) {
                *inclusive.entry(frame.clone()).or_default() += weight;
            }
        }
        if let Some(leaf) = stack.last() {
            *own.entry(leaf.clone()).or_default() += weight;
        }
    }
    (inclusive, own)
}

fn pct(n: u64, total: u64) -> f64 {
    100.0 * n as f64 / total as f64
}

/// One table. `running` adds pprof's `sum%`, the running total of the rows so
/// far, which is meaningful only where rows are disjoint (self time): it says
/// where to stop reading.
fn rows(
    out: &mut String,
    title: &str,
    table: HashMap<Frame, u64>,
    total: u64,
    top: usize,
    min: f64,
    running: bool,
) {
    let mut sorted: Vec<(Frame, u64)> = table
        .into_iter()
        .filter(|(_, n)| pct(*n, total) >= min)
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));
    let _ = writeln!(out, "{title}");
    let mut sum = 0_u64;
    for (frame, n) in sorted.into_iter().take(top) {
        sum += n;
        if running {
            let _ = writeln!(
                out,
                "{:>5.1}% {:>5.1}%  {}  {}",
                pct(n, total),
                pct(sum, total),
                frame.name,
                frame.at
            );
        } else {
            let _ = writeln!(out, "{:>5.1}%  {}  {}", pct(n, total), frame.name, frame.at);
        }
    }
}

fn hot(stacks: &Stacks, top: usize, min: f64) -> String {
    let (inclusive, own) = shares(stacks);
    let mut out = format!("{} samples\n", stacks.total);
    rows(
        &mut out,
        "inclusive",
        inclusive,
        stacks.total,
        top,
        min,
        false,
    );
    rows(&mut out, "self  sum%", own, stacks.total, top, min, true);
    out
}

/// `depth` frames above the match: three answers "who called it"; a deeper
/// window reaches the frame that owns an inlined library call.
fn callers(stacks: &Stacks, needle: &str, top: usize, depth: usize) -> Result<String, String> {
    let mut paths: HashMap<String, u64> = HashMap::new();
    let mut matched = 0_u64;
    for (stack, weight) in &stacks.stacks {
        let Some(i) = stack.iter().position(|f| f.name.contains(needle)) else {
            continue;
        };
        matched += weight;
        let path: Vec<&str> = stack[i.saturating_sub(depth)..=i]
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        *paths.entry(path.join(" > ")).or_default() += weight;
    }
    if matched == 0 {
        return Err(format!(
            "no sampled frame name contains `{needle}`; `hot --all` lists the names"
        ));
    }
    let mut sorted: Vec<(String, u64)> = paths.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out = format!(
        "{:.1}% of {} samples pass through `{needle}`\n",
        pct(matched, stacks.total),
        stacks.total
    );
    for (path, n) in sorted.into_iter().take(top) {
        let _ = writeln!(out, "{:>5.1}%  {path}", pct(n, stacks.total));
    }
    Ok(out)
}

fn diff(before: &Stacks, after: &Stacks, top: usize) -> String {
    let (a, _) = shares(before);
    let (b, _) = shares(after);
    let frames: HashSet<&Frame> = a.keys().chain(b.keys()).collect();
    let mut moved: Vec<(&Frame, f64, f64)> = frames
        .into_iter()
        .map(|f| {
            let pa = pct(a.get(f).copied().unwrap_or(0), before.total);
            let pb = pct(b.get(f).copied().unwrap_or(0), after.total);
            (f, pa, pb)
        })
        .collect();
    moved.sort_by(|x, y| {
        (y.2 - y.1)
            .abs()
            .total_cmp(&(x.2 - x.1).abs())
            .then_with(|| x.0.name.cmp(&y.0.name))
    });
    let mut out = format!(
        "inclusive share, {} -> {} samples\n",
        before.total, after.total
    );
    for (frame, pa, pb) in moved.into_iter().take(top) {
        let _ = writeln!(
            out,
            "{pa:>5.1}% -> {pb:>5.1}%  {}  {}",
            frame.name, frame.at
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(name: &str) -> Frame {
        Frame {
            name: name.to_owned(),
            at: String::new(),
        }
    }

    fn stacks(rows: &[(&[&str], u64)]) -> Stacks {
        let stacks: Vec<(Vec<Frame>, u64)> = rows
            .iter()
            .map(|(names, n)| (names.iter().map(|n| frame(n)).collect(), *n))
            .collect();
        Stacks {
            total: stacks.iter().map(|(_, n)| n).sum(),
            stacks,
        }
    }

    /// Fails by: a generic argument list surviving, or a nested one leaking a `>`.
    #[test]
    fn generic_arguments_collapse_to_one_marker() {
        assert_eq!(
            short("try_find<gix_odb::Cache<Handle<Rc<Store>>>>"),
            "try_find<…>"
        );
        assert_eq!(short("plain"), "plain");
        assert_eq!(short("<T as Trait>::call"), "<…>::call");
    }

    /// Fails by: a workspace path keeping its machine prefix, a registry path
    /// keeping the index hash, or a line number dropped.
    #[test]
    fn paths_keep_only_what_locates_the_line() {
        assert_eq!(
            short_path("/home/u/repo/crates/batten/src/store.rs", 363),
            "crates/batten/src/store.rs:363"
        );
        assert_eq!(
            short_path(
                "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zlib-rs-0.6.8/src/inflate.rs",
                9
            ),
            "zlib-rs-0.6.8/src/inflate.rs:9"
        );
        assert_eq!(short_path("/usr/lib/x.c", 0), "/usr/lib/x.c");
    }

    /// Fails by: recursion counting a frame twice in one stack, or self time
    /// charged to anything but the leaf.
    #[test]
    fn inclusive_counts_a_frame_once_per_stack_and_self_is_the_leaf() {
        let (inclusive, own) = shares(&stacks(&[(&["a", "b", "a"], 3), (&["a", "c"], 1)]));
        assert_eq!(inclusive[&frame("a")], 4);
        assert_eq!(inclusive[&frame("b")], 3);
        assert_eq!(own[&frame("a")], 3);
        assert_eq!(own[&frame("c")], 1);
        assert!(!own.contains_key(&frame("b")));
    }

    /// Fails by: a caller path missing, mis-weighted, or an absent name answered
    /// with an empty report instead of a refusal that says what to do.
    #[test]
    fn callers_name_every_path_and_refuse_an_absent_frame() {
        let s = stacks(&[
            (&["main", "x", "hot"], 3),
            (&["main", "y", "hot"], 1),
            (&["main", "z"], 4),
        ]);
        let report = callers(&s, "hot", 5, 3).unwrap();
        assert!(callers(&s, "hot", 5, 0).unwrap().contains("50.0%  hot"));
        assert!(report.starts_with("50.0% of 8 samples pass through `hot`"));
        assert!(report.contains("37.5%  main > x > hot"));
        assert!(report.contains("12.5%  main > y > hot"));
        assert!(callers(&s, "absent", 5, 3).is_err());
    }

    /// Fails by: a frame that vanished after a patch going unreported — the
    /// blind spot of a red/blue differential flame graph.
    #[test]
    fn a_diff_reports_a_frame_that_vanished() {
        let before = stacks(&[(&["main", "walk"], 9), (&["main"], 1)]);
        let after = stacks(&[(&["main"], 1)]);
        assert!(diff(&before, &after, 5).contains(" 90.0% ->   0.0%  walk"));
    }

    /// Fails by: a `calls=` attributed to the wrong callee or caller, or a
    /// compressed `(id)` name left unresolved.
    #[test]
    fn calls_are_summed_per_caller_through_compressed_names() {
        let text = "fn=(1) store::resolve\ncfn=(2) git::root_commits<T>\ncalls=2 0\n0 5\n\
                    fn=(3) run_state_record\ncfn=(2)\ncalls=1 0\n0 5\ncfn=(4) other\ncalls=7 0\n";
        let report = calls(text, "root_commits").unwrap();
        assert!(report.starts_with("3 calls into `root_commits`"));
        assert!(report.contains("       2  store::resolve -> git::root_commits<…>"));
        assert!(report.contains("       1  run_state_record -> git::root_commits<…>"));
        assert!(calls(text, "absent").is_err());
    }

    /// Fails by: a quote in a path breaking out of the `sh -c` word.
    #[test]
    fn a_quote_cannot_escape_its_word() {
        assert_eq!(quote("a'b"), r"'a'\''b'");
    }

    /// Fails by: the iteration script letting the deny channel's exit 2 reach
    /// samply, which then records one iteration of ten.
    #[test]
    fn an_iteration_exits_zero_whatever_the_arm_answers() {
        let script = wrapped(&["'/b/batten'".to_owned(), "< '/p.json'".to_owned()]);
        assert_eq!(script, "'/b/batten' < '/p.json'; exit 0");
        assert!(!script.starts_with("exec "));
    }
}

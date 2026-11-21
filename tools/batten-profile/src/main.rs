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

const USAGE: &str = "usage: batten-profile hot P.json [--top N] [--min PCT] [--all] \
                     | callers P.json NAME [--top N] | diff A.json B.json [--top N]";

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
        (Some("callers"), Some(path), Some(name)) => {
            callers(&load(Path::new(path), all)?, name, top)
        }
        (Some("diff"), Some(a), Some(b)) => Ok(diff(
            &load(Path::new(a), all)?,
            &load(Path::new(b), all)?,
            top,
        )),
        _ => Err(USAGE.to_owned()),
    }
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

fn callers(stacks: &Stacks, needle: &str, top: usize) -> Result<String, String> {
    let mut paths: HashMap<String, u64> = HashMap::new();
    let mut matched = 0_u64;
    for (stack, weight) in &stacks.stacks {
        let Some(i) = stack.iter().position(|f| f.name.contains(needle)) else {
            continue;
        };
        matched += weight;
        let path: Vec<&str> = stack[i.saturating_sub(3)..=i]
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

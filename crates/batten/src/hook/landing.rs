//! What a shell call LANDS at each file it writes by name (CLOUD-1636).
//!
//! A registration is decided by what arrives at a harness surface, never by how
//! its source is spelled. The review of #1287 measured the spelling reading
//! missing every move an agent makes by content: `cat <cs> > <rs>`, `cat <cs> |
//! tee <rs>`, `git show HEAD:<cs> > <rs>`, a relative or `$PWD` source behind a
//! `cd`, a whole `.claude` directory copied or linked, and any of them handed to
//! `sh -c`. So each target the call writes carries, beside its spelling:
//!
//! * `resolved` — the target against the directory in effect (every followed
//!   `cd`, `$PWD` expanded), or `null` where it cannot be placed;
//! * `origins` — each source, resolved the same way;
//! * `lands` — every file the write leaves at or under the target, as
//!   `{"path", "content"}`: a copied or linked file's text, each file of a
//!   copied or linked directory, or what a redirect or `tee` receives from the
//!   program feeding it (`cat` of files, `git show <rev>:<path>`, `echo` or
//!   `printf`). `content` is `null` where nothing could be read.
//!
//! READ BOUNDED. A file past [`CAP`] is not read, a directory yields at most
//! [`WALK`] files [`DEEP`] levels down, and a shell's script is unwrapped at most
//! [`NESTING`] deep, so the hook's cost is bounded by these and not by the tree.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::shell::Separator;

/// The largest file a landing reads: the prospective read's own cap.
const CAP: u64 = 1 << 20;

/// The most files a copied directory yields.
const WALK: usize = 256;

/// How many directory levels a copied directory is walked.
const DEEP: usize = 4;

/// How many `sh -c` scripts deep the reading unwraps.
const NESTING: usize = 4;

/// The shells whose inline script is a command line this reading re-enters,
/// read through the interpreter table's own grammar (CLOUD-2626).
const SHELLS: [&str; 8] = ["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash"];

/// Every target `command` writes by name, run from `start`; `None` for a
/// command that does not parse.
pub(super) fn targets(command: &str, start: Option<&Path>) -> Option<Vec<Value>> {
    let mut found = Vec::new();
    walk(command, start.map(Path::to_path_buf), 0, &mut found)?;
    Some(found)
}

/// One command line's targets, appended to `found`. An inner script that does
/// not parse is skipped rather than failing the outer reading.
fn walk(command: &str, start: Option<PathBuf>, depth: usize, found: &mut Vec<Value>) -> Option<()> {
    let crate::facts::Look::Is(parsed) = super::segments(command) else {
        return None;
    };
    let mut current = start;
    // What the previous stage writes to a pipe, for the stage reading it.
    let mut piped: Option<Option<String>> = None;
    let lines = super::per_line(&parsed);
    for (position, &(index, segment, line)) in lines.iter().enumerate() {
        let tokens: Vec<&str> = line.words.iter().map(String::as_str).collect();
        let handed = &tokens[..tokens.len().saturating_sub(line.redirects.len())];
        let stdin = piped.take().flatten();
        let last_of_segment = lines
            .get(position + 1)
            .is_none_or(|&(next, _, _)| next != index);
        if super::is_cd_segment(handed) {
            let placed = current
                .as_deref()
                .and_then(|here| super::placed_cd(segment, handed, here));
            if matches!(segment.terminator, Some(Separator::And | Separator::Semi)) {
                current = placed;
            }
            continue;
        }
        let Some(at) = super::effective_program(handed) else {
            continue;
        };
        let name = super::program_name(super::program_token(handed[at]));
        let arguments = &handed[at + 1..];
        if SHELLS.contains(&name) && depth < NESTING {
            let grammar = super::grammar(name);
            for script in super::inline_values(&grammar, arguments) {
                // An inner script that does not parse is that script's
                // abstention, not the whole call's.
                // A line's words arrive with quotes already resolved
                // (`SegmentLine::words`), so the script is the text as run.
                let _ = walk(&script, current.clone(), depth + 1, found);
            }
            continue;
        }
        let output = produced(
            name,
            handed,
            arguments,
            current.as_deref(),
            stdin.as_deref(),
        );
        let redirects: Vec<&str> = line.redirects.iter().map(String::as_str).collect();
        for target in super::redirect_writes(&redirects) {
            let path = crate::shell::unquote(target);
            found.push(stream_entry(
                &path,
                None,
                current.as_deref(),
                output.as_deref(),
            ));
        }
        for mut entry in super::named_writes(name, arguments) {
            let path = entry["path"].as_str().unwrap_or_default().to_owned();
            let extra = if name == "tee" {
                stream_entry(&path, Some(name), current.as_deref(), stdin.as_deref())
            } else {
                copy_fields(&entry, current.as_deref())
            };
            if let (Some(object), Value::Object(more)) = (entry.as_object_mut(), extra) {
                for (key, value) in more {
                    object.entry(key).or_insert(value);
                }
            }
            found.push(entry);
        }
        if last_of_segment && segment.terminator == Some(Separator::Pipe) {
            piped = Some(output);
        }
    }
    Some(())
}

/// A redirect's or `tee`'s target: what the feeding program writes lands there.
fn stream_entry(
    path: &str,
    program: Option<&str>,
    current: Option<&Path>,
    content: Option<&str>,
) -> Value {
    let resolved = resolve(path, current);
    let lands: Vec<Value> = resolved
        .iter()
        .map(|at| serde_json::json!({"path": at.display().to_string(), "content": content}))
        .collect();
    serde_json::json!({
        "path": path,
        "program": program,
        "sources": [],
        "symbolic": false,
        "resolved": resolved.map(|at| at.display().to_string()),
        "origins": [],
        "lands": lands,
    })
}

/// A copy's, link's or move's target: each source's files land at or under it.
fn copy_fields(entry: &Value, current: Option<&Path>) -> Value {
    let path = entry["path"].as_str().unwrap_or_default();
    let resolved = resolve(path, current);
    let into_dir = path.ends_with('/') || resolved.as_deref().is_some_and(Path::is_dir);
    let mut origins = Vec::new();
    let mut lands = Vec::new();
    for source in entry["sources"].as_array().into_iter().flatten() {
        let Some(origin) = source.as_str().and_then(|word| resolve(word, current)) else {
            continue;
        };
        origins.push(origin.display().to_string());
        let Some(target) = resolved.as_deref() else {
            continue;
        };
        let landing = match (into_dir, origin.file_name()) {
            (true, Some(base)) => target.join(base),
            _ => target.to_path_buf(),
        };
        if origin.is_dir() {
            lands.extend(directory_lands(&origin, &landing));
        } else {
            lands.push(serde_json::json!({
                "path": landing.display().to_string(),
                "content": read(&origin),
            }));
        }
    }
    serde_json::json!({
        "resolved": resolved.map(|at| at.display().to_string()),
        "origins": origins,
        "lands": lands,
    })
}

/// Each file under `source`, as it lands under `landing`.
fn directory_lands(source: &Path, landing: &Path) -> Vec<Value> {
    let mut lands = Vec::new();
    let mut pending = vec![(source.to_path_buf(), 0_usize)];
    while let Some((dir, level)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if lands.len() >= WALK {
                return lands;
            }
            let path = entry.path();
            if path.is_dir() {
                if level + 1 < DEEP {
                    pending.push((path, level + 1));
                }
                continue;
            }
            let Ok(relative) = path.strip_prefix(source) else {
                continue;
            };
            lands.push(serde_json::json!({
                "path": landing.join(relative).display().to_string(),
                "content": read(&path),
            }));
        }
    }
    lands
}

/// What one program writes to its standard output, where a static reading can
/// say: `cat`'s files (or its piped input), `git show <rev>:<path>`'s blob,
/// `echo`'s and `printf`'s words, and a `tee`'s input passed through.
fn produced(
    name: &str,
    handed: &[&str],
    arguments: &[&str],
    current: Option<&Path>,
    stdin: Option<&str>,
) -> Option<String> {
    // A line's words arrive with quotes resolved (`SegmentLine::words`), so a
    // second unquote would strip the quotes INSIDE an echoed JSON body.
    let words = || arguments.iter().map(|word| (*word).to_owned());
    match name {
        "cat" => {
            let files: Vec<String> = words().filter(|word| !word.starts_with('-')).collect();
            if files.is_empty() {
                return stdin.map(str::to_owned);
            }
            files
                .iter()
                .map(|word| resolve(word, current).and_then(|path| read(&path)))
                .collect::<Option<Vec<_>>>()
                .map(|texts| texts.concat())
        }
        "echo" | "printf" => Some(
            words()
                .skip_while(|word| name == "echo" && word.starts_with('-'))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "tee" => stdin.map(str::to_owned),
        "git" => {
            let dir = super::git_acting_dir(handed, current?)?;
            let end = super::subcommand_index(arguments, &super::GIT_VALUE_OPTIONS)?;
            if arguments.get(end).copied() != Some("show") {
                return None;
            }
            let spec = arguments[end + 1..]
                .iter()
                .find(|word| !word.starts_with('-') && word.contains(':'))?;
            let (rev, path) = spec.split_once(':')?;
            crate::git::show(&dir, if rev.is_empty() { "HEAD" } else { rev }, path).ok()
        }
        _ => None,
    }
}

/// A shell word naming a path, against the directory in effect: `$PWD` and
/// `${PWD}` expand to it; any other expansion or a home is not placed.
fn resolve(word: &str, current: Option<&Path>) -> Option<PathBuf> {
    for variable in ["${PWD}", "$PWD"] {
        if let Some(rest) = word.strip_prefix(variable)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            let here = current?;
            return Some(here.join(rest.trim_start_matches('/')));
        }
    }
    if word.is_empty() || word.contains('$') || word.starts_with('~') {
        return None;
    }
    super::shell_resolved(word, current)
}

/// A file's text, or `None` past [`CAP`] or where it cannot be read.
fn read(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > CAP {
        return None;
    }
    crate::fsio::read_to_string(path).ok()
}

/// The prior text of the file a write tool writes, so a module can tell a
/// write that ADDS a registration from one that keeps the file's own
/// (CLOUD-1636, the review's finding 4). `None` off a write tool, and where the
/// file is absent or unreadable.
pub(super) fn prior(envelope: &super::Envelope, start: Option<&Path>) -> Option<String> {
    if !envelope.command.is_empty() {
        return None;
    }
    envelope.writes.as_ref()?;
    let named = ["/file_path", "/notebook_path"]
        .iter()
        .find_map(|pointer| envelope.input.pointer(pointer).and_then(Value::as_str))?;
    let path = Path::new(named);
    let at = if path.is_absolute() {
        path.to_path_buf()
    } else {
        start?.join(path)
    };
    read(&at)
}

#[cfg(test)]
mod tests {
    // Panicking on a wrong reading is how these cases fail.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::targets;
    use std::path::Path;

    fn landed(command: &str) -> Vec<(String, Option<String>)> {
        targets(command, Some(Path::new("/w")))
            .expect("the command parses")
            .iter()
            .flat_map(|entry| entry["lands"].as_array().cloned().unwrap_or_default())
            .map(|land| {
                (
                    land["path"].as_str().unwrap().to_owned(),
                    land["content"].as_str().map(str::to_owned),
                )
            })
            .collect()
    }

    /// A shell's `-c` script is the command line it is, and what `echo`
    /// writes is what lands, whichever quoting carried it.
    ///
    /// Fails by: an inline script left unread (no landing), or unquoted twice,
    /// which strips the inner quotes and mangles the echoed text.
    #[test]
    fn a_shell_script_lands_what_its_echo_writes() {
        for command in [
            r#"bash -lc "echo '{\"a\": \"b\"}' > /r/x.json""#,
            r#"sh -c 'echo "{\"a\": \"b\"}" > /r/x.json'"#,
            r#"echo '{"a": "b"}' > /r/x.json"#,
        ] {
            assert_eq!(
                landed(command),
                vec![("/r/x.json".to_owned(), Some(r#"{"a": "b"}"#.to_owned()))],
                "{command}"
            );
        }
    }

    /// `$PWD` and a followed `cd` place a relative target and its source.
    #[test]
    fn a_target_is_placed_through_cd_and_pwd() {
        let found = targets("cd /a && ln -sfn $PWD/s.json t.json", Some(Path::new("/w"))).unwrap();
        assert_eq!(found[0]["resolved"], "/a/t.json");
        assert_eq!(found[0]["origins"][0], "/a/s.json");
    }
}

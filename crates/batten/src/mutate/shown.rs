//! THE COPY'S SOURCES READ AS THE CHECKOUT'S WHILE ITS CASES RUN (CLOUD-2911).
//!
//! The schema build writes each probed source's rendering over the copy's own
//! file, so cargo compiles the switches. A case reads the tree as well: a
//! census scanning `crates/**/*.rs`, a step whose cache key refuses a dirty
//! tree. Over the rendering each of those reads differs from the checkout's,
//! so the case went red in the unmutated baseline alone, and every mutant it
//! reaches was left unjudged (`prune_watch`'s step probe read the copy's
//! rendered sources as uncommitted and found no key).
//!
//! [`Shown`] puts each rendered file's original text back for the length of a
//! suite run, at the rendered file's own modification time. Cargo decides a
//! unit's freshness by those times, so the binaries the build made are the ones
//! the run executes and no unit is compiled from the original text. Dropped, it
//! writes each rendering back at that same time, so every digest, pack and later
//! build reads the tree exactly as the build left it.
//!
//! A sweep killed while the originals are shown leaves a file whose text is not
//! its rendering. The next render finds the text differs and writes it, its time
//! moves, and cargo rebuilds that crate: a build's cost, never a stale binary.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The rendered files of a copy, showing their originals until dropped.
#[derive(Debug)]
#[must_use = "the renderings go back the moment this is dropped"]
pub struct Shown {
    /// Each swapped file, its rendered bytes and the time it was built at.
    restore: Vec<(PathBuf, Vec<u8>, SystemTime)>,
}

impl Shown {
    /// Show `root`'s text of each of `files` in the copy at `work`, keeping the
    /// rendered text and its modification time. A file whose rendering is its
    /// original text is left alone.
    ///
    /// # Errors
    ///
    /// A file cannot be read, written or re-timed. What was already swapped
    /// goes back as the partial value drops.
    pub fn originals(root: &Path, work: &Path, files: &BTreeSet<String>) -> anyhow::Result<Self> {
        let mut shown = Self {
            restore: Vec::new(),
        };
        for file in files {
            let at = work.join(file);
            let rendered = crate::fsio::read(&at)?;
            let original = crate::fsio::read(root.join(file))?;
            if rendered == original {
                continue;
            }
            let modified = std::fs::metadata(&at)?.modified()?;
            // RECORDED BEFORE THE WRITE: a failure on it still puts this one back.
            shown.restore.push((at.clone(), rendered, modified));
            write_at(&at, &original, modified)?;
        }
        Ok(shown)
    }
}

impl Drop for Shown {
    fn drop(&mut self) {
        // NO VERDICT RIDES ON IT: a rendering that cannot be written back is
        // rewritten by the next render, which moves its time (module docs).
        for (at, rendered, modified) in self.restore.drain(..) {
            let _ = write_at(&at, &rendered, modified);
        }
    }
}

/// Replace `at` with `text`, then set its modification time to `modified`.
fn write_at(at: &Path, text: &[u8], modified: SystemTime) -> std::io::Result<()> {
    crate::durable::replace(at, text)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(at)?
        .set_modified(modified)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn modified(path: &Path) -> SystemTime {
        std::fs::metadata(path).unwrap().modified().unwrap()
    }

    /// Fails by: the copy keeping its rendering while shown, the shown text
    /// taking a new time (cargo would rebuild from the original), or the
    /// rendering or its time not coming back on drop.
    #[test]
    fn the_original_is_shown_at_the_rendered_time_and_the_rendering_returns() {
        let dir = crate::scratch::scratch("mutate-shown-swap");
        let (root, work) = (dir.join("root"), dir.join("work"));
        for tree in [&root, &work] {
            std::fs::create_dir_all(tree.join("src")).unwrap();
        }
        std::fs::write(root.join("src/lib.rs"), "fn f() {}\n").unwrap();
        std::fs::write(work.join("src/lib.rs"), "fn f() { probe(); }\n").unwrap();
        let built = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(work.join("src/lib.rs"))
            .unwrap()
            .set_modified(built)
            .unwrap();
        let files = BTreeSet::from([String::from("src/lib.rs")]);

        let shown = Shown::originals(&root, &work, &files).unwrap();
        assert_eq!(
            std::fs::read_to_string(work.join("src/lib.rs")).unwrap(),
            "fn f() {}\n"
        );
        assert_eq!(modified(&work.join("src/lib.rs")), built);
        drop(shown);
        assert_eq!(
            std::fs::read_to_string(work.join("src/lib.rs")).unwrap(),
            "fn f() { probe(); }\n"
        );
        assert_eq!(modified(&work.join("src/lib.rs")), built);
    }

    /// Fails by: a file whose rendering equals its original being rewritten,
    /// or a missing original passing as shown.
    #[test]
    fn an_unchanged_file_is_left_and_a_missing_original_refuses() {
        let dir = crate::scratch::scratch("mutate-shown-same");
        let (root, work) = (dir.join("root"), dir.join("work"));
        for tree in [&root, &work] {
            std::fs::create_dir_all(tree).unwrap();
            std::fs::write(tree.join("a.rs"), "same\n").unwrap();
        }
        let same = BTreeSet::from([String::from("a.rs")]);
        let shown = Shown::originals(&root, &work, &same).unwrap();
        assert!(shown.restore.is_empty());
        std::fs::write(work.join("b.rs"), "rendered\n").unwrap();
        let missing = BTreeSet::from([String::from("b.rs")]);
        assert!(Shown::originals(&root, &work, &missing).is_err());
        assert_eq!(
            std::fs::read_to_string(work.join("b.rs")).unwrap(),
            "rendered\n"
        );
    }
}

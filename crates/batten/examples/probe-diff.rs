//! Scratch: each probed function's digest in FILE at REV, with its first line.
use std::collections::BTreeSet;
fn main() {
    let mut args = std::env::args().skip(1);
    let rev = args.next().expect("rev");
    for file in args {
        let out = std::process::Command::new("git")
            .args(["show", &format!("{rev}:{file}")])
            .output()
            .expect("git");
        if !out.status.success() {
            continue;
        }
        let source = String::from_utf8_lossy(&out.stdout).into_owned();
        let scope = batten::mutate::schema::FileScope::of(&file);
        let r = batten::mutate::schema::render_in(&source, &[], &BTreeSet::new(), Some(0), &scope);
        for (digest, region) in r.probes.iter().zip(r.probe_regions.iter()) {
            let at = region.start.min(r.text.len());
            let head: String = r.text[..at].rsplit('\n').next().unwrap_or("").trim().chars().take(90).collect();
            println!("{file}\t{digest}\t{head}");
        }
    }
}

//! Scratch: recompute sealed records' selection digests over a tree.
use std::collections::{BTreeMap, BTreeSet};
use batten::mutate::schema as s;
fn main() -> anyhow::Result<()> {
    let mut a = std::env::args().skip(1);
    let base = std::path::PathBuf::from(a.next().unwrap());
    let root = std::path::PathBuf::from(a.next().unwrap());
    let sample: BTreeSet<String> = std::fs::read_to_string(a.next().unwrap())?
        .lines().map(str::to_owned).collect();
    let ids_root = a.next().map(std::path::PathBuf::from).unwrap_or_else(|| root.clone());
    let sealed: Vec<_> = s::sealed_cases(&base).into_iter()
        .filter(|r| sample.contains(&r.case.0)).collect();
    let resources = s::resource_ids(&ids_root)?;
    let mut formats: BTreeMap<&str, Vec<&s::Sealed>> = BTreeMap::new();
    for r in &sealed { formats.entry(&r.format).or_default().push(r); }
    let (mut same, mut moved, mut gone) = (0, 0, 0);
    for (key, records) in formats {
        let Some(format) = s::Format::load(&base, key) else { eprintln!("format {key} unreadable"); continue };
        let index = s::dependency_index(&root, &format)?;
        let mut resources = resources.clone();
        let target = base.parent().unwrap().join("tree/target");
        let built = s::built_outputs(&target, &format.dirs);
        eprintln!("built outputs: {:?}", built.keys().collect::<Vec<_>>());
        resources.extend(built);
        let cases: BTreeMap<(String, String), s::Ran> =
            records.iter().map(|r| (r.case.clone(), r.ran.clone())).collect();
        let now = s::test_digests(&root, &index, &format.dirs, &cases, &resources);
        let _ = &resources;
        for r in records {
            match now.get(&r.case).and_then(Option::as_deref) {
                Some(d) if d == r.tested => same += 1,
                Some(_) => { moved += 1; println!("moved\t{}\t{}", r.case.1, r.case.0) }
                None => { gone += 1; println!("unknown\t{}\t{}", r.case.1, r.case.0) }
            }
        }
    }
    eprintln!("sample {} sealed-in-sample {} same {same} moved {moved} unknown {gone}", sample.len(), sealed.len());
    Ok(())
}

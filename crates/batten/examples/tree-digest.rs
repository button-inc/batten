fn main() { for p in std::env::args().skip(1) { println!("{p}\t{}", batten::mutate::schema::tree_digest(std::path::Path::new(&p)).unwrap_or_default()); } }

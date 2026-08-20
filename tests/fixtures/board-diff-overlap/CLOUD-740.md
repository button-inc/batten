The last slice of CLOUD-320's `git.rs` row: everything the earlier three left behind.
Reads: `uncommitted`, `changed_paths`, `check_ignore`, `worktrees`. Writes: `update_ref`, `worktree_remove`, `stash_create`.
`no_second_git_invoker_exists` currently forbids a literal `Command::new("git")` outside this module.
`worktrees` reads git's OWN vocabulary (CLOUD-46). `worktree list --porcelain`: `locked` and `prunable`.
`stash_create` does not capture an untracked-only tree, pinned by `a_snapshot_captures_a_dirty_tree_and_nothing_else`.
The module doc rewritten from "mid-migration" to what it actually is.

//! Is this text shell logic? One detector, decided on the parser's AST
//! (CLOUD-2625).
//!
//! # Why a grammar and not a scan
//!
//! The census and the `shell-hygiene` preset each answered this with a
//! substring scan, kept in sync by comment, while the mediation boundary already
//! parsed shell with [`rable`]. The scans and the grammar disagreed: a quoted `|`
//! was shell to the scan and one argv to the parser, and `[[`, `{ }`, globs and
//! `~` were argv to the scan and structure to the parser. This module is the one
//! answer both callers now read.
//!
//! # The rule
//!
//! Parse the text, then decide on the AST. A single simple command whose words
//! are all literal is argv; quoting alone is not shell logic. Anything else — a
//! pipeline or list, a substitution, a redirect, a compound construct, an
//! expansion, a heredoc — is shell logic. Text the parser cannot read is shell.
//! The numbered arms in [`logic`] are the row's rules, in its order.
//!
//! # What this does not decide
//!
//! Which interpreters take a script (`perl -e`, `sh -c`), and which carriers run
//! a text through a shell, are later rows'. The mediation walk in `hook.rs`
//! parses with the same crate and is unchanged: this module calls the parser
//! itself and reads two of the walk's helpers, [`crate::hook::covered`] and
//! [`crate::hook::unquote`], rather than growing second copies.

/// The detector's answer for one text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// One plain command: its words, each with one level of quoting removed.
    /// Empty for a text holding no command at all.
    Argv(Vec<String>),
    /// Shell logic, with the reason: a `rable` node kind's name, or one of
    /// `unparseable`, `multi-command`, `assignment`, `glob`, `tilde`.
    Shell(&'static str),
}

/// The reason a text the parser rejected, or read only in part, carries.
const UNPARSEABLE: &str = "unparseable";

/// Decide whether `text` is shell logic.
///
/// `text` is the decoded scalar: a caller holding a TOML or YAML string strips
/// that format's quoting first, or `run = "a | b"` would read as one quoted word.
///
/// The detector's mutation rows. Each disables one numbered rule below and is
/// killed by the unit case it names, run from this file.
//MUTANT-SUITE crates/batten/src/shell.rs
//MUTANT detector-parse-failure-is-argv|s@^    let Ok(nodes) = rable::parse(text, false) else {$@    let Ok(nodes) = rable::parse(text, false).or_else(\x7c_\x7c rable::parse("", false)) else {@|text_the_parser_rejects_is_shell
//MUTANT detector-dropped-tail-is-argv|s@^    if !crate::hook::covered(&nodes, text) {$@    if false {@|an_unclosed_quote_is_shell
//MUTANT detector-multi-command-is-argv|s@^    if nodes.len() > 1 {$@    if false {@|two_plain_lines_are_a_multi_command_body
#[must_use]
pub fn logic(text: &str) -> Verdict {
    // `extglob` off, for `hook::segments`' reason: the shell that runs this text
    // is not guaranteed to have the option set.
    // 1. The parser rejected it.
    let Ok(nodes) = rable::parse(text, false) else {
        return Verdict::Shell(UNPARSEABLE);
    };
    // 2. Nothing to run: empty text, or only comments, which the lexer drops.
    if nodes.is_empty() {
        return Verdict::Argv(Vec::new());
    }
    // 3. `rable` 0.2.1 returns Ok for an unclosed quote and drops the word, so
    //    a parse that did not account for the whole text is no parse.
    if !crate::hook::covered(&nodes, text) {
        return Verdict::Shell(UNPARSEABLE);
    }
    // 4. One top-level node per line, so two are a list.
    if nodes.len() > 1 {
        return Verdict::Shell("multi-command");
    }
    let Some(node) = nodes.first() else {
        return Verdict::Argv(Vec::new());
    };
    command(node)
}

/// Rules 5 to 9, over the one top-level node.
fn command(node: &rable::Node) -> Verdict {
    let rable::NodeKind::Command {
        assignments,
        words,
        redirects,
    } = &node.kind
    else {
        // An `Empty` top level is nothing to run, not a construct.
        if matches!(node.kind, rable::NodeKind::Empty) {
            return Verdict::Argv(Vec::new());
        }
        // 5. Not a simple command.
        return Verdict::Shell(kind_name(&node.kind));
    };
    // 6. A redirect, then an assignment: an exec form has neither.
    if let Some(redirect) = redirects.first() {
        return Verdict::Shell(kind_name(&redirect.kind));
    }
    if !assignments.is_empty() {
        return Verdict::Shell("assignment");
    }
    // 7. A substitution or expansion anywhere in the words, by the first
    //    non-quoting part in word order, with no descent into it.
    for word in words {
        match &word.kind {
            rable::NodeKind::Word { parts, .. } => {
                if let Some(part) = parts.iter().find(|part| !quoting(&part.kind)) {
                    return Verdict::Shell(kind_name(&part.kind));
                }
            }
            other => return Verdict::Shell(kind_name(other)),
        }
    }
    // 8. Globs and tilde have no node in `rable` 0.2.1, so the raw word is
    //    walked with `unquote`'s quote states.
    let mut argv = Vec::with_capacity(words.len());
    for word in words {
        let (rable::NodeKind::Word { value, .. } | rable::NodeKind::WordLiteral { value }) =
            &word.kind
        else {
            return Verdict::Shell(kind_name(&word.kind));
        };
        if let Some(reason) = bare_pattern(value) {
            return Verdict::Shell(reason);
        }
        argv.push(crate::hook::unquote(value));
    }
    // 9. One plain command.
    Verdict::Argv(argv)
}

/// A word part that is quoting rather than an expansion.
const fn quoting(kind: &rable::NodeKind) -> bool {
    matches!(
        kind,
        rable::NodeKind::WordLiteral { .. }
            | rable::NodeKind::AnsiCQuote { .. }
            | rable::NodeKind::LocaleString { .. }
    )
}

/// `glob` for a `*`, `?` or `[` outside every quote and escape, `tilde` for a
/// leading `~`; `None` for a word only a shell's quoting touches.
///
/// The states are `hook::unquote`'s: single quotes are literal throughout, a
/// backslash inside double quotes escapes the next character, and one outside
/// any quote escapes it too.
//MUTANT-SUITE crates/batten/tests/it/census_shell.rs
//MUTANT detector-quoted-glob-is-shell|s@^            (None, '\\'' \x7c '"') => quote = Some(c),$@            (None, '\\'' \x7c '"') => {}@|the_census_counts_the_fixture_as_the_shapes_say
fn bare_pattern(raw: &str) -> Option<&'static str> {
    if raw.starts_with('~') {
        return Some("tilde");
    }
    let mut quote: Option<char> = None;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None | Some('"'), '\\') => {
                chars.next();
            }
            (None, '\'' | '"') => quote = Some(c),
            (Some(open), _) if c == open => quote = None,
            (None, '*' | '?' | '[') => return Some("glob"),
            _ => {}
        }
    }
    None
}

/// Shells a shebang may name (CLOUD-2625, widened by the owner beyond the
/// five the scans knew).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShellKind {
    /// `sh`
    Sh,
    /// `bash`
    Bash,
    /// `zsh`
    Zsh,
    /// `dash`
    Dash,
    /// `ksh`
    Ksh,
    /// `fish`
    Fish,
    /// `csh`
    Csh,
    /// `tcsh`
    Tcsh,
    /// `mksh`
    Mksh,
    /// `ash`
    Ash,
    /// `yash`
    Yash,
    /// `busybox sh`, the multi-call binary told which applet to be.
    BusyboxSh,
}

/// Every interpreter name a shebang may carry, and the shell it is.
const SHELLS: [(&str, ShellKind); 11] = [
    ("sh", ShellKind::Sh),
    ("bash", ShellKind::Bash),
    ("zsh", ShellKind::Zsh),
    ("dash", ShellKind::Dash),
    ("ksh", ShellKind::Ksh),
    ("fish", ShellKind::Fish),
    ("csh", ShellKind::Csh),
    ("tcsh", ShellKind::Tcsh),
    ("mksh", ShellKind::Mksh),
    ("ash", ShellKind::Ash),
    ("yash", ShellKind::Yash),
];

/// The shell a first line's shebang names, if it names one.
///
/// The interpreter is the shebang's first word, by its file name; `env` hands
/// over to the first word after it that is neither a flag nor an assignment, and
/// `busybox` is a shell only when told to be `sh` (or `ash`).
#[must_use]
pub fn shebang(first_line: &str) -> Option<ShellKind> {
    let rest = first_line.strip_prefix("#!")?;
    let mut words = rest.split_whitespace();
    let mut program = file_name(words.next()?);
    if program == "env" {
        program = file_name(words.find(|word| !word.starts_with('-') && !word.contains('='))?);
    }
    if program == "busybox" {
        return matches!(words.next(), Some("sh" | "ash")).then_some(ShellKind::BusyboxSh);
    }
    SHELLS
        .iter()
        .find(|(name, _)| *name == program)
        .map(|(_, kind)| *kind)
}

/// The last `/`-separated component.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// File extensions that are shell whatever the first line says.
const EXTENSIONS: [&str; 9] = [
    ".sh", ".bash", ".bats", ".zsh", ".ksh", ".fish", ".csh", ".tcsh", ".command",
];

/// Whether a path is shell by its name alone.
//MUTANT-SUITE crates/batten/tests/it/shell_banned.rs
//MUTANT file-extension-unread|s@^    EXTENSIONS.iter().any(.extension. path.ends_with(extension))$@    false@|an_added_shell_script_is_refused
#[must_use]
pub fn shell_path(path: &str) -> bool {
    EXTENSIONS.iter().any(|extension| path.ends_with(extension))
}

/// A node kind's name, exactly as its variant is spelled.
///
/// **EXHAUSTIVE, NO WILDCARD ARM.** `NodeKind` derives only `Debug`, so this is
/// the one place a name comes from, and a `rable` upgrade that adds a variant
/// fails to compile here rather than reading as some other kind.
#[must_use]
pub const fn kind_name(kind: &rable::NodeKind) -> &'static str {
    use rable::NodeKind as K;
    match kind {
        K::Word { .. } => "Word",
        K::WordLiteral { .. } => "WordLiteral",
        K::Command { .. } => "Command",
        K::Pipeline { .. } => "Pipeline",
        K::List { .. } => "List",
        K::If { .. } => "If",
        K::While { .. } => "While",
        K::Until { .. } => "Until",
        K::For { .. } => "For",
        K::ForArith { .. } => "ForArith",
        K::Select { .. } => "Select",
        K::Case { .. } => "Case",
        K::Function { .. } => "Function",
        K::Subshell { .. } => "Subshell",
        K::BraceGroup { .. } => "BraceGroup",
        K::Coproc { .. } => "Coproc",
        K::Redirect { .. } => "Redirect",
        K::HereDoc { .. } => "HereDoc",
        K::ParamExpansion { .. } => "ParamExpansion",
        K::ParamLength { .. } => "ParamLength",
        K::ParamIndirect { .. } => "ParamIndirect",
        K::CommandSubstitution { .. } => "CommandSubstitution",
        K::ProcessSubstitution { .. } => "ProcessSubstitution",
        K::AnsiCQuote { .. } => "AnsiCQuote",
        K::LocaleString { .. } => "LocaleString",
        K::BraceExpansion { .. } => "BraceExpansion",
        K::ArithmeticExpansion { .. } => "ArithmeticExpansion",
        K::ArithmeticCommand { .. } => "ArithmeticCommand",
        K::ArithNumber { .. } => "ArithNumber",
        K::ArithVar { .. } => "ArithVar",
        K::ArithBinaryOp { .. } => "ArithBinaryOp",
        K::ArithUnaryOp { .. } => "ArithUnaryOp",
        K::ArithPreIncr { .. } => "ArithPreIncr",
        K::ArithPostIncr { .. } => "ArithPostIncr",
        K::ArithPreDecr { .. } => "ArithPreDecr",
        K::ArithPostDecr { .. } => "ArithPostDecr",
        K::ArithAssign { .. } => "ArithAssign",
        K::ArithTernary { .. } => "ArithTernary",
        K::ArithComma { .. } => "ArithComma",
        K::ArithSubscript { .. } => "ArithSubscript",
        K::ArithEmpty => "ArithEmpty",
        K::ArithEscape { .. } => "ArithEscape",
        K::ArithDeprecated { .. } => "ArithDeprecated",
        K::ArithConcat { .. } => "ArithConcat",
        K::ConditionalExpr { .. } => "ConditionalExpr",
        K::UnaryTest { .. } => "UnaryTest",
        K::BinaryTest { .. } => "BinaryTest",
        K::CondAnd { .. } => "CondAnd",
        K::CondOr { .. } => "CondOr",
        K::CondNot { .. } => "CondNot",
        K::CondParen { .. } => "CondParen",
        K::CondTerm { .. } => "CondTerm",
        K::Negation { .. } => "Negation",
        K::Time { .. } => "Time",
        K::Array { .. } => "Array",
        K::Empty => "Empty",
        K::Comment { .. } => "Comment",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use rable::{CasePattern, ListItem, ListOperator, Node, NodeKind, PipeSep};

    fn shell(text: &str) -> &'static str {
        match logic(text) {
            Verdict::Shell(reason) => reason,
            Verdict::Argv(words) => panic!("{text:?} read as argv {words:?}"),
        }
    }

    fn argv(text: &str) -> Vec<String> {
        match logic(text) {
            Verdict::Argv(words) => words,
            Verdict::Shell(reason) => panic!("{text:?} read as shell ({reason})"),
        }
    }

    #[test]
    fn text_the_parser_rejects_is_shell() {
        // Rule 1, over the two inputs `hook.rs` already shows `rable` rejecting.
        assert_eq!(shell("if"), "unparseable");
        assert_eq!(shell("for x in"), "unparseable");
    }

    #[test]
    fn nothing_to_run_is_an_empty_argv() {
        // Rule 2: empty text, and a body of comments only.
        assert_eq!(argv(""), Vec::<String>::new());
        assert_eq!(argv("# why\n\n# and why not"), Vec::<String>::new());
    }

    #[test]
    fn an_unclosed_quote_is_shell() {
        // Rule 3: `rable` returns Ok and drops the word, so the parse is partial.
        assert_eq!(shell("echo \"a"), "unparseable");
        // A trailing comment holding a quote is the guard's stated residue.
        assert_eq!(shell("cargo build # don't"), "unparseable");
    }

    #[test]
    fn two_plain_lines_are_a_multi_command_body() {
        // Rule 4: one node per line, and two commands are a list.
        assert_eq!(shell("echo one\necho two"), "multi-command");
    }

    #[test]
    fn a_compound_construct_is_shell_by_its_node() {
        // Rule 5.
        assert_eq!(shell("for i in $(cmd); do :; done"), "For");
        assert_eq!(shell("[[ -n x ]]"), "ConditionalExpr");
        assert_eq!(shell("{ a; } > f"), "BraceGroup");
        assert_eq!(shell("a | b"), "Pipeline");
        assert_eq!(shell("cargo build && cargo test"), "List");
        assert_eq!(shell("cargo build; cargo test"), "List");
    }

    #[test]
    fn a_redirect_or_an_assignment_is_shell() {
        // Rule 6, redirect before assignment, and the assignment before its
        // own substitution.
        assert_eq!(shell("echo x > f"), "Redirect");
        assert_eq!(shell("cat <<EOF\nbody\nEOF"), "HereDoc");
        assert_eq!(shell("FOO=1 cargo test"), "assignment");
        assert_eq!(shell("X=$(rm f)"), "assignment");
    }

    #[test]
    fn an_expansion_is_shell_by_its_node() {
        // Rule 7.
        assert_eq!(shell("echo $(cmd)"), "CommandSubstitution");
        assert_eq!(shell("echo `cmd`"), "CommandSubstitution");
        assert_eq!(shell("echo $x"), "ParamExpansion");
        assert_eq!(shell("echo ${x:-y}"), "ParamExpansion");
        assert_eq!(shell("echo $((1))"), "ArithmeticExpansion");
        assert_eq!(shell("diff <(a) b"), "ProcessSubstitution");
        assert_eq!(shell("echo {a,b}"), "BraceExpansion");
        // Not brace expansion, so argv.
        assert_eq!(argv("echo {session} {{vars.x}}").len(), 3);
        // Quoting parts are quoting.
        assert_eq!(argv("echo $'a\\tb'"), ["echo", "$a\\tb"]);
    }

    #[test]
    fn a_bare_glob_or_tilde_is_shell_and_a_quoted_one_is_not() {
        // Rule 8.
        assert_eq!(shell("ls *.rs"), "glob");
        assert_eq!(shell("[ -n x ]"), "glob");
        assert_eq!(shell("curl https://x/?a=1"), "glob");
        assert_eq!(shell("cat ~/x"), "tilde");
        assert_eq!(
            argv("rg --exclude='*.md' \"a?\" \\*"),
            ["rg", "--exclude=*.md", "a?", "*"]
        );
        assert_eq!(argv("echo 'a*b'"), ["echo", "a*b"]);
    }

    #[test]
    fn quoting_alone_is_not_shell_logic() {
        // Rule 9.
        assert_eq!(argv("echo \">\" x"), ["echo", ">", "x"]);
        assert_eq!(argv("echo 'a|b'"), ["echo", "a|b"]);
        assert_eq!(argv("set -e"), ["set", "-e"]);
        assert_eq!(argv("cargo nextest run"), ["cargo", "nextest", "run"]);
        assert_eq!(argv("echo '$x'"), ["echo", "$x"]);
    }

    #[test]
    fn a_shebang_names_its_shell_by_the_interpreter_it_runs() {
        for (line, kind) in [
            ("#!/bin/sh", ShellKind::Sh),
            ("#!/bin/sh -e", ShellKind::Sh),
            ("#!/usr/bin/env bash", ShellKind::Bash),
            ("#!/usr/bin/env -S bash -eu", ShellKind::Bash),
            ("#!/bin/zsh", ShellKind::Zsh),
            ("#!/bin/dash", ShellKind::Dash),
            ("#!/bin/ksh", ShellKind::Ksh),
            ("#!/usr/bin/env fish", ShellKind::Fish),
            ("#!/bin/csh", ShellKind::Csh),
            ("#!/bin/tcsh", ShellKind::Tcsh),
            ("#!/bin/mksh", ShellKind::Mksh),
            ("#!/bin/ash", ShellKind::Ash),
            ("#!/usr/bin/yash", ShellKind::Yash),
            ("#!/bin/busybox sh", ShellKind::BusyboxSh),
            ("#!/usr/bin/env busybox sh", ShellKind::BusyboxSh),
        ] {
            assert_eq!(shebang(line), Some(kind), "{line}");
        }
        for line in [
            "#!/usr/bin/env python3",
            "#!/usr/bin/env bats",
            "#!/bin/busybox wget",
            "# bash",
            "bash",
        ] {
            assert_eq!(shebang(line), None, "{line}");
        }
    }

    #[test]
    fn a_shell_extension_is_shell_by_its_name() {
        for path in [
            "a.sh",
            "b/c.bash",
            "x.bats",
            "x.zsh",
            "x.ksh",
            "x.fish",
            "x.csh",
            "x.tcsh",
            "x.command",
        ] {
            assert!(shell_path(path), "{path}");
        }
        assert!(!shell_path("a/sh") && !shell_path("x.py"));
    }

    fn node(kind: NodeKind) -> Node {
        Node::empty(kind)
    }

    fn boxed(kind: NodeKind) -> Box<Node> {
        Box::new(node(kind))
    }

    /// Every `NodeKind` variant, one each, for the exhaustive table below.
    /// Three families, each lifted out whole for `clippy::too_many_lines`.
    fn every_kind() -> Vec<NodeKind> {
        let mut kinds = command_kinds();
        kinds.extend(word_kinds());
        kinds.extend(test_kinds());
        kinds
    }

    /// The simple and compound commands.
    fn command_kinds() -> Vec<NodeKind> {
        let s = String::new;
        vec![
            NodeKind::Word {
                value: s(),
                parts: Vec::new(),
                spans: Vec::new(),
            },
            NodeKind::WordLiteral { value: s() },
            NodeKind::Command {
                assignments: Vec::new(),
                words: Vec::new(),
                redirects: Vec::new(),
            },
            NodeKind::Pipeline {
                commands: Vec::new(),
                separators: vec![PipeSep::Pipe],
            },
            NodeKind::List {
                items: vec![ListItem {
                    command: node(NodeKind::Empty),
                    operator: Some(ListOperator::And),
                }],
            },
            NodeKind::If {
                condition: boxed(NodeKind::Empty),
                then_body: boxed(NodeKind::Empty),
                else_body: None,
                redirects: Vec::new(),
            },
            NodeKind::While {
                condition: boxed(NodeKind::Empty),
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::Until {
                condition: boxed(NodeKind::Empty),
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::For {
                var: s(),
                words: None,
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::ForArith {
                init: s(),
                cond: s(),
                incr: s(),
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::Select {
                var: s(),
                words: None,
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::Case {
                word: boxed(NodeKind::Empty),
                patterns: vec![CasePattern::new(Vec::new(), None, s())],
                redirects: Vec::new(),
            },
            NodeKind::Function {
                name: s(),
                body: boxed(NodeKind::Empty),
            },
            NodeKind::Subshell {
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::BraceGroup {
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::Coproc {
                name: None,
                command: boxed(NodeKind::Empty),
            },
        ]
    }

    /// Redirections, word parts and expansions.
    fn word_kinds() -> Vec<NodeKind> {
        let s = String::new;
        vec![
            NodeKind::Redirect {
                op: s(),
                target: boxed(NodeKind::Empty),
                fd: 1,
                varfd: None,
            },
            NodeKind::HereDoc {
                delimiter: s(),
                content: s(),
                strip_tabs: false,
                quoted: false,
                fd: 0,
                complete: true,
            },
            NodeKind::ParamExpansion {
                param: s(),
                op: None,
                arg: None,
            },
            NodeKind::ParamLength { param: s() },
            NodeKind::ParamIndirect {
                param: s(),
                op: None,
                arg: None,
            },
            NodeKind::CommandSubstitution {
                command: boxed(NodeKind::Empty),
                brace: false,
            },
            NodeKind::ProcessSubstitution {
                direction: s(),
                command: boxed(NodeKind::Empty),
            },
            NodeKind::AnsiCQuote {
                content: s(),
                decoded: s(),
            },
            NodeKind::LocaleString {
                content: s(),
                inner: s(),
            },
            NodeKind::BraceExpansion { content: s() },
            NodeKind::ArithmeticExpansion { expression: None },
            NodeKind::ArithmeticCommand {
                expression: None,
                redirects: Vec::new(),
                raw_content: s(),
            },
        ]
    }

    /// Arithmetic and conditional expression nodes, and the rest.
    fn test_kinds() -> Vec<NodeKind> {
        let s = String::new;
        vec![
            NodeKind::ArithNumber { value: s() },
            NodeKind::ArithVar { name: s() },
            NodeKind::ArithBinaryOp {
                op: s(),
                left: boxed(NodeKind::ArithEmpty),
                right: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithUnaryOp {
                op: s(),
                operand: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithPreIncr {
                operand: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithPostIncr {
                operand: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithPreDecr {
                operand: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithPostDecr {
                operand: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithAssign {
                op: s(),
                target: boxed(NodeKind::ArithEmpty),
                value: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithTernary {
                condition: boxed(NodeKind::ArithEmpty),
                if_true: None,
                if_false: None,
            },
            NodeKind::ArithComma {
                left: boxed(NodeKind::ArithEmpty),
                right: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithSubscript {
                array: s(),
                index: boxed(NodeKind::ArithEmpty),
            },
            NodeKind::ArithEmpty,
            NodeKind::ArithEscape { ch: s() },
            NodeKind::ArithDeprecated { expression: s() },
            NodeKind::ArithConcat { parts: Vec::new() },
            NodeKind::ConditionalExpr {
                body: boxed(NodeKind::Empty),
                redirects: Vec::new(),
            },
            NodeKind::UnaryTest {
                op: s(),
                operand: boxed(NodeKind::Empty),
            },
            NodeKind::BinaryTest {
                op: s(),
                left: boxed(NodeKind::Empty),
                right: boxed(NodeKind::Empty),
            },
            NodeKind::CondAnd {
                left: boxed(NodeKind::Empty),
                right: boxed(NodeKind::Empty),
            },
            NodeKind::CondOr {
                left: boxed(NodeKind::Empty),
                right: boxed(NodeKind::Empty),
            },
            NodeKind::CondNot {
                operand: boxed(NodeKind::Empty),
            },
            NodeKind::CondParen {
                inner: boxed(NodeKind::Empty),
            },
            NodeKind::CondTerm {
                value: s(),
                spans: Vec::new(),
            },
            NodeKind::Negation {
                pipeline: boxed(NodeKind::Empty),
            },
            NodeKind::Time {
                pipeline: boxed(NodeKind::Empty),
                posix: false,
            },
            NodeKind::Array {
                elements: Vec::new(),
            },
            NodeKind::Empty,
            NodeKind::Comment { text: s() },
        ]
    }

    #[test]
    fn every_node_kind_is_named_as_its_variant_is_spelled() {
        let kinds = every_kind();
        assert_eq!(kinds.len(), 57, "rable 0.2.1's `NodeKind` has 57 variants");
        let mut names = std::collections::BTreeSet::new();
        for kind in &kinds {
            let name = kind_name(kind);
            let debug = format!("{kind:?}");
            let spelled = debug
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap();
            assert_eq!(name, spelled, "{debug}");
            assert!(names.insert(name), "{name} named twice");
        }
    }

    #[test]
    fn a_top_level_kind_other_than_a_command_is_shell_by_its_name() {
        // Rule 5 over every variant: a lone node of each kind is shell named for
        // itself, save `Empty`, which is nothing to run.
        for kind in every_kind() {
            let name = kind_name(&kind);
            let verdict = command(&node(kind));
            match name {
                // An empty `Command` has no words, so it is an empty argv too.
                "Empty" | "Command" => assert_eq!(verdict, Verdict::Argv(Vec::new())),
                _ => assert_eq!(verdict, Verdict::Shell(name)),
            }
        }
    }
}

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
//! Which carriers run a text through a shell is a later row's. Which
//! interpreters take a script (`perl -e`, `sh -c`) is rule 10's, read from the
//! cited [`INTERPRETERS`] table through the mediation walk's own per-family
//! option grammar (CLOUD-2626). The mediation walk in `hook.rs`
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
    /// `unparseable`, `multi-command`, `assignment`, `glob`, `tilde`,
    /// `interpreter-script`.
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
    let verdict = command(node);
    // 10. One plain command whose program takes a script, and whose argv
    //     carries one (CLOUD-2626).
    if let Verdict::Argv(words) = &verdict
        && runs_script(&words.iter().map(String::as_str).collect::<Vec<_>>())
    {
        return Verdict::Shell(INTERPRETER_SCRIPT);
    }
    verdict
}

/// The reason rule 10 carries.
const INTERPRETER_SCRIPT: &str = "interpreter-script";

/// How a program in [`INTERPRETERS`] takes its script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Takes {
    /// Through an inline option only (`sh -c`, `perl -e`): a first operand is
    /// a script FILE, and whether that file is shell is not this table's
    /// question (CLOUD-2628's).
    Inline,
    /// Through an inline option, or as its first operand when no program-file
    /// option (`-f`) names it: the awk family and sed.
    Operand,
    /// A multi-call binary: its first operand names the applet, and the
    /// applet is the program, looked up in this table again.
    Applet,
}

/// One program that takes a script. Its option grammar (which flag is inline,
/// which takes a value) is `crate::hook`'s per-family `grammar`, the one the
/// mediation walk reads; this row names the program and how it takes a script,
/// and its doc comment carries the citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Interpreter {
    /// The program's name with any version suffix removed (`python3` is
    /// `python`).
    program: &'static str,
    /// How it takes its script.
    takes: Takes,
}

/// POSIX `sh`: `-c` reads commands from the command_string operand; otherwise
/// the first operand is a file of commands.
/// <https://pubs.opengroup.org/onlinepubs/9799919799/utilities/sh.html>
const SH: Interpreter = Interpreter {
    program: "sh",
    takes: Takes::Inline,
};

/// `dash`: as POSIX `sh`.
/// <https://manpages.debian.org/bookworm/dash/dash.1.en.html>
const DASH: Interpreter = Interpreter {
    program: "dash",
    takes: Takes::Inline,
};

/// `ksh` (OpenBSD): `-c string`; otherwise the first operand is a file.
/// <https://man.openbsd.org/ksh.1>
const KSH: Interpreter = Interpreter {
    program: "ksh",
    takes: Takes::Inline,
};

/// `mksh`: `-c cmd`; otherwise the first operand is a file, `-` or none stdin.
/// <https://manpages.debian.org/bookworm/mksh/mksh.1.en.html>
const MKSH: Interpreter = Interpreter {
    program: "mksh",
    takes: Takes::Inline,
};

/// `ash`, the Almquist shell as `BusyBox` ships it: `-c` as POSIX `sh`.
/// <https://busybox.net/downloads/BusyBox.html>
const ASH: Interpreter = Interpreter {
    program: "ash",
    takes: Takes::Inline,
};

/// `yash`: with `-c` "the shell interprets and executes the first operand as a
/// command string"; without it, the first operand is a file.
/// <https://magicant.github.io/yash/doc/invoke.html>
const YASH: Interpreter = Interpreter {
    program: "yash",
    takes: Takes::Inline,
};

/// `bash`: `-c command_string`; otherwise the first argument is a file of
/// commands. <https://manpages.debian.org/bookworm/bash/bash.1.en.html>
const BASH: Interpreter = Interpreter {
    program: "bash",
    takes: Takes::Inline,
};

/// `zsh`: `-c` takes the first argument as a command; otherwise it is a
/// script file. <https://manpages.debian.org/bookworm/zsh-common/zsh.1.en.html>
const ZSH: Interpreter = Interpreter {
    program: "zsh",
    takes: Takes::Inline,
};

/// `fish`: `-c`/`--command` and `-C`/`--init-command` carry commands;
/// `fish FILE` runs a file.
/// <https://fishshell.com/docs/current/cmds/fish.html>
const FISH: Interpreter = Interpreter {
    program: "fish",
    takes: Takes::Inline,
};

/// `csh`: "commands are read from the (single) following argument" of `-c`;
/// otherwise the first argument is a script file.
/// <https://manpages.debian.org/bookworm/csh/csh.1.en.html>
const CSH: Interpreter = Interpreter {
    program: "csh",
    takes: Takes::Inline,
};

/// `tcsh`: `-c` as `csh`; otherwise "the first argument is taken as the name
/// of a file of commands".
/// <https://manpages.debian.org/bookworm/tcsh/tcsh.1.en.html>
const TCSH: Interpreter = Interpreter {
    program: "tcsh",
    takes: Takes::Inline,
};

/// `busybox`: invoked as `busybox <applet> [arguments...]`, it behaves as the
/// applet, so `busybox sh -c …` is `sh -c …`.
/// <https://busybox.net/downloads/BusyBox.html>
const BUSYBOX: Interpreter = Interpreter {
    program: "busybox",
    takes: Takes::Applet,
};

/// `perl`: `-e`/`-E` (repeatable); otherwise the first argument is a file.
/// <https://perldoc.perl.org/perlrun>
const PERL: Interpreter = Interpreter {
    program: "perl",
    takes: Takes::Inline,
};

/// `python`: `-c`; otherwise a script, directory or zip, or `-`. `-m` runs a
/// module and carries no text. <https://docs.python.org/3/using/cmdline.html>
const PYTHON: Interpreter = Interpreter {
    program: "python",
    takes: Takes::Inline,
};

/// `node`: `-e`/`--eval` and `-p`/`--print`; otherwise an entry file.
/// <https://nodejs.org/api/cli.html>
const NODE: Interpreter = Interpreter {
    program: "node",
    takes: Takes::Inline,
};

/// `ruby`: `-e` "specifies script from command-line"; otherwise a
/// `program_file` operand. <https://manpages.debian.org/bookworm/ruby/ruby.1.en.html>
const RUBY: Interpreter = Interpreter {
    program: "ruby",
    takes: Takes::Inline,
};

/// POSIX `awk`: the first operand is the program unless `-f progfile` is
/// given. <https://pubs.opengroup.org/onlinepubs/9799919799/utilities/awk.html>
const AWK: Interpreter = Interpreter {
    program: "awk",
    takes: Takes::Operand,
};

/// `gawk`: as `awk`, adding `-e`/`--source` program text and `-E`/`--exec` as
/// a program file. <https://man7.org/linux/man-pages/man1/gawk.1.html>
const GAWK: Interpreter = Interpreter {
    program: "gawk",
    takes: Takes::Operand,
};

/// `mawk`: the first operand is the program text unless `-f program-file` is
/// given; it has no `-e`.
/// <https://manpages.debian.org/bookworm/mawk/mawk.1.en.html>
const MAWK: Interpreter = Interpreter {
    program: "mawk",
    takes: Takes::Operand,
};

/// `sed`: the first operand is the script unless `-e script` or `-f file` is
/// given. <https://pubs.opengroup.org/onlinepubs/9799919799/utilities/sed.html>
/// GNU `-i[SUFFIX]` edits in place and is an effect, not a script carrier:
/// <https://man7.org/linux/man-pages/man1/sed.1.html>
const SED: Interpreter = Interpreter {
    program: "sed",
    takes: Takes::Operand,
};

/// Every program that takes a script, researched and cited row by row
/// (CLOUD-2626). Every shell [`ShellKind`] names is here.
const INTERPRETERS: [Interpreter; 20] = [
    SH, DASH, KSH, MKSH, ASH, YASH, BASH, ZSH, FISH, CSH, TCSH, BUSYBOX, PERL, PYTHON, NODE, RUBY,
    AWK, GAWK, MAWK, SED,
];

/// Whether one argv runs a script: its program is in [`INTERPRETERS`] and the
/// argv carries one, or it is a wrapper whose utility does.
///
/// The detector's interpreter mutation rows, each killed by the unit case it
/// names, run from this file.
//MUTANT-SUITE crates/batten/src/shell.rs
//MUTANT wrapper-operand-unread|s@^    if wrapped.iter().any(\x7cutility\x7c runs_script(utility)) {$@    if false {@|a_wrapped_shell_is_a_script
fn runs_script(argv: &[&str]) -> bool {
    let Some((first, arguments)) = argv.split_first() else {
        return false;
    };
    let program = file_name(first);
    let wrapped = utilities(program, arguments);
    if wrapped.iter().any(|utility| runs_script(utility)) {
        return true;
    }
    interpreter(program, arguments)
}

/// Whether `program`, a table row, carries a script in `arguments`.
//MUTANT interpreter-inline-flag-unread|s@^        crate::hook::Carried::Inline => true,$@        crate::hook::Carried::Inline => false,@|an_interpreter_inline_flag_is_a_script
//MUTANT program-operand-unread|s@^        crate::hook::Carried::Operand => row.takes == Takes::Operand,$@        crate::hook::Carried::Operand => false,@|a_program_operand_is_a_script
fn interpreter(program: &str, arguments: &[&str]) -> bool {
    let family = crate::hook::family(program);
    let Some(row) = INTERPRETERS.iter().find(|row| row.program == family) else {
        return false;
    };
    if row.takes == Takes::Applet {
        return arguments
            .split_first()
            .is_some_and(|(applet, rest)| interpreter(file_name(applet), rest));
    }
    match crate::hook::carried(program, arguments) {
        crate::hook::Carried::Inline => true,
        crate::hook::Carried::Operand => row.takes == Takes::Operand,
        crate::hook::Carried::File | crate::hook::Carried::Elsewhere => false,
    }
}

/// The utilities a wrapper runs, each judged by the same rule; none for a
/// program that wraps nothing. The wrapper itself is argv: `env -S`, `xargs`
/// and `find -exec` take an argv, not shell, so what they run is the question.
fn utilities<'a>(program: &str, arguments: &[&'a str]) -> Vec<Vec<&'a str>> {
    match program {
        "find" => find_utilities(arguments),
        "env" => env_utility(arguments).into_iter().collect(),
        "xargs" => vec![after_options(arguments, XARGS_VALUED)],
        // The other wrappers the mediation walk looks through (`nohup`,
        // `timeout`, …): the utility follows their flags, assignments and
        // numeric arguments, as `hook::effective_program` steps over them.
        wrapper if crate::hook::is_lookthrough_wrapper(wrapper) => vec![
            arguments
                .iter()
                .copied()
                .skip_while(|word| {
                    word.starts_with('-')
                        || word.contains('=')
                        || word.starts_with(|c: char| c.is_ascii_digit())
                })
                .collect(),
        ],
        _ => Vec::new(),
    }
}

/// `find`'s utilities: the words after each `-exec`, `-execdir`, `-ok` or
/// `-okdir`, up to its `;` or `+`.
/// <https://pubs.opengroup.org/onlinepubs/9799919799/utilities/find.html>
fn find_utilities<'a>(arguments: &[&'a str]) -> Vec<Vec<&'a str>> {
    let mut found = Vec::new();
    let mut words = arguments.iter().copied();
    while let Some(word) = words.next() {
        if matches!(word, "-exec" | "-execdir" | "-ok" | "-okdir") {
            found.push(
                words
                    .by_ref()
                    .take_while(|word| !matches!(*word, ";" | "+"))
                    .collect(),
            );
        }
    }
    found
}

/// `xargs`' options that take a value: POSIX `-E eofstr`, `-I replstr`,
/// `-L number`, `-n number`, `-s size`, and GNU's `-a file`, `-d delim`,
/// `-P max-procs`. The utility is the first operand after them.
/// <https://pubs.opengroup.org/onlinepubs/9799919799/utilities/xargs.html>
const XARGS_VALUED: &[&str] = &["-E", "-I", "-L", "-n", "-s", "-a", "-d", "-P"];

/// `env`'s utility: the first word after its options and assignments, or the
/// `-S` string split into words, followed by whatever comes after it.
/// <https://man7.org/linux/man-pages/man1/env.1.html>
fn env_utility<'a>(arguments: &[&'a str]) -> Option<Vec<&'a str>> {
    let mut at = 0;
    while let Some(word) = arguments.get(at) {
        let split = match *word {
            "-S" | "--split-string" => arguments.get(at + 1).copied().map(|text| (text, at + 2)),
            _ => word
                .strip_prefix("--split-string=")
                .or_else(|| word.strip_prefix("-S").filter(|text| !text.is_empty()))
                .map(|text| (text, at + 1)),
        };
        if let Some((text, rest)) = split {
            let mut utility: Vec<&str> = text.split_whitespace().collect();
            utility.extend(arguments.get(rest..).unwrap_or_default());
            return Some(utility);
        }
        if matches!(*word, "-u" | "-C" | "--unset" | "--chdir") {
            at += 2;
        } else if word.starts_with('-') || word.contains('=') {
            at += 1;
        } else {
            return Some(arguments.get(at..).unwrap_or_default().to_vec());
        }
    }
    None
}

/// The words from the first operand on, past options and the values of those
/// in `valued` given as a separate word.
fn after_options<'a>(arguments: &[&'a str], valued: &[&str]) -> Vec<&'a str> {
    let mut at = 0;
    while let Some(word) = arguments.get(at) {
        if *word == "--" {
            at += 1;
            break;
        }
        if !word.starts_with('-') {
            break;
        }
        at += if valued.contains(word) { 2 } else { 1 };
    }
    arguments.get(at..).unwrap_or_default().to_vec()
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
    fn an_interpreter_inline_flag_is_a_script() {
        // Rule 10, one assertion per table row with an inline flag.
        for text in [
            "sh -c 'x'",
            "bash -c 'x'",
            "zsh -c 'x'",
            "dash -c 'x'",
            "ksh -c 'x'",
            "fish -c 'x'",
            "perl -e 'x'",
            "python -c 'x'",
            "node -e 'x'",
            "ruby -e 'x'",
            "gawk -e 'x'",
            // A bundle, a long form, a versioned name and a path.
            "bash -ec 'x'",
            "fish --command 'x'",
            "python3 -c 'x'",
            "/usr/bin/perl -E 'x'",
            "node --eval 'x'",
            "sed -n -e 's/a/b/p' f",
        ] {
            assert_eq!(shell(text), "interpreter-script", "{text}");
        }
        // A script file is argv here; whether it is shell is CLOUD-2628's.
        assert_eq!(argv("python script.py"), ["python", "script.py"]);
        assert_eq!(
            argv("python -m pytest -c x"),
            ["python", "-m", "pytest", "-c", "x"]
        );
        assert_eq!(argv("perl script.pl -e x").len(), 4);
        assert_eq!(argv("bash -e run").len(), 3);
    }

    #[test]
    fn every_shell_kind_runs_an_inline_script_and_a_file_is_argv() {
        // The owner's widening: every shell `ShellKind` names is a table row.
        for shell_name in [
            "sh",
            "bash",
            "zsh",
            "dash",
            "ksh",
            "fish",
            "csh",
            "tcsh",
            "mksh",
            "ash",
            "yash",
            "busybox sh",
            "busybox ash",
        ] {
            assert_eq!(
                shell(&format!("{shell_name} -c 'echo x'")),
                "interpreter-script",
                "{shell_name}"
            );
            let file = format!("{shell_name} script-file");
            assert_eq!(argv(&file).last().map(String::as_str), Some("script-file"));
        }
        assert_eq!(argv("busybox wget -c u").len(), 4);
    }

    #[test]
    fn a_program_operand_is_a_script() {
        for text in ["awk '{print}' f", "mawk '{print}' f", "sed 's/a/b/' f"] {
            assert_eq!(shell(text), "interpreter-script", "{text}");
        }
        assert_eq!(shell("awk -F, -v n=1 '{print}' f"), "interpreter-script");
        assert_eq!(argv("awk -f p.awk f"), ["awk", "-f", "p.awk", "f"]);
        assert_eq!(argv("sed -f p.sed f"), ["sed", "-f", "p.sed", "f"]);
        assert_eq!(argv("gawk --file=p.awk f").len(), 3);
        // A program-file option does not hide an inline one.
        assert_eq!(shell("gawk -f lib.awk -e 'x'"), "interpreter-script");
        // An inline-only interpreter's first operand is a file.
        assert_eq!(argv("ruby x.rb").len(), 2);
    }

    #[test]
    fn a_wrapped_shell_is_a_script() {
        for text in [
            "find . -exec sh -c 'x' \\;",
            "find . -name a -execdir bash -c 'x' {} +",
            "xargs sh -c 'x'",
            "xargs -I {} -n 1 sh -c 'x'",
            "env -S 'sh -c x'",
            "env FOO=1 perl -e 'x'",
            "nohup sh -c 'x'",
            "timeout 5 python3 -c 'x'",
        ] {
            assert_eq!(shell(text), "interpreter-script", "{text}");
        }
        assert_eq!(argv("find . -exec rm {} \\;").len(), 6);
        assert_eq!(argv("xargs rm"), ["xargs", "rm"]);
        assert_eq!(argv("env -S 'cargo test'").len(), 3);
        assert_eq!(argv("find . -name sh").len(), 4);
    }

    #[test]
    fn every_interpreter_row_carries_a_citation() {
        // Each `const … : Interpreter` row's doc comment names an https URL,
        // and the table holds exactly the rows declared.
        let source = include_str!("shell.rs");
        let lines: Vec<&str> = source.lines().collect();
        let mut rows = 0;
        for (at, line) in lines.iter().enumerate() {
            if !(line.starts_with("const ") && line.ends_with(": Interpreter = Interpreter {")) {
                continue;
            }
            rows += 1;
            let cited = lines[..at]
                .iter()
                .rev()
                .take_while(|above| above.starts_with("///"))
                .any(|above| above.contains("<https://"));
            assert!(cited, "{line} has no citation doc comment");
        }
        assert_eq!(rows, INTERPRETERS.len());
        let mut names = std::collections::BTreeSet::new();
        for row in INTERPRETERS {
            assert!(names.insert(row.program), "{} listed twice", row.program);
        }
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

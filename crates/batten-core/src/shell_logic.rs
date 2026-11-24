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
//! Which config fields run a text through a shell, and which spelling of one
//! avoids it, is the cited [`CARRIERS`] table (CLOUD-2627), read through
//! [`form`] and [`judge`]; a census reader exists for three of its rows. Which
//! interpreters take a script (`perl -e`, `sh -c`) is rule 10's, read from the
//! cited [`INTERPRETERS`] table through the mediation walk's own per-family
//! option grammar (CLOUD-2626). The mediation walk in `hook.rs`
//! parses with the same crate and is unchanged: this module calls the parser
//! itself and reads two of the walk's helpers, [`crate::shell::covered`] and
//! [`crate::shell::unquote`], rather than growing second copies.

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
    if !crate::shell::covered(&nodes, text) {
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
    /// Through a Windows switch (`cmd /C`, `pwsh -Command`), which the POSIX
    /// option grammar in `crate::hook` cannot read: switches are
    /// case-insensitive and PowerShell's may be shortened. Read by
    /// [`switch_script`].
    Switch,
}

/// One program that takes a script. Its option grammar (which flag is inline,
/// which takes a value) is `crate::interpreter`'s per-family `grammar`, the one
/// the mediation walk reads; this row names the program and how it takes a script,
/// and its doc comment carries the citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Interpreter {
    /// The program's name with any version suffix removed (`python3` is
    /// `python`).
    program: &'static str,
    /// How it takes its script.
    takes: Takes,
}

/// POSIX `sh`: `-c` reads commands from the `command_string` operand; otherwise
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

/// `cmd.exe`: `/C` carries out the command string and stops, `/K` carries it
/// out and remains, and `/R` is `/C`. Switches are case-insensitive, and the
/// string may follow the switch in the same word.
/// <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd>
const CMD: Interpreter = Interpreter {
    program: "cmd",
    takes: Takes::Switch,
};

/// Windows `PowerShell` (`powershell.exe`): `-Command` (`-c`) and
/// `-EncodedCommand` (`-e`, `-ec`) carry script text, `-` reads it from stdin,
/// and `-File` (`-f`) names a script file. With neither, the first operand is
/// a command, because `-Command` is the default parameter. Parameter names are
/// case-insensitive and may be shortened.
/// <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe>
const POWERSHELL: Interpreter = Interpreter {
    program: "powershell",
    takes: Takes::Switch,
};

/// `PowerShell` 7 (`pwsh`): as `powershell`, except that `-File` is the default
/// parameter, so a bare first operand is a script file.
/// <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh>
const PWSH: Interpreter = Interpreter {
    program: "pwsh",
    takes: Takes::Switch,
};

/// Every program that takes a script, researched and cited row by row
/// (CLOUD-2626). Every shell [`ShellKind`] names is here.
const INTERPRETERS: [Interpreter; 23] = [
    SH, DASH, KSH, MKSH, ASH, YASH, BASH, ZSH, FISH, CSH, TCSH, BUSYBOX, PERL, PYTHON, NODE, RUBY,
    AWK, GAWK, MAWK, SED, CMD, POWERSHELL, PWSH,
];

/// The Windows shell `program` names, read as Windows reads a program name:
/// case-insensitive, with or without `.exe`.
fn windows_shell(program: &str) -> Option<&'static str> {
    let stem = program
        .len()
        .checked_sub(".exe".len())
        .filter(|at| {
            program
                .get(*at..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
        })
        .and_then(|at| program.get(..at))
        .unwrap_or(program);
    INTERPRETERS
        .iter()
        .filter(|row| row.takes == Takes::Switch)
        .map(|row| row.program)
        .find(|name| stem.eq_ignore_ascii_case(name))
}

/// `PowerShell` parameters whose value is the next word, by full name and
/// documented alias; a shortened full name is read as the full name.
const POWERSHELL_VALUED: &[&str] = &[
    "configurationfile",
    "configurationname",
    "config",
    "custompipename",
    "executionpolicy",
    "ep",
    "ex",
    "inputformat",
    "in",
    "if",
    "outputformat",
    "o",
    "of",
    "psconsolefile",
    "settingsfile",
    "settings",
    "version",
    "v",
    "windowstyle",
    "w",
    "workingdirectory",
    "wd",
    "wo",
];

/// Whether a Windows shell's argv carries a script (the [`CMD`],
/// [`POWERSHELL`] and [`PWSH`] rows).
fn switch_script(program: &str, arguments: &[&str]) -> bool {
    if program == "cmd" {
        return arguments.iter().any(|word| cmd_switch(word));
    }
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        if *word == "-" {
            return true;
        }
        let Some(name) = word.strip_prefix('-').or_else(|| word.strip_prefix('/')) else {
            // The first operand: a command under `powershell`, a file under
            // `pwsh`.
            return program == "powershell";
        };
        let name = name
            .trim_start_matches('-')
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(name.as_str(), "c" | "e" | "ec")
            || (name.len() >= 3 && "command".starts_with(&name))
            || (name.len() >= 2 && "encodedcommand".starts_with(&name))
        {
            return true;
        }
        if name == "f" || (name.len() >= 2 && "file".starts_with(&name)) {
            return false;
        }
        let valued = POWERSHELL_VALUED.iter().any(|full| {
            *full == name || (name.len() >= 3 && full.len() > 3 && full.starts_with(&name))
        });
        if valued && !word.contains(':') {
            words.next();
        }
    }
    false
}

/// Whether one `cmd.exe` argument is `/C`, `/K` or `/R`, alone or with its
/// string attached.
fn cmd_switch(word: &str) -> bool {
    word.strip_prefix('/')
        .and_then(|rest| rest.chars().next())
        .is_some_and(|switch| matches!(switch.to_ascii_lowercase(), 'c' | 'k' | 'r'))
}

/// Whether one argv runs a script: its program is in [`INTERPRETERS`] and the
/// argv carries one, or it is a wrapper whose utility does.
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
fn interpreter(program: &str, arguments: &[&str]) -> bool {
    if let Some(windows) = windows_shell(program) {
        return switch_script(windows, arguments);
    }
    let family = crate::interpreter::family(program);
    let Some(row) = INTERPRETERS.iter().find(|row| row.program == family) else {
        return false;
    };
    match row.takes {
        Takes::Applet => {
            return arguments
                .split_first()
                .is_some_and(|(applet, rest)| interpreter(file_name(applet), rest));
        }
        Takes::Switch => return switch_script(row.program, arguments),
        Takes::Inline | Takes::Operand => {}
    }
    match crate::interpreter::carried(program, arguments) {
        crate::interpreter::Carried::Inline => true,
        crate::interpreter::Carried::Operand => row.takes == Takes::Operand,
        crate::interpreter::Carried::File | crate::interpreter::Carried::Elsewhere => false,
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
        wrapper if crate::interpreter::is_lookthrough_wrapper(wrapper) => vec![
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
        argv.push(crate::shell::unquote(value));
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
    /// `cmd.exe`, the Windows command interpreter.
    Cmd,
    /// `PowerShell`, as `powershell.exe` or `pwsh`.
    PowerShell,
}

/// Every interpreter name a shebang may carry, and the shell it is.
const SHELLS: [(&str, ShellKind); 14] = [
    ("cmd", ShellKind::Cmd),
    ("powershell", ShellKind::PowerShell),
    ("pwsh", ShellKind::PowerShell),
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
    let program = windows_shell(program).unwrap_or(program);
    SHELLS
        .iter()
        .find(|(name, _)| *name == program)
        .map(|(_, kind)| *kind)
}

/// Whether an argv engine source spawns runs a shell (CLOUD-2770): its first
/// word names a shell, read exactly as a shebang's interpreter is (`env` and
/// `busybox sh` included), or its program takes a script and the argv carries
/// one (rule 10's table). The census's spawn arm asks this, and declares no
/// list of its own.
#[must_use]
pub fn spawns_shell(argv: &[&str]) -> bool {
    shebang(&format!("#!{}", argv.join(" "))).is_some() || runs_script(argv)
}

/// The last `/`- or `\`-separated component: a Windows path names its program
/// after a backslash.
fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// File extensions that are shell whatever the first line says: the POSIX
/// family's, then `PowerShell`'s script and module, and `cmd.exe`'s batch files.
const EXTENSIONS: [&str; 13] = [
    ".sh", ".bash", ".bats", ".zsh", ".ksh", ".fish", ".csh", ".tcsh", ".command", ".ps1", ".psm1",
    ".bat", ".cmd",
];

/// Whether a path is shell by its name alone. The extension is read
/// case-insensitively, as Windows reads `RUN.BAT`.
#[must_use]
pub fn shell_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

// ---------------------------------------------------------------------------
// Carriers (CLOUD-2627): which config field hands its value to which shell,
// and which spelling of it avoids one.
// ---------------------------------------------------------------------------

/// Whether a value reaches a shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Form {
    /// The value is handed to a shell as a script: [`logic`] judges its text.
    Shell,
    /// The value is an argv the carrier spawns with no shell. Still judged by
    /// the interpreter table: `["sh", "-c", …]` re-enters a shell.
    Exec,
}

/// How a carrier's value is spelled, which is what decides its [`Form`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Spelling<'a> {
    /// One string.
    Text(&'a str),
    /// A list of strings.
    List(&'a [&'a str]),
    /// A command whose program and arguments are separate fields — a Claude
    /// Code hook's `command` beside `args`, an hk structured command — given
    /// as program then arguments.
    Structured(&'a [&'a str]),
}

/// How a carrier reads a one-string value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextForm {
    /// As a whole: the form named.
    Is(Form),
    /// A `!` prefix makes it a shell script (the text after the `!`); without
    /// one it is exec.
    Bang,
}

/// One carrier: a config field whose value a tool runs. Each row's doc
/// comment is its citation. A row holds no path: which files carry it is the
/// consumer's declaration.
///
/// A spelling a row does not declare (`None`) is read as [`Form::Shell`]: an
/// uncited spelling is never granted exec form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Carrier {
    /// The id a `[[census.shell.manifest]]` row names it by.
    pub id: &'static str,
    /// The fields whose values are commands, as they are spelled before
    /// `=` or `:`.
    pub fields: &'static [&'static str],
    /// How one string is read.
    text: Option<TextForm>,
    /// How a list of strings is read.
    list: Option<Form>,
    /// How a structured command is read.
    structured: Option<Form>,
}

/// mise task: a `run` string goes through `sh -o errexit -c` (Unix) or
/// `cmd /c` (Windows), and **a `run` array is a list of shell strings, not
/// argv**. A task-level `shell =` changes which shell, never the form; the
/// default-shell settings are global-only.
/// <https://mise.jdx.dev/tasks/toml-tasks.html>
/// <https://mise.jdx.dev/configuration/settings.html>
pub const MISE_TASK: Carrier = Carrier {
    id: "mise-task",
    fields: &["run"],
    text: Some(TextForm::Is(Form::Shell)),
    list: Some(Form::Shell), // a list of shell strings, never argv
    structured: None,
};

/// hk step: a `check`/`fix` string goes through `sh -o errexit -c`; a
/// structured command runs with no shell. A step's `shell` changes which.
/// <https://hk.jdx.dev/configuration.html>
pub const HK_STEP: Carrier = Carrier {
    id: "hk-step",
    fields: &["check", "fix"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: Some(Form::Exec),
};

/// GitHub Actions: `run:` goes through `bash -e {0}`, or with `shell: bash`
/// through `bash --noprofile --norc -eo pipefail {0}`. It has no no-shell
/// form; only `uses:` avoids a shell. Composite actions require `shell:`.
/// <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax>
pub const GHA_RUN: Carrier = Carrier {
    id: "gha-run",
    fields: &["run"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: None,
};

/// Dockerfile: the shell form of `RUN`/`CMD`/`ENTRYPOINT` goes through
/// `/bin/sh -c`; the JSON-array exec form runs with no shell. `SHELL` changes
/// only the shell form.
/// <https://docs.docker.com/reference/dockerfile/>
const DOCKERFILE: Carrier = Carrier {
    id: "dockerfile",
    fields: &["RUN", "CMD", "ENTRYPOINT"],
    text: Some(TextForm::Is(Form::Shell)),
    list: Some(Form::Exec),
    structured: None,
};

/// just: a recipe line runs through `sh -cu`, one shell per line; a shebang
/// recipe runs as a temporary file, and `[script]` through `sh -eu`. `set
/// shell` changes which. <https://just.systems/man/en/settings.html>
const JUST: Carrier = Carrier {
    id: "just",
    fields: &["recipe"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: None,
};

/// npm: a `scripts` entry runs through `/bin/sh` (`cmd.exe` on Windows);
/// `script-shell` changes which.
/// <https://docs.npmjs.com/cli/v10/using-npm/config#script-shell>
const NPM_SCRIPT: Carrier = Carrier {
    id: "npm-script",
    fields: &["scripts"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: None,
};

/// devcontainer: a lifecycle command string runs through `/bin/sh`; an array
/// runs with no shell. <https://containers.dev/implementors/json_reference/>
const DEVCONTAINER: Carrier = Carrier {
    id: "devcontainer",
    fields: &[
        "initializeCommand",
        "onCreateCommand",
        "updateContentCommand",
        "postCreateCommand",
        "postStartCommand",
        "postAttachCommand",
    ],
    text: Some(TextForm::Is(Form::Shell)),
    list: Some(Form::Exec),
    structured: None,
};

/// git: an `alias.*` value with a `!` prefix is a shell command; without one
/// it is a git subcommand. <https://git-scm.com/docs/git-config>
const GIT_ALIAS: Carrier = Carrier {
    id: "git-alias",
    fields: &["alias"],
    text: Some(TextForm::Bang),
    list: None,
    structured: None,
};

/// batten hook handler: `[[hook.handler]] run` is an argv array, spawned
/// with no shell. Source: this crate's own `[[hook.handler]]` schema.
const BATTEN_HANDLER: Carrier = Carrier {
    id: "batten-handler",
    fields: &["run"],
    text: None,
    list: Some(Form::Exec),
    structured: None,
};

/// batten bench: each `baseline` / `batten` workload step is one argv, run
/// through `exec::piped_argv` with no shell (CLOUD-2635; the row's earlier
/// `sh -c` per element is gone from the tree). Source: this crate's
/// `tokens.rs`, the bench's runner (`run_arm`).
const BATTEN_BENCH: Carrier = Carrier {
    id: "batten-bench",
    fields: &["baseline", "batten"],
    text: None,
    list: Some(Form::Exec),
    structured: None,
};

/// nextest setup script: a `command` string is split "using Unix shell
/// rules" into arguments, or given "as a list of arguments"; both run with no
/// shell, which appears only when the program is one (`sh -c`).
/// <https://nexte.st/docs/configuration/setup-scripts/> (fetched 2026-11-14)
const NEXTEST_SETUP: Carrier = Carrier {
    id: "nextest-setup",
    fields: &["command"],
    text: Some(TextForm::Is(Form::Exec)),
    list: Some(Form::Exec),
    structured: None,
};

/// mise template: `exec(command=…)` runs through "the default inline shell".
/// <https://mise.jdx.dev/templates.html> (fetched 2026-11-14)
const MISE_TEMPLATE: Carrier = Carrier {
    id: "mise-template",
    fields: &["exec"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: None,
};

/// Claude Code hook: `"command"` runs through `sh -c` when no `"args"` is
/// set; with `"args"` it is spawned directly, and `"shell"` is ignored.
/// <https://code.claude.com/docs/en/hooks> (fetched 2026-11-14)
const CLAUDE_HOOK: Carrier = Carrier {
    id: "claude-hook",
    fields: &["command"],
    text: Some(TextForm::Is(Form::Shell)),
    list: None,
    structured: Some(Form::Exec),
};

/// Every carrier, researched and cited row by row (CLOUD-2627). Make's recipe
/// lines go through `$(SHELL)` too, but its defaults are uncited, so it ships
/// no row.
pub const CARRIERS: [Carrier; 13] = [
    MISE_TASK,
    HK_STEP,
    GHA_RUN,
    DOCKERFILE,
    JUST,
    NPM_SCRIPT,
    DEVCONTAINER,
    GIT_ALIAS,
    BATTEN_HANDLER,
    BATTEN_BENCH,
    NEXTEST_SETUP,
    MISE_TEMPLATE,
    CLAUDE_HOOK,
];

/// The carrier a manifest row names by `id`.
#[must_use]
pub fn carrier(id: &str) -> Option<&'static Carrier> {
    CARRIERS.iter().find(|row| row.id == id)
}

/// Whether `carrier` hands `spelling` to a shell.
#[must_use]
pub fn form(carrier: &Carrier, spelling: &Spelling<'_>) -> Form {
    match spelling {
        Spelling::Text(text) => match carrier.text {
            Some(TextForm::Is(form)) => form,
            Some(TextForm::Bang) if !text.trim_start().starts_with('!') => Form::Exec,
            Some(TextForm::Bang) | None => Form::Shell,
        },
        Spelling::List(_) => carrier.list.unwrap_or(Form::Shell),
        Spelling::Structured(_) => carrier.structured.unwrap_or(Form::Shell),
    }
}

/// The detector's answer for one carrier value. `None` is a manifest no
/// carrier describes, whose every spelling is read as shell.
///
/// Shell form: a text is [`logic`]'s, and a list is shell when any of its
/// strings is (each is its own script), else its first string's argv. Exec
/// form: the argv, unless its program runs a script (rule 10).
#[must_use]
pub fn judge(carrier: Option<&Carrier>, spelling: &Spelling<'_>) -> Verdict {
    let form = carrier.map_or(Form::Shell, |carrier| form(carrier, spelling));
    match (form, spelling) {
        (Form::Shell, Spelling::Text(text)) => {
            let bang = carrier.is_some_and(|carrier| carrier.text == Some(TextForm::Bang));
            let script = if bang {
                text.trim_start().strip_prefix('!').unwrap_or(text)
            } else {
                text
            };
            logic(script)
        }
        (Form::Shell, Spelling::List(items) | Spelling::Structured(items)) => {
            let verdicts: Vec<Verdict> = items.iter().copied().map(logic).collect();
            verdicts
                .iter()
                .find(|verdict| matches!(verdict, Verdict::Shell(_)))
                .or_else(|| verdicts.first())
                .cloned()
                .unwrap_or(Verdict::Argv(Vec::new()))
        }
        (Form::Exec, Spelling::Text(text)) => exec(&text.split_whitespace().collect::<Vec<_>>()),
        (Form::Exec, Spelling::List(items) | Spelling::Structured(items)) => exec(items),
    }
}

/// An exec-form argv: shell only when its program runs a script.
fn exec(argv: &[&str]) -> Verdict {
    if runs_script(argv) {
        Verdict::Shell(INTERPRETER_SCRIPT)
    } else {
        Verdict::Argv(argv.iter().map(|word| (*word).to_owned()).collect())
    }
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
    fn a_windows_shell_switch_is_a_script() {
        // `cmd /C|/K|/R`, PowerShell's `-Command`/`-EncodedCommand` in any
        // case or shortening, stdin, and `powershell`'s default `-Command`.
        for text in [
            "cmd /C echo",
            "cmd /d /k dir",
            "CMD.EXE /cecho",
            "cmd /R x",
            "powershell -Command Get-Item",
            "powershell -c x",
            "pwsh -NoProfile -command x",
            "pwsh -Comm x",
            "pwsh -EncodedCommand AAAA",
            "pwsh -ec AAAA",
            "pwsh --command x",
            "pwsh /Command x",
            "pwsh -",
            "powershell -NoLogo Get-Item",
            "powershell -ExecutionPolicy Bypass Get-Item",
            // A valued switch's value is stepped over, so the `-c` after it is
            // still read: by its exact short name, and by a 3+ letter prefix.
            "pwsh -w Hidden -c x",
            "pwsh -exec Bypass -c x",
        ] {
            assert_eq!(shell(text), "interpreter-script", "{text}");
        }
        // A script file is argv here, as `bash script` is.
        for text in [
            "pwsh script.ps1",
            "pwsh -File script.ps1",
            "pwsh -ExecutionPolicy Bypass -File s.ps1",
            "powershell -f s.ps1",
            "pwsh -wd C:/x s.ps1",
            "cmd",
        ] {
            assert!(matches!(logic(text), Verdict::Argv(_)), "{text}");
        }
    }

    #[test]
    fn a_spawned_argv_runs_a_shell_by_its_program_or_its_script() {
        // CLOUD-2770: a shell program spawns a shell whatever its arguments; an
        // interpreter only when the argv carries a script.
        for argv in [
            &["sh"][..],
            &["/bin/bash", "script.sh"],
            &["env", "-i", "zsh"],
            &["busybox", "sh"],
            &["perl", "-e", "<computed>"],
            &["python3", "-c", "print(1)"],
            // Windows: a shell by its name, whatever its case or `.exe`.
            &["cmd", "/C"],
            &["CMD.EXE", "/c", "dir"],
            &["C:\\Windows\\System32\\cmd.exe", "/C", "x"],
            &["powershell", "-NoProfile"],
            &["pwsh.exe"],
        ] {
            assert!(spawns_shell(argv), "{argv:?}");
        }
        for argv in [
            &["git", "status"][..],
            &["python3", "x.py"],
            &["node", "-v"],
            &["cmdx", "/C"],
            &[],
        ] {
            assert!(!spawns_shell(argv), "{argv:?}");
        }
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
        // The words after the `-S` string, and only those, follow its split.
        assert_eq!(
            env_utility(&["-S", "sh -c x", "y"]),
            Some(vec!["sh", "-c", "x", "y"])
        );
        assert_eq!(
            env_utility(&["-i", "-S", "cargo test", "y"]),
            Some(vec!["cargo", "test", "y"])
        );
        assert_eq!(argv("find . -name sh").len(), 4);
    }

    #[test]
    fn the_carrier_table_bakes_in_no_consumer_path() {
        // Non-negotiable rule 1, held here for the table the census reads
        // (CLOUD-2627): which manifest or directory a carrier lives in is the
        // consumer's. Assembled so this test's own text is not a match.
        let source = include_str!("shell_logic.rs");
        for baked in [
            ["mise", ".toml"].concat(),
            [".github", "/workflows"].concat(),
            ["hk", ".pkl"].concat(),
            ["install", ".sh"].concat(),
            ["mise-", "tasks"].concat(),
        ] {
            assert!(
                !source.contains(&baked),
                "the carrier table names `{baked}`"
            );
        }
    }

    #[test]
    fn every_interpreter_row_carries_a_citation() {
        // Each `const … : Interpreter` row's doc comment names an https URL,
        // and the table holds exactly the rows declared.
        let source = include_str!("shell_logic.rs");
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
            ("#!/usr/bin/env pwsh", ShellKind::PowerShell),
            (
                "#!/opt/microsoft/powershell/7/pwsh -NoProfile",
                ShellKind::PowerShell,
            ),
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
            "x.ps1",
            "x.psm1",
            "x.bat",
            "RUN.BAT",
            "x.cmd",
        ] {
            assert!(shell_path(path), "{path}");
        }
        assert!(!shell_path("a/sh") && !shell_path("x.py") && !shell_path("x.psd1"));
    }

    fn text(row: &Carrier, value: &str) -> Form {
        form(row, &Spelling::Text(value))
    }

    fn list(row: &Carrier, values: &[&str]) -> Form {
        form(row, &Spelling::List(values))
    }

    #[test]
    fn a_docker_exec_array_is_exec_and_its_shell_form_is_shell() {
        assert_eq!(list(&DOCKERFILE, &["a", "b"]), Form::Exec);
        assert_eq!(text(&DOCKERFILE, "a b"), Form::Shell);
        // An exec form that names a shell re-enters one.
        assert_eq!(
            judge(Some(&DOCKERFILE), &Spelling::List(&["sh", "-c", "x"])),
            Verdict::Shell("interpreter-script")
        );
        assert_eq!(
            judge(Some(&DOCKERFILE), &Spelling::List(&["a", "b|c"])),
            Verdict::Argv(vec!["a".to_owned(), "b|c".to_owned()])
        );
    }

    #[test]
    fn every_carrier_reads_its_shell_form_as_shell_and_its_exec_form_as_exec() {
        // One shell-form value per row that has one.
        for row in [
            MISE_TASK,
            HK_STEP,
            GHA_RUN,
            DOCKERFILE,
            JUST,
            NPM_SCRIPT,
            DEVCONTAINER,
            MISE_TEMPLATE,
            CLAUDE_HOOK,
        ] {
            assert_eq!(text(&row, "a | b"), Form::Shell, "{}", row.id);
        }
        assert_eq!(list(&MISE_TASK, &["a && b"]), Form::Shell);
        assert_eq!(list(&BATTEN_BENCH, &["batten", "check"]), Form::Exec);
        assert_eq!(list(&BATTEN_HANDLER, &["batten", "hook"]), Form::Exec);
        // A spelling the row does not declare is never granted exec form.
        assert_eq!(text(&BATTEN_HANDLER, "batten hook"), Form::Shell);
        assert_eq!(list(&GHA_RUN, &["a"]), Form::Shell);
        // devcontainer: an array is exec, a string is shell.
        assert_eq!(list(&DEVCONTAINER, &["a", "b"]), Form::Exec);
        assert_eq!(text(&DEVCONTAINER, "a b"), Form::Shell);
        // git: `!` is shell, and the script is what follows it.
        assert_eq!(text(&GIT_ALIAS, "!git log | head"), Form::Shell);
        assert_eq!(text(&GIT_ALIAS, "log --oneline"), Form::Exec);
        assert_eq!(
            judge(Some(&GIT_ALIAS), &Spelling::Text("!git log | head")),
            Verdict::Shell("Pipeline")
        );
        assert_eq!(
            judge(Some(&GIT_ALIAS), &Spelling::Text("log --oneline")),
            Verdict::Argv(vec!["log".to_owned(), "--oneline".to_owned()])
        );
        // Claude Code: with `args` exec, without shell.
        assert_eq!(
            form(&CLAUDE_HOOK, &Spelling::Structured(&["batten", "hook"])),
            Form::Exec
        );
        assert_eq!(text(&CLAUDE_HOOK, "batten hook"), Form::Shell);
        // nextest: a string and an array are both exec.
        assert_eq!(text(&NEXTEST_SETUP, "cargo build"), Form::Exec);
        assert_eq!(list(&NEXTEST_SETUP, &["cargo", "build"]), Form::Exec);
        // ...and an exec `sh -c` is still a script.
        assert_eq!(
            judge(Some(&NEXTEST_SETUP), &Spelling::Text("sh -c x")),
            Verdict::Shell("interpreter-script")
        );
        // hk: a string is shell; a structured command is exec.
        assert_eq!(text(&HK_STEP, "cargo fmt"), Form::Shell);
        assert_eq!(
            form(&HK_STEP, &Spelling::Structured(&["cargo", "fmt"])),
            Form::Exec
        );
        // No carrier: every spelling is shell.
        assert_eq!(
            judge(None, &Spelling::List(&["a", "b && c"])),
            Verdict::Shell("List")
        );
    }

    #[test]
    fn every_carrier_row_carries_a_citation_and_a_listed_id() {
        let source = include_str!("shell_logic.rs");
        let lines: Vec<&str> = source.lines().collect();
        let mut rows = 0;
        for (at, line) in lines.iter().enumerate() {
            if !(line.contains("const ") && line.ends_with(": Carrier = Carrier {")) {
                continue;
            }
            rows += 1;
            let cited = lines[..at]
                .iter()
                .rev()
                .take_while(|above| above.starts_with("///"))
                .any(|above| above.contains("<https://") || above.contains("Source: "));
            assert!(cited, "{line} has no citation doc comment");
        }
        assert_eq!(rows, CARRIERS.len());
        let ids: Vec<&str> = CARRIERS.iter().map(|row| row.id).collect();
        assert_eq!(
            ids,
            [
                "mise-task",
                "hk-step",
                "gha-run",
                "dockerfile",
                "just",
                "npm-script",
                "devcontainer",
                "git-alias",
                "batten-handler",
                "batten-bench",
                "nextest-setup",
                "mise-template",
                "claude-hook",
            ]
        );
        for id in ids {
            assert_eq!(carrier(id).map(|row| row.id), Some(id));
        }
        assert!(carrier("make").is_none(), "Make's defaults are uncited");
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

    /// Fails by: a shortened `PowerShell` parameter name not read as the full
    /// valued one, so its value (`-c` here) is taken for the command switch.
    #[test]
    fn a_shortened_valued_powershell_parameter_consumes_its_value() {
        assert!(!switch_script("pwsh", &["-workingd", "-c", "x.ps1"]));
        assert!(switch_script("pwsh", &["-workingd", "dir", "-c", "x"]));
    }

    /// Fails by: any `cmd.exe` argument read as `/C`, `/K` or `/R`.
    #[test]
    fn only_a_run_switch_makes_cmd_run_a_script() {
        assert!(!switch_script("cmd", &["/d", "/q"]));
        assert!(!cmd_switch("/d"));
        assert!(!cmd_switch("c"));
        assert!(cmd_switch("/K"));
    }

    /// Fails by: the words after an attached `-S` string resumed from the
    /// wrong place, so the options before it are re-read as the utility's.
    #[test]
    fn an_attached_env_split_string_keeps_only_what_follows_it() {
        assert_eq!(
            env_utility(&["-i", "-Spython3 x.py", "y"]),
            Some(vec!["python3", "x.py", "y"])
        );
    }

    /// Fails by: a valued option's value not skipped, or the walk not
    /// advancing past an option at all.
    #[test]
    fn xargs_options_and_their_values_are_skipped_to_the_utility() {
        assert_eq!(
            after_options(&["-n", "1", "-t", "sh", "x.sh"], XARGS_VALUED),
            ["sh", "x.sh"]
        );
    }

    /// Fails by: a closing quote never closing, so a glob after a quoted
    /// span reads as quoted.
    #[test]
    fn a_glob_after_a_closed_quote_is_bare() {
        assert_eq!(bare_pattern("'a'*"), Some("glob"));
        assert_eq!(bare_pattern("\"a\"?"), Some("glob"));
        assert_eq!(bare_pattern("'a*'"), None);
    }

    /// Fails by: a `!`-carrier's text judged with its bang, or any other
    /// carrier's text judged without one.
    #[test]
    fn only_a_bang_carrier_strips_its_bang() {
        assert_ne!(logic("echo hi"), logic("!echo hi"), "the premise");
        let alias = carrier("git-alias").expect("the git alias row");
        assert_eq!(
            judge(Some(alias), &Spelling::Text("!echo hi")),
            logic("echo hi")
        );
        let shell = CARRIERS
            .iter()
            .find(|row| row.text == Some(TextForm::Is(Form::Shell)))
            .expect("a shell-text row");
        assert_eq!(
            judge(Some(shell), &Spelling::Text("!echo hi")),
            logic("!echo hi")
        );
    }

    /// Fails by: an abbreviated `-File` read as anything but a file switch.
    #[test]
    fn a_powershell_file_switch_abbreviates_from_two_letters() {
        for file in ["-f", "-fi", "-fil", "-file", "/File"] {
            assert!(!switch_script("powershell", &[file, "x.ps1"]), "{file}");
        }
        assert!(switch_script("powershell", &["x.ps1"]));
    }
}

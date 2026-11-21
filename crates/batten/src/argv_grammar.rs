//! How each interpreter family spells its options: the argv grammar the
//! hook's mediation walk and the shell detector both read (CLOUD-2304,
//! CLOUD-2626). A leaf, so the detector reaches it without reaching the hook.

/// How one interpreter family spells its options, as far as finding the script
/// operand needs (CLOUD-2304).
///
/// PER FAMILY, because one table cannot serve them: `-E` is an inline program
/// to perl, an encoding to ruby and "ignore the environment" to python; `-p` is
/// an inline program to node and a loop flag to perl and ruby; `-I` takes a
/// directory everywhere but python, where it is isolated mode. Reading every
/// family through one table admitted `python3 -E /tmp/x.py` and refused
/// `perl -ne '/re/ …' file`, whose program text it took for a script path.
pub(crate) struct Grammar {
    /// Short options that make the program INLINE, or point it at a module or
    /// stdin — no script file follows. Read inside a bundle too (`-ne`, `-Bc`).
    pub(crate) inline: &'static str,
    /// Long options that do the same.
    pub(crate) inline_long: &'static [&'static str],
    /// Short options whose value is the rest of the bundle or the next word.
    pub(crate) valued: &'static str,
    /// Long options whose value is the next word.
    pub(crate) valued_long: &'static [&'static str],
    /// Whether short options BUNDLE (`-ne`). Only a known family's do: the
    /// fallback also reads every program no table classifies, where `-verbose`
    /// is one word and reading its `e` as inline would refuse a mention.
    pub(crate) bundles: bool,
    /// The `inline` options that name a MODULE rather than carry program text
    /// (`python -m`): no script file follows, and no script text either
    /// (CLOUD-2626).
    pub(crate) module: &'static str,
    /// Short options whose value is a program FILE (`awk -f`, `sed -f`), which
    /// stops the first operand being the program text (CLOUD-2626). Not in
    /// `valued`, so `hook`'s `script_operand` steps over the letter alone and reads the
    /// file it names as the operand, as the fallback always did.
    pub(crate) program_file: &'static str,
    /// Long options that do the same.
    pub(crate) program_file_long: &'static [&'static str],
}

impl Grammar {
    /// The short options one argv word carries: every letter of a bundle, or
    /// the one letter of a lone `-x`, or none for a long option or an operand.
    pub(crate) fn shorts<'w>(&self, word: &'w str) -> Option<&'w str> {
        let rest = word.strip_prefix('-')?;
        if rest.is_empty() || rest.starts_with('-') {
            return None;
        }
        (self.bundles || rest.chars().count() == 1).then_some(rest)
    }

    /// The option that DECIDES a short bundle, read left to right: the first
    /// inline one (the program follows), or the first valued one (the rest of
    /// the bundle, or the next word, is its value). The one reading both
    /// `hook`'s `script_operand` and `inline_values` take.
    ///
    /// Only the bundle's leading LETTERS are options: `-W:no-deprecated` and
    /// `-d:Trace` attach a value after punctuation, and a letter inside that
    /// value is not a flag.
    pub(crate) fn decisive(&self, bundle: &str) -> Option<(usize, char)> {
        bundle
            .char_indices()
            .take_while(|(_, flag)| flag.is_ascii_alphanumeric())
            .find(|(_, flag)| self.inline.contains(*flag) || self.valued.contains(*flag))
    }
}

/// The fields every family leaves empty unless it says otherwise: no option of
/// any kind, and options that bundle. Each arm of [`grammar`] names only what it
/// adds.
const PLAIN: Grammar = Grammar {
    inline: "",
    inline_long: &[],
    valued: "",
    valued_long: &[],
    bundles: true,
    module: "",
    program_file: "",
    program_file_long: &[],
};

/// The grammar `program` is read through: its family's, or a conservative one
/// for an interpreter a consumer declared that no family describes.
pub(crate) fn grammar(program: &str) -> Grammar {
    match family(program) {
        "python" => Grammar {
            inline: "cm",
            valued: "WX",
            valued_long: &["--check-hash-based-pycs"],
            module: "m",
            ..PLAIN
        },
        "node" | "nodejs" => Grammar {
            inline: "ep",
            inline_long: &["--eval", "--print"],
            valued: "rC",
            valued_long: &[
                "--require",
                "--import",
                "--loader",
                "--conditions",
                "--input-type",
            ],
            ..PLAIN
        },
        "perl" => Grammar {
            inline: "eE",
            valued: "IMm",
            ..PLAIN
        },
        "ruby" => Grammar {
            inline: "e",
            valued: "rIEC",
            valued_long: &["--encoding"],
            ..PLAIN
        },
        // THE SHELLS (step 14): the POSIX shell family and the shells
        // the shell detector's `ShellKind` names (CLOUD-2626). `-c` makes the
        // first operand the command string, bundled or alone (`bash -lc '…'`,
        // `sh -ec '…'`), and `-o`/`-O` take an option name. Before this arm a
        // shell read through the fallback, which never bundles — so
        // `bash -lc 'git push --force'` handed no script to anything — and
        // which read `-e` (errexit to a shell) as a program. Each program's
        // citation is its row in the shell detector's interpreter table.
        "sh" | "dash" | "ksh" | "mksh" | "ash" | "yash" | "bash" | "zsh" | "csh" | "tcsh" => {
            Grammar {
                inline: "c",
                valued: "oO",
                valued_long: &["--rcfile", "--init-file"],
                ..PLAIN
            }
        }
        // fish: `-c`/`--command` and `-C`/`--init-command` both carry commands.
        "fish" => Grammar {
            inline: "cC",
            inline_long: &["--command", "--init-command"],
            valued: "dfo",
            valued_long: &["--debug", "--features", "--debug-output"],
            ..PLAIN
        },
        // POSIX awk and mawk: no inline option; the program is the first
        // operand unless `-f progfile` names it.
        "awk" | "mawk" => Grammar {
            valued: "FvW",
            program_file: "f",
            ..PLAIN
        },
        // gawk adds `-e`/`--source` text and `-E`/`--exec` as a program file.
        "gawk" => Grammar {
            inline: "e",
            inline_long: &["--source"],
            valued: "FvilW",
            valued_long: &["--assign", "--field-separator", "--include", "--load"],
            program_file: "fE",
            program_file_long: &["--file", "--exec"],
            ..PLAIN
        },
        // sed: `-e script`; `-f file`; otherwise the first operand.
        "sed" => Grammar {
            inline: "e",
            inline_long: &["--expression"],
            valued: "l",
            valued_long: &["--line-length"],
            program_file: "f",
            program_file_long: &["--file"],
            ..PLAIN
        },
        // The fallback keeps CLOUD-2231's original reading: exact `-c`, `-e`,
        // `-E`, `--command`, `--eval`, never a bundle.
        _ => Grammar {
            inline: "ceE",
            inline_long: &["--command", "--eval"],
            bundles: false,
            ..PLAIN
        },
    }
}

/// Where an interpreter's argv carries its program, read through its family's
/// [`grammar`] (CLOUD-2626). The detector's question, `shell_detect::logic`'s
/// rule 10; `hook`'s `script_operand` asks the operand gate's narrower one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carried {
    /// An inline option carries program text (`-c`, `-e`, `--eval`), wherever
    /// it stands among the options.
    Inline,
    /// A program-file option names it (`awk -f`), and no inline option
    /// carries text.
    File,
    /// The first operand: a script file to most families, the program text
    /// itself to awk's and sed's.
    Operand,
    /// None of those: a module, stdin, or nothing at all.
    Elsewhere,
}

/// Read `arguments`, the words after `program`, for where they carry its
/// program: the options up to the first operand, `--` or `-`, each through the
/// family's [`grammar`].
pub(crate) fn carried(program: &str, arguments: &[&str]) -> Carried {
    // The answer where the options end: a program-file option outranks the
    // operand it leaves behind.
    fn stop(file: bool, operand: bool) -> Carried {
        match (file, operand) {
            (true, _) => Carried::File,
            (false, true) => Carried::Operand,
            (false, false) => Carried::Elsewhere,
        }
    }
    let grammar = grammar(program);
    let mut file = false;
    let mut words = arguments.iter().copied();
    while let Some(word) = words.next() {
        if word == "--" {
            return stop(file, words.next().is_some());
        }
        if word == "-" {
            return stop(file, false);
        }
        let (name, attached) = long_option(word);
        if grammar.inline_long.contains(&name) {
            return Carried::Inline;
        }
        let file_long = grammar.program_file_long.contains(&name);
        if file_long || grammar.valued_long.contains(&name) {
            file |= file_long;
            if attached.is_none() {
                words.next();
            }
            continue;
        }
        if word.starts_with("--") {
            continue;
        }
        if !word.starts_with('-') {
            return stop(file, true);
        }
        let Some(bundle) = grammar.shorts(word) else {
            continue;
        };
        // The first letter that decides the bundle, a program-file option
        // included: what follows it is that option's value.
        let decisive = bundle
            .char_indices()
            .take_while(|(_, flag)| flag.is_ascii_alphanumeric())
            .find(|(_, flag)| {
                grammar.inline.contains(*flag)
                    || grammar.valued.contains(*flag)
                    || grammar.program_file.contains(*flag)
            });
        match decisive {
            Some((_, flag)) if grammar.module.contains(flag) => return stop(file, false),
            Some((_, flag)) if grammar.inline.contains(flag) => return Carried::Inline,
            Some((at, flag)) => {
                file |= grammar.program_file.contains(flag);
                if at + flag.len_utf8() == bundle.len() {
                    words.next();
                }
            }
            None => {}
        }
    }
    stop(file, false)
}

/// A long option split at its `=`: `--eval=code` is `("--eval", Some("code"))`.
/// Any other word is itself with nothing attached.
pub(crate) fn long_option(word: &str) -> (&str, Option<&str>) {
    match word.split_once('=') {
        Some((name, value)) if name.starts_with("--") => (name, Some(value)),
        _ => (word, None),
    }
}

/// A character of a version suffix: `3.12`, `5.36`, `-22`.
pub(crate) fn is_version_char(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, '.' | '-')
}

/// The family `program` belongs to: its name with any version suffix removed,
/// so `perl5.36` and `node22` read through `perl`'s and `node`'s grammar just
/// as [`declares`] admits them.
pub(crate) fn family(program: &str) -> &str {
    program.trim_end_matches(is_version_char)
}

#[cfg(test)]
mod tests {
    /// Each family's grammar decides where its argv carries the program, field
    /// by field (CLOUD-2626): an inline option, a program-file option, a value
    /// skipped, a module, or the first operand.
    ///
    /// Fails by: a family arm or a grammar field going unread, which moves a
    /// case to the fallback's answer or to the bare first operand.
    #[test]
    fn each_familys_grammar_says_where_its_program_is_carried() {
        use super::Carried::{Elsewhere, File, Inline, Operand};
        let cases: &[(&str, &[&str], super::Carried)] = &[
            // python: `-c`, `-m` module, a valued long option.
            ("python3", &["-c", "x"], Inline),
            ("python3", &["-m", "pytest"], Elsewhere),
            ("python3", &["--check-hash-based-pycs", "always"], Elsewhere),
            ("python3", &["x.py"], Operand),
            // ruby: `-e`, and `--encoding` takes a value.
            ("ruby", &["-e", "x"], Inline),
            ("ruby", &["--encoding", "utf-8"], Elsewhere),
            // The shell family: `-c` in a bundle, `-o` and `--rcfile` valued,
            // and a value attached to its letter or not.
            ("sh", &["-c", "x"], Inline),
            ("bash", &["-ec", "x"], Inline),
            ("zsh", &["-o", "pipefail"], Elsewhere),
            ("bash", &["--rcfile", "rc"], Elsewhere),
            ("bash", &["-opipefail", "x"], Operand),
            ("bash", &["-eo", "pipefail"], Elsewhere),
            ("bash", &["--", "x"], Operand),
            ("bash", &["-", "x"], Elsewhere),
            ("bash", &["script"], Operand),
            // fish: both inline options, short and long, and its valued ones.
            ("fish", &["-C", "x"], Inline),
            ("fish", &["--init-command", "x"], Inline),
            ("fish", &["-d", "3"], Elsewhere),
            ("fish", &["--features", "x"], Elsewhere),
            // awk: `-f` names a file, `-v` takes a value, else the operand.
            ("awk", &["-f", "p.awk"], File),
            ("mawk", &["-v", "n=1"], Elsewhere),
            ("awk", &["{print}"], Operand),
            // gawk: every option kind, short and long.
            ("gawk", &["-e", "x"], Inline),
            ("gawk", &["--source", "x"], Inline),
            ("gawk", &["-i", "lib"], Elsewhere),
            ("gawk", &["--include", "lib"], Elsewhere),
            ("gawk", &["-E", "p.awk"], File),
            ("gawk", &["--file", "p.awk"], File),
            // sed: likewise.
            ("sed", &["-e", "x"], Inline),
            ("sed", &["--expression", "x"], Inline),
            ("sed", &["-l", "5"], Elsewhere),
            ("sed", &["--line-length", "5"], Elsewhere),
            ("sed", &["-f", "p.sed"], File),
            ("sed", &["--file", "p.sed"], File),
            // The fallback: exact `-c`/`-e`/`--eval`/`--command`, no bundle.
            ("an-interpreter", &["--command", "x"], Inline),
            ("an-interpreter", &["-ec", "x"], Operand),
        ];
        for (program, arguments, expected) in cases {
            assert_eq!(
                super::carried(program, arguments),
                *expected,
                "{program} {arguments:?}"
            );
        }
    }
}

//! How an interpreter's argv names its program (CLOUD-2304): each family's
//! option grammar, the script operand it runs, and the inline program text it
//! carries.
//!
//! A leaf below `hook` (CLOUD-2789), beside the parse in [`crate::shell`]: the
//! grammar is DATA over an argv and carries no judgement, so the shell detector
//! ported from #1278 and every hook reach it from below rather than calling up
//! into `hook`. It lived in `hook.rs` until the detector needed it, which would
//! have put a `batten-core` module above the hooks.

/// How one interpreter family spells its options, as far as finding the script
/// operand needs (CLOUD-2304).
///
/// PER FAMILY, because one table cannot serve them: `-E` is an inline program
/// to perl, an encoding to ruby and "ignore the environment" to python; `-p` is
/// an inline program to node and a loop flag to perl and ruby; `-I` takes a
/// directory everywhere but python, where it is isolated mode. Reading every
/// family through one table admitted `python3 -E /tmp/x.py` and refused
/// `perl -ne '/re/ …' file`, whose program text it took for a script path.
#[derive(Debug)]
pub struct Grammar {
    /// Short options that make the program INLINE, or point it at a module or
    /// stdin — no script file follows. Read inside a bundle too (`-ne`, `-Bc`).
    pub inline: &'static str,
    /// Long options that do the same.
    pub inline_long: &'static [&'static str],
    /// Short options whose value is the rest of the bundle or the next word.
    pub valued: &'static str,
    /// Long options whose value is the next word.
    pub valued_long: &'static [&'static str],
    /// Whether short options BUNDLE (`-ne`). Only a known family's do: the
    /// fallback also reads every program no table classifies, where `-verbose`
    /// is one word and reading its `e` as inline would refuse a mention.
    pub bundles: bool,
    /// The `inline` options that name a MODULE rather than carry program text
    /// (`python -m`): no script file follows, and no script text either
    /// (CLOUD-2626).
    pub module: &'static str,
    /// Short options whose value is a program FILE (`awk -f`, `sed -f`), which
    /// stops the first operand being the program text (CLOUD-2626). Not in
    /// `valued`, so [`script_operand`] steps over the letter alone and reads the
    /// file it names as the operand, as the fallback always did.
    pub program_file: &'static str,
    /// Long options that do the same.
    pub program_file_long: &'static [&'static str],
}

impl Grammar {
    /// The short options one argv word carries: every letter of a bundle, or
    /// the one letter of a lone `-x`, or none for a long option or an operand.
    #[must_use]
    pub fn shorts<'w>(&self, word: &'w str) -> Option<&'w str> {
        let rest = word.strip_prefix('-')?;
        if rest.is_empty() || rest.starts_with('-') {
            return None;
        }
        (self.bundles || rest.chars().count() == 1).then_some(rest)
    }

    /// The option that DECIDES a short bundle, read left to right: the first
    /// inline one (the program follows), or the first valued one (the rest of
    /// the bundle, or the next word, is its value). The one reading both
    /// [`script_operand`] and [`inline_values`] take.
    ///
    /// Only the bundle's leading LETTERS are options: `-W:no-deprecated` and
    /// `-d:Trace` attach a value after punctuation, and a letter inside that
    /// value is not a flag.
    #[must_use]
    pub fn decisive(&self, bundle: &str) -> Option<(usize, char)> {
        bundle
            .char_indices()
            .take_while(|(_, flag)| flag.is_ascii_alphanumeric())
            .find(|(_, flag)| self.inline.contains(*flag) || self.valued.contains(*flag))
    }
}

/// The fields every family leaves empty unless it says otherwise: no option of
/// any kind, and options that bundle. Each arm of [`grammar`] names only what it
/// adds (ported from #1278's 665c4a17).
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
#[must_use]
pub fn grammar(program: &str) -> Grammar {
    match family(program) {
        // THE SHELLS (step 14). `-c` takes the script, bundled or alone
        // (`bash -lc '…'`, `sh -ec '…'`), and `-o`/`-O` take an option name.
        // Before this arm a shell read through the fallback, which never
        // bundles — so `bash -lc 'git push --force'` handed no script to
        // anything — and which read `-e` (errexit to a shell) as a program.
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "ash" | "yash" | "csh" | "tcsh" => {
            Grammar {
                inline: "c",
                valued: "oO",
                valued_long: &["--rcfile", "--init-file"],
                ..PLAIN
            }
        }
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
        // fish: `-c`/`--command` and `-C`/`--init-command` both carry commands
        // (CLOUD-2626, ported from #1278).
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

/// A long option split at its `=`: `--eval=code` is `("--eval", Some("code"))`.
/// Any other word is itself with nothing attached.
/// Where an interpreter's argv carries its program, read through its family's
/// [`grammar`] (CLOUD-2626). The detector's question, [`crate::shell::logic`]'s
/// rule 10; [`script_operand`] asks the operand gate's narrower one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
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
#[must_use]
pub fn carried(program: &str, arguments: &[&str]) -> Carried {
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

#[must_use]
pub fn long_option(word: &str) -> (&str, Option<&str>) {
    match word.split_once('=') {
        Some((name, value)) if name.starts_with("--") => (name, Some(value)),
        _ => (word, None),
    }
}

/// Whether the declared `entry` names `program`: exactly, or as a versioned
/// spelling of it (`python3` declares `python3.12`), since a row lists the
/// interpreter and not every minor version the host installs.
#[must_use]
pub fn declares(entry: &str, program: &str) -> bool {
    program
        .strip_prefix(entry)
        .is_some_and(|version| version.chars().all(is_version_char))
}

/// A character of a version suffix: `3.12`, `5.36`, `-22`.
#[must_use]
pub fn is_version_char(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, '.' | '-')
}

/// The family `program` belongs to: its name with any version suffix removed,
/// so `perl5.36` and `node22` read through `perl`'s and `node`'s grammar just
/// as [`declares`] admits them.
pub fn family(program: &str) -> &str {
    program.trim_end_matches(is_version_char)
}

/// The values of every INLINE option in an interpreter's argv: the program
/// text it runs, read through the same [`grammar`] [`script_operand`] stops at,
/// so the protected-path scan reads exactly what the operand gate leaves to it
/// (CLOUD-2304). A value is the rest of the bundle (`-e'…'`) or the next word.
pub fn inline_values(grammar: &Grammar, arguments: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    let mut words = arguments.iter().copied();
    while let Some(word) = words.next() {
        let (name, attached) = long_option(word);
        if grammar.inline_long.contains(&name) {
            match attached {
                Some(value) => values.push(value.to_owned()),
                None => values.extend(words.next().map(str::to_owned)),
            }
            continue;
        }
        let Some(bundle) = grammar.shorts(word) else {
            continue;
        };
        // The first inline option, unless a valued one comes first and takes
        // the rest of the bundle as its own value (`-MFile::Temp`).
        let Some((at, flag)) = grammar
            .decisive(bundle)
            .filter(|(_, flag)| grammar.inline.contains(*flag))
        else {
            continue;
        };
        let rest = &bundle[at + flag.len_utf8()..];
        // Further inline options (`-pe`) leave the program to the next word;
        // anything else attached is the program itself (`-e'…'`).
        if rest.chars().all(|flag| grammar.inline.contains(flag)) {
            values.extend(words.next().map(str::to_owned));
        } else {
            values.push(rest.to_owned());
        }
    }
    values
}

/// The script file an interpreter's argv names, read through its `grammar`, or
/// `None` when it runs an inline program, a module or stdin, or names nothing
/// this can place. Each word is NORMALISED as the program is: a grouped
/// command's closing paren rides on its last word.
#[must_use]
pub fn script_operand<'a>(grammar: &Grammar, arguments: &[&'a str]) -> Option<&'a str> {
    let mut words = arguments.iter().map(|word| program_token(word));
    while let Some(word) = words.next() {
        if word == "--" {
            return words.next().filter(|word| placeable(word));
        }
        let (name, attached) = long_option(word);
        if word == "-" || grammar.inline_long.contains(&name) {
            return None;
        }
        if grammar.valued_long.contains(&name) {
            if attached.is_none() {
                words.next();
            }
            continue;
        }
        if word.starts_with("--") {
            continue;
        }
        if !word.starts_with('-') {
            return placeable(word).then_some(word);
        }
        // An option word that is not a bundle this grammar reads skips alone.
        let Some(bundle) = grammar.shorts(word) else {
            continue;
        };
        // An inline option ends the search; a valued one at the bundle's end
        // takes the next word.
        match grammar.decisive(bundle) {
            Some((_, flag)) if grammar.inline.contains(flag) => return None,
            Some((at, flag)) if at + flag.len_utf8() == bundle.len() => {
                words.next();
            }
            _ => {}
        }
    }
    None
}

/// A word a static reading can resolve: no expansion, no home, no redirection.
#[must_use]
pub fn placeable(word: &str) -> bool {
    !word.is_empty()
        && !word.contains('$')
        && !word.starts_with('~')
        && !word.contains('>')
        && !word.contains('<')
}

/// The token with any GROUPING punctuation it was written against removed.
///
/// `(git` is one word to [`segments`], because `(` is not a separator and a
/// grouping construct needs no space after it. So the identity and the token are
/// different strings here in exactly the way they are for `/usr/bin/git`, and
/// [`program_name`] is the precedent: the boundary answers what this IS, and a
/// caller comparing the raw token answers no for the spelling that carries the
/// bypass.
///
/// # BOTH ENDS, and the opening-only version was a bypass of its own
///
/// This stripped `(` and said a trailing `)` *"belongs to whichever operand it
/// was written against"*. That reasoning holds for a path and is false for the
/// LAST token of a grouped command, which is where the closing paren actually
/// lands — and every predicate matching an exact flag or an exact path is
/// decided on exactly that token. Measured over the shipped binary, this
/// repository's committed config:
///
/// * `(git push origin main --force)` — allowed, because `arguments` ended
///   `--force)` and `trunk push forced` compares for equality. The same command with
///   the flag written earlier denied, so the bypass was a matter of word order.
/// * `(rm batten.toml)` — allowed, because the operand was `batten.toml)` and no
///   protected path matches it. That one predates this row and is the same
///   defect one gate over: `rm batten.toml` and `time rm batten.toml` both
///   refuse.
///
/// # The bound, stated
///
/// Leading `(`/`{` are stripped unconditionally; trailing `)`/`}` are stripped
/// only where the remainder carries no opener of its own. That keeps a command
/// substitution intact — `binary=$(which gh)` is ONE word to [`segments`], and
/// its `)` closes the `$(` inside it rather than a group around it — while
/// reaching every case above. It is a rule about two characters, not a parser,
/// and CLOUD-1381 is still what replaces it.
#[must_use]
pub fn program_token(token: &str) -> &str {
    let opened = token.trim_start_matches(['(', '{']);
    if opened.contains(['(', '{']) {
        return opened;
    }
    opened.trim_end_matches([')', '}'])
}

/// The wrapper programs the boundary's program reading (`hook::effective_program`)
/// looks through **unconditionally**.
///
/// Declared once because three surfaces read it: the matcher, to step past a
/// wrapper and judge what it wraps; the config validator, to refuse a `pattern`
/// naming one — by the time a pattern is compared the wrapper has already been
/// stepped past, so `pattern = "nohup rm"` is a row that can never fire
/// (CLOUD-401); and the shell detector, which reads what a wrapper hands on
/// (CLOUD-2626). Data over an argv that names no policy, so it lives beside the
/// grammar rather than in the config model (plan step 5's layering).
///
/// `mise` is deliberately **not** here: only `mise exec`/`mise x` is looked
/// through, so `mise run` is judged as `mise` and `pattern = "mise run"` is a
/// row the matcher honours.
pub const LOOKTHROUGH_WRAPPERS: [&str; 10] = [
    "env", "command", "nice", "stdbuf", "timeout", "xargs", "sudo", "doas", "nohup", "exec",
];

/// Is this token a program the boundary always looks through?
#[must_use]
pub fn is_lookthrough_wrapper(token: &str) -> bool {
    LOOKTHROUGH_WRAPPERS.contains(&token)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Fails by: fish read through the fallback, which knows neither
    /// `-C`/`--init-command` nor a bundle, so each of those carries no
    /// command.
    #[test]
    fn fish_carries_a_command_in_its_init_option_and_in_a_bundle() {
        for arguments in [&["-C", "x"][..], &["--init-command", "x"], &["-lc", "x"]] {
            assert_eq!(carried("fish", arguments), Carried::Inline, "{arguments:?}");
        }
    }

    /// Fails by: awk's `-f` read as no option, so the program file it names
    /// is taken for the program text (`Operand`) rather than a file the
    /// program is read from (CLOUD-2789).
    #[test]
    fn awk_reads_its_program_from_the_file_dash_f_names() {
        for program in ["awk", "mawk"] {
            assert_eq!(
                carried(program, &["-f", "prog.awk", "data"]),
                Carried::File,
                "{program}"
            );
            assert_eq!(
                carried(program, &["{ print }", "data"]),
                Carried::Operand,
                "{program}"
            );
        }
    }

    /// Fails by: a shell's `-c` dropped from its inline options (shard 4/16's
    /// `inline` survivor), so `bash -c text` reads the text as a script file.
    #[test]
    fn a_shells_dash_c_carries_an_inline_program() {
        let bash = grammar("bash");
        assert_eq!(script_operand(&bash, &["-c", "run.sh"]), None);
        assert_eq!(script_operand(&bash, &["run.sh"]), Some("run.sh"));
    }

    /// Fails by: node's `--eval` or `--print` dropped from its inline long
    /// options, or the lone-dash-or-inline test's `||` read as `&&` (shard
    /// 4/16's survivors), so the code or stdin reads as a script file.
    #[test]
    fn nodes_eval_print_and_a_lone_dash_name_no_script() {
        let node = grammar("node");
        for inline in ["--eval", "--print", "-"] {
            assert_eq!(script_operand(&node, &[inline, "app.js"]), None, "{inline}");
        }
        assert_eq!(script_operand(&node, &["app.js"]), Some("app.js"));
    }

    /// Fails by: ruby's valued `-r` dropped (shard 4/16's `valued` survivor),
    /// so the library it loads reads as the script.
    #[test]
    fn rubys_dash_r_takes_its_library_before_the_script() {
        assert_eq!(
            script_operand(&grammar("ruby"), &["-r", "json", "app.rb"]),
            Some("app.rb")
        );
    }

    /// Fails by: the fallback's long options dropped, so an interpreter no
    /// family describes reads `--eval code` or `--command=code` as carrying
    /// nothing, and the program text in it goes unread (CLOUD-2789).
    #[test]
    fn the_fallback_carries_a_program_in_its_long_inline_options() {
        assert_eq!(family("tclsh"), "tclsh", "no family describes it");
        for arguments in [&["--eval", "x"][..], &["--command=x"]] {
            assert_eq!(
                carried("tclsh", arguments),
                Carried::Inline,
                "{arguments:?}"
            );
        }
        assert_ne!(carried("tclsh", &["--verbose", "x"]), Carried::Inline);
    }
}

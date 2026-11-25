//! The shell parse every hook judges a command by (CLOUD-2388): a command line
//! split into its segments, each segment's words with quotes resolved, and the
//! here-doc and here-string text fed to its stdin, through `rable`.
//!
//! A leaf below `hook` (CLOUD-2789), which judges what this reads: a parser
//! names no policy, so the modules that only need the words (`testing`, the
//! census) do not reach up into the hooks.
//!
//! Whether a text is shell LOGIC is [`crate::shell_logic`]'s, a sibling that
//! reads this parse: kept out of this module so every reader of the words does
//! not also reach the interpreter grammar the detector needs.

/// Every command a shell text runs, each as its words with quotes resolved and
/// comments dropped, with the here-doc and here-string text fed to its stdin,
/// through the parse every hook judges by (CLOUD-2388); `None` when that parse
/// could not read all of it.
#[must_use]
pub fn shell_commands(command: &str) -> Option<Vec<(Vec<String>, Vec<String>)>> {
    let crate::facts::Look::Is(parsed) = segments(command) else {
        return None;
    };
    Some(
        parsed
            .into_iter()
            .flat_map(|segment| {
                let mut lines: Vec<(Vec<String>, Vec<String>)> = if segment.lines.is_empty() {
                    vec![(segment.words, Vec::new())]
                } else {
                    segment
                        .lines
                        .into_iter()
                        .map(|line| (line.words, Vec::new()))
                        .collect()
                };
                // A redirection belongs to the segment, so its last line takes it.
                if let Some(last) = lines.last_mut() {
                    last.1 = segment.stdin_text;
                }
                lines
            })
            .collect(),
    )
}

/// One shell-separated span of a mediated command, in the two forms policy needs.
///
/// `words` is the span split into arguments with quoting resolved, so a quoted
/// operand survives as a single **word** rather than being thrown away. `raw` is
/// the same span exactly as written, for the one kind of predicate that must
/// look *inside* a quoted span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The span's arguments, quotes resolved and escapes applied.
    pub words: Vec<String>,
    /// The redirection tokens, exactly the suffix of `words` (CLOUD-2670):
    /// what `program_reach` strips before it reads what a program was handed.
    pub redirects: Vec<String>,
    /// The span exactly as written, quotes and all.
    pub raw: String,
    /// The operator that FOLLOWED this span, or `None` where the command ended.
    ///
    /// Retained since CLOUD-443, and the reason is that three predicates are
    /// about the structure a command sits in rather than about its words: what
    /// its status is handed to, what replaces it, whether it was detached. The
    /// parser used to split on exactly these operators and discard them, so the
    /// structure was destroyed before any rule could see it.
    pub terminator: Option<Separator>,
    /// Whether this span binds an input redirection — `<`, `<<` or `<<<`.
    ///
    /// **Per SEGMENT, which is the entire predicate** (CLOUD-613). A heredoc
    /// opener binds to the element it is written in, so
    /// `git commit -F - && mise run land <<'EOF'` hands the message to `land`
    /// and leaves git reading the harness's `/dev/null`. The command STRING
    /// carries an opener either way; only the segment that owns it can tell
    /// those two apart, which is why this is a field here rather than a
    /// question a module could ask of [`crate::hook`]'s `command`.
    ///
    /// Read outside quoted spans only, so a `<` written inside a commit message
    /// is not a redirection — and heredoc BODIES are gone by the time this is
    /// set, so prose in a body cannot set it either.
    pub input_redirect: bool,
    /// The text this span's own stdin redirections hand it: every heredoc body
    /// and here-string bound here.
    ///
    /// **Read by one gate only, and only as PROGRAM TEXT** (CLOUD-2231). An
    /// unclassified interpreter handed `python3 - <<'EOF'` runs its body as
    /// code, so a protected path named there is a path that code acts on — the
    /// same fact an operand states, in a place argv never shows. Measured: a
    /// write to a registered policy module through exactly that shape was
    /// admitted while `python3 /dev/null <module>` was refused.
    pub stdin_text: Vec<String>,
    /// Each word that is exactly a `cat` heredoc substitution, as `words`
    /// spells it, with the heredoc's body (CLOUD-2683). Keyed by spelling, not
    /// index: index alignment between `words` and the parse broke once.
    pub cat_bodies: Vec<(String, String)>,
    /// Each CONSTITUENT command's own words, where a newline joined several into
    /// this one segment.
    ///
    /// **Two things need to stay apart here and collapsing them is a defect in
    /// both directions** (CLOUD-1287, and CLOUD-1381 which re-made the mistake).
    /// A newline is whitespace for SEGMENT identity, because promoting it would
    /// move every landed `verdict-not-discarded` verdict — `mise run verify` and
    /// `| tail -1` on the next line is one segment, so the pager still discards
    /// the status and the call is still refused. But it is a boundary for
    /// PROGRAM identity, because `cd /tmp` on line one must not own line two's
    /// operands; that was measured as `stat` refused while naming `cd`.
    ///
    /// So the segment spans the newline and this carries the per-command split
    /// the mutation and unknown-program walks read. It is derived from the parse
    /// rather than by re-splitting `raw`, which is what the walk had to do.
    ///
    /// Not projected to the policy input: no module asks this, and adding a key
    /// no predicate reads would be schema surface with no consumer.
    pub lines: Vec<SegmentLine>,
    /// The control-flow node this segment sits inside, and which half of it.
    ///
    /// `None` at the top level. `Some(("until", "condition"))` for the test of
    /// an `until` loop, `Some(("until", "body"))` for a command in its body.
    ///
    /// **This exists so a module can decide from STRUCTURE rather than from a
    /// keyword** (CLOUD-1381). `run-shape.rego` used to establish "this call
    /// waits on a condition" by finding the literal word `until` or `while` in
    /// some segment's `words` — which the character walk supplied only because
    /// it split on `;` and had no idea what a loop was. A parse has no such
    /// token: the keyword IS the node type. Projecting the node type is both
    /// what makes the module expressible again and a tightening — `for` is
    /// excluded because it is a different node rather than because a list of
    /// words happens to omit it, and a `!` between the keyword and the test no
    /// longer has to be filtered out by hand.
    pub construct: Option<(&'static str, &'static str)>,
    /// Did this segment come from INSIDE a word rather than from command
    /// position — a `$(…)`, a `` `…` `` or a `<(…)`?
    ///
    /// Private and unprojected, like [`Segment::lines`]: no module asks it. It
    /// exists because the per-line split walks two readings of one command
    /// positionally, and a nested segment lands at a DIFFERENT position in each
    /// — the unjoined parse emits it between the lines it sits between, the
    /// joined parse after the command that fused them. A nested command is also
    /// not a LINE of the one containing it, so it is excluded from both sides of
    /// that walk rather than merely tolerated.
    pub nested: bool,
    /// Did this segment come from inside a `( … )` subshell (CLOUD-1690)?
    ///
    /// Private and unprojected, like [`Segment::nested`]. The walk flattens a
    /// subshell's body into ordinary segments, which is right for every predicate
    /// about WHAT runs — but a `cd` inside one does not outlive the parentheses,
    /// so the one reader that follows a `cd` has to be able to tell.
    pub grouped: bool,
}

/// One constituent command of a segment: its own words, and its own span.
///
/// **The `raw` half is what makes `contains` decidable per line**, and it is the
/// reason this is a struct rather than the bare word list it replaced. A `shape`
/// row's extra literal is matched against the span AS WRITTEN, because the thing
/// it looks for lives inside a quoted argument and so is not one of the words. If
/// that match reads the whole SEGMENT, line one's text qualifies line two's
/// program: `echo origin/main` followed by `git rebase --continue` satisfies a
/// row keyed on `origin/main` and the second line is refused for a string it
/// never contained. That is an over-deny, which is the direction that gets a
/// guard switched off rather than the sanctioned one.
///
/// Pairing them in one type rather than carrying two lists is deliberate: a
/// parallel `Vec` of spans is a second reading that can desync from the words it
/// describes, and nothing would notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentLine {
    /// This command's arguments, quotes resolved and escapes applied.
    pub words: Vec<String>,
    /// This line's redirection tokens, the suffix of its `words` (CLOUD-2670).
    pub redirects: Vec<String>,
    /// This command's own span, exactly as written.
    pub raw: String,
    /// Whether this command CALLS A SHELL FUNCTION the text defines before it
    /// (CLOUD-2840): its first word, unwrapped, names a definition written
    /// earlier in the same list or one enclosing it. Such a call runs the
    /// function's body, which is judged as segments of its own, and nothing on
    /// `PATH`.
    ///
    /// Decided by the walk, in order, never by name alone. A definition after
    /// the call, inside a branch, loop, group or subshell that may not run, or
    /// in another pipeline stage does not count, and a call through `env`,
    /// `command`, `sudo` or any other wrapper runs the `PATH` program, so its
    /// first word is the wrapper's and this stays `false`. Each of those was a
    /// way to hide a real program behind a name.
    ///
    /// A definition counts only once it CERTAINLY ran and was not removed: one
    /// behind `&&` or `||`, one sent to the background with `&`, and one an
    /// `unset` removed, does not.
    pub function_call: bool,
    /// What a [`SegmentLine::function_call`] runs WITH ITS ARGUMENTS: each body
    /// line that reads `$@`, `$*`, `$1`… with the call's arguments put there
    /// (CLOUD-2840 review, findings 1 and 5). `f() { "$@"; }; f git push`
    /// runs `git push`, which a reading of the call's first word never sees.
    ///
    /// A body that hands its arguments on in a way this cannot follow — a
    /// variable in command position, an expansion this does not resolve —
    /// also yields every suffix of the arguments, so whatever program they
    /// name is read. Empty for a line that calls no function.
    pub forwarded: Vec<Vec<String>>,
}

/// A shell function the walk has seen defined (CLOUD-2840): its name, the
/// argv of every line its body runs, and the names its body `unset`s.
///
/// Several entries may share a name where a definition MAY have replaced
/// another — inside a branch — and a call then runs either body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The function's name.
    pub name: String,
    /// Each body line's argv, redirections dropped, `$@` and the rest as
    /// written, nested commands included.
    pub lines: Vec<Vec<String>>,
    /// The names the body removes with `unset`, which a call removes too.
    pub unsets: Vec<String>,
}

/// How deep a call through one function into another is followed: past it, a
/// line is read as written, which names the function as its program.
const CALL_DEPTH: usize = 6;

/// The shell operator between two segments — what happens to the first one's
/// exit status.
///
/// A vocabulary rather than a boolean because the four answers differ in the one
/// way that matters here. [`Separator::And`] is the only one that **preserves** a
/// failure: it short-circuits, so a non-zero status propagates and there is no
/// false green to stop. The other three each substitute something — the next
/// stage's status, the next element's, or nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    /// `|` — the pipeline exits with the LAST stage's status.
    Pipe,
    /// `;` — the list exits with the last element's status.
    Semi,
    /// `||` — the list exits with the last element that ran.
    Or,
    /// `&&` — short-circuits, so a failure still propagates. Not a defect.
    And,
    /// `&` — detaches; the call returns before the work does.
    Background,
}

impl Separator {
    /// The operator as the shell spells it, for the policy input (CLOUD-857).
    ///
    /// The SHELL's spelling rather than the variant's name, so a module reads
    /// what an author wrote: a predicate about `&&` is written `"&&"`. Naming
    /// the variants would oblige every module to learn a second vocabulary for
    /// something the command line already states.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pipe => "|",
            Self::Semi => ";",
            Self::Or => "||",
            Self::And => "&&",
            Self::Background => "&",
        }
    }
}

/// What bash runs of a call it cannot parse whole: the longest prefix of whole
/// lines that parses, as [`segments`] reads it (CLOUD-2707's suite, measured on
/// `rable` 0.2.2).
///
/// `bash -c` executes each complete command before the line it cannot parse,
/// so that prefix is what reaches the system, and judging it is strictly
/// tighter than abstaining on the whole call. Only a call whose first line
/// already fails abstains. Bounded: each step is one line shorter, and the
/// recursion into [`segments`] is only ever over a prefix that parsed.
#[must_use]
pub fn runnable_prefix(command: &str) -> crate::facts::Look<Vec<Segment>> {
    let lines: Vec<&str> = command.split_inclusive('\n').collect();
    for end in (1..lines.len()).rev() {
        let prefix = lines[..end].concat();
        if rable::parse(&prefix, false).is_ok() {
            return segments(&prefix);
        }
    }
    crate::facts::Look::CouldNotLook
}

/// Split a command into shell-separated segments, over a real bash PARSE.
///
/// **This was a character walk until CLOUD-1381, and the replacement is the
/// row's whole point.** The walk hand-rolled quoting, escapes, heredoc bodies,
/// here-strings and a positional test for whether an `&` belonged to a
/// redirection. Every one of those is a place a shell grammar already has an
/// answer for, and the walk's answers were *unfalsifiable*: it could not fail,
/// so a command it mis-split produced a confident wrong shape that no gate could
/// tell from a correct one. CLOUD-857 is that measured — `git push --force`
/// denied while `cd /tmp && git push --force` was allowed, with a green suite
/// over it — and CLOUD-269 was an earlier patch to the same loop, which is the
/// pattern this replaces rather than continues.
///
/// [`rable`] is a GNU Bash 5.3-compatible recursive-descent parser. What it buys
/// is not tidiness, it is the two properties a scanner cannot have:
///
/// * **It can say it does not know.** An unparseable command is
///   [`Look::CouldNotLook`] rather than a plausible `Vec`, so under-denial stops
///   being byte-identical to a clean read. That is the direction CLOUD-1381
///   calls bypass.
/// * **It descends.** `$(...)`, `<(...)`, a subshell and a compound body all
///   carry real commands, and the walk was blind to every one of them
///   (CLOUD-1257). Each inner command is a segment here, so a protected write
///   inside a substitution is judged rather than missed.
///
/// **THE PARSER DELIMITS WORDS; IT DOES NOT REMOVE QUOTES**, and that boundary
/// is stated rather than absorbed because it is where a reader will expect more
/// than arrived. Measured: `echo "gh pr merge"` yields one word whose value is
/// `"gh pr merge"` — quote characters included. [`unquote`] is what resolves
/// them, and it stays hand-written on purpose. It is a leaf operation over a
/// token whose extent the parser has already decided, which is a different risk
/// class from deciding the extent: a mistake there changes one word, where a
/// mistake in the walk changed the command's shape.
///
/// The quoting contract is unchanged from CLOUD-269's: a quoted span stays ONE
/// word with its contents intact, so `rm "some/guarded path"` is still an
/// operand a path gate can see, and `git commit -m "gh pr merge"` is still one
/// word that never equals the adjacent pair a `gh` policy matches on.
///
/// **A NEWLINE IS STILL WHITESPACE HERE, NOT A SEPARATOR**, and it is preserved
/// deliberately across the swap. bash disagrees and so does [`rable`], which
/// returns one top-level node per line; those are rejoined below. Promoting a
/// newline to a [`Separator::Semi`] would move every landed
/// `verdict-not-discarded` verdict — `mise run verify` on one line and anything
/// at all on the next becomes a discarded status — which is a decision about
/// that rule's reach and not about this parser. Changing it here would have been
/// a behaviour change smuggled inside a substrate change.
#[must_use]
pub fn segments(command: &str) -> crate::facts::Look<Vec<Segment>> {
    // `extglob` off: this is a pre-execution gate over what an agent wrote, and
    // the shell that will run it is not guaranteed to have the option set.
    let Ok(nodes) = rable::parse(command, false) else {
        // THE ARM THE CHARACTER WALK COULD NOT HAVE. A refusal here would block
        // a call on a parse failure, which the exit table forbids (`3` never
        // blocks); a clean `Vec` would be the silent under-denial the row is
        // about.
        //
        // BUT BASH DOES NOT ABSTAIN (measured, `rable` 0.2.2): `bash -c` runs
        // every complete command BEFORE the line it cannot parse, then exits
        // 2. `echo ran\n| tail -1` prints `ran`. So a whole-call abstention let
        // `rm <protected>` followed by any unparseable line run unjudged. What
        // bash runs is the longest prefix of whole lines that parses, and that
        // prefix is judged; only a call with no such prefix abstains.
        return runnable_prefix(command);
    };
    // AND A PARSE THAT SUCCEEDED IS NOT YET A PARSE THAT READ EVERYTHING.
    //
    // Measured on `rable` 0.2.1: `rm "unclosed path` returns Ok with the word
    // silently GONE — one command, one word, `rm`. A protected operand written
    // with an unbalanced quote would be judged as a bare `rm`, which is the same
    // silent under-denial this row replaced a character walk to remove, arriving
    // through the parser instead of through the walk. Adopting a dependency is
    // not the same as trusting its every arm, so the conservation is checked
    // here rather than assumed.
    if !covered(&nodes, command) {
        return crate::facts::Look::CouldNotLook;
    }
    // A NEWLINE IS WHITESPACE FOR SEGMENT IDENTITY, AND A BOUNDARY FOR PROGRAM
    // IDENTITY — two answers over one character, and the tree pins both.
    //
    // `mediated_verbs::a_newline_did_not_become_a_separator` pins the first:
    // `mise run verify` with `| tail -1` on the next line must stay ONE
    // pipeline, so the pager discards the status and the call is refused.
    // CLOUD-1287 pins the second, measured over the shipped binary: `cd /tmp`
    // on line one must not own line two's operands, or `stat` is refused while
    // the refusal names `cd`.
    //
    // **Merging the parsed halves cannot produce the first, and that is the
    // mistake this replaces.** `rable` reads the newline as bash does, so
    // `mise run verify\n| tail -1` is TWO top-level nodes rather than an error;
    // concatenating their words fuses the text but loses the structure, and
    // segment one comes out with no terminator where it needs a `Pipe`. The
    // relationship lives between the nodes, so no merge of their outputs
    // recovers it.
    //
    // So the JOINED text is parsed, once, and that parse decides segments —
    // which is what the character walk did implicitly by never treating a
    // newline as a separator in the first place. Per-line words come from the
    // ORIGINAL parse, so both answers are the same parser's and neither is
    // re-derived by splitting a string.
    // THE SOURCE MUST BE THE STRING THE SPANS WERE COMPUTED AGAINST. `flatten`
    // slices `raw` out of it by span, so handing it the original text while
    // reading nodes parsed from the joined text is a latent mis-slice. It
    // happens to be harmless today — the join replaces one `\n` with one space,
    // so every offset is preserved — but that is an accident of this particular
    // join, not a property anything holds, and an earlier revision wrote
    // `map_or(command, |_| command)`, which returned the original from both arms
    // and so could never have used the joined text at all.
    let joined = joined_parse(command, &nodes);
    let (reading, source) = joined
        .as_ref()
        .map_or((&nodes, command), |(text, parsed)| (parsed, text.as_str()));
    let mut out: Vec<Segment> = Vec::new();
    // ONE SCOPE ACROSS THE TOP-LEVEL NODES: a definition on one line is visible
    // to a call on the next (CLOUD-2840).
    let mut defined: Vec<Definition> = Vec::new();
    for (position, node) in reading.iter().enumerate() {
        let first = out.len();
        flatten_scoped(node, source, None, None, &mut defined, &mut out);
        // A NEWLINE BETWEEN TWO TOP-LEVEL COMMANDS IS A `;` (CLOUD-2234). The
        // joined reading folds such lines into one segment, but a heredoc keeps
        // the parse as written, and there the next command is its own node: the
        // element before it ended with no terminator, so a verdict on it read as
        // the list's last and its replaced status went unseen. Measured: a
        // refused `git commit -F - <<'EOF'` with `git log` after `EOF`
        // reported exit 0.
        if position + 1 < reading.len()
            && let Some(last) = out[first..]
                .iter_mut()
                .rev()
                .find(|segment| !segment.nested)
            && last.terminator.is_none()
        {
            last.terminator = Some(Separator::Semi);
        }
    }
    // Where the join happened, `flatten` gave every segment one `lines` entry
    // over the FUSED words. Replace it with the per-line reading, segment by
    // segment, which is the split CLOUD-1287 needs.
    //
    // **EVERY SEGMENT, and the `out.len() == 1` guard this replaces is why it is
    // spelled out.** That guard was right for the case it was written against
    // and silently wrong for the common one: a multi-line call carrying an
    // operator, or one whose word holds a substitution, produces more than one
    // segment and kept its fused list. `protected_mutation` then walked that
    // single line, `effective_program` resolved the FIRST line's program, and
    // line two's operand was judged as its own — CLOUD-1287's measured over-deny
    // on a protected READ, re-introduced by the change that claimed to remove
    // it. Measured on `cd /tmp\nstat -c %s batten.toml && echo hi`.
    //
    // An ordered consume rather than a match on content: both readings are the
    // same parser's over the same text, and `joined_parse` refuses the join
    // unless their total word counts agree, so taking lines until the running
    // count reaches each segment's own length lands on a boundary every time.
    // Matching by value would break on a command that repeats a word.
    if joined.is_some() {
        // Named for what it holds rather than `per_line`, which is the helper
        // every walk reads this through — a local shadowing that name reads as the
        // function to anybody scanning for it.
        let mut line_readings: Vec<SegmentLine> = Vec::new();
        let mut defined: Vec<Definition> = Vec::new();
        for node in &nodes {
            let mut produced: Vec<Segment> = Vec::new();
            flatten_scoped(node, command, None, None, &mut defined, &mut produced);
            for segment in produced {
                if !segment.nested {
                    let function_call = segment.lines.iter().any(|line| line.function_call);
                    let forwarded = segment
                        .lines
                        .into_iter()
                        .flat_map(|line| line.forwarded)
                        .collect();
                    line_readings.push(SegmentLine {
                        words: segment.words,
                        redirects: segment.redirects,
                        raw: segment.raw,
                        function_call,
                        forwarded,
                    });
                }
            }
        }
        // ONE PASS, ALL OR NOTHING — a per-segment abstention is not available
        // here and pretending otherwise was a defect. The line list is SHARED
        // across segments, so a segment that keeps its fused list has already
        // drained the entries it walked; every later segment then takes lines
        // belonging to an earlier one, and `protected_mutation` walks a "line"
        // that is not its command. That is a mis-assignment wearing the words of
        // an abstention, which is worse than either.
        //
        // So the whole reassignment is computed first and applied only if every
        // segment landed. If any did not, no segment's `lines` moves and all of
        // them keep the single fused entry `flatten` gave them — which is the
        // pre-CLOUD-1287 reading, conservative and consistent, rather than a
        // half-applied one.
        let mut lines = line_readings.into_iter();
        let mut assignment: Vec<Vec<SegmentLine>> = Vec::new();
        let mut landed = true;
        for segment in out.iter().filter(|segment| !segment.nested) {
            let wanted = segment.words.len();
            let mut taken: Vec<SegmentLine> = Vec::new();
            let mut counted = 0;
            // AT LEAST ONE LINE, THEN UNTIL THE COUNT IS MET (CLOUD-2840 review
            // M3): a segment of no words — `''` — is a line of no words, and a
            // loop that stops once the count is met took none for it, refused,
            // and cancelled the per-line reading for every segment.
            for line in lines.by_ref() {
                counted += line.words.len();
                taken.push(line);
                if counted >= wanted {
                    break;
                }
            }
            // TWO REFUSALS, KEPT APART: a segment that took no line and one whose
            // count missed are each a reassignment that did not land, and neither
            // is implied by the other where a word count can be zero.
            if taken.is_empty() {
                landed = false;
                break;
            }
            if counted != wanted {
                landed = false;
                break;
            }
            assignment.push(taken);
        }
        // Applied only where every segment landed AND no line is left over but
        // a line of no words, which no segment can own.
        if landed && lines.all(|line| line.words.is_empty()) {
            for (segment, taken) in out
                .iter_mut()
                .filter(|segment| !segment.nested)
                .zip(assignment)
            {
                segment.lines = taken;
            }
        }
    }
    crate::facts::Look::Is(out)
}

/// The command re-parsed with its newlines as whitespace, where that is safe.
///
/// `None` means read the original parse — the command is one line, or carries a
/// heredoc, or the joined text does not parse.
///
/// **The heredoc guard is the load-bearing half.** A body's newlines are DATA:
/// joining them would run the body's words together with the opener's and, worse,
/// dissolve the delimiter line that ends it. So a command carrying one is read as
/// parsed, and the newline-as-whitespace reading is not available there. That
/// bound is narrower than it sounds — a heredoc's own newline already cannot
/// separate two commands, because everything up to the delimiter belongs to the
/// body.
pub fn joined_parse(command: &str, nodes: &[rable::Node]) -> Option<(String, Vec<rable::Node>)> {
    if !command.contains('\n') || nodes.len() < 2 || nodes.iter().any(opens_heredoc) {
        return None;
    }
    // A COMMENT WOULD SWALLOW WHAT FOLLOWS IT, so a command carrying one keeps
    // the per-line reading. Decided from the parse rather than by scanning for a
    // `#`: a `#` inside a quoted operand is not a comment, and asking the text
    // would be the second authority this module refuses to grow. A comment ends
    // at a newline, so the joined text is shorter in TOKENS than the original
    // whenever one was absorbed — and that is what this compares.
    let joined = command.replace('\n', " ");
    let reparsed = rable::parse(&joined, false).ok()?;
    // The joined TEXT travels with its parse, because the caller slices spans
    // out of it. Returning the nodes alone is what let the source and the spans
    // come from different strings.
    (words_in(&reparsed) == words_in(nodes)).then_some((joined, reparsed))
}

/// Every word any command in this forest carries, for the conservation check
/// above. Order is irrelevant to it; the count is the whole question.
#[must_use]
pub fn words_in(nodes: &[rable::Node]) -> usize {
    let mut segments = Vec::new();
    for node in nodes {
        flatten(node, "", None, &mut segments);
    }
    segments.iter().map(|segment| segment.words.len()).sum()
}

/// Did the parse account for the whole command, or did it drop a tail?
///
/// Spans are the parser's own, so this asks the parse about itself rather than
/// re-reading the text: everything past the last node's end must be whitespace.
///
/// **A heredoc BODY legitimately lives past that end**, so a command carrying
/// one is exempt — the body is data the parser deliberately does not span. The
/// cost is stated rather than absorbed: an unbalanced quote in a command that
/// ALSO opens a heredoc is not caught here. That is a miss, never a false
/// refusal, and it is a strictly smaller hole than the one this closes.
pub fn covered(nodes: &[rable::Node], command: &str) -> bool {
    let Some(end) = nodes.iter().map(|node| node.span.end).max() else {
        // No nodes at all: an empty or whitespace-only command reads clean, and
        // `segments("")` giving an empty list is relied on elsewhere.
        return command.trim().is_empty();
    };
    if nodes.iter().any(opens_heredoc) {
        return true;
    }
    // `skip` COUNTS THE SAME UNIT THE SPAN DOES, and getting that wrong makes
    // this guard pass on exactly the inputs it exists for. `rable`'s `Span`
    // carries CHARACTER indices — its own doc says so, and `Node::source_text`
    // converts them to byte offsets before slicing — so the tail has to be
    // walked in characters too. Mixing the two overshoots on any command with a
    // multi-byte character before the last node's end (an em-dash in a commit
    // message, a UTF-8 path): `all()` then runs over an empty iterator, returns
    // true vacuously, and the dropped-tail case reads clean instead of
    // abstaining. Asserted rather than reasoned — see the unterminated-quote
    // case, which carries a multi-byte operand for this reason.
    // **THE TAIL IS JUDGED BY WHETHER IT COULD HOLD A DROPPED WORD, NOT BY
    // WHETHER IT IS EMPTY**, and requiring emptiness was a total bypass.
    //
    // `rable` does not extend a node's span over the separator that follows it,
    // so `rm batten.toml;` leaves `;` after the last span. Requiring the tail to
    // be whitespace therefore made every command ending in a separator or a
    // comment could-not-look -- and could-not-look ALLOWS on this surface.
    // Measured over the shipped binary: `git push --force origin main;` exited
    // 0 where the same command without the semicolon exited 2, and likewise for
    // `rm batten.toml;`, `mise run verify | tail -1;` and `sleep 60;`. One
    // keystroke disabled every mediated gate -- strictly worse than the
    // character walk this row replaced, and introduced by the guard meant to
    // make it safer.
    //
    // What the guard is actually for is narrow and stays: `rable` 0.2.1 returns
    // Ok for `rm "unclosed path` with the operand silently GONE, so a protected
    // path written with an unbalanced quote would be judged as a bare `rm`. A
    // word is dropped because its QUOTE never closed, so a tail carrying a
    // quote character is the signal; a tail of separators and comment text is
    // not.
    //
    // The residue, stated rather than absorbed: a trailing comment that itself
    // contains a quote (`echo x # say "hi"`) abstains where it could be read.
    // That is an under-deny, it is recorded rather than silent, and it is many
    // orders narrower than the one it replaces.
    let tail: String = command.chars().skip(end).collect();
    !tail.contains('"') && !tail.contains('\'')
}

/// Does this node, anywhere inside it, open a heredoc?
///
/// **EVERY COMPOUND, AND ITS OWN REDIRECTIONS** (CLOUD-2840 review M5): a
/// heredoc written on `{ … }`, a loop, an `if`, a `case`, `[[ … ]]` or
/// `(( … ))` is a heredoc too. Missed, its body read as a tail the parse
/// dropped, a quote there made the whole call could-not-look, and every
/// command in it went unjudged.
pub fn opens_heredoc(node: &rable::Node) -> bool {
    let any = |nodes: &[rable::Node]| nodes.iter().any(opens_heredoc);
    match &node.kind {
        rable::NodeKind::HereDoc { .. } => true,
        rable::NodeKind::Command { redirects, .. }
        | rable::NodeKind::ConditionalExpr { redirects, .. }
        | rable::NodeKind::ArithmeticCommand { redirects, .. } => any(redirects),
        rable::NodeKind::Pipeline { commands, .. } => any(commands),
        rable::NodeKind::List { items } => items.iter().any(|item| opens_heredoc(&item.command)),
        rable::NodeKind::Subshell { body, redirects }
        | rable::NodeKind::BraceGroup { body, redirects }
        | rable::NodeKind::For {
            body, redirects, ..
        }
        | rable::NodeKind::ForArith {
            body, redirects, ..
        }
        | rable::NodeKind::Select {
            body, redirects, ..
        } => opens_heredoc(body) || any(redirects),
        rable::NodeKind::While {
            condition,
            body,
            redirects,
        }
        | rable::NodeKind::Until {
            condition,
            body,
            redirects,
        } => opens_heredoc(condition) || opens_heredoc(body) || any(redirects),
        rable::NodeKind::If {
            condition,
            then_body,
            else_body,
            redirects,
        } => {
            opens_heredoc(condition)
                || opens_heredoc(then_body)
                || else_body.as_deref().is_some_and(opens_heredoc)
                || any(redirects)
        }
        rable::NodeKind::Case {
            patterns,
            redirects,
            ..
        } => {
            patterns
                .iter()
                .filter_map(|arm| arm.body.as_ref())
                .any(opens_heredoc)
                || any(redirects)
        }
        rable::NodeKind::Function { body, .. } => opens_heredoc(body),
        rable::NodeKind::Negation { pipeline } | rable::NodeKind::Time { pipeline, .. } => {
            opens_heredoc(pipeline)
        }
        rable::NodeKind::Coproc { command, .. } => opens_heredoc(command),
        _ => false,
    }
}

/// A redirection's tokens, as the words the old walk left in place.
///
/// A WHITESPACE SPLIT OF A SPAN THE PARSER DELIMITED, plus the descriptor the
/// span leaves out. The grammar has already decided where this redirection
/// starts and ends; what remains is which of its characters are one token, and
/// answering that with the shell's own rules here would be the second authority
/// this module refuses to grow.
///
/// **The explicit fd is restored from the typed field, because the span omits
/// it.** Measured on `rable` 0.2.1: `2>&1` spans `>&1` and carries `fd: 2`
/// beside it, so a split of the span alone yields `">&1"` and silently drops the
/// descriptor the author wrote. Caught by this file's own
/// `a_redirections_ampersand_is_not_a_separator`, whose expectation was written
/// from the walk's output — which is what that corpus is for.
///
/// Measured against the walk's output on every case in this file: `> notes.md`
/// gives `[">", "notes.md"]`, `2>&1` gives `["2>&1"]`, and `<<'EOF'` gives
/// `["<<'EOF'"]` — identical, token for token.
pub fn redirect_words(redirect: &rable::Node, source: &str) -> Vec<String> {
    let mut tokens = redirect
        .source_text(source)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<String>>();
    // `fd` is -1 where the author named none, and the default descriptor is not
    // a token anybody wrote — so only an EXPLICIT one is put back.
    if let rable::NodeKind::Redirect { fd, .. } = &redirect.kind
        && *fd >= 0
        && let Some(first) = tokens.first_mut()
        && !first.starts_with(|c: char| c.is_ascii_digit())
    {
        first.insert_str(0, &fd.to_string());
    }
    tokens
}

/// Walk one AST node, appending a [`Segment`] per command it contains.
///
/// `after` is the operator that follows the node as a whole, handed down so that
/// the LAST command of a nested structure carries it — `(a; b) && c` gives `b`
/// the `&&`, which is where the status a rule reasons about actually flows.
pub fn flatten(node: &rable::Node, source: &str, after: Option<Separator>, out: &mut Vec<Segment>) {
    flatten_in(node, source, after, None, out);
}

/// One command's words AS WRITTEN, which is not what the parse files them under.
///
/// AN ENV ASSIGNMENT PREFIX IS A WORD HERE, and dropping it is an under-deny
/// rather than a tidier shape. `effective_program` steps past `VAR=value` to find
/// the program, and `hook_skip_local` reads the assignment itself —
/// `HK_SKIP_STEPS=… git commit` is refused BECAUSE of the prefix. The parser
/// files those under `assignments`, correctly for a grammar and wrongly for this
/// consumer, so they go back at the front where they were written.
///
/// A REDIRECTION'S TOKENS ARE STILL WORDS, and restoring them is not cosmetic:
/// `protected_mutation` reads a redirect TARGET as a mutation candidate with no
/// program at all, so `rm > guarded.md` is judged on the target. The parser moves
/// those tokens out of `words` and into `redirects`, which is again right for a
/// grammar and wrong here — dropping them was an under-deny on a WRITE, measured
/// by `a_redirect_target_is_a_mutation_even_with_no_program`.
#[must_use]
pub fn command_words(
    assignments: &[rable::Node],
    words: &[rable::Node],
    redirects: &[rable::Node],
    source: &str,
) -> Vec<String> {
    let mut spelled: Vec<String> = assignments
        .iter()
        .map(|word| unquote(&word_text(word)))
        .chain(words.iter().map(|word| unquote(&word_text(word))))
        .collect();
    for redirect in redirects {
        spelled.extend(redirect_words(redirect, source));
    }
    spelled
}

/// The commands nested INSIDE this one's words and redirect targets.
///
/// A word may CONTAIN commands: `rm $(cat list)` runs `cat`, and the character
/// walk this replaces could not see them at all (CLOUD-1257). A redirect target
/// may be a substitution too — `diff <(a) <(b)`.
///
/// The functions `defined` where the command runs are defined inside its
/// substitutions too: a `$( … )` is a subshell, which inherits them.
#[must_use]
pub fn nested_commands(
    words: &[rable::Node],
    redirects: &[rable::Node],
    source: &str,
    defined: &[Definition],
) -> Vec<Segment> {
    let mut nested = Vec::new();
    for word in words {
        descend_word_in(word, source, defined, &mut nested);
    }
    for redirect in redirects {
        descend_redirect_in(redirect, source, defined, &mut nested);
    }
    nested
}

/// One `Command` node as a [`Segment`], plus the commands nested in its words.
///
/// The node is taken whole rather than pre-destructured so this stays inside the
/// argument ceiling; the caller has already matched the kind, so the `else` arm
/// is unreachable and returns rather than inventing a segment.
pub fn flatten_command(
    node: &rable::Node,
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    defined: &mut Vec<Definition>,
    out: &mut Vec<Segment>,
) {
    let rable::NodeKind::Command {
        assignments,
        words,
        redirects,
    } = &node.kind
    else {
        return;
    };
    // THE SAME WORDS, AFTER the empty ones are dropped. Snapshotting the list
    // before the retain put one in `lines` that `words` no longer matched, so the
    // two readings of one command disagreed on token indices — and
    // `protected_mutation` reads `lines` while everything else reads `words`.
    let mut segment = Segment {
        lines: Vec::new(),
        words: command_words(assignments, words, redirects, source),
        redirects: redirects
            .iter()
            .flat_map(|redirect| redirect_words(redirect, source))
            .collect(),
        raw: node.source_text(source).to_owned(),
        terminator: after,
        input_redirect: redirects.iter().any(binds_stdin),
        stdin_text: redirects.iter().filter_map(stdin_text).collect(),
        cat_bodies: Vec::new(),
        construct,
        nested: false,
        grouped: false,
    };
    for word in words {
        if let Some(body) = cat_heredoc_body(word) {
            segment.cat_bodies.push((unquote(&word_text(word)), body));
        }
    }
    // AN ASSIGNMENT'S SUBSTITUTION RUNS TOO, and first (step 14): `out=$(git
    // push)` is a command whose only words are an assignment, so descending the
    // words alone left the push inside it unseen while `echo $(git push)` was
    // judged.
    let mut nested = Vec::new();
    for assignment in assignments {
        descend_word_in(assignment, source, defined, &mut nested);
    }
    nested.append(&mut nested_commands(words, redirects, source, defined));
    if segment.words.iter().any(String::is_empty) {
        segment.words.retain(|word| !word.is_empty());
    }
    // THE FIRST WORD UNWRAPPED, against the definitions visible here: a
    // wrapper's call (`env f`, `command f`) has the wrapper as its first word.
    let call: Vec<String> = words.iter().map(|word| unquote(&word_text(word))).collect();
    let function_call = call
        .first()
        .is_some_and(|name| defined.iter().any(|definition| definition.name == *name));
    // A CALL RUNS ITS BODY WITH ITS ARGUMENTS, and removes what that body
    // `unset`s; an `unset` here removes its names from this point on.
    let forwarded = if function_call {
        let forwarded = call_lines(&call, defined, CALL_DEPTH);
        let removed: Vec<String> = defined
            .iter()
            .filter(|definition| Some(&definition.name) == call.first())
            .flat_map(|definition| definition.unsets.iter().cloned())
            .collect();
        defined.retain(|definition| !removed.contains(&definition.name));
        forwarded
    } else {
        if let Some(names) = unset_functions(&call) {
            defined.retain(|definition| !names.contains(&definition.name));
        }
        Vec::new()
    };
    segment.lines = vec![SegmentLine {
        words: segment.words.clone(),
        redirects: segment.redirects.clone(),
        raw: segment.raw.clone(),
        function_call,
        forwarded,
    }];
    // Everything the descent produced is nested, however deep: an inner `$(…)`
    // inside an outer one is still not a line of the command that contains them.
    for inner in &mut nested {
        inner.nested = true;
    }
    out.push(segment);
    out.append(&mut nested);
}

/// [`flatten`], carrying the control-flow node the walk is currently inside.
pub fn flatten_in(
    node: &rable::Node,
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    out: &mut Vec<Segment>,
) {
    flatten_scoped(node, source, after, construct, &mut Vec::new(), out);
}

/// A REDIRECTION WRITTEN ON A COMPOUND COMMAND applies to every command inside
/// it (CLOUD-2840 review M5): `{ cat f; } > out` and `for …; done > all` write
/// the file exactly as `cat f > out` does. `rable` keeps such a redirection on
/// the `BraceGroup`, `Subshell`, loop, `If` or `Case` node, so a walk that read
/// only the body dropped it, and the reads inside were granted as reads.
///
/// The tokens are appended to each command's words, redirections and lines, so
/// they stay the suffix of its words; a command substitution inside runs with
/// its output captured, so a nested segment takes none.
///
/// A REDIRECTION'S TARGET MAY ITSELF RUN A COMMAND (CLOUD-2840 review M5):
/// `{ cat f; } > >(tee out)` runs `tee`, so each target is descended too, as a
/// simple command's is.
fn redirected(
    out: &mut Vec<Segment>,
    first: usize,
    redirects: &[rable::Node],
    source: &str,
    defined: &[Definition],
) {
    if redirects.is_empty() {
        return;
    }
    let mut nested = Vec::new();
    for redirect in redirects {
        descend_redirect_in(redirect, source, defined, &mut nested);
    }
    for inner in &mut nested {
        inner.nested = true;
    }
    let tokens: Vec<String> = redirects
        .iter()
        .flat_map(|redirect| redirect_words(redirect, source))
        .collect();
    let binds = redirects.iter().any(binds_stdin);
    let bodies: Vec<String> = redirects.iter().filter_map(stdin_text).collect();
    for segment in out.iter_mut().skip(first).filter(|segment| !segment.nested) {
        segment.words.extend(tokens.iter().cloned());
        segment.redirects.extend(tokens.iter().cloned());
        segment.input_redirect |= binds;
        segment.stdin_text.extend(bodies.iter().cloned());
        for line in &mut segment.lines {
            line.words.extend(tokens.iter().cloned());
            line.redirects.extend(tokens.iter().cloned());
        }
    }
    out.append(&mut nested);
}

/// A `[[ … ]]` or `(( … ))` carrying a redirection, as the segment of its
/// redirect tokens alone (CLOUD-2840 review M5): it runs no program, and its
/// target is written all the same, as `> out` alone writes it.
fn flatten_test(
    node: &rable::Node,
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    defined: &[Definition],
    out: &mut Vec<Segment>,
) {
    let (rable::NodeKind::ConditionalExpr { redirects, .. }
    | rable::NodeKind::ArithmeticCommand { redirects, .. }) = &node.kind
    else {
        return;
    };
    if redirects.is_empty() {
        return;
    }
    let tokens: Vec<String> = redirects
        .iter()
        .flat_map(|redirect| redirect_words(redirect, source))
        .collect();
    let raw = node.source_text(source).to_owned();
    out.push(Segment {
        words: tokens.clone(),
        redirects: tokens.clone(),
        raw: raw.clone(),
        terminator: after,
        input_redirect: redirects.iter().any(binds_stdin),
        stdin_text: redirects.iter().filter_map(stdin_text).collect(),
        cat_bodies: Vec::new(),
        lines: vec![SegmentLine {
            words: tokens.clone(),
            redirects: tokens,
            raw,
            function_call: false,
            forwarded: Vec::new(),
        }],
        construct,
        nested: false,
        grouped: false,
    });
    let mut nested = Vec::new();
    for redirect in redirects {
        descend_redirect_in(redirect, source, defined, &mut nested);
    }
    for inner in &mut nested {
        inner.nested = true;
    }
    out.append(&mut nested);
}

/// The definitions after a part of the walk that MAY have run, merged into
/// those before it (CLOUD-2840 review B2): a name stays a function only where
/// it was one before AND still is after — a definition that may not have run
/// adds nothing, an `unset` that may have run removes — and a call may run
/// either body, so both are kept.
fn merge_uncertain(defined: &mut Vec<Definition>, branch: &[Definition]) {
    let mut merged: Vec<Definition> = defined
        .iter()
        .filter(|before| branch.iter().any(|after| after.name == before.name))
        .cloned()
        .collect();
    for after in branch {
        if defined.iter().any(|before| before.name == after.name) && !merged.contains(after) {
            merged.push(after.clone());
        }
    }
    *defined = merged;
}

/// The function names an `unset` removes, or `None` where `call` is not one
/// that can remove a function: `unset -v` and `unset -n` name variables only.
/// A plain `unset NAME` removes the function where no variable has the name,
/// so it is read as removing it — the direction that reads more programs.
fn unset_functions(call: &[String]) -> Option<Vec<String>> {
    let at = call
        .iter()
        .position(|word| !matches!(word.as_str(), "builtin" | "command"))?;
    if call[at] != "unset" {
        return None;
    }
    let mut names = Vec::new();
    let mut options = true;
    for word in &call[at + 1..] {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') {
            if word.contains(['v', 'n']) {
                return None;
            }
        } else {
            names.push(word.clone());
        }
    }
    Some(names)
}

/// The argv of each line a call to the function `call` names runs with its
/// arguments, through every body that name may have (CLOUD-2840 review,
/// findings 1 and 5). A line whose command word is itself a defined function
/// is that function's call, followed `depth` deep.
fn call_lines(call: &[String], defined: &[Definition], depth: usize) -> Vec<Vec<String>> {
    let Some((name, arguments)) = call.split_first() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for definition in defined.iter().filter(|definition| definition.name == *name) {
        for line in substituted(&definition.lines, arguments) {
            let at = line
                .iter()
                .position(|word| !is_assignment_word(word))
                .unwrap_or(line.len());
            let inner = &line[at..];
            let calls = inner
                .first()
                .is_some_and(|first| defined.iter().any(|other| other.name == *first));
            match depth.checked_sub(1) {
                Some(deeper) if calls => found.extend(call_lines(inner, defined, deeper)),
                _ => found.push(line),
            }
        }
    }
    found
}

/// The body `lines` that read the positional parameters, with `arguments` put
/// in their place.
///
/// `shift` moves which arguments those are, and a branch may skip it, so each
/// line is read at every offset a `shift` before it may leave. A line that
/// still holds an expansion in command position after that, or one whose
/// expansion this cannot resolve (`${1:-x}`, `${!1}`), is a body this cannot
/// read: every suffix of the arguments is then read as a command too, which
/// is where a forwarded program can begin.
fn substituted(lines: &[Vec<String>], arguments: &[String]) -> Vec<Vec<String>> {
    let mut offsets: Vec<usize> = vec![0];
    let mut found = Vec::new();
    let mut opaque = false;
    let mut reads = false;
    for line in lines {
        if line.first().is_some_and(|word| word == "shift") {
            let by = match line.get(1).map(|count| count.parse::<usize>()) {
                None => 1,
                Some(Ok(by)) => by,
                Some(Err(_)) => {
                    opaque = true;
                    0
                }
            };
            let shifted: Vec<usize> = offsets
                .iter()
                .map(|offset| (offset + by).min(arguments.len()))
                .collect();
            for offset in shifted {
                if !offsets.contains(&offset) {
                    offsets.push(offset);
                }
            }
            continue;
        }
        if command_word(line).is_some_and(|word| word.contains('$')) {
            opaque = true;
        }
        if !line.iter().any(|word| reads_positional(word)) {
            continue;
        }
        reads = true;
        for &offset in &offsets {
            let rest = &arguments[offset.min(arguments.len())..];
            let mut words = Vec::new();
            for word in line {
                if let Some(expanded) = expand_positional(word, rest) {
                    words.extend(expanded);
                } else {
                    opaque = true;
                    words.push(word.clone());
                }
            }
            words.retain(|word| !word.is_empty());
            if command_word(&words).is_some_and(|word| word.contains('$')) {
                opaque = true;
            }
            if !found.contains(&words) {
                found.push(words);
            }
        }
    }
    if opaque && reads {
        for start in 0..arguments.len() {
            found.push(arguments[start..].to_vec());
        }
    }
    found
}

/// The first word of `line` that is not a `NAME=value` assignment.
fn command_word(line: &[String]) -> Option<&String> {
    line.iter().find(|word| !is_assignment_word(word))
}

/// Is `word` a `NAME=value` (or `NAME+=value`) assignment?
fn is_assignment_word(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        let name = name.strip_suffix('+').unwrap_or(name);
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Does `word` read a positional parameter: `$@`, `$*`, `$1`…, or any
/// `${…}` over one of them or through `!`?
fn reads_positional(word: &str) -> bool {
    word.match_indices('$').any(|(at, _)| {
        let rest = &word[at + 1..];
        let rest = rest.strip_prefix('{').unwrap_or(rest);
        rest.starts_with(|c: char| matches!(c, '@' | '*' | '!' | '1'..='9'))
    })
}

/// `word` with `arguments` in place of each positional parameter it reads, or
/// `None` where it reads one in a form this does not resolve.
///
/// A word that is exactly `$@`, `$*` or a `${@:N[:M]}` slice is the arguments
/// as words; anywhere else they are joined by a space, as `"$*"` joins them.
fn expand_positional(word: &str, arguments: &[String]) -> Option<Vec<String>> {
    if !reads_positional(word) {
        return Some(vec![word.to_owned()]);
    }
    if matches!(word, "$@" | "$*" | "${@}" | "${*}") {
        return Some(arguments.to_vec());
    }
    if let Some(slice) = word
        .strip_prefix("${@:")
        .or_else(|| word.strip_prefix("${*:"))
        .and_then(|rest| rest.strip_suffix('}'))
    {
        let mut bounds = slice.splitn(2, ':');
        let start: usize = bounds.next()?.trim().parse().ok()?;
        let start = start.saturating_sub(1).min(arguments.len());
        let rest = &arguments[start..];
        let length = match bounds.next() {
            Some(length) => length.trim().parse::<usize>().ok()?.min(rest.len()),
            None => rest.len(),
        };
        return Some(rest[..length].to_vec());
    }
    let joined = arguments.join(" ");
    let mut text = String::with_capacity(word.len());
    let mut rest = word;
    while let Some(at) = rest.find('$') {
        text.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (value, used) = if let Some(inner) = after.strip_prefix('{') {
            let close = inner.find('}')?;
            (
                positional_value(&inner[..close], arguments, &joined)?,
                close + 2,
            )
        } else {
            match after.chars().next() {
                Some(c @ ('@' | '*' | '1'..='9')) => {
                    (positional_value(&c.to_string(), arguments, &joined)?, 1)
                }
                _ => (String::from("$"), 0),
            }
        };
        text.push_str(&value);
        rest = &after[used..];
    }
    text.push_str(rest);
    Some(vec![text])
}

/// The value of the parameter `name` names, where it is a positional one: a
/// non-positional name is kept as written, and one this does not resolve
/// (`1:-x`, `!1`) is `None`.
fn positional_value(name: &str, arguments: &[String], joined: &str) -> Option<String> {
    match name {
        "@" | "*" => Some(joined.to_owned()),
        _ if name.chars().all(|c| c.is_ascii_digit()) && !name.is_empty() => {
            let index: usize = name.parse().ok()?;
            Some(match index.checked_sub(1) {
                Some(index) => arguments.get(index).cloned().unwrap_or_default(),
                None => String::from("$0"),
            })
        }
        _ if name.starts_with(|c: char| matches!(c, '@' | '*' | '!' | '0'..='9')) => None,
        _ => Some(format!("${{{name}}}")),
    }
}

/// [`flatten_in`], over the shell functions `defined` before `node` runs
/// (CLOUD-2840 review B2).
///
/// A definition is visible to the LATER items of the list it is written in, and
/// to everything nested in them, once it CERTAINLY ran. It does not escape a
/// subshell or a pipeline stage, whose definitions die with it, nor a branch,
/// loop, group or `&&`/`||` operand that may not run; but an `unset` in one of
/// those may have run, so it does remove. That reads fewer calls as functions
/// than bash might, which reports a program where there may be none: the safe
/// direction, where the other hid a real one.
pub fn flatten_scoped(
    node: &rable::Node,
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    defined: &mut Vec<Definition>,
    out: &mut Vec<Segment>,
) {
    let first = out.len();
    match &node.kind {
        rable::NodeKind::Command { .. } => {
            flatten_command(node, source, after, construct, defined, out);
        }
        rable::NodeKind::Pipeline { commands, .. } => {
            flatten_pipeline(commands, source, after, construct, defined, out);
        }
        rable::NodeKind::List { items } => {
            flatten_list(items, source, after, construct, defined, out);
        }
        // A GROUPING runs its body in this call's own right, so it is walked.
        // A SUBSHELL's body is also marked, because its `cd` dies with it; a
        // brace group runs in this shell, so its `cd` does not.
        rable::NodeKind::Subshell { body, redirects } => {
            flatten_scoped(body, source, after, construct, &mut defined.clone(), out);
            for segment in &mut out[first..] {
                segment.grouped = true;
            }
            redirected(out, first, redirects, source, defined);
        }
        rable::NodeKind::BraceGroup { body, redirects } => {
            let mut inner = defined.clone();
            flatten_scoped(body, source, after, construct, &mut inner, out);
            merge_uncertain(defined, &inner);
            redirected(out, first, redirects, source, defined);
        }
        rable::NodeKind::ConditionalExpr { .. } | rable::NodeKind::ArithmeticCommand { .. } => {
            flatten_test(node, source, after, construct, defined, out);
        }
        rable::NodeKind::While { .. }
        | rable::NodeKind::Until { .. }
        | rable::NodeKind::If { .. }
        | rable::NodeKind::For { .. }
        | rable::NodeKind::ForArith { .. }
        | rable::NodeKind::Select { .. }
        | rable::NodeKind::Case { .. } => flatten_control(node, source, after, defined, out),
        // A DEFINITION is visible to the items after it, and to its own body
        // (recursion); the body is walked and judged where it is written, and
        // its lines are kept for a call to run with its arguments.
        rable::NodeKind::Function { name, body } => {
            let mut inner = defined.clone();
            inner.retain(|definition| definition.name != *name);
            inner.push(Definition {
                name: name.clone(),
                lines: Vec::new(),
                unsets: Vec::new(),
            });
            let tag = Some(("function", "body"));
            let start = out.len();
            flatten_scoped(body, source, after, tag, &mut inner, out);
            let lines: Vec<Vec<String>> = out[start..]
                .iter()
                .flat_map(|segment| &segment.lines)
                .map(|line| {
                    let handed = line.words.len().saturating_sub(line.redirects.len());
                    line.words[..handed].to_vec()
                })
                .collect();
            let unsets = lines
                .iter()
                .filter_map(|line| unset_functions(line))
                .flatten()
                .collect();
            defined.retain(|definition| definition.name != *name);
            defined.push(Definition {
                name: name.clone(),
                lines,
                unsets,
            });
        }
        // `! cmd` and `time cmd` WRAP a pipeline rather than being one, so the
        // command is one level down. Missing these is an under-deny and was
        // measured: `until ! pgrep -f '<pattern>'; do sleep 20; done` is the
        // canonical process-polling wait `run-shape-guard` exists to refuse, and
        // with the negation unwalked its `pgrep` reached no segment at all, so
        // the guard allowed the exact command it was written for.
        rable::NodeKind::Negation { pipeline } | rable::NodeKind::Time { pipeline, .. } => {
            let mut inner = defined.clone();
            flatten_scoped(pipeline, source, after, construct, &mut inner, out);
            merge_uncertain(defined, &inner);
        }
        rable::NodeKind::Coproc { command, .. } => {
            flatten_scoped(command, source, after, construct, &mut defined.clone(), out);
        }
        // Anything else contains no command position.
        //
        // **A CATCH-ALL HERE IS AN UNDER-DENY GENERATOR, which is why the arms
        // above are enumerated rather than left to it.** A node kind this walk
        // does not name produces no segment, and no segment is byte-identical to
        // a clean command on the decision surface — the same silence CLOUD-1381
        // replaced a character walk to remove, arriving through an unhandled
        // variant instead. `Negation` was exactly that, found by a landed case
        // rather than by reading the enum.
        //
        // What remains here genuinely holds no command position: words and their
        // expansions, the `[[ ]]` conditional family's inner nodes, arithmetic,
        // and the separator tokens.
        _ => {}
    }
}

/// [`flatten_scoped`]'s pipeline arm: each stage in a copy of the scope, since
/// a stage runs in its own subshell.
fn flatten_pipeline(
    commands: &[rable::Node],
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    defined: &[Definition],
    out: &mut Vec<Segment>,
) {
    for (index, command) in commands.iter().enumerate() {
        // A stage's terminator is the pipe that FOLLOWS it; the last
        // stage inherits whatever followed the pipeline itself.
        //
        // BOTH PIPE SPELLINGS ARE `Pipe`, DELIBERATELY. `rable`
        // distinguishes `|` from `|&` (`PipeSep::PipeBoth`) and this
        // collapses them, because the only question `Separator` exists
        // to answer is what happens to the first stage's exit STATUS —
        // and that is identical for both: the pipeline exits with the
        // last stage's. `|&` additionally redirects stderr, which is a
        // question about output rather than about status and which no
        // `pipeline` row asks.
        //
        // Written as a plain value rather than a lookup: an earlier
        // revision consulted `separators.get(index)` and returned the
        // same thing from both arms, which read as a distinction being
        // made and was not one.
        let follows = if index + 1 < commands.len() {
            Some(Separator::Pipe)
        } else {
            after
        };
        flatten_scoped(
            command,
            source,
            follows,
            construct,
            &mut defined.to_vec(),
            out,
        );
    }
}

/// [`flatten_scoped`]'s list arm: the items share the scope, so a definition is
/// visible to the items after it — where it certainly ran (CLOUD-2840 review
/// B2). The operand after `&&` or `||` may not run, so its definitions add
/// nothing; an item sent to the background with `&` runs in a subshell, so
/// nothing it does reaches the items after it.
fn flatten_list(
    items: &[rable::ListItem],
    source: &str,
    after: Option<Separator>,
    construct: Option<(&'static str, &'static str)>,
    defined: &mut Vec<Definition>,
    out: &mut Vec<Segment>,
) {
    let mut uncertain = false;
    for item in items {
        let follows = match item.operator {
            Some(rable::ListOperator::And) => Some(Separator::And),
            Some(rable::ListOperator::Or) => Some(Separator::Or),
            Some(rable::ListOperator::Semi) => Some(Separator::Semi),
            Some(rable::ListOperator::Background) => Some(Separator::Background),
            // The final element carries whatever followed the list, and
            // it is the only one `rable` leaves without an operator.
            None => after,
        };
        if matches!(item.operator, Some(rable::ListOperator::Background)) {
            flatten_scoped(
                &item.command,
                source,
                follows,
                construct,
                &mut defined.clone(),
                out,
            );
        } else if uncertain {
            let mut branch = defined.clone();
            flatten_scoped(&item.command, source, follows, construct, &mut branch, out);
            merge_uncertain(defined, &branch);
        } else {
            flatten_scoped(&item.command, source, follows, construct, defined, out);
        }
        uncertain = matches!(
            item.operator,
            Some(rable::ListOperator::And | rable::ListOperator::Or)
        );
    }
}

/// [`flatten_scoped`]'s control-flow arms, each in a copy of the scope and
/// each carrying the redirection written on the node to every command inside.
///
/// **A CONTROL-FLOW BODY IS WALKED AND TAGGED**, which is what makes a module
/// able to decide from structure (CLOUD-1381).
///
/// An earlier revision walked these UNTAGGED, and at the time that was an
/// over-deny: `run-shape` then exempted a `sleep` inside a condition loop, and a
/// body command lifted into a bare segment carries nothing saying it was in a
/// loop, so a conditioned wait was refused as a bare timer. A second revision
/// withdrew the walk entirely, which stopped that over-deny and left the module
/// unable to see the loop at all.
///
/// CLOUD-1337 has since withdrawn the exemption, so that particular over-deny is
/// no longer possible -- but the tagging is not vestigial:
/// `polls-a-local-process` and `background-timer` PARTITION on what the loop
/// body reads, and neither can see a body it was never handed.
///
/// Tagging is the answer both attempts were missing. The condition and the body
/// are DIFFERENT roles and a module needs them apart: the condition is where a
/// process probe lives, the body is where a sleep does.
///
/// `for` COUNTS rather than tests, so it is a different node and a different
/// answer: `for i in $(seq 60); do sleep 10; done` exits on the clock like any
/// timer. The bash guard named that a deliberate non-catch "because narrowing
/// that costs a real parser"; it costs none now, and the narrowing is that this
/// is not a `while`.
fn flatten_control(
    node: &rable::Node,
    source: &str,
    after: Option<Separator>,
    defined: &mut Vec<Definition>,
    out: &mut Vec<Segment>,
) {
    let first = out.len();
    let mut inner = defined.clone();
    // Each arm that may not run, walked apart and merged as uncertain.
    let mut arms: Vec<Vec<Definition>> = Vec::new();
    let redirects = match &node.kind {
        rable::NodeKind::While {
            condition,
            body,
            redirects,
        } => {
            flatten_loop("while", condition, body, source, after, &mut inner, out);
            redirects
        }
        rable::NodeKind::Until {
            condition,
            body,
            redirects,
        } => {
            flatten_loop("until", condition, body, source, after, &mut inner, out);
            redirects
        }
        rable::NodeKind::If {
            condition,
            then_body,
            else_body,
            redirects,
        } => {
            let tag = Some(("if", "body"));
            flatten_scoped(
                condition,
                source,
                None,
                Some(("if", "condition")),
                &mut inner,
                out,
            );
            let mut then_arm = inner.clone();
            flatten_scoped(then_body, source, None, tag, &mut then_arm, out);
            arms.push(then_arm);
            if let Some(body) = else_body {
                flatten_scoped(body, source, after, tag, &mut inner, out);
            }
            redirects
        }
        rable::NodeKind::For {
            body, redirects, ..
        }
        | rable::NodeKind::ForArith {
            body, redirects, ..
        } => {
            flatten_scoped(body, source, after, Some(("for", "body")), &mut inner, out);
            redirects
        }
        rable::NodeKind::Select {
            body, redirects, ..
        } => {
            flatten_scoped(
                body,
                source,
                after,
                Some(("select", "body")),
                &mut inner,
                out,
            );
            redirects
        }
        rable::NodeKind::Case {
            patterns,
            redirects,
            ..
        } => {
            for body in patterns.iter().filter_map(|arm| arm.body.as_ref()) {
                let tag = Some(("case", "body"));
                let mut arm = inner.clone();
                flatten_scoped(body, source, None, tag, &mut arm, out);
                arms.push(arm);
            }
            redirects
        }
        _ => return,
    };
    arms.push(inner);
    for arm in &arms {
        merge_uncertain(defined, arm);
    }
    redirected(out, first, redirects, source, defined);
}

/// A `while` or `until`: its condition and its body, tagged apart, in one scope.
fn flatten_loop(
    keyword: &'static str,
    condition: &rable::Node,
    body: &rable::Node,
    source: &str,
    after: Option<Separator>,
    inner: &mut Vec<Definition>,
    out: &mut Vec<Segment>,
) {
    flatten_scoped(
        condition,
        source,
        None,
        Some((keyword, "condition")),
        inner,
        out,
    );
    flatten_scoped(body, source, after, Some((keyword, "body")), inner, out);
}

/// A word's source text, from the parts the lexer resolved.
#[must_use]
pub fn word_text(word: &rable::Node) -> String {
    match &word.kind {
        rable::NodeKind::Word { value, .. } | rable::NodeKind::WordLiteral { value } => {
            value.clone()
        }
        _ => String::new(),
    }
}

/// The body of a word that is exactly `$(cat <<EOF … EOF)`, bare or in double
/// quotes (CLOUD-2683): one substitution, whose command is a lone `cat` with no
/// assignment and one complete heredoc. Anything else is `None`.
#[must_use]
pub fn cat_heredoc_body(word: &rable::Node) -> Option<String> {
    let rable::NodeKind::Word { parts, .. } = &word.kind else {
        return None;
    };
    let quote = |node: &rable::Node| matches!(&node.kind, rable::NodeKind::WordLiteral { value } if value == "\"");
    let substitution = match parts.as_slice() {
        [only] => only,
        [open, only, close] if quote(open) && quote(close) => only,
        _ => return None,
    };
    let rable::NodeKind::CommandSubstitution { command, .. } = &substitution.kind else {
        return None;
    };
    let rable::NodeKind::Command {
        assignments,
        words,
        redirects,
    } = &command.kind
    else {
        return None;
    };
    let [cat] = words.as_slice() else {
        return None;
    };
    let [heredoc] = redirects.as_slice() else {
        return None;
    };
    if !assignments.is_empty() || word_text(cat) != "cat" {
        return None;
    }
    match &heredoc.kind {
        rable::NodeKind::HereDoc {
            content,
            complete: true,
            ..
        } => Some(content.clone()),
        _ => None,
    }
}

/// Append a segment for every command hiding inside a word.
///
/// `$(...)`, `` `...` `` and `<(...)` each carry a parsed command, and each of
/// them is a command this call will run. They are appended AFTER the command
/// that contains them and carry no terminator: nothing takes their status.
pub fn descend_word(word: &rable::Node, source: &str, out: &mut Vec<Segment>) {
    descend_word_in(word, source, &[], out);
}

/// [`descend_word`], with the functions `defined` where the word is expanded
/// (CLOUD-2840 review, finding 5): a substitution is a subshell, which
/// inherits them, so a call to one inside `$( … )` runs the function and
/// nothing on `PATH`. Its own definitions die with it, so it walks a copy.
pub fn descend_word_in(
    word: &rable::Node,
    source: &str,
    defined: &[Definition],
    out: &mut Vec<Segment>,
) {
    match &word.kind {
        rable::NodeKind::Word { parts, .. } => {
            for part in parts {
                descend_word_in(part, source, defined, out);
            }
        }
        rable::NodeKind::CommandSubstitution { command, .. }
        | rable::NodeKind::ProcessSubstitution { command, .. } => {
            flatten_scoped(command, source, None, None, &mut defined.to_vec(), out);
        }
        _ => {}
    }
}

/// The same, for a redirection's target: `diff <(a) <(b)` runs three programs.
pub fn descend_redirect(redirect: &rable::Node, source: &str, out: &mut Vec<Segment>) {
    descend_redirect_in(redirect, source, &[], out);
}

/// [`descend_redirect`], with the functions `defined` where it runs.
pub fn descend_redirect_in(
    redirect: &rable::Node,
    source: &str,
    defined: &[Definition],
    out: &mut Vec<Segment>,
) {
    if let rable::NodeKind::Redirect { target, .. } = &redirect.kind {
        descend_word_in(target, source, defined, out);
    }
}

/// The text a stdin redirection hands its command: a heredoc's body, or a
/// here-string's word unquoted. A file redirect (`<`) hands a path, not text.
///
/// The here-string's word is read off its token value, never its source span:
/// the parser builds a redirect target spanless (`Node::empty`), so
/// `source_text` hands back nothing and the script would go unread.
#[must_use]
pub fn stdin_text(redirect: &rable::Node) -> Option<String> {
    match &redirect.kind {
        rable::NodeKind::HereDoc { content, .. } => Some(content.clone()),
        rable::NodeKind::Redirect { op, target, .. } if op == "<<<" => match &target.kind {
            rable::NodeKind::Word { value, .. } | rable::NodeKind::WordLiteral { value } => {
                Some(unquote(value))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Does this redirection bind stdin — `<`, `<<`, `<<-` or `<<<`?
///
/// **Per SEGMENT, which is the entire predicate** (CLOUD-613), and the reason it
/// is a question about a typed redirection rather than about the command STRING
/// is unchanged: `git commit -F - && mise run land <<'EOF'` hands the message to
/// `land`, and both spellings carry an opener in the line. What has changed is
/// that the parser decides which command owns the opener, where the walk decided
/// it from the position of a `<` it had to prove was unquoted first.
#[must_use]
pub fn binds_stdin(redirect: &rable::Node) -> bool {
    match &redirect.kind {
        // A heredoc IS an input redirection, and its body is AST data rather
        // than text this function has to skip past (CLOUD-723).
        rable::NodeKind::HereDoc { .. } => true,
        rable::NodeKind::Redirect { op, .. } => matches!(op.as_str(), "<" | "<<" | "<<-" | "<<<"),
        _ => false,
    }
}

/// Remove one level of shell quoting from a word the parser has already
/// delimited.
///
/// **The parser's job ends at the word boundary and this begins there**, which
/// is why a hand-written routine here is not the character walk CLOUD-1381
/// retired coming back. That walk had to decide *where a word ended* while also
/// deciding what a quote meant, in one pass, over the whole line — so a quoting
/// mistake moved a segment boundary and changed the command's shape. This runs
/// over a token whose extent is already settled, and its worst failure is one
/// wrong word.
///
/// Single quotes are literal throughout. Double quotes let a backslash escape
/// exactly `"`, `\`, `$` and `` ` ``, which is bash's rule and not a
/// simplification of it. An unterminated quote keeps its tail, matching what the
/// parser accepted.
#[must_use]
pub fn unquote(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        break;
                    }
                    out.push(inner);
                }
            }
            '"' => {
                while let Some(inner) = chars.next() {
                    if inner == '"' {
                        break;
                    }
                    if inner == '\\'
                        && chars
                            .peek()
                            .is_some_and(|next| matches!(*next, '"' | '\\' | '$' | '`'))
                        && let Some(next) = chars.next()
                    {
                        out.push(next);
                        continue;
                    }
                    out.push(inner);
                }
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::segments;
    use crate::facts::Look;

    /// Fails by: an empty word kept and the command's real words dropped, so
    /// `echo '' x` reads as a command with no program.
    #[test]
    fn an_empty_word_is_dropped_and_the_rest_kept() {
        let Look::Is(parsed) = segments("echo '' x") else {
            panic!("the command parses");
        };
        assert_eq!(parsed[0].words, ["echo", "x"]);
        assert_eq!(parsed[0].lines[0].words, ["echo", "x"]);
    }

    /// Every segment the command parses to, or a panic naming it.
    fn parsed(command: &str) -> Vec<super::Segment> {
        let Look::Is(parsed) = segments(command) else {
            panic!("`{command}` parses");
        };
        parsed
    }

    /// A REDIRECTION ON `[[ … ]]` OR `(( … ))` WRITES ITS TARGET (CLOUD-2840
    /// review M5, finding 3), as one on any other compound does.
    ///
    /// Fails by: the conditional or arithmetic command yielding no segment, so
    /// its redirect target is no write anybody sees.
    #[test]
    fn a_test_or_arithmetic_commands_redirect_is_a_segments() {
        for command in ["[[ -n x ]] > batten.toml", "(( 1 )) > batten.toml"] {
            let parsed = parsed(command);
            assert!(
                parsed
                    .iter()
                    .any(|segment| segment.redirects == [">", "batten.toml"]
                        && segment.words == [">", "batten.toml"]),
                "`{command}`: {parsed:?}"
            );
        }
    }

    /// A PROCESS SUBSTITUTION IN A COMPOUND'S REDIRECT RUNS (finding 3).
    ///
    /// Fails by: the compound's redirect copied as tokens but never descended,
    /// so `tee` reaches no segment.
    #[test]
    fn a_compounds_redirect_target_is_descended() {
        for command in [
            "{ cat f; } > >(tee out)",
            "( cat f ) > >(tee out)",
            "while false; do :; done > >(tee out)",
            "[[ -n x ]] > >(tee out)",
        ] {
            let parsed = parsed(command);
            assert!(
                parsed.iter().any(|segment| segment.nested
                    && segment.words.first().is_some_and(|word| word == "tee")),
                "`{command}`: {parsed:?}"
            );
        }
    }

    /// A HEREDOC ON A COMPOUND IS A HEREDOC (finding 3): its body is data, so
    /// the command after its delimiter is still read.
    ///
    /// Fails by: the newlines joined through the body, or a quote in it read as
    /// an unclosed word, so the whole call abstains and the push is unjudged.
    #[test]
    fn a_heredoc_on_a_compound_keeps_the_command_after_it() {
        for command in [
            "{ cat; } <<'EOF'\nsay \"hi\nEOF\ngit push --force origin main",
            "while read l; do echo \"$l\"; done <<'EOF'\nsay 'hi\nEOF\ngit push --force origin main",
            "if true; then cat; fi <<'EOF'\nx\nEOF\ngit push --force origin main",
            "git push --force origin main\n{ cat; } <<'EOF'\nsay \"hi\nEOF",
            "git push --force origin main\nwhile read l; do :; done <<'EOF'\nit's\nEOF",
            "git push --force origin main\n[[ -n x ]] <<'EOF'\nsay \"hi\nEOF",
        ] {
            let parsed = parsed(command);
            assert!(
                parsed
                    .iter()
                    .flat_map(|segment| &segment.lines)
                    .any(|line| line.words.first().is_some_and(|word| word == "git")),
                "`{command}`: {parsed:?}"
            );
        }
    }
}

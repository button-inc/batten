#compdef batten

autoload -U is-at-least

_batten() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_batten_commands" \
"*::: :->batten" \
&& ret=0
    case $state in
    (batten)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-command-$line[1]:"
        case $line[1] in
            (bench)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__bench_commands" \
"*::: :->bench" \
&& ret=0

    case $state in
    (bench)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-bench-command-$line[1]:"
        case $line[1] in
            (tokens)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--check[Diff a fresh run against the committed table instead of writing it]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__bench__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-bench-help-command-$line[1]:"
        case $line[1] in
            (tokens)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(check)
_arguments "${_arguments_options[@]}" : \
'*--rule=[Run only the declared rules with these ids (repeatable)]:rule:_default' \
'--since=[Judge only the paths changed against this rev]:since:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--staged[Judge only the paths staged in the git index]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(enforce)
_arguments "${_arguments_options[@]}" : \
'*--rule=[Run only the declared rules with these ids (repeatable)]:rule:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(exec)
_arguments "${_arguments_options[@]}" : \
'--jobs=[How many of a \`\:\:\:\` bundle'\''s commands run at once]:jobs:_default' \
'--lock=[Hold this clone'\''s named singleton lock for the child'\''s lifetime]:lock:_default' \
'--lock-path=[Hold the lock at this path, for a resource the clone does not own]:lock_path:_default' \
'--lock-attempts=[How many times to ask for the lock before reporting it held]:lock_attempts:_default' \
'--lock-label=[What the wait is for, named by the caller for the refusal line]:lock_label:_default' \
'*--tracked=[Append the tracked paths this pathspec selects to the command; run nothing if none]:tracked:_default' \
'*--except=[Drop the tracked paths this glob matches from what --tracked selected]:except:_default' \
'--format=[How Batten'\''s own record is encoded (hk'\''s axis)]: :((human\:"Pointer lines, one per fact"
json\:"One JSON document"
jsonl\:"One JSON record per line"))' \
'--style=[How a teed child'\''s bytes are presented, and whose output is suppressed (mise'\''s axis)]: :((prefix\:"Each line carries the child'\''s program name"
interleave\:"The child'\''s bytes, verbatim and as they arrive"
keep-order\:"Each stream whole, in a fixed order, after the child exits"
replacing\:"As \[\`OutputStyle\:\:Prefix\`\]\: redrawing in place needs a terminal Batten never assumes it has"
timed\:"As \[\`OutputStyle\:\:Prefix\`\], minus the clock — see the type'\''s docs"
quiet\:"Batten says nothing of its own; the child still speaks"
silent\:"Nobody speaks"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--capture-only[Store the child'\''s streams and report their handles instead of passing the bytes through]' \
'--tee[Copy the child'\''s streams onto Batten'\''s own, as well as capturing them]' \
'--continue-on-error[Run the rest of a \`\:\:\:\` bundle after a command fails]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'*::command -- The command to run, after `--`, with its own arguments intact:_default' \
&& ret=0
;;
(capture)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__capture_commands" \
"*::: :->capture" \
&& ret=0

    case $state in
    (capture)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-capture-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
'--lines=[A 1-indexed inclusive line range, \`FROM\:TO\`, clamped to the capture]:lines:_default' \
'--grep=[Only lines containing this literal substring]:grep:_default' \
'--bytes=[A 0-indexed half-open byte range, \`FROM\:TO\`, either side omittable, clamped to the capture]:bytes:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--raw[Write the selected bytes to stdout verbatim, with no decode and no added newline]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':handle -- The `<stream>\:<digest>` handle to read:_default' \
&& ret=0
;;
(find)
_arguments "${_arguments_options[@]}" : \
'*--tool=[The tool whose response to resolve, matched whole or as a \`__\`-delimited final segment; repeatable]:tool:_default' \
'--key-at=[The dotted path the key sits at in the response]:key_at:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--raw[Write the selected bytes to stdout verbatim, with no decode and no added newline]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':key -- The key the response must carry, e.g. an issue id:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'--stream=[Only captures of this stream]:stream:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--calls[List recorded calls instead of stored captures, in a byte-stable order]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(prune)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__capture__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-capture-help-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(find)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(prune)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(mcp)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__mcp_commands" \
"*::: :->mcp" \
&& ret=0

    case $state in
    (mcp)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-mcp-command-$line[1]:"
        case $line[1] in
            (call)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':server -- The server to dispatch to, as a `\[\[mcp.source\]\]` names it:_default' \
':method -- The method to call:_default' \
'::params -- The method'\''s arguments, as a JSON object; omitted is `{}`:_default' \
&& ret=0
;;
(spawn)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':server -- The server this launch is for, as the spawn ledger and `mcp-attach-check` name it:_default' \
'*::command -- The launch line, run verbatim — Batten execs it and does not supervise it:_default' \
&& ret=0
;;
(grant)
_arguments "${_arguments_options[@]}" : \
'--config=[The host-injected MCP config to resolve server names through]:config:_default' \
'--settings=[The permission settings file to judge, instead of the declared one]:settings:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--guard[Read a hook payload on stdin and refuse the call the committed settings deny]' \
'--aliases[List the portable alias each server in the injected config resolves to]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::tool -- The tool name to resolve, as `mcp__<server>__<tool>`; absent under --guard or --aliases:_default' \
&& ret=0
;;
(posture)
_arguments "${_arguments_options[@]}" : \
'--settings=[The permission settings file to judge, instead of the declared one]:settings:_default' \
'--config=[The host-injected MCP config to resolve server names through]:config:_default' \
'--logs=[The host'\''s MCP connection log tree, instead of the one it keeps for this project]:logs:_default' \
'--spawns=[The spawn ledger \`mcp spawn\` appends to, instead of this clone'\''s]:spawns:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__mcp__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-mcp-help-command-$line[1]:"
        case $line[1] in
            (call)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(spawn)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(grant)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(posture)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(target)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__target_commands" \
"*::: :->target" \
&& ret=0

    case $state in
    (target)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-target-command-$line[1]:"
        case $line[1] in
            (prune)
_arguments "${_arguments_options[@]}" : \
'--root=[The build directory to prune, instead of the configured one]:root:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__target__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-target-help-command-$line[1]:"
        case $line[1] in
            (prune)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(ci)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__ci_commands" \
"*::: :->ci" \
&& ret=0

    case $state in
    (ci)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-ci-command-$line[1]:"
        case $line[1] in
            (slow-needed)
_arguments "${_arguments_options[@]}" : \
'--base=[The revision this checkout is diffed against]:base:_default' \
'--head=[The revision whose tree the checkout must carry; refused when it does not]:head:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(suites)
_arguments "${_arguments_options[@]}" : \
'--base=[The revision this checkout is diffed against]:base:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__ci__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-ci-help-command-$line[1]:"
        case $line[1] in
            (slow-needed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(suites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(release)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__release_commands" \
"*::: :->release" \
&& ret=0

    case $state in
    (release)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-release-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(sums)
_arguments "${_arguments_options[@]}" : \
'--manifest=[The checksum manifest'\''s file name, as the release carries it]:manifest:_default' \
'--out-dir=[Write the manifest under this directory (default\: checksums)]:out_dir:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--names[Print the manifest'\''s path as sums=<path> and exit, with no tag, network or download]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::tag -- The release'\''s tag; empty or absent is the latest release:_default' \
&& ret=0
;;
(backfill)
_arguments "${_arguments_options[@]}" : \
'*--tag=[A release tag to record (repeatable); absent, every tag the pattern selects, oldest first]:tag:_default' \
'--workflow=[The workflow file dispatched once per tag]:workflow:_default' \
'--ref=[The branch the dispatched runs execute on]:ref:_default' \
'--pattern=[The glob a release tag matches, as \`git tag --list\` matches it]:pattern:_default' \
'--poll-interval=[Seconds between polls; the forge'\''s own interval raises it (default\: 5)]:poll_interval:_default' \
'--max-polls=[Polls per tag before its run reads as never finishing (default\: 240)]:max_polls:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--dry-run[Print the plan, oldest first, and dispatch nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__release__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-release-help-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sums)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(backfill)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(config)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__config_commands" \
"*::: :->config" \
&& ret=0

    case $state in
    (config)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-config-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(epoch)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--no-cache[Recompute the epoch from the tracked files'\'' bytes, ignoring the cached value]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(deprecations)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':against -- The git ref whose published schema is the baseline (e.g. v0.0.111):_default' \
&& ret=0
;;
(lint)
_arguments "${_arguments_options[@]}" : \
'--host-rules=[Compare the committed \[ci\] table against a host ruleset payload (path, or - for stdin)]:host_rules:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__config__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-config-help-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(epoch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(deprecations)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lint)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(lint)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__lint_commands" \
"*::: :->lint" \
&& ret=0

    case $state in
    (lint)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-lint-command-$line[1]:"
        case $line[1] in
            (brief)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::brief -- The brief to read; omitted or `-` reads stdin:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__lint__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-lint-help-command-$line[1]:"
        case $line[1] in
            (brief)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(spec)
_arguments "${_arguments_options[@]}" : \
'--format=[The output format for the spec]: :((json\:"Byte-stable JSON — the agent-facing contract (§6)"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(doctor)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__doctor_commands" \
"*::: :->doctor" \
&& ret=0

    case $state in
    (doctor)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-doctor-command-$line[1]:"
        case $line[1] in
            (target)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':target -- The target triple to install, as `rustup target list` spells it:_default' \
&& ret=0
;;
(mediator)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(egress)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(toolchain)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':manifest -- The manifest whose declared tool table to read:_default' \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(session)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__doctor__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-doctor-help-command-$line[1]:"
        case $line[1] in
            (target)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(mediator)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(egress)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(toolchain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(session)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(init)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(baseline)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--prune[Drop baseline entries whose finding no longer exists, and ratchet reduced counts down]' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(generate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__generate_commands" \
"*::: :->generate" \
&& ret=0

    case $state in
    (generate)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-generate-command-$line[1]:"
        case $line[1] in
            (completions)
_arguments "${_arguments_options[@]}" : \
'--shell=[The shell whose completion script to emit]: :(bash elvish fish powershell zsh)' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
'--harness=[The harness whose hook registrations to emit]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(man)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::command -- The root-relative command path to document ('\''config show'\''); omit for the root page:_default' \
&& ret=0
;;
(markdown)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(schema)
_arguments "${_arguments_options[@]}" : \
'--surface=[Which surface to describe\: the committed authority, the override layer, or a policy-input document]: :((authority\:"The committed authority\: \`batten.toml\`"
override\:"The raise-only override layer\: \`batten.local.toml\`"
policy-input\:"The \`input\` document a \`scope = "tree"\` Rego module reads"
policy-call\:"The \`input\` document a \`scope = "mediated_call"\` Rego module reads"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__generate__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-generate-help-command-$line[1]:"
        case $line[1] in
            (completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(man)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(markdown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(schema)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(perf)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__perf_commands" \
"*::: :->perf" \
&& ret=0

    case $state in
    (perf)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-perf-command-$line[1]:"
        case $line[1] in
            (pair)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--null[Measure HEAD against itself, so the ratio is the noise floor rather than a comparison]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(measure)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--null[Measure HEAD against itself, so the ratio is the noise floor rather than a comparison]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__perf__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-perf-help-command-$line[1]:"
        case $line[1] in
            (pair)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(measure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(mutate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__mutate_commands" \
"*::: :->mutate" \
&& ret=0

    case $state in
    (mutate)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-mutate-command-$line[1]:"
        case $line[1] in
            (sweep)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__mutate__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-mutate-help-command-$line[1]:"
        case $line[1] in
            (sweep)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(policy)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__policy_commands" \
"*::: :->policy" \
&& ret=0

    case $state in
    (policy)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-policy-command-$line[1]:"
        case $line[1] in
            (budget)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(test)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(tools)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':token -- The verdict token to resolve, e.g. task name undefined:_default' \
&& ret=0
;;
(rule)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':id -- The rule id to resolve, e.g. no-raw-issue-read:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__policy__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-policy-help-command-$line[1]:"
        case $line[1] in
            (budget)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(test)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tools)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rule)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(verdict)
_arguments "${_arguments_options[@]}" : \
'--findings=[How many blocking findings the run produced]:findings:_default' \
'--unjudgeable=[How many subjects the run could not read]:unjudgeable:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(commit)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__commit_commands" \
"*::: :->commit" \
&& ret=0

    case $state in
    (commit)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-commit-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'--message=[Judge one pending commit message file, before the commit exists]:message:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::range -- Judge every non-merge commit in this range (<base>..<head>):_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__commit__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-commit-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(ready)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__ready_commands" \
"*::: :->ready" \
&& ret=0

    case $state in
    (ready)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-ready-command-$line[1]:"
        case $line[1] in
            (lint)
_arguments "${_arguments_options[@]}" : \
'--issue=[Read the issue payload from the capture store by key, where \`mcp call ... get_issue\` put it]:issue:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__ready__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-ready-help-command-$line[1]:"
        case $line[1] in
            (lint)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(landed)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__landed_commands" \
"*::: :->landed" \
&& ret=0

    case $state in
    (landed)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-landed-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'--claimed=[\`<CLOUD-id>\` lines a commit on origin/main closes, from \`claimed-keys --closing-only\`]:claimed:_default' \
'--merged-prs=[\`<CLOUD-id><TAB><pr-number>\` lines, one per closing key in a MERGED pull request]:merged_prs:_default' \
'--landed-by=[\`<CLOUD-id><TAB><ref>\` lines the caller asserts carry the work]:landed_by:_default' \
'--declined=[\`<CLOUD-id>\` lines a pull request body declined with DO-NOT-CLOSE]:declined:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(abandoned)
_arguments "${_arguments_options[@]}" : \
'--claimed=[\`<CLOUD-id>\` lines a commit on origin/main closes, from \`claimed-keys --closing-only\`]:claimed:_default' \
'--merged-prs=[\`<CLOUD-id><TAB><pr-number>\` lines, one per closing key in a MERGED pull request]:merged_prs:_default' \
'--landed-by=[\`<CLOUD-id><TAB><ref>\` lines the caller asserts carry the work]:landed_by:_default' \
'--refs=[Branch names the remote carries, one per line]:refs:_default' \
'--instant=[The instant to measure the idle bound against, ISO-8601 (default\: now)]:instant:_default' \
'--max-idle-days=[Days a claim may be idle before it reads as abandoned (default\: 2)]:max_idle_days:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--gather[Acquire each evidence arm no file was named for\: the trunk'\''s closing keys, merged pull requests, and the remote'\''s branches]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__landed__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-landed-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(abandoned)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(hk)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__hk_commands" \
"*::: :->hk" \
&& ret=0

    case $state in
    (hk)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-hk-command-$line[1]:"
        case $line[1] in
            (contract)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(observe)
_arguments "${_arguments_options[@]}" : \
'--session=[The host'\''s session identifier; without one no receipt is written]:session:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(drift)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__hk__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-hk-help-command-$line[1]:"
        case $line[1] in
            (contract)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(observe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(drift)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(checks)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__checks_commands" \
"*::: :->checks" \
&& ret=0

    case $state in
    (checks)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-checks-command-$line[1]:"
        case $line[1] in
            (green)
_arguments "${_arguments_options[@]}" : \
'--required=[Comma-separated check names that carry a verdict about this repository]:required:_default' \
'--absent-ok=[Comma-separated check names for which having no run at all is a legitimate reading]:absent_ok:_default' \
'--answered=[Comma-separated conclusions that constitute an answer; anything else is not yet one]:answered:_default' \
'--fanin=[The fan-in check whose failure a cancelled sibling can manufacture]:fanin:_default' \
'--sha=[Read this commit'\''s check runs from the forge instead of a reading on stdin]:sha:_default' \
'--repo=[The repository to read, in the forge client'\''s own spelling]:repo:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__checks__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-checks-help-command-$line[1]:"
        case $line[1] in
            (green)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(pr)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__pr_commands" \
"*::: :->pr" \
&& ret=0

    case $state in
    (pr)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-pr-command-$line[1]:"
        case $line[1] in
            (watch)
_arguments "${_arguments_options[@]}" : \
'--sha=[The commit whose check runs to read — a sha, or a ref this checkout resolves]:sha:_default' \
'--repo=[The repository to read, in the forge client'\''s own spelling]:repo:_default' \
'--interval=[Seconds between requests; a server-requested floor raises it and nothing lowers it]:interval:_default' \
'--progress=[Program to record the poll'\''s tick and reading-change signals]:progress:_default' \
'--progress-id=[The identity the progress recorder keys its entries on]:progress_id:_default' \
'--required=[Comma-separated check names that carry a verdict about this repository]:required:_default' \
'--absent-ok=[Comma-separated check names for which having no run at all is a legitimate reading]:absent_ok:_default' \
'--answered=[Comma-separated conclusions that constitute an answer; anything else is not yet one]:answered:_default' \
'--fanin=[The fan-in check whose failure a cancelled sibling can manufacture]:fanin:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pr -- The pull request number this verb is about:_default' \
&& ret=0
;;
(file)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pr -- The pull request number this verb is about:_default' \
&& ret=0
;;
(link)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pr -- The pull request number this verb is about:_default' \
':key -- The tracker key the pull request should close:_default' \
&& ret=0
;;
(ensure)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pr -- The pull request number this verb is about:_default' \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pr -- The pull request number this verb is about:_default' \
&& ret=0
;;
(unsubscribed)
_arguments "${_arguments_options[@]}" : \
'--session-env=[The name of the environment variable holding this host'\''s session id; unset is no session]:session_env:_default' \
'--token-env=[The name of the environment variable holding the path of the credential file \`drop\` sends]:token_env:_default' \
'--endpoint=[The endpoint \`drop\` calls, with \`{session}\` where the session id goes]:endpoint:_default' \
'--tool=[The tool \`drop\` asks the endpoint to call]:tool:_default' \
'--arguments=[The tool'\''s arguments \`drop\` sends\: a JSON object whose strings may name {owner}, {repo}, {pr} and {session}]:arguments:_default' \
'--family=[The record family \`check\` writes, and the prefix of this session'\''s receipts]:family:_default' \
'--rule=[The declared rule \`check\` decides with over the record it writes]:rule:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':verb -- drop | record | check:_default' \
':pr -- The pull request number this verb is about:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__pr__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-pr-help-command-$line[1]:"
        case $line[1] in
            (watch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(link)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ensure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unsubscribed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(task)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__task_commands" \
"*::: :->task" \
&& ret=0

    case $state in
    (task)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-task-command-$line[1]:"
        case $line[1] in
            (register)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':task -- The task'\''s name, as its callers know it:_default' \
':pid -- The process the record is keyed by:_default' \
'::phase -- What the task is doing; absent is `starting`:_default' \
&& ret=0
;;
(phase)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pid -- The process the record is keyed by:_default' \
':value -- The value to record; its stamp moves only when it changes:_default' \
&& ret=0
;;
(tick)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pid -- The process the record is keyed by:_default' \
':value -- The value to record; its stamp moves only when it changes:_default' \
&& ret=0
;;
(sig)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pid -- The process the record is keyed by:_default' \
':value -- The value to record; its stamp moves only when it changes:_default' \
&& ret=0
;;
(unregister)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pid -- The process the record is keyed by:_default' \
&& ret=0
;;
(read)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':pid -- The process the record is keyed by:_default' \
':field -- The record field to print:_default' \
&& ret=0
;;
(alive)
_arguments "${_arguments_options[@]}" : \
'--program-root=[The directory this consumer keeps its task programs in, matched inside a live process'\''s cmdline]:program_root:_default' \
'--instant=[The epoch second to judge time-dependent records against, supplied as data]:instant:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__task__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-task-help-command-$line[1]:"
        case $line[1] in
            (register)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(phase)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tick)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sig)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unregister)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(read)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(alive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(singleton)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__singleton_commands" \
"*::: :->singleton" \
&& ret=0

    case $state in
    (singleton)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-singleton-command-$line[1]:"
        case $line[1] in
            (acquire)
_arguments "${_arguments_options[@]}" : \
'--recheck-ms=[Milliseconds between the two sightings a reclaim requires]:recheck_ms:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':task -- The task'\''s name, which is what the lock is keyed by:_default' \
':pid -- The process the record is keyed by:_default' \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':task -- The task'\''s name, which is what the lock is keyed by:_default' \
&& ret=0
;;
(detach)
_arguments "${_arguments_options[@]}" : \
'--marker=[Where a failed run'\''s pointers wait, announced and cleared by the next invocation]:marker:_default' \
'--log=[Where the background run'\''s whole output is written]:log:_default' \
'--pattern=[The \`\[\[pattern\]\]\` row whose matching output lines are the failure'\''s pointers]:pattern:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--attached[Run as the background copy\: take the lock, run the command, record a failure]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':task -- The task'\''s name, which is what the lock is keyed by:_default' \
'*::command -- The command to run in the background, after `--`:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__singleton__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-singleton-help-command-$line[1]:"
        case $line[1] in
            (acquire)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(detach)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(claim)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__claim_commands" \
"*::: :->claim" \
&& ret=0

    case $state in
    (claim)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-claim-command-$line[1]:"
        case $line[1] in
            (merged)
_arguments "${_arguments_options[@]}" : \
'--limit=[The most pull requests to read before the answer is truncated (default 5000)]:limit:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(keys)
_arguments "${_arguments_options[@]}" : \
'--branch=[The head branch, standing in for source 2]:branch:_default' \
'--title=[The pull request title, also source 2 — a body is not, because a body cites evidence]:title:_default' \
'--log=[Commit messages, standing in for sources 1 and 3]:log:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--closing-only[Answer from a closing keyword alone, never falling through to the branch or a trailer]' \
'--refs-first-only[Answer from the first key of each \`Refs\:\` trailer alone, never sources 1 or 2]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
'--adopt-from=[The branch name the receipt being adopted was minted under]:adopt_from:_default' \
'--issue=[Read the issue payload from the capture store by key, where \`mcp call ... get_issue\` put it]:issue:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--takeover[Claim over the competitor refusals, recording in the receipt which ones were overridden]' \
'--bypass-sequence[Skip the refinement-sequence rules, recorded in the receipt as a bypass]' \
'--adopt[Re-key an orphaned claim receipt onto this branch instead of judging a payload]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(bot)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(race)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(carry)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__claim__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-claim-help-command-$line[1]:"
        case $line[1] in
            (merged)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keys)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(bot)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(race)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(carry)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(semver)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__semver_commands" \
"*::: :->semver" \
&& ret=0

    case $state in
    (semver)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-semver-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'--baseline=[The rev to measure the API delta against (default\: origin/main)]:baseline:_default' \
'--release-type=[The bump being claimed, which is what the delta is judged against]:release_type:_default' \
'--package=[The package whose public API is compared (default\: batten)]:package:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__semver__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-semver-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(attribution)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__attribution_commands" \
"*::: :->attribution" \
&& ret=0

    case $state in
    (attribution)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-attribution-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'--message=[Judge one pending commit message file, before the commit exists]:message:_default' \
'--harness=[Report the attribution capabilities this host declares, and capture at that fidelity]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::range -- Judge every non-merge commit in this range (<base>..<head>):_default' \
&& ret=0
;;
(tagger)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':tag -- The tag to judge, by short name (v0.0.162):_default' \
&& ret=0
;;
(identity)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(signing)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__attribution__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-attribution-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tagger)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(identity)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(signing)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(worktree)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__worktree_commands" \
"*::: :->worktree" \
&& ret=0

    case $state in
    (worktree)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-worktree-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__worktree__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-worktree-help-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(override)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__override_commands" \
"*::: :->override" \
&& ret=0

    case $state in
    (override)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-override-command-$line[1]:"
        case $line[1] in
            (request)
_arguments "${_arguments_options[@]}" : \
'--rule=[The rule whose refusal is being overridden]:rule:_default' \
'--verdict=[The verdict token that refusal carries, e.g. diff ship early]:verdict:_default' \
'--subject=[The gate'\''s canonical subject, exactly as its refusal names it]:subject:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(spend)
_arguments "${_arguments_options[@]}" : \
'--admission=[The admission address to spend]:admission:_default' \
'--rule=[The rule whose refusal is being overridden]:rule:_default' \
'--verdict=[The verdict token that refusal carries, e.g. diff ship early]:verdict:_default' \
'--subject=[The gate'\''s canonical subject, exactly as its refusal names it]:subject:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__override__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-override-help-command-$line[1]:"
        case $line[1] in
            (request)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(spend)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(provision)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__provision_commands" \
"*::: :->provision" \
&& ret=0

    case $state in
    (provision)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-provision-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(apply)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__provision__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-provision-help-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(apply)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(startup)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--repair[Run each failing row'\''s declared repair, then re-decide its check]' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(adjudicate)
_arguments "${_arguments_options[@]}" : \
'--instant=[The epoch second to judge time-dependent records against, supplied as data]:instant:_default' \
'--harness=[The harness whose payload to decode and whose decision channel to answer in]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(payload)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__payload_commands" \
"*::: :->payload" \
&& ret=0

    case $state in
    (payload)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-payload-command-$line[1]:"
        case $line[1] in
            (field)
_arguments "${_arguments_options[@]}" : \
'--harness=[The harness whose payload dialect to decode]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--name=[Which payload field to print; an allowlist, never a JSON path]: :((hook-event-name\:"The host'\''s own event spelling, echoed back untouched"
session-id\:"The host'\''s session id"
tool-name\:"The tool being mediated"
command\:"The command text, for shell-shaped tools"
cwd\:"The host'\''s working directory"
stop-hook-active\:"Whether this is a re-entered \`Stop\` hook"
last-assistant-message\:"The assistant'\''s last message"
transcript-path\:"The path to the session transcript"
prompt\:"The prompt a subagent spawn commits a fresh context window to"
run-in-background\:"Whether the host was asked to run this call in the background"
input-id\:"The \`id\` a structured call names its subject by (CLOUD-987)"
input-state\:"The \`state\` a structured call moves its subject to (CLOUD-987)"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__payload__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-payload-help-command-$line[1]:"
        case $line[1] in
            (field)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__receipt_commands" \
"*::: :->receipt" \
&& ret=0

    case $state in
    (receipt)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-receipt-command-$line[1]:"
        case $line[1] in
            (clean)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':check -- The check whose conclusion is being recorded:_default' \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
'*--or=[Another check whose receipt satisfies this one; any one valid receipt passes (repeatable)]:or:_default' \
'--key=[Which git fact the receipt is judged against\: the exact commit, or the branch]: :((head\:"Keyed to the exact commit; an amend, a rebase, or a moved trunk expires it"
branch\:"Keyed to the branch; every commit on it continues to serve the claim"
named\:"Keyed to a value the CALL names, read through \[\`Rule\:\:key_from\`\] (CLOUD-987)"
delta\:"Keyed to the identity of the branch'\''s whole CHANGE against \[\`Rule\:\:key_base\`\] (CLOUD-1547) — the read side of \[\`crate\:\:mint\:\:MintKey\:\:Delta\`\]"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':check -- The check whose receipt is judged:_default' \
&& ret=0
;;
(verified)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__receipt__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-receipt-help-command-$line[1]:"
        case $line[1] in
            (clean)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verified)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(defects)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__defects_commands" \
"*::: :->defects" \
&& ret=0

    case $state in
    (defects)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-defects-command-$line[1]:"
        case $line[1] in
            (query)
_arguments "${_arguments_options[@]}" : \
'--class=[Only records in this taxonomy class]:class:_default' \
'--id=[Only the record with this id]:id:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--ungated[Only records no rule or gate discharges yet]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__defects__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-defects-help-command-$line[1]:"
        case $line[1] in
            (query)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(design)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__design_commands" \
"*::: :->design" \
&& ret=0

    case $state in
    (design)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-design-command-$line[1]:"
        case $line[1] in
            (audit)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__design__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-design-help-command-$line[1]:"
        case $line[1] in
            (audit)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(state)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__state_commands" \
"*::: :->state" \
&& ret=0

    case $state in
    (state)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-state-command-$line[1]:"
        case $line[1] in
            (adopt)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::store -- The store id to bind, when resolution cannot decide for itself:_default' \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(migrate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(settle)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':identity -- The stored finding'\''s identity, as `state list` prints it:_default' \
':disposition -- What was decided\: acted, rejected-by-design or rejected-wrong:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__state__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-state-help-command-$line[1]:"
        case $line[1] in
            (adopt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(migrate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(settle)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(record)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__record_commands" \
"*::: :->record" \
&& ret=0

    case $state in
    (record)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-command-$line[1]:"
        case $line[1] in
            (suites)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--write[Write the corpus to its committed path instead of printing it]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(tool)
_arguments "${_arguments_options[@]}" : \
'--pick=[Reduce \`key=value\` lines\: \`<name-key>=<token-key>\` names the field that labels a record line and the one that scores it]:pick:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':id -- The `\[\[rule.tools\]\]` id whose verdict is being recorded:_default' \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
'--fanin=[With --fetch\: record nothing until this check has an answered conclusion]:fanin:_default' \
'--answered=[With --fetch\: comma-separated conclusions that constitute an answer; anything else is not recorded]:answered:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fetch[Read the commit'\''s check-runs from the forge instead of \`<check> <conclusion>\` lines on stdin]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':ref -- The ref or sha the verdict was taken against:_default' \
&& ret=0
;;
(validate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':id -- The `\[\[rule.tools\]\]` id whose argv runs and whose verdict is recorded:_default' \
&& ret=0
;;
(named)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The record family, which is the key a module reads it under:_default' \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
'*--input=[A \`<key>=<value>\` input this family needs beyond stdin (repeatable)]:input:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The record family, which selects the reading and is the key a module reads it under:_default' \
&& ret=0
;;
(keyed)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The store family the record belongs to:_default' \
':key -- The key the record is filed under:_default' \
&& ret=0
;;
(journal)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The store family the record belongs to:_default' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The store family to read:_default' \
':key -- The key to look under:_default' \
&& ret=0
;;
(fold)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The store family to fold:_default' \
&& ret=0
;;
(plan)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(query)
_arguments "${_arguments_options[@]}" : \
'*--input=[A \`<name>=<value>\` binding for one of the query'\''s own placeholders (repeatable)]:input:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':id -- The `\[\[forge.query\]\]` id, which is also the record family written:_default' \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
'*--input=[A \`<key>=<value>\` input this family needs beyond stdin (repeatable)]:input:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The record family, which selects the reading and is the key a module reads it under:_default' \
'*::command -- The probe command, after `--`\: its exit status is the `status` input and its output the document:_default' \
&& ret=0
;;
(decide)
_arguments "${_arguments_options[@]}" : \
'*--input=[A \`<key>=<value>\` input this family needs beyond stdin (repeatable)]:input:_default' \
'*--rule=[The declared rule that decides over the record just written (repeatable, at least one)]:rule:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':family -- The record family, which selects the reading and is the key a module reads it under:_default' \
&& ret=0
;;
(divergence)
_arguments "${_arguments_options[@]}" : \
'--ci-workflow=[The workflow file whose runs are the graded CI runs (default\: \$LAND_CI_WORKFLOW)]:ci_workflow:_default' \
'--land-workflow=[The workflow file whose runs are the landing bot'\''s answers (default\: \$LAND_WORKFLOW)]:land_workflow:_default' \
'--since=[The window'\''s start, ISO-8601 (default\: 24 hours before now)]:since:_default' \
'--max-pages=[Pages of runs to read per workflow before the window reads as truncated (default\: 10)]:max_pages:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(nonverdict)
_arguments "${_arguments_options[@]}" : \
'--window=[How many recent failed runs to read, 1 to 100 (default\: 30)]:window:_default' \
'*--required-check=[A required job, by exact name; only these are counted (repeatable; default\: \$CI_REQUIRED_CHECKS)]:required_check:_default' \
'*--exclude-job=[A job never counted, such as a fan-in whose failure its siblings cause (repeatable; default\: \$CI_FANIN_CHECK)]:exclude_job:_default' \
'*--verdict-step=[A step-name prefix that marks a failed step as verdict-bearing (repeatable; default\: \$CI_VERDICT_STEPS)]:verdict_step:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(attestation)
_arguments "${_arguments_options[@]}" : \
'--binary=[The binary'\''s file name inside each archive (a \`.exe\` suffix also matches)]:binary:_default' \
'--verifier=[The program that downloads the release and verifies each binary (default\: gh)]:verifier:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::tag -- The release tag to judge; absent is the latest release:_default' \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__record__subcmd__census_commands" \
"*::: :->census" \
&& ret=0

    case $state in
    (census)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-census-command-$line[1]:"
        case $line[1] in
            (note)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':kind -- h for a landing'\''s beat, x for a deliberate stop:_default' \
'::reason -- Why the loop stopped, one word, recorded beside an x:_default' \
&& ret=0
;;
(record-boot)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(report)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--once[Report once per boot\: record that this boot'\''s verdict was read, and stay silent after]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(tally)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__record__subcmd__census__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-census-help-command-$line[1]:"
        case $line[1] in
            (note)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record-boot)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(report)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tally)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(release)
_arguments "${_arguments_options[@]}" : \
'--manifest=[The checksum manifest'\''s file name, as the release carries it]:manifest:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'::tag -- The release'\''s tag; empty or absent is the latest release:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__record__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-help-command-$line[1]:"
        case $line[1] in
            (suites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tool)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(validate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(named)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keyed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(journal)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fold)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(plan)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(query)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decide)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(divergence)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(nonverdict)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(attestation)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__record__subcmd__help__subcmd__census_commands" \
"*::: :->census" \
&& ret=0

    case $state in
    (census)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-help-census-command-$line[1]:"
        case $line[1] in
            (note)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record-boot)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(report)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tally)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(show)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__show_commands" \
"*::: :->show" \
&& ret=0

    case $state in
    (show)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-show-command-$line[1]:"
        case $line[1] in
            (agent)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__show__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-show-help-command-$line[1]:"
        case $line[1] in
            (agent)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(wiring)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__wiring_commands" \
"*::: :->wiring" \
&& ret=0

    case $state in
    (wiring)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-wiring-command-$line[1]:"
        case $line[1] in
            (reclaim)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-n[Preview what would be applied, writing nothing]' \
'--dry-run[Preview what would be applied, writing nothing]' \
'--check[Exit non-zero if a repair is owed, and remove nothing]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':body -- The hook body to link, relative to the repository root:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__wiring__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-wiring-help-command-$line[1]:"
        case $line[1] in
            (reclaim)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(lease)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__lease_commands" \
"*::: :->lease" \
&& ret=0

    case $state in
    (lease)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-lease-command-$line[1]:"
        case $line[1] in
            (authorises)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':branch -- The branch being asked about:_default' \
&& ret=0
;;
(carries)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':head -- The head commit being judged:_default' \
&& ret=0
;;
(guard)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':head -- The head commit being judged:_default' \
':branch -- The branch being asked about:_default' \
':run -- The run to cancel on a stop:_default' \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(peek)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':field -- Which advisory field to print\: branch, head or next:_default' \
&& ret=0
;;
(held)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(acquire)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':branch -- The branch being asked about:_default' \
&& ret=0
;;
(renew)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(hold)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(reserve)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':branch -- The branch being asked about:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__lease__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-lease-help-command-$line[1]:"
        case $line[1] in
            (authorises)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(carries)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(guard)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(peek)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(held)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(acquire)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(renew)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hold)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reserve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(land)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__land_commands" \
"*::: :->land" \
&& ret=0

    case $state in
    (land)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-land-command-$line[1]:"
        case $line[1] in
            (replay)
_arguments "${_arguments_options[@]}" : \
'*--resolve=[A path whose conflict is resolved in the worktree (repeatable)]:resolve:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':reference -- The remote reference to replay onto:_default' \
&& ret=0
;;
(wait)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':reference -- The remote reference to replay onto:_default' \
&& ret=0
;;
(push)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(fast-forward)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(lap)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':reference -- The remote reference to replay onto:_default' \
&& ret=0
;;
(linear)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':reference -- The remote reference to replay onto:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__land__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-land-help-command-$line[1]:"
        case $line[1] in
            (replay)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(wait)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(push)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fast-forward)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lap)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(linear)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(step)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__step_commands" \
"*::: :->step" \
&& ret=0

    case $state in
    (step)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-step-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'*--arg=[A value the step'\''s verdict depends on beyond its inputs, keyed in order (repeatable)]:arg:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':step -- The step'\''s name, as the consumer'\''s step table declares it:_default' \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
'*--arg=[A value the step'\''s verdict depends on beyond its inputs, keyed in order (repeatable)]:arg:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':step -- The step'\''s name, as the consumer'\''s step table declares it:_default' \
&& ret=0
;;
(run)
_arguments "${_arguments_options[@]}" : \
'*--arg=[A value the step'\''s verdict depends on beyond its inputs, keyed in order (repeatable)]:arg:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':step -- The step'\''s name, as the consumer'\''s step table declares it:_default' \
'*::command -- The step'\''s command, after `--`\: run only on a miss, recorded only when it exits 0:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__step__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-step-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(run)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(sbom)
_arguments "${_arguments_options[@]}" : \
'--binary=[Inventory this built binary from its own bytes instead of the tree]:binary:_default' \
'--target=[The target triple the binary was built for, which names its asset]:target:_default' \
'--out-dir=[Write the documents under this directory instead of the declared one]:out_dir:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--names[Print the asset names as KEY=VALUE lines and exit, without scanning]' \
'--record[Derive the tree'\''s documents twice into scratch and record their counts under the declared tool row]' \
'--conformance[Derive the SPDX document into scratch and record the declared checker'\''s exit code per standard]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(dist)
_arguments "${_arguments_options[@]}" : \
'--build-tool=[How to build for the target\: cargo, cross or zigbuild (default\: \$DIST_BUILD_TOOL, else cargo)]:build_tool:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--stem[Print the target'\''s asset stem and exit, without building]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':target -- The target triple to build, which must already be installed:_default' \
&& ret=0
;;
(board)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__board_commands" \
"*::: :->board" \
&& ret=0

    case $state in
    (board)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-board-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
'*--issue=[Read this issue'\''s payload from the capture store rather than stdin (repeatable)]:issue:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--cites[Judge each payload'\''s Ready-block citations against the tree instead of the graph]' \
'--refs[Judge the tree'\''s clause citations against the payloads instead of the graph]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(sweep)
_arguments "${_arguments_options[@]}" : \
'*--issue=[Read this issue'\''s payload from the capture store rather than stdin (repeatable)]:issue:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__board__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-board-help-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sweep)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(census)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__census_commands" \
"*::: :->census" \
&& ret=0

    case $state in
    (census)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-census-command-$line[1]:"
        case $line[1] in
            (shell)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'-J[Emit byte-stable JSON instead of pointer lines]' \
'--json[Emit byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__census__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-census-help-command-$line[1]:"
        case $line[1] in
            (shell)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(artifacts)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_batten__subcmd__artifacts_commands" \
"*::: :->artifacts" \
&& ret=0

    case $state in
    (artifacts)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-artifacts-command-$line[1]:"
        case $line[1] in
            (write)
_arguments "${_arguments_options[@]}" : \
'--completions=[Write the bash, zsh and fish completion scripts into this directory]:completions:_default' \
'--man=[Write one man page per command into this directory, removing stale pages]:man:_default' \
'--schema=[Write the config and policy-input JSON Schemas into this directory]:schema:_default' \
'--reference=[Write the markdown CLI reference to this file]:reference:_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]:config_from:_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]:config_in:_default' \
'--log-level=[Set the verbosity rung by name]: :((silent\:"Say nothing but a verdict or a usage error"
quiet\:"Suppress ordinary progress; keep warnings"
normal\:"The default"
verbose\:"Explain what is being checked"
debug\:"Add resolution detail"
trace\:"Add everything"))' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'*--silent[Say nothing but a verdict or a usage error]' \
'*-q[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*--quiet[Suppress ordinary progress (repeatable\: -qq is silent)]' \
'*-v[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--verbose[Explain what is being checked (repeatable\: -vv is debug)]' \
'*--debug[Add resolution detail]' \
'*--trace[Add everything]' \
'--no-color[Never colour stderr, whatever it is attached to]' \
'--no-input[Never prompt; treat the run as unattended]' \
'-y[Confirm a destructive operation that would otherwise refuse]' \
'--yes[Confirm a destructive operation that would otherwise refuse]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__artifacts__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-artifacts-help-command-$line[1]:"
        case $line[1] in
            (write)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-command-$line[1]:"
        case $line[1] in
            (bench)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__bench_commands" \
"*::: :->bench" \
&& ret=0

    case $state in
    (bench)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-bench-command-$line[1]:"
        case $line[1] in
            (tokens)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enforce)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(exec)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(capture)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__capture_commands" \
"*::: :->capture" \
&& ret=0

    case $state in
    (capture)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-capture-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(find)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(prune)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(mcp)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__mcp_commands" \
"*::: :->mcp" \
&& ret=0

    case $state in
    (mcp)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-mcp-command-$line[1]:"
        case $line[1] in
            (call)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(spawn)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(grant)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(posture)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(target)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__target_commands" \
"*::: :->target" \
&& ret=0

    case $state in
    (target)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-target-command-$line[1]:"
        case $line[1] in
            (prune)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(ci)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__ci_commands" \
"*::: :->ci" \
&& ret=0

    case $state in
    (ci)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-ci-command-$line[1]:"
        case $line[1] in
            (slow-needed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(suites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(release)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__release_commands" \
"*::: :->release" \
&& ret=0

    case $state in
    (release)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-release-command-$line[1]:"
        case $line[1] in
            (install)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sums)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(backfill)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(config)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__config_commands" \
"*::: :->config" \
&& ret=0

    case $state in
    (config)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-config-command-$line[1]:"
        case $line[1] in
            (show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(epoch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(deprecations)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lint)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(lint)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__lint_commands" \
"*::: :->lint" \
&& ret=0

    case $state in
    (lint)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-lint-command-$line[1]:"
        case $line[1] in
            (brief)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(spec)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(doctor)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__doctor_commands" \
"*::: :->doctor" \
&& ret=0

    case $state in
    (doctor)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-doctor-command-$line[1]:"
        case $line[1] in
            (target)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(mediator)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(egress)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(toolchain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(session)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(init)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(baseline)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(generate)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__generate_commands" \
"*::: :->generate" \
&& ret=0

    case $state in
    (generate)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-generate-command-$line[1]:"
        case $line[1] in
            (completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(man)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(markdown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(schema)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(perf)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__perf_commands" \
"*::: :->perf" \
&& ret=0

    case $state in
    (perf)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-perf-command-$line[1]:"
        case $line[1] in
            (pair)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(measure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(compare)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(mutate)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__mutate_commands" \
"*::: :->mutate" \
&& ret=0

    case $state in
    (mutate)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-mutate-command-$line[1]:"
        case $line[1] in
            (sweep)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(policy)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__policy_commands" \
"*::: :->policy" \
&& ret=0

    case $state in
    (policy)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-policy-command-$line[1]:"
        case $line[1] in
            (budget)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hooks)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(test)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tools)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(explain)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rule)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(verdict)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(commit)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__commit_commands" \
"*::: :->commit" \
&& ret=0

    case $state in
    (commit)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-commit-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(ready)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__ready_commands" \
"*::: :->ready" \
&& ret=0

    case $state in
    (ready)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-ready-command-$line[1]:"
        case $line[1] in
            (lint)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(landed)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__landed_commands" \
"*::: :->landed" \
&& ret=0

    case $state in
    (landed)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-landed-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(abandoned)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(hk)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__hk_commands" \
"*::: :->hk" \
&& ret=0

    case $state in
    (hk)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-hk-command-$line[1]:"
        case $line[1] in
            (contract)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(observe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(drift)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(checks)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__checks_commands" \
"*::: :->checks" \
&& ret=0

    case $state in
    (checks)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-checks-command-$line[1]:"
        case $line[1] in
            (green)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(pr)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__pr_commands" \
"*::: :->pr" \
&& ret=0

    case $state in
    (pr)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-pr-command-$line[1]:"
        case $line[1] in
            (watch)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(file)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(link)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(ensure)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unsubscribed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(task)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__task_commands" \
"*::: :->task" \
&& ret=0

    case $state in
    (task)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-task-command-$line[1]:"
        case $line[1] in
            (register)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(phase)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tick)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sig)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(unregister)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(read)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(alive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(singleton)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__singleton_commands" \
"*::: :->singleton" \
&& ret=0

    case $state in
    (singleton)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-singleton-command-$line[1]:"
        case $line[1] in
            (acquire)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(detach)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(claim)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__claim_commands" \
"*::: :->claim" \
&& ret=0

    case $state in
    (claim)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-claim-command-$line[1]:"
        case $line[1] in
            (merged)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keys)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(bot)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(race)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(carry)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(semver)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__semver_commands" \
"*::: :->semver" \
&& ret=0

    case $state in
    (semver)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-semver-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(attribution)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__attribution_commands" \
"*::: :->attribution" \
&& ret=0

    case $state in
    (attribution)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-attribution-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tagger)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(identity)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(signing)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(worktree)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__worktree_commands" \
"*::: :->worktree" \
&& ret=0

    case $state in
    (worktree)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-worktree-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(override)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__override_commands" \
"*::: :->override" \
&& ret=0

    case $state in
    (override)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-override-command-$line[1]:"
        case $line[1] in
            (request)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(spend)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(provision)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__provision_commands" \
"*::: :->provision" \
&& ret=0

    case $state in
    (provision)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-provision-command-$line[1]:"
        case $line[1] in
            (status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(apply)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(startup)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(adjudicate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(payload)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__payload_commands" \
"*::: :->payload" \
&& ret=0

    case $state in
    (payload)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-payload-command-$line[1]:"
        case $line[1] in
            (field)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__receipt_commands" \
"*::: :->receipt" \
&& ret=0

    case $state in
    (receipt)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-receipt-command-$line[1]:"
        case $line[1] in
            (clean)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verified)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(defects)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__defects_commands" \
"*::: :->defects" \
&& ret=0

    case $state in
    (defects)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-defects-command-$line[1]:"
        case $line[1] in
            (query)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(design)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__design_commands" \
"*::: :->design" \
&& ret=0

    case $state in
    (design)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-design-command-$line[1]:"
        case $line[1] in
            (audit)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(state)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__state_commands" \
"*::: :->state" \
&& ret=0

    case $state in
    (state)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-state-command-$line[1]:"
        case $line[1] in
            (adopt)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(migrate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(settle)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(record)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__record_commands" \
"*::: :->record" \
&& ret=0

    case $state in
    (record)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-record-command-$line[1]:"
        case $line[1] in
            (suites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tool)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(validate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(named)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(derive)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keyed)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(journal)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fold)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(plan)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(closes)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(query)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(probe)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(decide)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(divergence)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(nonverdict)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(attestation)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(census)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__record__subcmd__census_commands" \
"*::: :->census" \
&& ret=0

    case $state in
    (census)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-record-census-command-$line[1]:"
        case $line[1] in
            (note)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record-boot)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(report)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tally)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(show)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__show_commands" \
"*::: :->show" \
&& ret=0

    case $state in
    (show)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-show-command-$line[1]:"
        case $line[1] in
            (agent)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(wiring)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__wiring_commands" \
"*::: :->wiring" \
&& ret=0

    case $state in
    (wiring)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-wiring-command-$line[1]:"
        case $line[1] in
            (reclaim)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(gate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(lease)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__lease_commands" \
"*::: :->lease" \
&& ret=0

    case $state in
    (lease)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-lease-command-$line[1]:"
        case $line[1] in
            (authorises)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(carries)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(guard)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(peek)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(held)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(acquire)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(renew)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(hold)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(release)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reserve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(land)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__land_commands" \
"*::: :->land" \
&& ret=0

    case $state in
    (land)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-land-command-$line[1]:"
        case $line[1] in
            (replay)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(wait)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(push)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(fast-forward)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(lap)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(linear)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(step)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__step_commands" \
"*::: :->step" \
&& ret=0

    case $state in
    (step)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-step-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(run)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(sbom)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(dist)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(board)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__board_commands" \
"*::: :->board" \
&& ret=0

    case $state in
    (board)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-board-command-$line[1]:"
        case $line[1] in
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(sweep)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(census)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__census_commands" \
"*::: :->census" \
&& ret=0

    case $state in
    (census)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-census-command-$line[1]:"
        case $line[1] in
            (shell)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(artifacts)
_arguments "${_arguments_options[@]}" : \
":: :_batten__subcmd__help__subcmd__artifacts_commands" \
"*::: :->artifacts" \
&& ret=0

    case $state in
    (artifacts)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-help-artifacts-command-$line[1]:"
        case $line[1] in
            (write)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_batten_commands] )) ||
_batten_commands() {
    local commands; commands=(
'bench:Measure what a capability costs an agent'\''s context' \
'check:Run the applicable read-only gates against the repository' \
'enforce:Run every configured rule, including kinds that execute a configured command' \
'exec:Run a command — or a \`\:\:\:\` bundle — and report a pointer to what it wrote' \
'capture:Captured command output\: navigate what \`exec\` already ran, without running it again' \
'mcp:Dispatch a declared MCP call and hand back a reduction instead of the payload' \
'target:Inspect and reclaim this repository'\''s build tree' \
'ci:Answer what this repository'\''s continuous integration needs of a change' \
'release:Answer whether a release is installable as it says it is, hash its assets, and backfill its tracking' \
'config:Inspect configuration' \
'lint:Lint an artifact against a declared schema' \
'spec:Print the tool'\''s own command spec' \
'doctor:Diagnose whether Batten can run in this repository' \
'init:Write a starter batten.toml, refusing to overwrite an existing one' \
'baseline:Record the findings that already exist, so only new ones fail' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'perf:Measure this repository'\''s own invocation cost' \
'mutate:Decide whether this repository'\''s gates discriminate, rather than merely parse' \
'policy:Inspect the thresholds and path sets this repository holds itself to' \
'verdict:Fold a run'\''s findings and blind spots into this tool'\''s exit code' \
'commit:The shape a commit must take here\: what its subject may say' \
'ready:Whether an issue'\''s Ready block satisfies the checkable clauses of the gate' \
'landed:Whether a board column is honest about what git and the forge already did' \
'hk:The adopted gate runner'\''s surface contract' \
'checks:Whether a commit'\''s check runs answer the question a landing depends on' \
'pr:The pull request a landing drives, and the answers it waits on' \
'task:What long-running tasks are doing, recorded where it can be read without a log' \
'singleton:Whether a second copy of a task may start in this clone' \
'claim:Whether the issue you are about to pull is actually unclaimed' \
'semver:Whether this branch'\''s API delta is compatible with the bump it claims' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'override:Issued admissions\: an override is a record, never a variable somebody knows' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'startup:Report whether this container matches what the repository declares' \
'adjudicate:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'record:Out-of-tree verdict stores\: what something else judged, keyed so a stale answer cannot answer' \
'show:Report what something is, without changing it' \
'wiring:Repair a host'\''s hook registrations' \
'lease:The landing lease\: one branch spends a matrix at a time' \
'land:The landing lap\: replay this branch onto a base that moved' \
'step:Answer a step from its receipt when its exact inputs, arguments and tools already passed' \
'sbom:Derive the SPDX and CycloneDX inventories of this tree, or of a built binary, under the names its release assets carry' \
'dist:Build the release binary for a target and stage its archive, printing KEY=VALUE pointers to both' \
'board:Whether the board'\''s columns and graph tell the truth about the work' \
'census:Count what this repository declares it is retiring, as pointers' \
'artifacts:Write the committed derivations of the command surface' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten commands' commands "$@"
}
(( $+functions[_batten__subcmd__adjudicate_commands] )) ||
_batten__subcmd__adjudicate_commands() {
    local commands; commands=()
    _describe -t commands 'batten adjudicate commands' commands "$@"
}
(( $+functions[_batten__subcmd__artifacts_commands] )) ||
_batten__subcmd__artifacts_commands() {
    local commands; commands=(
'write:Write completions, man pages, schemas or the CLI reference where the caller names' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten artifacts commands' commands "$@"
}
(( $+functions[_batten__subcmd__artifacts__subcmd__help_commands] )) ||
_batten__subcmd__artifacts__subcmd__help_commands() {
    local commands; commands=(
'write:Write completions, man pages, schemas or the CLI reference where the caller names' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten artifacts help commands' commands "$@"
}
(( $+functions[_batten__subcmd__artifacts__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__artifacts__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten artifacts help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__artifacts__subcmd__help__subcmd__write_commands] )) ||
_batten__subcmd__artifacts__subcmd__help__subcmd__write_commands() {
    local commands; commands=()
    _describe -t commands 'batten artifacts help write commands' commands "$@"
}
(( $+functions[_batten__subcmd__artifacts__subcmd__write_commands] )) ||
_batten__subcmd__artifacts__subcmd__write_commands() {
    local commands; commands=()
    _describe -t commands 'batten artifacts write commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution_commands] )) ||
_batten__subcmd__attribution_commands() {
    local commands; commands=(
'check:Refuse vendor authorship, branding or session links in commit metadata' \
'tagger:Refuse a tag cut by an identity this repository is not accountable to' \
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
'signing:Switch signing off in this clone when its signer cannot be verified or reproduced' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten attribution commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__check_commands] )) ||
_batten__subcmd__attribution__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution check commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help_commands] )) ||
_batten__subcmd__attribution__subcmd__help_commands() {
    local commands; commands=(
'check:Refuse vendor authorship, branding or session links in commit metadata' \
'tagger:Refuse a tag cut by an identity this repository is not accountable to' \
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
'signing:Switch signing off in this clone when its signer cannot be verified or reproduced' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten attribution help commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__attribution__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__attribution__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help__subcmd__identity_commands] )) ||
_batten__subcmd__attribution__subcmd__help__subcmd__identity_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution help identity commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help__subcmd__signing_commands] )) ||
_batten__subcmd__attribution__subcmd__help__subcmd__signing_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution help signing commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__help__subcmd__tagger_commands] )) ||
_batten__subcmd__attribution__subcmd__help__subcmd__tagger_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution help tagger commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__identity_commands] )) ||
_batten__subcmd__attribution__subcmd__identity_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution identity commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__signing_commands] )) ||
_batten__subcmd__attribution__subcmd__signing_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution signing commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution__subcmd__tagger_commands] )) ||
_batten__subcmd__attribution__subcmd__tagger_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution tagger commands' commands "$@"
}
(( $+functions[_batten__subcmd__baseline_commands] )) ||
_batten__subcmd__baseline_commands() {
    local commands; commands=()
    _describe -t commands 'batten baseline commands' commands "$@"
}
(( $+functions[_batten__subcmd__bench_commands] )) ||
_batten__subcmd__bench_commands() {
    local commands; commands=(
'tokens:Measure the token economics of the Batten-wrapped path against the raw tool, from committed fixtures' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten bench commands' commands "$@"
}
(( $+functions[_batten__subcmd__bench__subcmd__help_commands] )) ||
_batten__subcmd__bench__subcmd__help_commands() {
    local commands; commands=(
'tokens:Measure the token economics of the Batten-wrapped path against the raw tool, from committed fixtures' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten bench help commands' commands "$@"
}
(( $+functions[_batten__subcmd__bench__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__bench__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten bench help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__bench__subcmd__help__subcmd__tokens_commands] )) ||
_batten__subcmd__bench__subcmd__help__subcmd__tokens_commands() {
    local commands; commands=()
    _describe -t commands 'batten bench help tokens commands' commands "$@"
}
(( $+functions[_batten__subcmd__bench__subcmd__tokens_commands] )) ||
_batten__subcmd__bench__subcmd__tokens_commands() {
    local commands; commands=()
    _describe -t commands 'batten bench tokens commands' commands "$@"
}
(( $+functions[_batten__subcmd__board_commands] )) ||
_batten__subcmd__board_commands() {
    local commands; commands=(
'check:Refuse a board whose columns, graph or citations lie, and print the ready frontier' \
'sweep:Run every declared board gate over one payload set and report the set of refusals' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten board commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__check_commands] )) ||
_batten__subcmd__board__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten board check commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__help_commands] )) ||
_batten__subcmd__board__subcmd__help_commands() {
    local commands; commands=(
'check:Refuse a board whose columns, graph or citations lie, and print the ready frontier' \
'sweep:Run every declared board gate over one payload set and report the set of refusals' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten board help commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__board__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten board help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__board__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten board help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__help__subcmd__sweep_commands] )) ||
_batten__subcmd__board__subcmd__help__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten board help sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__board__subcmd__sweep_commands] )) ||
_batten__subcmd__board__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten board sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture_commands] )) ||
_batten__subcmd__capture_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'find:Resolve a stored tool response by the key it carries, with no handle to look up first' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten capture commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__find_commands] )) ||
_batten__subcmd__capture__subcmd__find_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture find commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help_commands] )) ||
_batten__subcmd__capture__subcmd__help_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'find:Resolve a stored tool response by the key it carries, with no handle to look up first' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten capture help commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help__subcmd__find_commands] )) ||
_batten__subcmd__capture__subcmd__help__subcmd__find_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture help find commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__capture__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help__subcmd__list_commands] )) ||
_batten__subcmd__capture__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture help list commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help__subcmd__prune_commands] )) ||
_batten__subcmd__capture__subcmd__help__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture help prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help__subcmd__show_commands] )) ||
_batten__subcmd__capture__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture help show commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__list_commands] )) ||
_batten__subcmd__capture__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture list commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__prune_commands] )) ||
_batten__subcmd__capture__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__show_commands] )) ||
_batten__subcmd__capture__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten capture show commands' commands "$@"
}
(( $+functions[_batten__subcmd__census_commands] )) ||
_batten__subcmd__census_commands() {
    local commands; commands=(
'shell:Count every shell line in the declared manifests, workflows and shell files, as pointers' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten census commands' commands "$@"
}
(( $+functions[_batten__subcmd__census__subcmd__help_commands] )) ||
_batten__subcmd__census__subcmd__help_commands() {
    local commands; commands=(
'shell:Count every shell line in the declared manifests, workflows and shell files, as pointers' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten census help commands' commands "$@"
}
(( $+functions[_batten__subcmd__census__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__census__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten census help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__census__subcmd__help__subcmd__shell_commands] )) ||
_batten__subcmd__census__subcmd__help__subcmd__shell_commands() {
    local commands; commands=()
    _describe -t commands 'batten census help shell commands' commands "$@"
}
(( $+functions[_batten__subcmd__census__subcmd__shell_commands] )) ||
_batten__subcmd__census__subcmd__shell_commands() {
    local commands; commands=()
    _describe -t commands 'batten census shell commands' commands "$@"
}
(( $+functions[_batten__subcmd__check_commands] )) ||
_batten__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten check commands' commands "$@"
}
(( $+functions[_batten__subcmd__checks_commands] )) ||
_batten__subcmd__checks_commands() {
    local commands; commands=(
'green:Refuse a head whose required checks are red, still running, or not yet registered' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten checks commands' commands "$@"
}
(( $+functions[_batten__subcmd__checks__subcmd__green_commands] )) ||
_batten__subcmd__checks__subcmd__green_commands() {
    local commands; commands=()
    _describe -t commands 'batten checks green commands' commands "$@"
}
(( $+functions[_batten__subcmd__checks__subcmd__help_commands] )) ||
_batten__subcmd__checks__subcmd__help_commands() {
    local commands; commands=(
'green:Refuse a head whose required checks are red, still running, or not yet registered' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten checks help commands' commands "$@"
}
(( $+functions[_batten__subcmd__checks__subcmd__help__subcmd__green_commands] )) ||
_batten__subcmd__checks__subcmd__help__subcmd__green_commands() {
    local commands; commands=()
    _describe -t commands 'batten checks help green commands' commands "$@"
}
(( $+functions[_batten__subcmd__checks__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__checks__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten checks help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci_commands] )) ||
_batten__subcmd__ci_commands() {
    local commands; commands=(
'slow-needed:Decide whether a diff can move the slow tier, so a diff that cannot does not pay for it' \
'suites:Name the bats suites a diff can move, or every suite where it cannot prove one inert' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten ci commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__help_commands] )) ||
_batten__subcmd__ci__subcmd__help_commands() {
    local commands; commands=(
'slow-needed:Decide whether a diff can move the slow tier, so a diff that cannot does not pay for it' \
'suites:Name the bats suites a diff can move, or every suite where it cannot prove one inert' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten ci help commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__ci__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten ci help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__help__subcmd__slow-needed_commands] )) ||
_batten__subcmd__ci__subcmd__help__subcmd__slow-needed_commands() {
    local commands; commands=()
    _describe -t commands 'batten ci help slow-needed commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__help__subcmd__suites_commands] )) ||
_batten__subcmd__ci__subcmd__help__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten ci help suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__slow-needed_commands] )) ||
_batten__subcmd__ci__subcmd__slow-needed_commands() {
    local commands; commands=()
    _describe -t commands 'batten ci slow-needed commands' commands "$@"
}
(( $+functions[_batten__subcmd__ci__subcmd__suites_commands] )) ||
_batten__subcmd__ci__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten ci suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim_commands] )) ||
_batten__subcmd__claim_commands() {
    local commands; commands=(
'merged:The keys merged pull request bodies close, as \`<key>\\t<number>\` rows' \
'keys:The issue keys this branch CLAIMS, as distinct from the ones it merely mentions' \
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
'race:Refuse a claim a different open pull request already carries, judged by head SHA' \
'carry:Attest that this branch only carries licence rows forward, and mint the receipt when it does' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten claim commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__bot_commands] )) ||
_batten__subcmd__claim__subcmd__bot_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim bot commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__carry_commands] )) ||
_batten__subcmd__claim__subcmd__carry_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim carry commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__check_commands] )) ||
_batten__subcmd__claim__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim check commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help_commands] )) ||
_batten__subcmd__claim__subcmd__help_commands() {
    local commands; commands=(
'merged:The keys merged pull request bodies close, as \`<key>\\t<number>\` rows' \
'keys:The issue keys this branch CLAIMS, as distinct from the ones it merely mentions' \
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
'race:Refuse a claim a different open pull request already carries, judged by head SHA' \
'carry:Attest that this branch only carries licence rows forward, and mint the receipt when it does' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten claim help commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__bot_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__bot_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help bot commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__carry_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__carry_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help carry commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__keys_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__keys_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help keys commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__merged_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__merged_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help merged commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__help__subcmd__race_commands] )) ||
_batten__subcmd__claim__subcmd__help__subcmd__race_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim help race commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__keys_commands] )) ||
_batten__subcmd__claim__subcmd__keys_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim keys commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__merged_commands] )) ||
_batten__subcmd__claim__subcmd__merged_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim merged commands' commands "$@"
}
(( $+functions[_batten__subcmd__claim__subcmd__race_commands] )) ||
_batten__subcmd__claim__subcmd__race_commands() {
    local commands; commands=()
    _describe -t commands 'batten claim race commands' commands "$@"
}
(( $+functions[_batten__subcmd__commit_commands] )) ||
_batten__subcmd__commit_commands() {
    local commands; commands=(
'check:Refuse a commit subject that does not follow the configured convention' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten commit commands' commands "$@"
}
(( $+functions[_batten__subcmd__commit__subcmd__check_commands] )) ||
_batten__subcmd__commit__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten commit check commands' commands "$@"
}
(( $+functions[_batten__subcmd__commit__subcmd__help_commands] )) ||
_batten__subcmd__commit__subcmd__help_commands() {
    local commands; commands=(
'check:Refuse a commit subject that does not follow the configured convention' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten commit help commands' commands "$@"
}
(( $+functions[_batten__subcmd__commit__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__commit__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten commit help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__commit__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__commit__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten commit help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__config_commands] )) ||
_batten__subcmd__config_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'epoch:Print the content hash of the governing config surface' \
'deprecations:Report schema keys removed since a published release with no deprecation window' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__deprecations_commands] )) ||
_batten__subcmd__config__subcmd__deprecations_commands() {
    local commands; commands=()
    _describe -t commands 'batten config deprecations commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__epoch_commands] )) ||
_batten__subcmd__config__subcmd__epoch_commands() {
    local commands; commands=()
    _describe -t commands 'batten config epoch commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help_commands] )) ||
_batten__subcmd__config__subcmd__help_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'epoch:Print the content hash of the governing config surface' \
'deprecations:Report schema keys removed since a published release with no deprecation window' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config help commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help__subcmd__deprecations_commands] )) ||
_batten__subcmd__config__subcmd__help__subcmd__deprecations_commands() {
    local commands; commands=()
    _describe -t commands 'batten config help deprecations commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help__subcmd__epoch_commands] )) ||
_batten__subcmd__config__subcmd__help__subcmd__epoch_commands() {
    local commands; commands=()
    _describe -t commands 'batten config help epoch commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__config__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten config help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help__subcmd__lint_commands] )) ||
_batten__subcmd__config__subcmd__help__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten config help lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help__subcmd__show_commands] )) ||
_batten__subcmd__config__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten config help show commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__lint_commands] )) ||
_batten__subcmd__config__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten config lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__show_commands] )) ||
_batten__subcmd__config__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten config show commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects_commands] )) ||
_batten__subcmd__defects_commands() {
    local commands; commands=(
'query:List recorded defects, as pointers' \
'add:Append defect records read as JSONL on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten defects commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__add_commands] )) ||
_batten__subcmd__defects__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'batten defects add commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__help_commands] )) ||
_batten__subcmd__defects__subcmd__help_commands() {
    local commands; commands=(
'query:List recorded defects, as pointers' \
'add:Append defect records read as JSONL on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten defects help commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__help__subcmd__add_commands] )) ||
_batten__subcmd__defects__subcmd__help__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'batten defects help add commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__defects__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten defects help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__help__subcmd__query_commands] )) ||
_batten__subcmd__defects__subcmd__help__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten defects help query commands' commands "$@"
}
(( $+functions[_batten__subcmd__defects__subcmd__query_commands] )) ||
_batten__subcmd__defects__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten defects query commands' commands "$@"
}
(( $+functions[_batten__subcmd__design_commands] )) ||
_batten__subcmd__design_commands() {
    local commands; commands=(
'audit:Audit a JSONL design-evidence claim stream on stdin for record integrity' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten design commands' commands "$@"
}
(( $+functions[_batten__subcmd__design__subcmd__audit_commands] )) ||
_batten__subcmd__design__subcmd__audit_commands() {
    local commands; commands=()
    _describe -t commands 'batten design audit commands' commands "$@"
}
(( $+functions[_batten__subcmd__design__subcmd__help_commands] )) ||
_batten__subcmd__design__subcmd__help_commands() {
    local commands; commands=(
'audit:Audit a JSONL design-evidence claim stream on stdin for record integrity' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten design help commands' commands "$@"
}
(( $+functions[_batten__subcmd__design__subcmd__help__subcmd__audit_commands] )) ||
_batten__subcmd__design__subcmd__help__subcmd__audit_commands() {
    local commands; commands=()
    _describe -t commands 'batten design help audit commands' commands "$@"
}
(( $+functions[_batten__subcmd__design__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__design__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten design help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__dist_commands] )) ||
_batten__subcmd__dist_commands() {
    local commands; commands=()
    _describe -t commands 'batten dist commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor_commands] )) ||
_batten__subcmd__doctor_commands() {
    local commands; commands=(
'target:Make one rustup target installed, purging a half-installed one first, behind the toolchain'\''s own lock' \
'mediator:Diagnose whether the engine the registrations reach was built from this tree' \
'egress:Diagnose whether the agent proxy would carry this container'\''s requests' \
'forge:Diagnose whether the forge credential carries the claims this repository'\''s tasks declare' \
'gate:Diagnose whether this checkout'\''s commit path runs the gate' \
'toolchain:Diagnose whether every tool the manifest declares is installed' \
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
'session:Diagnose whether this session has declared work it has not finished' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten doctor commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__egress_commands] )) ||
_batten__subcmd__doctor__subcmd__egress_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor egress commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__forge_commands] )) ||
_batten__subcmd__doctor__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__gate_commands] )) ||
_batten__subcmd__doctor__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help_commands] )) ||
_batten__subcmd__doctor__subcmd__help_commands() {
    local commands; commands=(
'target:Make one rustup target installed, purging a half-installed one first, behind the toolchain'\''s own lock' \
'mediator:Diagnose whether the engine the registrations reach was built from this tree' \
'egress:Diagnose whether the agent proxy would carry this container'\''s requests' \
'forge:Diagnose whether the forge credential carries the claims this repository'\''s tasks declare' \
'gate:Diagnose whether this checkout'\''s commit path runs the gate' \
'toolchain:Diagnose whether every tool the manifest declares is installed' \
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
'session:Diagnose whether this session has declared work it has not finished' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten doctor help commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__egress_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__egress_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help egress commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__forge_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__gate_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__hooks_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__mediator_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__mediator_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help mediator commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__session_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__session_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help session commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__target_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__target_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help target commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help__subcmd__toolchain_commands] )) ||
_batten__subcmd__doctor__subcmd__help__subcmd__toolchain_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor help toolchain commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__hooks_commands] )) ||
_batten__subcmd__doctor__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__mediator_commands] )) ||
_batten__subcmd__doctor__subcmd__mediator_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor mediator commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__session_commands] )) ||
_batten__subcmd__doctor__subcmd__session_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor session commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__target_commands] )) ||
_batten__subcmd__doctor__subcmd__target_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor target commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__toolchain_commands] )) ||
_batten__subcmd__doctor__subcmd__toolchain_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor toolchain commands' commands "$@"
}
(( $+functions[_batten__subcmd__enforce_commands] )) ||
_batten__subcmd__enforce_commands() {
    local commands; commands=()
    _describe -t commands 'batten enforce commands' commands "$@"
}
(( $+functions[_batten__subcmd__exec_commands] )) ||
_batten__subcmd__exec_commands() {
    local commands; commands=()
    _describe -t commands 'batten exec commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate_commands] )) ||
_batten__subcmd__generate_commands() {
    local commands; commands=(
'completions:Emit the shell completion script for one shell' \
'hooks:Emit one harness'\''s hook registrations, on stdout' \
'man:Emit the roff man page for one command, on stdout' \
'markdown:Emit the whole command surface as one markdown reference, on stdout' \
'schema:Emit the JSON Schema for a config or policy-input surface, derived from the types that define it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten generate commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__completions_commands] )) ||
_batten__subcmd__generate__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate completions commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help_commands] )) ||
_batten__subcmd__generate__subcmd__help_commands() {
    local commands; commands=(
'completions:Emit the shell completion script for one shell' \
'hooks:Emit one harness'\''s hook registrations, on stdout' \
'man:Emit the roff man page for one command, on stdout' \
'markdown:Emit the whole command surface as one markdown reference, on stdout' \
'schema:Emit the JSON Schema for a config or policy-input surface, derived from the types that define it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten generate help commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__completions_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help completions commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__hooks_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__man_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__man_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help man commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__markdown_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__markdown_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help markdown commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__schema_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__schema_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help schema commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__hooks_commands] )) ||
_batten__subcmd__generate__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__man_commands] )) ||
_batten__subcmd__generate__subcmd__man_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate man commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__markdown_commands] )) ||
_batten__subcmd__generate__subcmd__markdown_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate markdown commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate__subcmd__schema_commands] )) ||
_batten__subcmd__generate__subcmd__schema_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate schema commands' commands "$@"
}
(( $+functions[_batten__subcmd__help_commands] )) ||
_batten__subcmd__help_commands() {
    local commands; commands=(
'bench:Measure what a capability costs an agent'\''s context' \
'check:Run the applicable read-only gates against the repository' \
'enforce:Run every configured rule, including kinds that execute a configured command' \
'exec:Run a command — or a \`\:\:\:\` bundle — and report a pointer to what it wrote' \
'capture:Captured command output\: navigate what \`exec\` already ran, without running it again' \
'mcp:Dispatch a declared MCP call and hand back a reduction instead of the payload' \
'target:Inspect and reclaim this repository'\''s build tree' \
'ci:Answer what this repository'\''s continuous integration needs of a change' \
'release:Answer whether a release is installable as it says it is, hash its assets, and backfill its tracking' \
'config:Inspect configuration' \
'lint:Lint an artifact against a declared schema' \
'spec:Print the tool'\''s own command spec' \
'doctor:Diagnose whether Batten can run in this repository' \
'init:Write a starter batten.toml, refusing to overwrite an existing one' \
'baseline:Record the findings that already exist, so only new ones fail' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'perf:Measure this repository'\''s own invocation cost' \
'mutate:Decide whether this repository'\''s gates discriminate, rather than merely parse' \
'policy:Inspect the thresholds and path sets this repository holds itself to' \
'verdict:Fold a run'\''s findings and blind spots into this tool'\''s exit code' \
'commit:The shape a commit must take here\: what its subject may say' \
'ready:Whether an issue'\''s Ready block satisfies the checkable clauses of the gate' \
'landed:Whether a board column is honest about what git and the forge already did' \
'hk:The adopted gate runner'\''s surface contract' \
'checks:Whether a commit'\''s check runs answer the question a landing depends on' \
'pr:The pull request a landing drives, and the answers it waits on' \
'task:What long-running tasks are doing, recorded where it can be read without a log' \
'singleton:Whether a second copy of a task may start in this clone' \
'claim:Whether the issue you are about to pull is actually unclaimed' \
'semver:Whether this branch'\''s API delta is compatible with the bump it claims' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'override:Issued admissions\: an override is a record, never a variable somebody knows' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'startup:Report whether this container matches what the repository declares' \
'adjudicate:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'record:Out-of-tree verdict stores\: what something else judged, keyed so a stale answer cannot answer' \
'show:Report what something is, without changing it' \
'wiring:Repair a host'\''s hook registrations' \
'lease:The landing lease\: one branch spends a matrix at a time' \
'land:The landing lap\: replay this branch onto a base that moved' \
'step:Answer a step from its receipt when its exact inputs, arguments and tools already passed' \
'sbom:Derive the SPDX and CycloneDX inventories of this tree, or of a built binary, under the names its release assets carry' \
'dist:Build the release binary for a target and stage its archive, printing KEY=VALUE pointers to both' \
'board:Whether the board'\''s columns and graph tell the truth about the work' \
'census:Count what this repository declares it is retiring, as pointers' \
'artifacts:Write the committed derivations of the command surface' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten help commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__adjudicate_commands] )) ||
_batten__subcmd__help__subcmd__adjudicate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help adjudicate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__artifacts_commands] )) ||
_batten__subcmd__help__subcmd__artifacts_commands() {
    local commands; commands=(
'write:Write completions, man pages, schemas or the CLI reference where the caller names' \
    )
    _describe -t commands 'batten help artifacts commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__artifacts__subcmd__write_commands] )) ||
_batten__subcmd__help__subcmd__artifacts__subcmd__write_commands() {
    local commands; commands=()
    _describe -t commands 'batten help artifacts write commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution_commands] )) ||
_batten__subcmd__help__subcmd__attribution_commands() {
    local commands; commands=(
'check:Refuse vendor authorship, branding or session links in commit metadata' \
'tagger:Refuse a tag cut by an identity this repository is not accountable to' \
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
'signing:Switch signing off in this clone when its signer cannot be verified or reproduced' \
    )
    _describe -t commands 'batten help attribution commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__attribution__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help attribution check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution__subcmd__identity_commands] )) ||
_batten__subcmd__help__subcmd__attribution__subcmd__identity_commands() {
    local commands; commands=()
    _describe -t commands 'batten help attribution identity commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution__subcmd__signing_commands] )) ||
_batten__subcmd__help__subcmd__attribution__subcmd__signing_commands() {
    local commands; commands=()
    _describe -t commands 'batten help attribution signing commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution__subcmd__tagger_commands] )) ||
_batten__subcmd__help__subcmd__attribution__subcmd__tagger_commands() {
    local commands; commands=()
    _describe -t commands 'batten help attribution tagger commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__baseline_commands] )) ||
_batten__subcmd__help__subcmd__baseline_commands() {
    local commands; commands=()
    _describe -t commands 'batten help baseline commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__bench_commands] )) ||
_batten__subcmd__help__subcmd__bench_commands() {
    local commands; commands=(
'tokens:Measure the token economics of the Batten-wrapped path against the raw tool, from committed fixtures' \
    )
    _describe -t commands 'batten help bench commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__bench__subcmd__tokens_commands] )) ||
_batten__subcmd__help__subcmd__bench__subcmd__tokens_commands() {
    local commands; commands=()
    _describe -t commands 'batten help bench tokens commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__board_commands] )) ||
_batten__subcmd__help__subcmd__board_commands() {
    local commands; commands=(
'check:Refuse a board whose columns, graph or citations lie, and print the ready frontier' \
'sweep:Run every declared board gate over one payload set and report the set of refusals' \
    )
    _describe -t commands 'batten help board commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__board__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__board__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help board check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__board__subcmd__sweep_commands] )) ||
_batten__subcmd__help__subcmd__board__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten help board sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture_commands] )) ||
_batten__subcmd__help__subcmd__capture_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'find:Resolve a stored tool response by the key it carries, with no handle to look up first' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
    )
    _describe -t commands 'batten help capture commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture__subcmd__find_commands] )) ||
_batten__subcmd__help__subcmd__capture__subcmd__find_commands() {
    local commands; commands=()
    _describe -t commands 'batten help capture find commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture__subcmd__list_commands] )) ||
_batten__subcmd__help__subcmd__capture__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten help capture list commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture__subcmd__prune_commands] )) ||
_batten__subcmd__help__subcmd__capture__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten help capture prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture__subcmd__show_commands] )) ||
_batten__subcmd__help__subcmd__capture__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten help capture show commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__census_commands] )) ||
_batten__subcmd__help__subcmd__census_commands() {
    local commands; commands=(
'shell:Count every shell line in the declared manifests, workflows and shell files, as pointers' \
    )
    _describe -t commands 'batten help census commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__census__subcmd__shell_commands] )) ||
_batten__subcmd__help__subcmd__census__subcmd__shell_commands() {
    local commands; commands=()
    _describe -t commands 'batten help census shell commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__checks_commands] )) ||
_batten__subcmd__help__subcmd__checks_commands() {
    local commands; commands=(
'green:Refuse a head whose required checks are red, still running, or not yet registered' \
    )
    _describe -t commands 'batten help checks commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__checks__subcmd__green_commands] )) ||
_batten__subcmd__help__subcmd__checks__subcmd__green_commands() {
    local commands; commands=()
    _describe -t commands 'batten help checks green commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__ci_commands] )) ||
_batten__subcmd__help__subcmd__ci_commands() {
    local commands; commands=(
'slow-needed:Decide whether a diff can move the slow tier, so a diff that cannot does not pay for it' \
'suites:Name the bats suites a diff can move, or every suite where it cannot prove one inert' \
    )
    _describe -t commands 'batten help ci commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__ci__subcmd__slow-needed_commands] )) ||
_batten__subcmd__help__subcmd__ci__subcmd__slow-needed_commands() {
    local commands; commands=()
    _describe -t commands 'batten help ci slow-needed commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__ci__subcmd__suites_commands] )) ||
_batten__subcmd__help__subcmd__ci__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten help ci suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim_commands] )) ||
_batten__subcmd__help__subcmd__claim_commands() {
    local commands; commands=(
'merged:The keys merged pull request bodies close, as \`<key>\\t<number>\` rows' \
'keys:The issue keys this branch CLAIMS, as distinct from the ones it merely mentions' \
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
'race:Refuse a claim a different open pull request already carries, judged by head SHA' \
'carry:Attest that this branch only carries licence rows forward, and mint the receipt when it does' \
    )
    _describe -t commands 'batten help claim commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__bot_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__bot_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim bot commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__carry_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__carry_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim carry commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__keys_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__keys_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim keys commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__merged_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__merged_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim merged commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__claim__subcmd__race_commands] )) ||
_batten__subcmd__help__subcmd__claim__subcmd__race_commands() {
    local commands; commands=()
    _describe -t commands 'batten help claim race commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__commit_commands] )) ||
_batten__subcmd__help__subcmd__commit_commands() {
    local commands; commands=(
'check:Refuse a commit subject that does not follow the configured convention' \
    )
    _describe -t commands 'batten help commit commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__commit__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__commit__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help commit check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config_commands] )) ||
_batten__subcmd__help__subcmd__config_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'epoch:Print the content hash of the governing config surface' \
'deprecations:Report schema keys removed since a published release with no deprecation window' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
    )
    _describe -t commands 'batten help config commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config__subcmd__deprecations_commands] )) ||
_batten__subcmd__help__subcmd__config__subcmd__deprecations_commands() {
    local commands; commands=()
    _describe -t commands 'batten help config deprecations commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config__subcmd__epoch_commands] )) ||
_batten__subcmd__help__subcmd__config__subcmd__epoch_commands() {
    local commands; commands=()
    _describe -t commands 'batten help config epoch commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config__subcmd__lint_commands] )) ||
_batten__subcmd__help__subcmd__config__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten help config lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config__subcmd__show_commands] )) ||
_batten__subcmd__help__subcmd__config__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten help config show commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__defects_commands] )) ||
_batten__subcmd__help__subcmd__defects_commands() {
    local commands; commands=(
'query:List recorded defects, as pointers' \
'add:Append defect records read as JSONL on stdin' \
    )
    _describe -t commands 'batten help defects commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__defects__subcmd__add_commands] )) ||
_batten__subcmd__help__subcmd__defects__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'batten help defects add commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__defects__subcmd__query_commands] )) ||
_batten__subcmd__help__subcmd__defects__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten help defects query commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__design_commands] )) ||
_batten__subcmd__help__subcmd__design_commands() {
    local commands; commands=(
'audit:Audit a JSONL design-evidence claim stream on stdin for record integrity' \
    )
    _describe -t commands 'batten help design commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__design__subcmd__audit_commands] )) ||
_batten__subcmd__help__subcmd__design__subcmd__audit_commands() {
    local commands; commands=()
    _describe -t commands 'batten help design audit commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__dist_commands] )) ||
_batten__subcmd__help__subcmd__dist_commands() {
    local commands; commands=()
    _describe -t commands 'batten help dist commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor_commands] )) ||
_batten__subcmd__help__subcmd__doctor_commands() {
    local commands; commands=(
'target:Make one rustup target installed, purging a half-installed one first, behind the toolchain'\''s own lock' \
'mediator:Diagnose whether the engine the registrations reach was built from this tree' \
'egress:Diagnose whether the agent proxy would carry this container'\''s requests' \
'forge:Diagnose whether the forge credential carries the claims this repository'\''s tasks declare' \
'gate:Diagnose whether this checkout'\''s commit path runs the gate' \
'toolchain:Diagnose whether every tool the manifest declares is installed' \
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
'session:Diagnose whether this session has declared work it has not finished' \
    )
    _describe -t commands 'batten help doctor commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__egress_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__egress_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor egress commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__forge_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__gate_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__hooks_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__mediator_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__mediator_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor mediator commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__session_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__session_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor session commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__target_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__target_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor target commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__toolchain_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__toolchain_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor toolchain commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__enforce_commands] )) ||
_batten__subcmd__help__subcmd__enforce_commands() {
    local commands; commands=()
    _describe -t commands 'batten help enforce commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__exec_commands] )) ||
_batten__subcmd__help__subcmd__exec_commands() {
    local commands; commands=()
    _describe -t commands 'batten help exec commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate_commands] )) ||
_batten__subcmd__help__subcmd__generate_commands() {
    local commands; commands=(
'completions:Emit the shell completion script for one shell' \
'hooks:Emit one harness'\''s hook registrations, on stdout' \
'man:Emit the roff man page for one command, on stdout' \
'markdown:Emit the whole command surface as one markdown reference, on stdout' \
'schema:Emit the JSON Schema for a config or policy-input surface, derived from the types that define it' \
    )
    _describe -t commands 'batten help generate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__completions_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate completions commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__hooks_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__man_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__man_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate man commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__markdown_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__markdown_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate markdown commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__schema_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__schema_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate schema commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__hk_commands] )) ||
_batten__subcmd__help__subcmd__hk_commands() {
    local commands; commands=(
'contract:Regenerate the committed plan projection from the pinned runner' \
'observe:Record what this session resolved of the runner, once per contract digest' \
'drift:Whether the committed plan projection still matches the pinned runner' \
    )
    _describe -t commands 'batten help hk commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__hk__subcmd__contract_commands] )) ||
_batten__subcmd__help__subcmd__hk__subcmd__contract_commands() {
    local commands; commands=()
    _describe -t commands 'batten help hk contract commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__hk__subcmd__drift_commands] )) ||
_batten__subcmd__help__subcmd__hk__subcmd__drift_commands() {
    local commands; commands=()
    _describe -t commands 'batten help hk drift commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__hk__subcmd__observe_commands] )) ||
_batten__subcmd__help__subcmd__hk__subcmd__observe_commands() {
    local commands; commands=()
    _describe -t commands 'batten help hk observe commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__init_commands] )) ||
_batten__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'batten help init commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land_commands] )) ||
_batten__subcmd__help__subcmd__land_commands() {
    local commands; commands=(
'replay:Advance the base and replay this branch onto it, recording the outcome' \
'wait:Ask whether this head is green and whether its base still holds; the first answer decides' \
'push:Push this branch to its own ref, under receive-pack'\''s compare-and-swap' \
'verify:Run the configured gate over this head and record what it answered' \
'fast-forward:Ask this head'\''s pull request to fast-forward, and read the answer that request got' \
'lap:Drive the whole lap and lap again on any refusal a rebase would clear' \
'linear:Whether this head is built on the reference'\''s current tip, so it can fast-forward' \
    )
    _describe -t commands 'batten help land commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__fast-forward_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__fast-forward_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land fast-forward commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__lap_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__lap_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land lap commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__linear_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__linear_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land linear commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__push_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__push_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land push commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__replay_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land replay commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__verify_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land verify commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__land__subcmd__wait_commands] )) ||
_batten__subcmd__help__subcmd__land__subcmd__wait_commands() {
    local commands; commands=()
    _describe -t commands 'batten help land wait commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__landed_commands] )) ||
_batten__subcmd__help__subcmd__landed_commands() {
    local commands; commands=(
'check:Refuse a board column that contradicts main'\''s history or a declined key' \
'abandoned:Refuse an In Progress claim with no landing, no pull request, no branch and no recent touch' \
    )
    _describe -t commands 'batten help landed commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__landed__subcmd__abandoned_commands] )) ||
_batten__subcmd__help__subcmd__landed__subcmd__abandoned_commands() {
    local commands; commands=()
    _describe -t commands 'batten help landed abandoned commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__landed__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__landed__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help landed check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease_commands] )) ||
_batten__subcmd__help__subcmd__lease_commands() {
    local commands; commands=(
'authorises:May this branch spend a matrix right now?' \
'carries:Gate\: this head carries the landing mechanism trunk has, so it can be serialised' \
'guard:The runner'\''s step-0 guard\: may this branch spend a matrix right now?' \
'check:Gate\: the lease is free or a live, well-formed hold — never a wedge and never garbage' \
'status:Report who holds the lease, for how much longer, and who is admitted behind them' \
'peek:Print one advisory field of the held lease, or nothing' \
'held:Is this clone'\''s lease still held, with a beat of margin to act on?' \
'acquire:Take the lease, waiting out a live holder and reaping a dead one' \
'renew:Extend this clone'\''s lease by one term' \
'hold:Renew this clone'\''s lease every beat until it is lost or the hold ends' \
'release:Hand the lease back, leaving a tombstone rather than deleting the ref' \
'reserve:Take the one slot behind the current holder' \
    )
    _describe -t commands 'batten help lease commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__acquire_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__authorises_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__authorises_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease authorises commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__carries_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__carries_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease carries commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__guard_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__guard_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease guard commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__held_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__held_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease held commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__hold_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__hold_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease hold commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__peek_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__peek_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease peek commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__release_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease release commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__renew_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__renew_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease renew commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__reserve_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__reserve_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease reserve commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lease__subcmd__status_commands] )) ||
_batten__subcmd__help__subcmd__lease__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lease status commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lint_commands] )) ||
_batten__subcmd__help__subcmd__lint_commands() {
    local commands; commands=(
'brief:Check a delegation brief against the handoff schema (any missing section is a violation)' \
    )
    _describe -t commands 'batten help lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__lint__subcmd__brief_commands] )) ||
_batten__subcmd__help__subcmd__lint__subcmd__brief_commands() {
    local commands; commands=()
    _describe -t commands 'batten help lint brief commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp_commands] )) ||
_batten__subcmd__help__subcmd__mcp_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
'spawn:Record that a client actually spawned this server, then exec the launch line unchanged' \
'grant:Apply the committed MCP permissions to whichever server name the host exposed this session' \
'posture:Refuse an enabled MCP server this session did not attach, or a grant the connector would still prompt for' \
    )
    _describe -t commands 'batten help mcp commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp__subcmd__call_commands] )) ||
_batten__subcmd__help__subcmd__mcp__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mcp call commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp__subcmd__grant_commands] )) ||
_batten__subcmd__help__subcmd__mcp__subcmd__grant_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mcp grant commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp__subcmd__posture_commands] )) ||
_batten__subcmd__help__subcmd__mcp__subcmd__posture_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mcp posture commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp__subcmd__spawn_commands] )) ||
_batten__subcmd__help__subcmd__mcp__subcmd__spawn_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mcp spawn commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mutate_commands] )) ||
_batten__subcmd__help__subcmd__mutate_commands() {
    local commands; commands=(
'sweep:Apply every declared mutation to its source and report the ones its declared suite did not catch' \
'census:Report every gate in the tree that is neither mutation-enforced nor carrying a filed exemption' \
    )
    _describe -t commands 'batten help mutate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mutate__subcmd__census_commands] )) ||
_batten__subcmd__help__subcmd__mutate__subcmd__census_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mutate census commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mutate__subcmd__sweep_commands] )) ||
_batten__subcmd__help__subcmd__mutate__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mutate sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__override_commands] )) ||
_batten__subcmd__help__subcmd__override_commands() {
    local commands; commands=(
'request:Answer a class'\''s declared precondition and receive an admission for one situation' \
'spend:Spend an issued admission against the situation it was issued for' \
    )
    _describe -t commands 'batten help override commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__override__subcmd__request_commands] )) ||
_batten__subcmd__help__subcmd__override__subcmd__request_commands() {
    local commands; commands=()
    _describe -t commands 'batten help override request commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__override__subcmd__spend_commands] )) ||
_batten__subcmd__help__subcmd__override__subcmd__spend_commands() {
    local commands; commands=()
    _describe -t commands 'batten help override spend commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__payload_commands] )) ||
_batten__subcmd__help__subcmd__payload_commands() {
    local commands; commands=(
'field:Print one field of a hook payload read from stdin, for a shell hook that must not depend on jq' \
    )
    _describe -t commands 'batten help payload commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__payload__subcmd__field_commands] )) ||
_batten__subcmd__help__subcmd__payload__subcmd__field_commands() {
    local commands; commands=()
    _describe -t commands 'batten help payload field commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf_commands] )) ||
_batten__subcmd__help__subcmd__perf_commands() {
    local commands; commands=(
'pair:Measure this branch and its merge base back to back on one machine, and print both arms as paired records' \
'measure:Measure this binary'\''s invocation cost on every path and print one record per path' \
'record:Append a measurement to the trunk'\''s invocation-cost series, read as \`perf measure\` records on stdin' \
'compare:Decide whether a paired measurement read on stdin regressed past the threshold' \
'gate:Measure this branch against its merge base and refuse a regression' \
    )
    _describe -t commands 'batten help perf commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__compare_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf compare commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__gate_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__measure_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__measure_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf measure commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__pair_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy_commands] )) ||
_batten__subcmd__help__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'hooks:Judge this session'\''s hook output against its declared per-session budget' \
'test:Run each registered module'\''s own \`test_\` rules and report the predicates none exercised' \
'tools:Print the tool names the mediated-call rows decide, one per line' \
'explain:Resolve a verdict token to its class definition and the routes out of it' \
'rule:Resolve a rule id to the remedy its row declares' \
    )
    _describe -t commands 'batten help policy commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__budget_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy budget commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__explain_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy explain commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__hooks_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__rule_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__rule_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy rule commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__test_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__test_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy test commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__tools_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__tools_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy tools commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr_commands] )) ||
_batten__subcmd__help__subcmd__pr_commands() {
    local commands; commands=(
'watch:Poll a head'\''s check runs until the required set answers, then report the verdict' \
'derive:The tracker row a bot'\''s pull request implies, as a payload the refinement gate reads' \
'file:Open the mirror issue a bot'\''s pull request implies, and report its number' \
'link:Write the closing key into a bot pull request'\''s body, so its merge moves the row' \
'ensure:File the row and link it, doing whatever this tick can and saying what it did' \
'closes:Whether a pull request'\''s body still closes a tracker key, asked at the last moment' \
'unsubscribed:Drop this session'\''s webhook subscription to a pull request, attest it, or record and decide the reading' \
    )
    _describe -t commands 'batten help pr commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__closes_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__derive_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__ensure_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__ensure_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr ensure commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__file_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__file_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr file commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__link_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__link_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr link commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__unsubscribed_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__unsubscribed_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr unsubscribed commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__pr__subcmd__watch_commands] )) ||
_batten__subcmd__help__subcmd__pr__subcmd__watch_commands() {
    local commands; commands=()
    _describe -t commands 'batten help pr watch commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__provision_commands] )) ||
_batten__subcmd__help__subcmd__provision_commands() {
    local commands; commands=(
'status:Report which provisioned tools do not match the manifest' \
'apply:Fetch, verify against the pinned checksum, and install into the out-of-tree cache' \
    )
    _describe -t commands 'batten help provision commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__provision__subcmd__apply_commands] )) ||
_batten__subcmd__help__subcmd__provision__subcmd__apply_commands() {
    local commands; commands=()
    _describe -t commands 'batten help provision apply commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__provision__subcmd__status_commands] )) ||
_batten__subcmd__help__subcmd__provision__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten help provision status commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__ready_commands] )) ||
_batten__subcmd__help__subcmd__ready_commands() {
    local commands; commands=(
'lint:Refuse an issue whose Ready block fails a checkable clause of the Definition of Ready' \
    )
    _describe -t commands 'batten help ready commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__ready__subcmd__lint_commands] )) ||
_batten__subcmd__help__subcmd__ready__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten help ready lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__receipt_commands] )) ||
_batten__subcmd__help__subcmd__receipt_commands() {
    local commands; commands=(
'clean:Refuse when the working tree differs from HEAD, so a receipt keyed to HEAD would attest bytes no commit contains' \
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
'verified:Is HEAD verified — every declared check'\''s receipt valid against this commit?' \
    )
    _describe -t commands 'batten help receipt commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__receipt__subcmd__clean_commands] )) ||
_batten__subcmd__help__subcmd__receipt__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'batten help receipt clean commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__receipt__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__receipt__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten help receipt record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__receipt__subcmd__status_commands] )) ||
_batten__subcmd__help__subcmd__receipt__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten help receipt status commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__receipt__subcmd__verified_commands] )) ||
_batten__subcmd__help__subcmd__receipt__subcmd__verified_commands() {
    local commands; commands=()
    _describe -t commands 'batten help receipt verified commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__record_commands() {
    local commands; commands=(
'suites:Derive what each bats suite costs from the report the runner wrote, and record it where an author reads it' \
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin or with --fetch from the forge' \
'validate:Run a declared tool row'\''s \`run\` argv and record its exit code under the row'\''s key' \
'named:Record one named family under this branch, read from stdin' \
'derive:Derive one named family'\''s record from its input and write it' \
'keyed:Put one value into a keyed store family, read from stdin' \
'journal:Append one record to an append-and-fold store family, read from stdin' \
'show:Read one keyed record back\: \`hit\` and the value, or \`miss\`' \
'fold:Fold a journal family\: \`nothing\`, its records, or \`unreadable <path>\`' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
'query:Run a declared \`\[\[forge.query\]\]\` read and record its reduction as the family it names' \
'probe:Run a probe command and record the family'\''s reading of its exit status and output' \
'decide:Derive a family'\''s reading, record it without echoing it, and decide over it with the named rules' \
'divergence:Record how far the landing loop diverged from linear over a window of runs' \
'nonverdict:Record which recent required-check failures never reached a verdict' \
'attestation:Record a release'\''s attestation posture and what the verifier says of each archive'\''s binary' \
'census:Record whether a landing was in flight when a container was replaced, and read the verdict back' \
'release:Record a published release'\''s assets, its checksum manifest'\''s entries, and the entries whose bytes disagree' \
    )
    _describe -t commands 'batten help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__attestation_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__attestation_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record attestation commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__census_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__census_commands() {
    local commands; commands=(
'note:Append a landing'\''s beat or its deliberate stop under this container'\''s boot' \
'record-boot:Record this container'\''s boot, once' \
'report:Say whether a landing was in flight when the previous container was replaced' \
'tally:Count every recorded replacement by what it interrupted' \
    )
    _describe -t commands 'batten help record census commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__note_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__note_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record census note commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__record-boot_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__record-boot_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record census record-boot commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__report_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__report_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record census report commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__tally_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__census__subcmd__tally_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record census tally commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__closes_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__decide_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__decide_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record decide commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__derive_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__divergence_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__divergence_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record divergence commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__fold_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__fold_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record fold commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__forge_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__journal_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__journal_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record journal commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__keyed_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__keyed_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record keyed commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__named_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__named_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record named commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__nonverdict_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__nonverdict_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record nonverdict commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__plan_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__probe_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record probe commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__query_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record query commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__release_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record release commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__show_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record show commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__suites_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__tool_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record tool commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__validate_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__validate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record validate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__release_commands] )) ||
_batten__subcmd__help__subcmd__release_commands() {
    local commands; commands=(
'install:Decide whether install.sh, the release matrix and the binstall manifest agree on every asset name, and that no binary is committed' \
'sums:Hash a published release'\''s own assets into a checksum manifest, never the manifest itself' \
'backfill:Dispatch a backfill workflow once per release tag, oldest first, waiting on each run and stopping at the first that does not succeed' \
    )
    _describe -t commands 'batten help release commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__release__subcmd__backfill_commands] )) ||
_batten__subcmd__help__subcmd__release__subcmd__backfill_commands() {
    local commands; commands=()
    _describe -t commands 'batten help release backfill commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__release__subcmd__install_commands] )) ||
_batten__subcmd__help__subcmd__release__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'batten help release install commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__release__subcmd__sums_commands] )) ||
_batten__subcmd__help__subcmd__release__subcmd__sums_commands() {
    local commands; commands=()
    _describe -t commands 'batten help release sums commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__sbom_commands] )) ||
_batten__subcmd__help__subcmd__sbom_commands() {
    local commands; commands=()
    _describe -t commands 'batten help sbom commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__semver_commands] )) ||
_batten__subcmd__help__subcmd__semver_commands() {
    local commands; commands=(
'check:Refuse an API break this branch'\''s commits do not declare' \
    )
    _describe -t commands 'batten help semver commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__semver__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__semver__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help semver check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__show_commands] )) ||
_batten__subcmd__help__subcmd__show_commands() {
    local commands; commands=(
'agent:What an agent may do in this repository\: the read-only verbs, the exit contract, and the declared gates' \
    )
    _describe -t commands 'batten help show commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__show__subcmd__agent_commands] )) ||
_batten__subcmd__help__subcmd__show__subcmd__agent_commands() {
    local commands; commands=()
    _describe -t commands 'batten help show agent commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__singleton_commands] )) ||
_batten__subcmd__help__subcmd__singleton_commands() {
    local commands; commands=(
'acquire:Take a task'\''s lock for a pid, or refuse naming the process that holds it' \
'release:Drop a task'\''s lock, which its exit trap does and a kill cannot' \
'detach:Run a command in the background under a task'\''s lock, and report the previous run'\''s failure' \
    )
    _describe -t commands 'batten help singleton commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__singleton__subcmd__acquire_commands] )) ||
_batten__subcmd__help__subcmd__singleton__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten help singleton acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__singleton__subcmd__detach_commands] )) ||
_batten__subcmd__help__subcmd__singleton__subcmd__detach_commands() {
    local commands; commands=()
    _describe -t commands 'batten help singleton detach commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__singleton__subcmd__release_commands] )) ||
_batten__subcmd__help__subcmd__singleton__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten help singleton release commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__spec_commands] )) ||
_batten__subcmd__help__subcmd__spec_commands() {
    local commands; commands=()
    _describe -t commands 'batten help spec commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__startup_commands] )) ||
_batten__subcmd__help__subcmd__startup_commands() {
    local commands; commands=()
    _describe -t commands 'batten help startup commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state_commands] )) ||
_batten__subcmd__help__subcmd__state_commands() {
    local commands; commands=(
'adopt:Bind this checkout to its findings store, minting one only if none exists' \
'record:Record this ref'\''s findings into the store, and GC instances whose ref is gone' \
'migrate:Upgrade the findings store to this binary'\''s record version' \
'settle:Record what was decided about a stored finding' \
'list:List stored findings and the refs they were observed in' \
    )
    _describe -t commands 'batten help state commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state__subcmd__adopt_commands] )) ||
_batten__subcmd__help__subcmd__state__subcmd__adopt_commands() {
    local commands; commands=()
    _describe -t commands 'batten help state adopt commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state__subcmd__list_commands] )) ||
_batten__subcmd__help__subcmd__state__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten help state list commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state__subcmd__migrate_commands] )) ||
_batten__subcmd__help__subcmd__state__subcmd__migrate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help state migrate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__state__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten help state record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state__subcmd__settle_commands] )) ||
_batten__subcmd__help__subcmd__state__subcmd__settle_commands() {
    local commands; commands=()
    _describe -t commands 'batten help state settle commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__step_commands] )) ||
_batten__subcmd__help__subcmd__step_commands() {
    local commands; commands=(
'check:Say hit or miss for a step'\''s inputs, arguments and tools, and remember the key a record must match' \
'record:Record that a step passed, refusing when its inputs changed since the paired check' \
'run:Run a step'\''s command only when its receipt misses, and record the receipt when it passes' \
    )
    _describe -t commands 'batten help step commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__step__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__step__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help step check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__step__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__step__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten help step record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__step__subcmd__run_commands] )) ||
_batten__subcmd__help__subcmd__step__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'batten help step run commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__target_commands] )) ||
_batten__subcmd__help__subcmd__target_commands() {
    local commands; commands=(
'prune:Reclaim superseded build artifacts, and refuse below the measured disk floor for the build the next lap will run' \
    )
    _describe -t commands 'batten help target commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__target__subcmd__prune_commands] )) ||
_batten__subcmd__help__subcmd__target__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten help target prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task_commands] )) ||
_batten__subcmd__help__subcmd__task_commands() {
    local commands; commands=(
'register:Record that a task has started, under its pid' \
'phase:Record what a registered task is now doing' \
'tick:Record that a task'\''s loop went round' \
'sig:Record that the world a task is watching moved' \
'unregister:Drop a task'\''s record, which its exit path does and a kill cannot' \
'read:One field of one task'\''s record, so a prober composes rather than parsing the layout' \
'alive:What tasks are running right now and what phase each is in — one call, no log reading' \
    )
    _describe -t commands 'batten help task commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__alive_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__alive_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task alive commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__phase_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__phase_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task phase commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__read_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task read commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__register_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__register_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task register commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__sig_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__sig_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task sig commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__tick_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__tick_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task tick commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__task__subcmd__unregister_commands] )) ||
_batten__subcmd__help__subcmd__task__subcmd__unregister_commands() {
    local commands; commands=()
    _describe -t commands 'batten help task unregister commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__verdict_commands] )) ||
_batten__subcmd__help__subcmd__verdict_commands() {
    local commands; commands=()
    _describe -t commands 'batten help verdict commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__wiring_commands] )) ||
_batten__subcmd__help__subcmd__wiring_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
'gate:Link this clone'\''s two commit hooks to a hook body the repository checks in' \
    )
    _describe -t commands 'batten help wiring commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__wiring__subcmd__gate_commands] )) ||
_batten__subcmd__help__subcmd__wiring__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten help wiring gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__wiring__subcmd__reclaim_commands] )) ||
_batten__subcmd__help__subcmd__wiring__subcmd__reclaim_commands() {
    local commands; commands=()
    _describe -t commands 'batten help wiring reclaim commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__worktree_commands] )) ||
_batten__subcmd__help__subcmd__worktree_commands() {
    local commands; commands=(
'status:Report work that is uncommitted, unpushed, or not landed on the configured target' \
    )
    _describe -t commands 'batten help worktree commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__worktree__subcmd__status_commands] )) ||
_batten__subcmd__help__subcmd__worktree__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten help worktree status commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk_commands] )) ||
_batten__subcmd__hk_commands() {
    local commands; commands=(
'contract:Regenerate the committed plan projection from the pinned runner' \
'observe:Record what this session resolved of the runner, once per contract digest' \
'drift:Whether the committed plan projection still matches the pinned runner' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten hk commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__contract_commands] )) ||
_batten__subcmd__hk__subcmd__contract_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk contract commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__drift_commands] )) ||
_batten__subcmd__hk__subcmd__drift_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk drift commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__help_commands] )) ||
_batten__subcmd__hk__subcmd__help_commands() {
    local commands; commands=(
'contract:Regenerate the committed plan projection from the pinned runner' \
'observe:Record what this session resolved of the runner, once per contract digest' \
'drift:Whether the committed plan projection still matches the pinned runner' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten hk help commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__help__subcmd__contract_commands] )) ||
_batten__subcmd__hk__subcmd__help__subcmd__contract_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk help contract commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__help__subcmd__drift_commands] )) ||
_batten__subcmd__hk__subcmd__help__subcmd__drift_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk help drift commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__hk__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__help__subcmd__observe_commands] )) ||
_batten__subcmd__hk__subcmd__help__subcmd__observe_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk help observe commands' commands "$@"
}
(( $+functions[_batten__subcmd__hk__subcmd__observe_commands] )) ||
_batten__subcmd__hk__subcmd__observe_commands() {
    local commands; commands=()
    _describe -t commands 'batten hk observe commands' commands "$@"
}
(( $+functions[_batten__subcmd__init_commands] )) ||
_batten__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'batten init commands' commands "$@"
}
(( $+functions[_batten__subcmd__land_commands] )) ||
_batten__subcmd__land_commands() {
    local commands; commands=(
'replay:Advance the base and replay this branch onto it, recording the outcome' \
'wait:Ask whether this head is green and whether its base still holds; the first answer decides' \
'push:Push this branch to its own ref, under receive-pack'\''s compare-and-swap' \
'verify:Run the configured gate over this head and record what it answered' \
'fast-forward:Ask this head'\''s pull request to fast-forward, and read the answer that request got' \
'lap:Drive the whole lap and lap again on any refusal a rebase would clear' \
'linear:Whether this head is built on the reference'\''s current tip, so it can fast-forward' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten land commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__fast-forward_commands] )) ||
_batten__subcmd__land__subcmd__fast-forward_commands() {
    local commands; commands=()
    _describe -t commands 'batten land fast-forward commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help_commands] )) ||
_batten__subcmd__land__subcmd__help_commands() {
    local commands; commands=(
'replay:Advance the base and replay this branch onto it, recording the outcome' \
'wait:Ask whether this head is green and whether its base still holds; the first answer decides' \
'push:Push this branch to its own ref, under receive-pack'\''s compare-and-swap' \
'verify:Run the configured gate over this head and record what it answered' \
'fast-forward:Ask this head'\''s pull request to fast-forward, and read the answer that request got' \
'lap:Drive the whole lap and lap again on any refusal a rebase would clear' \
'linear:Whether this head is built on the reference'\''s current tip, so it can fast-forward' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten land help commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__fast-forward_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__fast-forward_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help fast-forward commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__lap_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__lap_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help lap commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__linear_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__linear_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help linear commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__push_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__push_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help push commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__replay_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help replay commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__verify_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help verify commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__help__subcmd__wait_commands] )) ||
_batten__subcmd__land__subcmd__help__subcmd__wait_commands() {
    local commands; commands=()
    _describe -t commands 'batten land help wait commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__lap_commands] )) ||
_batten__subcmd__land__subcmd__lap_commands() {
    local commands; commands=()
    _describe -t commands 'batten land lap commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__linear_commands] )) ||
_batten__subcmd__land__subcmd__linear_commands() {
    local commands; commands=()
    _describe -t commands 'batten land linear commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__push_commands] )) ||
_batten__subcmd__land__subcmd__push_commands() {
    local commands; commands=()
    _describe -t commands 'batten land push commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__replay_commands] )) ||
_batten__subcmd__land__subcmd__replay_commands() {
    local commands; commands=()
    _describe -t commands 'batten land replay commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__verify_commands] )) ||
_batten__subcmd__land__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'batten land verify commands' commands "$@"
}
(( $+functions[_batten__subcmd__land__subcmd__wait_commands] )) ||
_batten__subcmd__land__subcmd__wait_commands() {
    local commands; commands=()
    _describe -t commands 'batten land wait commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed_commands] )) ||
_batten__subcmd__landed_commands() {
    local commands; commands=(
'check:Refuse a board column that contradicts main'\''s history or a declined key' \
'abandoned:Refuse an In Progress claim with no landing, no pull request, no branch and no recent touch' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten landed commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__abandoned_commands] )) ||
_batten__subcmd__landed__subcmd__abandoned_commands() {
    local commands; commands=()
    _describe -t commands 'batten landed abandoned commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__check_commands] )) ||
_batten__subcmd__landed__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten landed check commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__help_commands] )) ||
_batten__subcmd__landed__subcmd__help_commands() {
    local commands; commands=(
'check:Refuse a board column that contradicts main'\''s history or a declined key' \
'abandoned:Refuse an In Progress claim with no landing, no pull request, no branch and no recent touch' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten landed help commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__help__subcmd__abandoned_commands] )) ||
_batten__subcmd__landed__subcmd__help__subcmd__abandoned_commands() {
    local commands; commands=()
    _describe -t commands 'batten landed help abandoned commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__landed__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten landed help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__landed__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__landed__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten landed help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease_commands] )) ||
_batten__subcmd__lease_commands() {
    local commands; commands=(
'authorises:May this branch spend a matrix right now?' \
'carries:Gate\: this head carries the landing mechanism trunk has, so it can be serialised' \
'guard:The runner'\''s step-0 guard\: may this branch spend a matrix right now?' \
'check:Gate\: the lease is free or a live, well-formed hold — never a wedge and never garbage' \
'status:Report who holds the lease, for how much longer, and who is admitted behind them' \
'peek:Print one advisory field of the held lease, or nothing' \
'held:Is this clone'\''s lease still held, with a beat of margin to act on?' \
'acquire:Take the lease, waiting out a live holder and reaping a dead one' \
'renew:Extend this clone'\''s lease by one term' \
'hold:Renew this clone'\''s lease every beat until it is lost or the hold ends' \
'release:Hand the lease back, leaving a tombstone rather than deleting the ref' \
'reserve:Take the one slot behind the current holder' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten lease commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__acquire_commands] )) ||
_batten__subcmd__lease__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__authorises_commands] )) ||
_batten__subcmd__lease__subcmd__authorises_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease authorises commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__carries_commands] )) ||
_batten__subcmd__lease__subcmd__carries_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease carries commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__check_commands] )) ||
_batten__subcmd__lease__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease check commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__guard_commands] )) ||
_batten__subcmd__lease__subcmd__guard_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease guard commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__held_commands] )) ||
_batten__subcmd__lease__subcmd__held_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease held commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help_commands] )) ||
_batten__subcmd__lease__subcmd__help_commands() {
    local commands; commands=(
'authorises:May this branch spend a matrix right now?' \
'carries:Gate\: this head carries the landing mechanism trunk has, so it can be serialised' \
'guard:The runner'\''s step-0 guard\: may this branch spend a matrix right now?' \
'check:Gate\: the lease is free or a live, well-formed hold — never a wedge and never garbage' \
'status:Report who holds the lease, for how much longer, and who is admitted behind them' \
'peek:Print one advisory field of the held lease, or nothing' \
'held:Is this clone'\''s lease still held, with a beat of margin to act on?' \
'acquire:Take the lease, waiting out a live holder and reaping a dead one' \
'renew:Extend this clone'\''s lease by one term' \
'hold:Renew this clone'\''s lease every beat until it is lost or the hold ends' \
'release:Hand the lease back, leaving a tombstone rather than deleting the ref' \
'reserve:Take the one slot behind the current holder' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten lease help commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__acquire_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__authorises_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__authorises_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help authorises commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__carries_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__carries_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help carries commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__guard_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__guard_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help guard commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__held_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__held_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help held commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__hold_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__hold_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help hold commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__peek_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__peek_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help peek commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__release_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help release commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__renew_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__renew_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help renew commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__reserve_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__reserve_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help reserve commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__help__subcmd__status_commands] )) ||
_batten__subcmd__lease__subcmd__help__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease help status commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__hold_commands] )) ||
_batten__subcmd__lease__subcmd__hold_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease hold commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__peek_commands] )) ||
_batten__subcmd__lease__subcmd__peek_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease peek commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__release_commands] )) ||
_batten__subcmd__lease__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease release commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__renew_commands] )) ||
_batten__subcmd__lease__subcmd__renew_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease renew commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__reserve_commands] )) ||
_batten__subcmd__lease__subcmd__reserve_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease reserve commands' commands "$@"
}
(( $+functions[_batten__subcmd__lease__subcmd__status_commands] )) ||
_batten__subcmd__lease__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten lease status commands' commands "$@"
}
(( $+functions[_batten__subcmd__lint_commands] )) ||
_batten__subcmd__lint_commands() {
    local commands; commands=(
'brief:Check a delegation brief against the handoff schema (any missing section is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__lint__subcmd__brief_commands] )) ||
_batten__subcmd__lint__subcmd__brief_commands() {
    local commands; commands=()
    _describe -t commands 'batten lint brief commands' commands "$@"
}
(( $+functions[_batten__subcmd__lint__subcmd__help_commands] )) ||
_batten__subcmd__lint__subcmd__help_commands() {
    local commands; commands=(
'brief:Check a delegation brief against the handoff schema (any missing section is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten lint help commands' commands "$@"
}
(( $+functions[_batten__subcmd__lint__subcmd__help__subcmd__brief_commands] )) ||
_batten__subcmd__lint__subcmd__help__subcmd__brief_commands() {
    local commands; commands=()
    _describe -t commands 'batten lint help brief commands' commands "$@"
}
(( $+functions[_batten__subcmd__lint__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__lint__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten lint help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp_commands] )) ||
_batten__subcmd__mcp_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
'spawn:Record that a client actually spawned this server, then exec the launch line unchanged' \
'grant:Apply the committed MCP permissions to whichever server name the host exposed this session' \
'posture:Refuse an enabled MCP server this session did not attach, or a grant the connector would still prompt for' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mcp commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__call_commands] )) ||
_batten__subcmd__mcp__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp call commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__grant_commands] )) ||
_batten__subcmd__mcp__subcmd__grant_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp grant commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help_commands] )) ||
_batten__subcmd__mcp__subcmd__help_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
'spawn:Record that a client actually spawned this server, then exec the launch line unchanged' \
'grant:Apply the committed MCP permissions to whichever server name the host exposed this session' \
'posture:Refuse an enabled MCP server this session did not attach, or a grant the connector would still prompt for' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mcp help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__call_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help call commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__grant_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__grant_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help grant commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__posture_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__posture_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help posture commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__spawn_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__spawn_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help spawn commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__posture_commands] )) ||
_batten__subcmd__mcp__subcmd__posture_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp posture commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__spawn_commands] )) ||
_batten__subcmd__mcp__subcmd__spawn_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp spawn commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate_commands] )) ||
_batten__subcmd__mutate_commands() {
    local commands; commands=(
'sweep:Apply every declared mutation to its source and report the ones its declared suite did not catch' \
'census:Report every gate in the tree that is neither mutation-enforced nor carrying a filed exemption' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mutate commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__census_commands] )) ||
_batten__subcmd__mutate__subcmd__census_commands() {
    local commands; commands=()
    _describe -t commands 'batten mutate census commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__help_commands] )) ||
_batten__subcmd__mutate__subcmd__help_commands() {
    local commands; commands=(
'sweep:Apply every declared mutation to its source and report the ones its declared suite did not catch' \
'census:Report every gate in the tree that is neither mutation-enforced nor carrying a filed exemption' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mutate help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__help__subcmd__census_commands] )) ||
_batten__subcmd__mutate__subcmd__help__subcmd__census_commands() {
    local commands; commands=()
    _describe -t commands 'batten mutate help census commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__mutate__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten mutate help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__help__subcmd__sweep_commands] )) ||
_batten__subcmd__mutate__subcmd__help__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten mutate help sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__mutate__subcmd__sweep_commands] )) ||
_batten__subcmd__mutate__subcmd__sweep_commands() {
    local commands; commands=()
    _describe -t commands 'batten mutate sweep commands' commands "$@"
}
(( $+functions[_batten__subcmd__override_commands] )) ||
_batten__subcmd__override_commands() {
    local commands; commands=(
'request:Answer a class'\''s declared precondition and receive an admission for one situation' \
'spend:Spend an issued admission against the situation it was issued for' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten override commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__help_commands] )) ||
_batten__subcmd__override__subcmd__help_commands() {
    local commands; commands=(
'request:Answer a class'\''s declared precondition and receive an admission for one situation' \
'spend:Spend an issued admission against the situation it was issued for' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten override help commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__override__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten override help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__help__subcmd__request_commands] )) ||
_batten__subcmd__override__subcmd__help__subcmd__request_commands() {
    local commands; commands=()
    _describe -t commands 'batten override help request commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__help__subcmd__spend_commands] )) ||
_batten__subcmd__override__subcmd__help__subcmd__spend_commands() {
    local commands; commands=()
    _describe -t commands 'batten override help spend commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__request_commands] )) ||
_batten__subcmd__override__subcmd__request_commands() {
    local commands; commands=()
    _describe -t commands 'batten override request commands' commands "$@"
}
(( $+functions[_batten__subcmd__override__subcmd__spend_commands] )) ||
_batten__subcmd__override__subcmd__spend_commands() {
    local commands; commands=()
    _describe -t commands 'batten override spend commands' commands "$@"
}
(( $+functions[_batten__subcmd__payload_commands] )) ||
_batten__subcmd__payload_commands() {
    local commands; commands=(
'field:Print one field of a hook payload read from stdin, for a shell hook that must not depend on jq' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten payload commands' commands "$@"
}
(( $+functions[_batten__subcmd__payload__subcmd__field_commands] )) ||
_batten__subcmd__payload__subcmd__field_commands() {
    local commands; commands=()
    _describe -t commands 'batten payload field commands' commands "$@"
}
(( $+functions[_batten__subcmd__payload__subcmd__help_commands] )) ||
_batten__subcmd__payload__subcmd__help_commands() {
    local commands; commands=(
'field:Print one field of a hook payload read from stdin, for a shell hook that must not depend on jq' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten payload help commands' commands "$@"
}
(( $+functions[_batten__subcmd__payload__subcmd__help__subcmd__field_commands] )) ||
_batten__subcmd__payload__subcmd__help__subcmd__field_commands() {
    local commands; commands=()
    _describe -t commands 'batten payload help field commands' commands "$@"
}
(( $+functions[_batten__subcmd__payload__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__payload__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten payload help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf_commands] )) ||
_batten__subcmd__perf_commands() {
    local commands; commands=(
'pair:Measure this branch and its merge base back to back on one machine, and print both arms as paired records' \
'measure:Measure this binary'\''s invocation cost on every path and print one record per path' \
'record:Append a measurement to the trunk'\''s invocation-cost series, read as \`perf measure\` records on stdin' \
'compare:Decide whether a paired measurement read on stdin regressed past the threshold' \
'gate:Measure this branch against its merge base and refuse a regression' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten perf commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__compare_commands] )) ||
_batten__subcmd__perf__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf compare commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__gate_commands] )) ||
_batten__subcmd__perf__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help_commands] )) ||
_batten__subcmd__perf__subcmd__help_commands() {
    local commands; commands=(
'pair:Measure this branch and its merge base back to back on one machine, and print both arms as paired records' \
'measure:Measure this binary'\''s invocation cost on every path and print one record per path' \
'record:Append a measurement to the trunk'\''s invocation-cost series, read as \`perf measure\` records on stdin' \
'compare:Decide whether a paired measurement read on stdin regressed past the threshold' \
'gate:Measure this branch against its merge base and refuse a regression' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten perf help commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__compare_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__compare_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help compare commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__gate_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__measure_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__measure_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help measure commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__pair_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__measure_commands] )) ||
_batten__subcmd__perf__subcmd__measure_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf measure commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__pair_commands] )) ||
_batten__subcmd__perf__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__record_commands] )) ||
_batten__subcmd__perf__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf record commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy_commands] )) ||
_batten__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'hooks:Judge this session'\''s hook output against its declared per-session budget' \
'test:Run each registered module'\''s own \`test_\` rules and report the predicates none exercised' \
'tools:Print the tool names the mediated-call rows decide, one per line' \
'explain:Resolve a verdict token to its class definition and the routes out of it' \
'rule:Resolve a rule id to the remedy its row declares' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten policy commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__budget_commands] )) ||
_batten__subcmd__policy__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy budget commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__explain_commands] )) ||
_batten__subcmd__policy__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy explain commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help_commands] )) ||
_batten__subcmd__policy__subcmd__help_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'hooks:Judge this session'\''s hook output against its declared per-session budget' \
'test:Run each registered module'\''s own \`test_\` rules and report the predicates none exercised' \
'tools:Print the tool names the mediated-call rows decide, one per line' \
'explain:Resolve a verdict token to its class definition and the routes out of it' \
'rule:Resolve a rule id to the remedy its row declares' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten policy help commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__budget_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help budget commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__explain_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__explain_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help explain commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__hooks_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__rule_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__rule_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help rule commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__test_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__test_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help test commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__tools_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__tools_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help tools commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__hooks_commands] )) ||
_batten__subcmd__policy__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy hooks commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__rule_commands] )) ||
_batten__subcmd__policy__subcmd__rule_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy rule commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__test_commands] )) ||
_batten__subcmd__policy__subcmd__test_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy test commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__tools_commands] )) ||
_batten__subcmd__policy__subcmd__tools_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy tools commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr_commands] )) ||
_batten__subcmd__pr_commands() {
    local commands; commands=(
'watch:Poll a head'\''s check runs until the required set answers, then report the verdict' \
'derive:The tracker row a bot'\''s pull request implies, as a payload the refinement gate reads' \
'file:Open the mirror issue a bot'\''s pull request implies, and report its number' \
'link:Write the closing key into a bot pull request'\''s body, so its merge moves the row' \
'ensure:File the row and link it, doing whatever this tick can and saying what it did' \
'closes:Whether a pull request'\''s body still closes a tracker key, asked at the last moment' \
'unsubscribed:Drop this session'\''s webhook subscription to a pull request, attest it, or record and decide the reading' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten pr commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__closes_commands] )) ||
_batten__subcmd__pr__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__derive_commands] )) ||
_batten__subcmd__pr__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__ensure_commands] )) ||
_batten__subcmd__pr__subcmd__ensure_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr ensure commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__file_commands] )) ||
_batten__subcmd__pr__subcmd__file_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr file commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help_commands] )) ||
_batten__subcmd__pr__subcmd__help_commands() {
    local commands; commands=(
'watch:Poll a head'\''s check runs until the required set answers, then report the verdict' \
'derive:The tracker row a bot'\''s pull request implies, as a payload the refinement gate reads' \
'file:Open the mirror issue a bot'\''s pull request implies, and report its number' \
'link:Write the closing key into a bot pull request'\''s body, so its merge moves the row' \
'ensure:File the row and link it, doing whatever this tick can and saying what it did' \
'closes:Whether a pull request'\''s body still closes a tracker key, asked at the last moment' \
'unsubscribed:Drop this session'\''s webhook subscription to a pull request, attest it, or record and decide the reading' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten pr help commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__closes_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__derive_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__ensure_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__ensure_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help ensure commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__file_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__file_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help file commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__link_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__link_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help link commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__unsubscribed_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__unsubscribed_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help unsubscribed commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__help__subcmd__watch_commands] )) ||
_batten__subcmd__pr__subcmd__help__subcmd__watch_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr help watch commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__link_commands] )) ||
_batten__subcmd__pr__subcmd__link_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr link commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__unsubscribed_commands] )) ||
_batten__subcmd__pr__subcmd__unsubscribed_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr unsubscribed commands' commands "$@"
}
(( $+functions[_batten__subcmd__pr__subcmd__watch_commands] )) ||
_batten__subcmd__pr__subcmd__watch_commands() {
    local commands; commands=()
    _describe -t commands 'batten pr watch commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision_commands] )) ||
_batten__subcmd__provision_commands() {
    local commands; commands=(
'status:Report which provisioned tools do not match the manifest' \
'apply:Fetch, verify against the pinned checksum, and install into the out-of-tree cache' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten provision commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__apply_commands] )) ||
_batten__subcmd__provision__subcmd__apply_commands() {
    local commands; commands=()
    _describe -t commands 'batten provision apply commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__help_commands] )) ||
_batten__subcmd__provision__subcmd__help_commands() {
    local commands; commands=(
'status:Report which provisioned tools do not match the manifest' \
'apply:Fetch, verify against the pinned checksum, and install into the out-of-tree cache' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten provision help commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__help__subcmd__apply_commands] )) ||
_batten__subcmd__provision__subcmd__help__subcmd__apply_commands() {
    local commands; commands=()
    _describe -t commands 'batten provision help apply commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__provision__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten provision help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__help__subcmd__status_commands] )) ||
_batten__subcmd__provision__subcmd__help__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten provision help status commands' commands "$@"
}
(( $+functions[_batten__subcmd__provision__subcmd__status_commands] )) ||
_batten__subcmd__provision__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten provision status commands' commands "$@"
}
(( $+functions[_batten__subcmd__ready_commands] )) ||
_batten__subcmd__ready_commands() {
    local commands; commands=(
'lint:Refuse an issue whose Ready block fails a checkable clause of the Definition of Ready' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten ready commands' commands "$@"
}
(( $+functions[_batten__subcmd__ready__subcmd__help_commands] )) ||
_batten__subcmd__ready__subcmd__help_commands() {
    local commands; commands=(
'lint:Refuse an issue whose Ready block fails a checkable clause of the Definition of Ready' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten ready help commands' commands "$@"
}
(( $+functions[_batten__subcmd__ready__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__ready__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten ready help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__ready__subcmd__help__subcmd__lint_commands] )) ||
_batten__subcmd__ready__subcmd__help__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten ready help lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__ready__subcmd__lint_commands] )) ||
_batten__subcmd__ready__subcmd__lint_commands() {
    local commands; commands=()
    _describe -t commands 'batten ready lint commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt_commands] )) ||
_batten__subcmd__receipt_commands() {
    local commands; commands=(
'clean:Refuse when the working tree differs from HEAD, so a receipt keyed to HEAD would attest bytes no commit contains' \
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
'verified:Is HEAD verified — every declared check'\''s receipt valid against this commit?' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten receipt commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__clean_commands] )) ||
_batten__subcmd__receipt__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt clean commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help_commands] )) ||
_batten__subcmd__receipt__subcmd__help_commands() {
    local commands; commands=(
'clean:Refuse when the working tree differs from HEAD, so a receipt keyed to HEAD would attest bytes no commit contains' \
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
'verified:Is HEAD verified — every declared check'\''s receipt valid against this commit?' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten receipt help commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help__subcmd__clean_commands] )) ||
_batten__subcmd__receipt__subcmd__help__subcmd__clean_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt help clean commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__receipt__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__receipt__subcmd__help__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help__subcmd__status_commands] )) ||
_batten__subcmd__receipt__subcmd__help__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt help status commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help__subcmd__verified_commands] )) ||
_batten__subcmd__receipt__subcmd__help__subcmd__verified_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt help verified commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__record_commands] )) ||
_batten__subcmd__receipt__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt record commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__status_commands] )) ||
_batten__subcmd__receipt__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt status commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__verified_commands] )) ||
_batten__subcmd__receipt__subcmd__verified_commands() {
    local commands; commands=()
    _describe -t commands 'batten receipt verified commands' commands "$@"
}
(( $+functions[_batten__subcmd__record_commands] )) ||
_batten__subcmd__record_commands() {
    local commands; commands=(
'suites:Derive what each bats suite costs from the report the runner wrote, and record it where an author reads it' \
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin or with --fetch from the forge' \
'validate:Run a declared tool row'\''s \`run\` argv and record its exit code under the row'\''s key' \
'named:Record one named family under this branch, read from stdin' \
'derive:Derive one named family'\''s record from its input and write it' \
'keyed:Put one value into a keyed store family, read from stdin' \
'journal:Append one record to an append-and-fold store family, read from stdin' \
'show:Read one keyed record back\: \`hit\` and the value, or \`miss\`' \
'fold:Fold a journal family\: \`nothing\`, its records, or \`unreadable <path>\`' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
'query:Run a declared \`\[\[forge.query\]\]\` read and record its reduction as the family it names' \
'probe:Run a probe command and record the family'\''s reading of its exit status and output' \
'decide:Derive a family'\''s reading, record it without echoing it, and decide over it with the named rules' \
'divergence:Record how far the landing loop diverged from linear over a window of runs' \
'nonverdict:Record which recent required-check failures never reached a verdict' \
'attestation:Record a release'\''s attestation posture and what the verifier says of each archive'\''s binary' \
'census:Record whether a landing was in flight when a container was replaced, and read the verdict back' \
'release:Record a published release'\''s assets, its checksum manifest'\''s entries, and the entries whose bytes disagree' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__attestation_commands] )) ||
_batten__subcmd__record__subcmd__attestation_commands() {
    local commands; commands=()
    _describe -t commands 'batten record attestation commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census_commands] )) ||
_batten__subcmd__record__subcmd__census_commands() {
    local commands; commands=(
'note:Append a landing'\''s beat or its deliberate stop under this container'\''s boot' \
'record-boot:Record this container'\''s boot, once' \
'report:Say whether a landing was in flight when the previous container was replaced' \
'tally:Count every recorded replacement by what it interrupted' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record census commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help_commands() {
    local commands; commands=(
'note:Append a landing'\''s beat or its deliberate stop under this container'\''s boot' \
'record-boot:Record this container'\''s boot, once' \
'report:Say whether a landing was in flight when the previous container was replaced' \
'tally:Count every recorded replacement by what it interrupted' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record census help commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__note_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__note_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census help note commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__record-boot_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__record-boot_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census help record-boot commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__report_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__report_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census help report commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__tally_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__help__subcmd__tally_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census help tally commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__note_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__note_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census note commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__record-boot_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__record-boot_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census record-boot commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__report_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__report_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census report commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__census__subcmd__tally_commands] )) ||
_batten__subcmd__record__subcmd__census__subcmd__tally_commands() {
    local commands; commands=()
    _describe -t commands 'batten record census tally commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__closes_commands] )) ||
_batten__subcmd__record__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten record closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__decide_commands] )) ||
_batten__subcmd__record__subcmd__decide_commands() {
    local commands; commands=()
    _describe -t commands 'batten record decide commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__derive_commands] )) ||
_batten__subcmd__record__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten record derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__divergence_commands] )) ||
_batten__subcmd__record__subcmd__divergence_commands() {
    local commands; commands=()
    _describe -t commands 'batten record divergence commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__fold_commands] )) ||
_batten__subcmd__record__subcmd__fold_commands() {
    local commands; commands=()
    _describe -t commands 'batten record fold commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__forge_commands] )) ||
_batten__subcmd__record__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten record forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help_commands] )) ||
_batten__subcmd__record__subcmd__help_commands() {
    local commands; commands=(
'suites:Derive what each bats suite costs from the report the runner wrote, and record it where an author reads it' \
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin or with --fetch from the forge' \
'validate:Run a declared tool row'\''s \`run\` argv and record its exit code under the row'\''s key' \
'named:Record one named family under this branch, read from stdin' \
'derive:Derive one named family'\''s record from its input and write it' \
'keyed:Put one value into a keyed store family, read from stdin' \
'journal:Append one record to an append-and-fold store family, read from stdin' \
'show:Read one keyed record back\: \`hit\` and the value, or \`miss\`' \
'fold:Fold a journal family\: \`nothing\`, its records, or \`unreadable <path>\`' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
'query:Run a declared \`\[\[forge.query\]\]\` read and record its reduction as the family it names' \
'probe:Run a probe command and record the family'\''s reading of its exit status and output' \
'decide:Derive a family'\''s reading, record it without echoing it, and decide over it with the named rules' \
'divergence:Record how far the landing loop diverged from linear over a window of runs' \
'nonverdict:Record which recent required-check failures never reached a verdict' \
'attestation:Record a release'\''s attestation posture and what the verifier says of each archive'\''s binary' \
'census:Record whether a landing was in flight when a container was replaced, and read the verdict back' \
'release:Record a published release'\''s assets, its checksum manifest'\''s entries, and the entries whose bytes disagree' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record help commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__attestation_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__attestation_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help attestation commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__census_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__census_commands() {
    local commands; commands=(
'note:Append a landing'\''s beat or its deliberate stop under this container'\''s boot' \
'record-boot:Record this container'\''s boot, once' \
'report:Say whether a landing was in flight when the previous container was replaced' \
'tally:Count every recorded replacement by what it interrupted' \
    )
    _describe -t commands 'batten record help census commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__note_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__note_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help census note commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__record-boot_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__record-boot_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help census record-boot commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__report_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__report_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help census report commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__tally_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__census__subcmd__tally_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help census tally commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__closes_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__decide_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__decide_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help decide commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__derive_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__derive_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help derive commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__divergence_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__divergence_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help divergence commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__fold_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__fold_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help fold commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__forge_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__journal_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__journal_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help journal commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__keyed_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__keyed_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help keyed commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__named_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__named_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help named commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__nonverdict_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__nonverdict_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help nonverdict commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__plan_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__probe_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help probe commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__query_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help query commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__release_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help release commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__show_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help show commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__suites_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__tool_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help tool commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__validate_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__validate_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help validate commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__journal_commands] )) ||
_batten__subcmd__record__subcmd__journal_commands() {
    local commands; commands=()
    _describe -t commands 'batten record journal commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__keyed_commands] )) ||
_batten__subcmd__record__subcmd__keyed_commands() {
    local commands; commands=()
    _describe -t commands 'batten record keyed commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__named_commands] )) ||
_batten__subcmd__record__subcmd__named_commands() {
    local commands; commands=()
    _describe -t commands 'batten record named commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__nonverdict_commands] )) ||
_batten__subcmd__record__subcmd__nonverdict_commands() {
    local commands; commands=()
    _describe -t commands 'batten record nonverdict commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__plan_commands] )) ||
_batten__subcmd__record__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten record plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__probe_commands] )) ||
_batten__subcmd__record__subcmd__probe_commands() {
    local commands; commands=()
    _describe -t commands 'batten record probe commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__query_commands] )) ||
_batten__subcmd__record__subcmd__query_commands() {
    local commands; commands=()
    _describe -t commands 'batten record query commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__release_commands] )) ||
_batten__subcmd__record__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten record release commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__show_commands] )) ||
_batten__subcmd__record__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'batten record show commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__suites_commands] )) ||
_batten__subcmd__record__subcmd__suites_commands() {
    local commands; commands=()
    _describe -t commands 'batten record suites commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__tool_commands] )) ||
_batten__subcmd__record__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten record tool commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__validate_commands] )) ||
_batten__subcmd__record__subcmd__validate_commands() {
    local commands; commands=()
    _describe -t commands 'batten record validate commands' commands "$@"
}
(( $+functions[_batten__subcmd__release_commands] )) ||
_batten__subcmd__release_commands() {
    local commands; commands=(
'install:Decide whether install.sh, the release matrix and the binstall manifest agree on every asset name, and that no binary is committed' \
'sums:Hash a published release'\''s own assets into a checksum manifest, never the manifest itself' \
'backfill:Dispatch a backfill workflow once per release tag, oldest first, waiting on each run and stopping at the first that does not succeed' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten release commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__backfill_commands] )) ||
_batten__subcmd__release__subcmd__backfill_commands() {
    local commands; commands=()
    _describe -t commands 'batten release backfill commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__help_commands] )) ||
_batten__subcmd__release__subcmd__help_commands() {
    local commands; commands=(
'install:Decide whether install.sh, the release matrix and the binstall manifest agree on every asset name, and that no binary is committed' \
'sums:Hash a published release'\''s own assets into a checksum manifest, never the manifest itself' \
'backfill:Dispatch a backfill workflow once per release tag, oldest first, waiting on each run and stopping at the first that does not succeed' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten release help commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__help__subcmd__backfill_commands] )) ||
_batten__subcmd__release__subcmd__help__subcmd__backfill_commands() {
    local commands; commands=()
    _describe -t commands 'batten release help backfill commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__release__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten release help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__help__subcmd__install_commands] )) ||
_batten__subcmd__release__subcmd__help__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'batten release help install commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__help__subcmd__sums_commands] )) ||
_batten__subcmd__release__subcmd__help__subcmd__sums_commands() {
    local commands; commands=()
    _describe -t commands 'batten release help sums commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__install_commands] )) ||
_batten__subcmd__release__subcmd__install_commands() {
    local commands; commands=()
    _describe -t commands 'batten release install commands' commands "$@"
}
(( $+functions[_batten__subcmd__release__subcmd__sums_commands] )) ||
_batten__subcmd__release__subcmd__sums_commands() {
    local commands; commands=()
    _describe -t commands 'batten release sums commands' commands "$@"
}
(( $+functions[_batten__subcmd__sbom_commands] )) ||
_batten__subcmd__sbom_commands() {
    local commands; commands=()
    _describe -t commands 'batten sbom commands' commands "$@"
}
(( $+functions[_batten__subcmd__semver_commands] )) ||
_batten__subcmd__semver_commands() {
    local commands; commands=(
'check:Refuse an API break this branch'\''s commits do not declare' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten semver commands' commands "$@"
}
(( $+functions[_batten__subcmd__semver__subcmd__check_commands] )) ||
_batten__subcmd__semver__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten semver check commands' commands "$@"
}
(( $+functions[_batten__subcmd__semver__subcmd__help_commands] )) ||
_batten__subcmd__semver__subcmd__help_commands() {
    local commands; commands=(
'check:Refuse an API break this branch'\''s commits do not declare' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten semver help commands' commands "$@"
}
(( $+functions[_batten__subcmd__semver__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__semver__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten semver help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__semver__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__semver__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten semver help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__show_commands] )) ||
_batten__subcmd__show_commands() {
    local commands; commands=(
'agent:What an agent may do in this repository\: the read-only verbs, the exit contract, and the declared gates' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten show commands' commands "$@"
}
(( $+functions[_batten__subcmd__show__subcmd__agent_commands] )) ||
_batten__subcmd__show__subcmd__agent_commands() {
    local commands; commands=()
    _describe -t commands 'batten show agent commands' commands "$@"
}
(( $+functions[_batten__subcmd__show__subcmd__help_commands] )) ||
_batten__subcmd__show__subcmd__help_commands() {
    local commands; commands=(
'agent:What an agent may do in this repository\: the read-only verbs, the exit contract, and the declared gates' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten show help commands' commands "$@"
}
(( $+functions[_batten__subcmd__show__subcmd__help__subcmd__agent_commands] )) ||
_batten__subcmd__show__subcmd__help__subcmd__agent_commands() {
    local commands; commands=()
    _describe -t commands 'batten show help agent commands' commands "$@"
}
(( $+functions[_batten__subcmd__show__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__show__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten show help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton_commands] )) ||
_batten__subcmd__singleton_commands() {
    local commands; commands=(
'acquire:Take a task'\''s lock for a pid, or refuse naming the process that holds it' \
'release:Drop a task'\''s lock, which its exit trap does and a kill cannot' \
'detach:Run a command in the background under a task'\''s lock, and report the previous run'\''s failure' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten singleton commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__acquire_commands] )) ||
_batten__subcmd__singleton__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__detach_commands] )) ||
_batten__subcmd__singleton__subcmd__detach_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton detach commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__help_commands] )) ||
_batten__subcmd__singleton__subcmd__help_commands() {
    local commands; commands=(
'acquire:Take a task'\''s lock for a pid, or refuse naming the process that holds it' \
'release:Drop a task'\''s lock, which its exit trap does and a kill cannot' \
'detach:Run a command in the background under a task'\''s lock, and report the previous run'\''s failure' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten singleton help commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__help__subcmd__acquire_commands] )) ||
_batten__subcmd__singleton__subcmd__help__subcmd__acquire_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton help acquire commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__help__subcmd__detach_commands] )) ||
_batten__subcmd__singleton__subcmd__help__subcmd__detach_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton help detach commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__singleton__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__help__subcmd__release_commands] )) ||
_batten__subcmd__singleton__subcmd__help__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton help release commands' commands "$@"
}
(( $+functions[_batten__subcmd__singleton__subcmd__release_commands] )) ||
_batten__subcmd__singleton__subcmd__release_commands() {
    local commands; commands=()
    _describe -t commands 'batten singleton release commands' commands "$@"
}
(( $+functions[_batten__subcmd__spec_commands] )) ||
_batten__subcmd__spec_commands() {
    local commands; commands=()
    _describe -t commands 'batten spec commands' commands "$@"
}
(( $+functions[_batten__subcmd__startup_commands] )) ||
_batten__subcmd__startup_commands() {
    local commands; commands=()
    _describe -t commands 'batten startup commands' commands "$@"
}
(( $+functions[_batten__subcmd__state_commands] )) ||
_batten__subcmd__state_commands() {
    local commands; commands=(
'adopt:Bind this checkout to its findings store, minting one only if none exists' \
'record:Record this ref'\''s findings into the store, and GC instances whose ref is gone' \
'migrate:Upgrade the findings store to this binary'\''s record version' \
'settle:Record what was decided about a stored finding' \
'list:List stored findings and the refs they were observed in' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten state commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__adopt_commands] )) ||
_batten__subcmd__state__subcmd__adopt_commands() {
    local commands; commands=()
    _describe -t commands 'batten state adopt commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help_commands] )) ||
_batten__subcmd__state__subcmd__help_commands() {
    local commands; commands=(
'adopt:Bind this checkout to its findings store, minting one only if none exists' \
'record:Record this ref'\''s findings into the store, and GC instances whose ref is gone' \
'migrate:Upgrade the findings store to this binary'\''s record version' \
'settle:Record what was decided about a stored finding' \
'list:List stored findings and the refs they were observed in' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten state help commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__adopt_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__adopt_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help adopt commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__list_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help list commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__migrate_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__migrate_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help migrate commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__help__subcmd__settle_commands] )) ||
_batten__subcmd__state__subcmd__help__subcmd__settle_commands() {
    local commands; commands=()
    _describe -t commands 'batten state help settle commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__list_commands] )) ||
_batten__subcmd__state__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'batten state list commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__migrate_commands] )) ||
_batten__subcmd__state__subcmd__migrate_commands() {
    local commands; commands=()
    _describe -t commands 'batten state migrate commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__record_commands] )) ||
_batten__subcmd__state__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten state record commands' commands "$@"
}
(( $+functions[_batten__subcmd__state__subcmd__settle_commands] )) ||
_batten__subcmd__state__subcmd__settle_commands() {
    local commands; commands=()
    _describe -t commands 'batten state settle commands' commands "$@"
}
(( $+functions[_batten__subcmd__step_commands] )) ||
_batten__subcmd__step_commands() {
    local commands; commands=(
'check:Say hit or miss for a step'\''s inputs, arguments and tools, and remember the key a record must match' \
'record:Record that a step passed, refusing when its inputs changed since the paired check' \
'run:Run a step'\''s command only when its receipt misses, and record the receipt when it passes' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten step commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__check_commands] )) ||
_batten__subcmd__step__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten step check commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__help_commands] )) ||
_batten__subcmd__step__subcmd__help_commands() {
    local commands; commands=(
'check:Say hit or miss for a step'\''s inputs, arguments and tools, and remember the key a record must match' \
'record:Record that a step passed, refusing when its inputs changed since the paired check' \
'run:Run a step'\''s command only when its receipt misses, and record the receipt when it passes' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten step help commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__step__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten step help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__step__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten step help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__step__subcmd__help__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten step help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__help__subcmd__run_commands] )) ||
_batten__subcmd__step__subcmd__help__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'batten step help run commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__record_commands] )) ||
_batten__subcmd__step__subcmd__record_commands() {
    local commands; commands=()
    _describe -t commands 'batten step record commands' commands "$@"
}
(( $+functions[_batten__subcmd__step__subcmd__run_commands] )) ||
_batten__subcmd__step__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'batten step run commands' commands "$@"
}
(( $+functions[_batten__subcmd__target_commands] )) ||
_batten__subcmd__target_commands() {
    local commands; commands=(
'prune:Reclaim superseded build artifacts, and refuse below the measured disk floor for the build the next lap will run' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten target commands' commands "$@"
}
(( $+functions[_batten__subcmd__target__subcmd__help_commands] )) ||
_batten__subcmd__target__subcmd__help_commands() {
    local commands; commands=(
'prune:Reclaim superseded build artifacts, and refuse below the measured disk floor for the build the next lap will run' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten target help commands' commands "$@"
}
(( $+functions[_batten__subcmd__target__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__target__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten target help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__target__subcmd__help__subcmd__prune_commands] )) ||
_batten__subcmd__target__subcmd__help__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten target help prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__target__subcmd__prune_commands] )) ||
_batten__subcmd__target__subcmd__prune_commands() {
    local commands; commands=()
    _describe -t commands 'batten target prune commands' commands "$@"
}
(( $+functions[_batten__subcmd__task_commands] )) ||
_batten__subcmd__task_commands() {
    local commands; commands=(
'register:Record that a task has started, under its pid' \
'phase:Record what a registered task is now doing' \
'tick:Record that a task'\''s loop went round' \
'sig:Record that the world a task is watching moved' \
'unregister:Drop a task'\''s record, which its exit path does and a kill cannot' \
'read:One field of one task'\''s record, so a prober composes rather than parsing the layout' \
'alive:What tasks are running right now and what phase each is in — one call, no log reading' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten task commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__alive_commands] )) ||
_batten__subcmd__task__subcmd__alive_commands() {
    local commands; commands=()
    _describe -t commands 'batten task alive commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help_commands] )) ||
_batten__subcmd__task__subcmd__help_commands() {
    local commands; commands=(
'register:Record that a task has started, under its pid' \
'phase:Record what a registered task is now doing' \
'tick:Record that a task'\''s loop went round' \
'sig:Record that the world a task is watching moved' \
'unregister:Drop a task'\''s record, which its exit path does and a kill cannot' \
'read:One field of one task'\''s record, so a prober composes rather than parsing the layout' \
'alive:What tasks are running right now and what phase each is in — one call, no log reading' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten task help commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__alive_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__alive_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help alive commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__phase_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__phase_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help phase commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__read_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help read commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__register_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__register_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help register commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__sig_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__sig_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help sig commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__tick_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__tick_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help tick commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__help__subcmd__unregister_commands] )) ||
_batten__subcmd__task__subcmd__help__subcmd__unregister_commands() {
    local commands; commands=()
    _describe -t commands 'batten task help unregister commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__phase_commands] )) ||
_batten__subcmd__task__subcmd__phase_commands() {
    local commands; commands=()
    _describe -t commands 'batten task phase commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__read_commands] )) ||
_batten__subcmd__task__subcmd__read_commands() {
    local commands; commands=()
    _describe -t commands 'batten task read commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__register_commands] )) ||
_batten__subcmd__task__subcmd__register_commands() {
    local commands; commands=()
    _describe -t commands 'batten task register commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__sig_commands] )) ||
_batten__subcmd__task__subcmd__sig_commands() {
    local commands; commands=()
    _describe -t commands 'batten task sig commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__tick_commands] )) ||
_batten__subcmd__task__subcmd__tick_commands() {
    local commands; commands=()
    _describe -t commands 'batten task tick commands' commands "$@"
}
(( $+functions[_batten__subcmd__task__subcmd__unregister_commands] )) ||
_batten__subcmd__task__subcmd__unregister_commands() {
    local commands; commands=()
    _describe -t commands 'batten task unregister commands' commands "$@"
}
(( $+functions[_batten__subcmd__verdict_commands] )) ||
_batten__subcmd__verdict_commands() {
    local commands; commands=()
    _describe -t commands 'batten verdict commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring_commands] )) ||
_batten__subcmd__wiring_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
'gate:Link this clone'\''s two commit hooks to a hook body the repository checks in' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten wiring commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__gate_commands] )) ||
_batten__subcmd__wiring__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten wiring gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__help_commands] )) ||
_batten__subcmd__wiring__subcmd__help_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
'gate:Link this clone'\''s two commit hooks to a hook body the repository checks in' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten wiring help commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__help__subcmd__gate_commands] )) ||
_batten__subcmd__wiring__subcmd__help__subcmd__gate_commands() {
    local commands; commands=()
    _describe -t commands 'batten wiring help gate commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__wiring__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten wiring help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__help__subcmd__reclaim_commands] )) ||
_batten__subcmd__wiring__subcmd__help__subcmd__reclaim_commands() {
    local commands; commands=()
    _describe -t commands 'batten wiring help reclaim commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__reclaim_commands] )) ||
_batten__subcmd__wiring__subcmd__reclaim_commands() {
    local commands; commands=()
    _describe -t commands 'batten wiring reclaim commands' commands "$@"
}
(( $+functions[_batten__subcmd__worktree_commands] )) ||
_batten__subcmd__worktree_commands() {
    local commands; commands=(
'status:Report work that is uncommitted, unpushed, or not landed on the configured target' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten worktree commands' commands "$@"
}
(( $+functions[_batten__subcmd__worktree__subcmd__help_commands] )) ||
_batten__subcmd__worktree__subcmd__help_commands() {
    local commands; commands=(
'status:Report work that is uncommitted, unpushed, or not landed on the configured target' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten worktree help commands' commands "$@"
}
(( $+functions[_batten__subcmd__worktree__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__worktree__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten worktree help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__worktree__subcmd__help__subcmd__status_commands] )) ||
_batten__subcmd__worktree__subcmd__help__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten worktree help status commands' commands "$@"
}
(( $+functions[_batten__subcmd__worktree__subcmd__status_commands] )) ||
_batten__subcmd__worktree__subcmd__status_commands() {
    local commands; commands=()
    _describe -t commands 'batten worktree status commands' commands "$@"
}

if [ "$funcstack[1]" = "_batten" ]; then
    _batten "$@"
else
    compdef _batten batten
fi

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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
            (check)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(enforce)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--jobs=[How many of a \`\:\:\:\` bundle'\''s commands run at once]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--lines=[A 1-indexed inclusive line range, \`FROM\:TO\`, clamped to the capture]: :_default' \
'--grep=[Only lines containing this literal substring]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
':handle -- The `<stream>\:<digest>` handle to read:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'--stream=[Only captures of this stream]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(prune)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(config)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(lint)
_arguments "${_arguments_options[@]}" : \
'--host-rules=[Compare the committed \[ci\] table against a host ruleset payload (path, or - for stdin)]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(init)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--surface=[Which config surface to describe\: the committed authority, or the override layer]: :((authority\:"The committed authority\: \`batten.toml\`"
override\:"The raise-only override layer\: \`batten.local.toml\`"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(policy)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(commit)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--message=[Judge one pending commit message file, before the commit exists]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(attribution)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--message=[Judge one pending commit message file, before the commit exists]: :_default' \
'--harness=[Report the attribution capabilities this host declares, and capture at that fidelity]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(identity)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(identity)
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(provision)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(hook)
_arguments "${_arguments_options[@]}" : \
'--harness=[The harness whose payload to decode and whose decision channel to answer in]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
cursor\:"Cursor. Two payload families under one host\: a generic \`preToolUse\` that looks like Claude'\''s, and specialized events (\`beforeShellExecution\`, \`beforeReadFile\`, \`beforeMCPExecution\`) that carry the operand at top level and **no** \`tool_name\` at all. Session is \`conversation_id\`"
copilot-cli\:"GitHub Copilot CLI, registered in its **\`PascalCase\`** dialect — which yields \`hook_event_name\` natively. The camelCase dialect omits the event name entirely, so Batten does not speak it"
gemini-cli\:"Gemini CLI. Claude-identical payload fields, different event names (\`BeforeTool\` rather than \`PreToolUse\`)"
codex-cli\:"Codex CLI, whose wire format is a near-verbatim clone of Claude Code'\''s — its own repo says so. No payload shim is needed; the adapter exists so the host is nameable and its fixture is pinned against drift"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
run-in-background\:"Whether the host was asked to run this call in the background"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
            (record)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--key=[Which git fact the receipt is judged against\: the exact commit, or the branch]: :((head\:"Keyed to the exact commit; an amend, a rebase, or a moved trunk expires it"
branch\:"Keyed to the branch; every commit on it continues to serve the claim"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
            (record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
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
(defects)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--class=[Only records in this taxonomy class]: :_default' \
'--id=[Only the record with this id]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
(list)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
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
&& ret=0
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
        esac
    ;;
esac
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
(identity)
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
(hook)
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
            (record)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(status)
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
(list)
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
'check:Run the applicable read-only gates against the repository' \
'enforce:Run every configured rule, including kinds that execute a configured command' \
'exec:Run a command — or a \`\:\:\:\` bundle — and report a pointer to what it wrote' \
'capture:Captured command output\: navigate what \`exec\` already ran, without running it again' \
'config:Inspect configuration' \
'lint:Lint an artifact against a declared schema' \
'spec:Print the tool'\''s own command spec' \
'doctor:Diagnose whether Batten can run in this repository' \
'init:Write a starter batten.toml, refusing to overwrite an existing one' \
'baseline:Record the findings that already exist, so only new ones fail' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'policy:Inspect the thresholds and path sets this repository holds itself to' \
'commit:The shape a commit must take here\: what its subject may say' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten commands' commands "$@"
}
(( $+functions[_batten__subcmd__attribution_commands] )) ||
_batten__subcmd__attribution_commands() {
    local commands; commands=(
'check:Refuse vendor authorship, branding or session links in commit metadata' \
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
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
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
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
(( $+functions[_batten__subcmd__attribution__subcmd__identity_commands] )) ||
_batten__subcmd__attribution__subcmd__identity_commands() {
    local commands; commands=()
    _describe -t commands 'batten attribution identity commands' commands "$@"
}
(( $+functions[_batten__subcmd__baseline_commands] )) ||
_batten__subcmd__baseline_commands() {
    local commands; commands=()
    _describe -t commands 'batten baseline commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture_commands] )) ||
_batten__subcmd__capture_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten capture commands' commands "$@"
}
(( $+functions[_batten__subcmd__capture__subcmd__help_commands] )) ||
_batten__subcmd__capture__subcmd__help_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten capture help commands' commands "$@"
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
(( $+functions[_batten__subcmd__check_commands] )) ||
_batten__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten check commands' commands "$@"
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
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config commands' commands "$@"
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
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config help commands' commands "$@"
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
(( $+functions[_batten__subcmd__doctor_commands] )) ||
_batten__subcmd__doctor_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor commands' commands "$@"
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
'schema:Emit the JSON Schema for a config surface, derived from the config types' \
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
'schema:Emit the JSON Schema for a config surface, derived from the config types' \
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
'check:Run the applicable read-only gates against the repository' \
'enforce:Run every configured rule, including kinds that execute a configured command' \
'exec:Run a command — or a \`\:\:\:\` bundle — and report a pointer to what it wrote' \
'capture:Captured command output\: navigate what \`exec\` already ran, without running it again' \
'config:Inspect configuration' \
'lint:Lint an artifact against a declared schema' \
'spec:Print the tool'\''s own command spec' \
'doctor:Diagnose whether Batten can run in this repository' \
'init:Write a starter batten.toml, refusing to overwrite an existing one' \
'baseline:Record the findings that already exist, so only new ones fail' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'policy:Inspect the thresholds and path sets this repository holds itself to' \
'commit:The shape a commit must take here\: what its subject may say' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten help commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__attribution_commands] )) ||
_batten__subcmd__help__subcmd__attribution_commands() {
    local commands; commands=(
'check:Refuse vendor authorship, branding or session links in commit metadata' \
'identity:Set this clone'\''s repo-local git identity when it is unset or denied' \
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
(( $+functions[_batten__subcmd__help__subcmd__baseline_commands] )) ||
_batten__subcmd__help__subcmd__baseline_commands() {
    local commands; commands=()
    _describe -t commands 'batten help baseline commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__capture_commands] )) ||
_batten__subcmd__help__subcmd__capture_commands() {
    local commands; commands=(
'show:Print a capture'\''s pointer, or the lines a selection asks for, with no second run' \
'list:List this repository'\''s captures as handles, in a fixed order' \
'prune:Remove this repository'\''s captures — the one removal path; captures never expire on their own' \
    )
    _describe -t commands 'batten help capture commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help check commands' commands "$@"
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
'lint:Report policy smells in batten.toml (any smell is a violation)' \
    )
    _describe -t commands 'batten help config commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__doctor_commands] )) ||
_batten__subcmd__help__subcmd__doctor_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor commands' commands "$@"
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
'schema:Emit the JSON Schema for a config surface, derived from the config types' \
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
(( $+functions[_batten__subcmd__help__subcmd__hook_commands] )) ||
_batten__subcmd__help__subcmd__hook_commands() {
    local commands; commands=()
    _describe -t commands 'batten help hook commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__init_commands] )) ||
_batten__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'batten help init commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__policy_commands] )) ||
_batten__subcmd__help__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
    )
    _describe -t commands 'batten help policy commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy__subcmd__budget_commands] )) ||
_batten__subcmd__help__subcmd__policy__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten help policy budget commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__receipt_commands] )) ||
_batten__subcmd__help__subcmd__receipt_commands() {
    local commands; commands=(
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
    )
    _describe -t commands 'batten help receipt commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__spec_commands] )) ||
_batten__subcmd__help__subcmd__spec_commands() {
    local commands; commands=()
    _describe -t commands 'batten help spec commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__state_commands] )) ||
_batten__subcmd__help__subcmd__state_commands() {
    local commands; commands=(
'adopt:Bind this checkout to its findings store, minting one only if none exists' \
'record:Record this ref'\''s findings into the store, and GC instances whose ref is gone' \
'migrate:Upgrade the findings store to this binary'\''s record version' \
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
(( $+functions[_batten__subcmd__hook_commands] )) ||
_batten__subcmd__hook_commands() {
    local commands; commands=()
    _describe -t commands 'batten hook commands' commands "$@"
}
(( $+functions[_batten__subcmd__init_commands] )) ||
_batten__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'batten init commands' commands "$@"
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
(( $+functions[_batten__subcmd__policy_commands] )) ||
_batten__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten policy commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__budget_commands] )) ||
_batten__subcmd__policy__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy budget commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help_commands] )) ||
_batten__subcmd__policy__subcmd__help_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten policy help commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__budget_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__budget_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help budget commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__policy__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten policy help help commands' commands "$@"
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
(( $+functions[_batten__subcmd__receipt_commands] )) ||
_batten__subcmd__receipt_commands() {
    local commands; commands=(
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten receipt commands' commands "$@"
}
(( $+functions[_batten__subcmd__receipt__subcmd__help_commands] )) ||
_batten__subcmd__receipt__subcmd__help_commands() {
    local commands; commands=(
'record:Record that the named check concluded pass against the current HEAD' \
'status:Judge the named check'\''s recorded receipt against HEAD and origin/main' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten receipt help commands' commands "$@"
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
(( $+functions[_batten__subcmd__spec_commands] )) ||
_batten__subcmd__spec_commands() {
    local commands; commands=()
    _describe -t commands 'batten spec commands' commands "$@"
}
(( $+functions[_batten__subcmd__state_commands] )) ||
_batten__subcmd__state_commands() {
    local commands; commands=(
'adopt:Bind this checkout to its findings store, minting one only if none exists' \
'record:Record this ref'\''s findings into the store, and GC instances whose ref is gone' \
'migrate:Upgrade the findings store to this binary'\''s record version' \
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

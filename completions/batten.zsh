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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--rule=[Run only the declared rule with this id]: :_default' \
'--since=[Judge only the paths changed against this rev]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--bytes=[A 0-indexed half-open byte range, \`FROM\:TO\`, either side omittable, clamped to the capture]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'*--tool=[The tool whose response to resolve, matched whole or as a \`__\`-delimited final segment; repeatable]: :_default' \
'--key-at=[The dotted path the key sits at in the response]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--stream=[Only captures of this stream]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--root=[The build directory to prune, instead of the configured one]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
(config)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--host-rules=[Compare the committed \[ci\] table against a host ruleset payload (path, or - for stdin)]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (hooks)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (hooks)
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--issue=[Resolve the payload from the capture store by this issue key instead of reading stdin]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
(checks)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--required=[Comma-separated check names that carry a verdict about this repository]: :_default' \
'--absent-ok=[Comma-separated check names for which having no run at all is a legitimate reading]: :_default' \
'--answered=[Comma-separated conclusions that constitute an answer; anything else is not yet one]: :_default' \
'--fanin=[The fan-in check whose failure a cancelled sibling can manufacture]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--sha=[The commit whose check runs to read]: :_default' \
'--repo=[The repository to read, in the forge client'\''s own spelling]: :_default' \
'--interval=[Seconds between requests; a server-requested floor raises it and nothing lowers it]: :_default' \
'--progress=[Program to record the poll'\''s tick and reading-change signals]: :_default' \
'--progress-id=[The identity the progress recorder keys its entries on]: :_default' \
'--required=[Comma-separated check names that carry a verdict about this repository]: :_default' \
'--absent-ok=[Comma-separated check names for which having no run at all is a legitimate reading]: :_default' \
'--answered=[Comma-separated conclusions that constitute an answer; anything else is not yet one]: :_default' \
'--fanin=[The fan-in check whose failure a cancelled sibling can manufacture]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (check)
_arguments "${_arguments_options[@]}" : \
'--adopt-from=[The branch name the receipt being adopted was minted under]: :_default' \
'--issue=[Resolve the payload from the capture store by this issue key instead of reading stdin]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(bot)
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--baseline=[The rev to measure the API delta against (default\: origin/main)]: :_default' \
'--release-type=[The bump being claimed, which is what the delta is judged against]: :_default' \
'--package=[The package whose public API is compared (default\: batten)]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--rule=[The rule whose refusal is being overridden]: :_default' \
'--verdict=[The verdict token that refusal carries, e.g. diff ship early]: :_default' \
'--subject=[The gate'\''s canonical subject, exactly as its refusal names it]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--admission=[The admission address to spend]: :_default' \
'--rule=[The rule whose refusal is being overridden]: :_default' \
'--verdict=[The verdict token that refusal carries, e.g. diff ship early]: :_default' \
'--subject=[The gate'\''s canonical subject, exactly as its refusal names it]: :_default' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
branch\:"Keyed to the branch; every commit on it continues to serve the claim"
named\:"Keyed to a value the CALL names, read through \[\`Rule\:\:key_from\`\] (CLOUD-987)"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (tool)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
':ref -- The ref or sha the verdict was taken against:_default' \
&& ret=0
;;
(plan)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
":: :_batten__subcmd__record__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:batten-record-help-command-$line[1]:"
        case $line[1] in
            (tool)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--config-in=[Read the committed config from this directory instead of the directory being judged]: :_default' \
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
            (hooks)
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
            (check)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(bot)
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
            (tool)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(forge)
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
'mcp:Dispatch a declared MCP call and hand back a reduction instead of the payload' \
'target:Inspect and reclaim this repository'\''s build tree' \
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
'commit:The shape a commit must take here\: what its subject may say' \
'ready:Whether an issue'\''s Ready block satisfies the checkable clauses of the gate' \
'checks:Whether a commit'\''s check runs answer the question a landing depends on' \
'pr:The pull request a landing drives, and the answers it waits on' \
'claim:Whether the issue you are about to pull is actually unclaimed' \
'semver:Whether this branch'\''s API delta is compatible with the bump it claims' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'override:Issued admissions\: an override is a record, never a variable somebody knows' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'record:Out-of-tree verdict stores\: what something else judged, keyed so a stale answer cannot answer' \
'wiring:Repair a host'\''s hook registrations' \
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
(( $+functions[_batten__subcmd__claim_commands] )) ||
_batten__subcmd__claim_commands() {
    local commands; commands=(
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
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
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
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
(( $+functions[_batten__subcmd__doctor_commands] )) ||
_batten__subcmd__doctor_commands() {
    local commands; commands=(
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten doctor commands' commands "$@"
}
(( $+functions[_batten__subcmd__doctor__subcmd__help_commands] )) ||
_batten__subcmd__doctor__subcmd__help_commands() {
    local commands; commands=(
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten doctor help commands' commands "$@"
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
(( $+functions[_batten__subcmd__doctor__subcmd__hooks_commands] )) ||
_batten__subcmd__doctor__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten doctor hooks commands' commands "$@"
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
'check:Run the applicable read-only gates against the repository' \
'enforce:Run every configured rule, including kinds that execute a configured command' \
'exec:Run a command — or a \`\:\:\:\` bundle — and report a pointer to what it wrote' \
'capture:Captured command output\: navigate what \`exec\` already ran, without running it again' \
'mcp:Dispatch a declared MCP call and hand back a reduction instead of the payload' \
'target:Inspect and reclaim this repository'\''s build tree' \
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
'commit:The shape a commit must take here\: what its subject may say' \
'ready:Whether an issue'\''s Ready block satisfies the checkable clauses of the gate' \
'checks:Whether a commit'\''s check runs answer the question a landing depends on' \
'pr:The pull request a landing drives, and the answers it waits on' \
'claim:Whether the issue you are about to pull is actually unclaimed' \
'semver:Whether this branch'\''s API delta is compatible with the bump it claims' \
'attribution:What produced commits may carry about the tooling that made them' \
'worktree:Worktrees and the work in them\: what is at risk' \
'override:Issued admissions\: an override is a record, never a variable somebody knows' \
'provision:Pinned tools this repository provisions, cached out of tree' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'payload:Read a hook payload from stdin' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'defects:The append-only defect ledger\: the lessons this repository has already paid for' \
'design:Design-evidence claims\: the integrity of the record behind a decision' \
'state:The out-of-tree findings store\: which store belongs to this checkout' \
'record:Out-of-tree verdict stores\: what something else judged, keyed so a stale answer cannot answer' \
'wiring:Repair a host'\''s hook registrations' \
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
(( $+functions[_batten__subcmd__help__subcmd__claim_commands] )) ||
_batten__subcmd__help__subcmd__claim_commands() {
    local commands; commands=(
'check:Refuse a pull of an issue somebody is already on, and mint the receipt when it is free' \
'bot:Attest a bot branch from the lane'\''s public facts, and mint the receipt when they hold' \
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
(( $+functions[_batten__subcmd__help__subcmd__doctor_commands] )) ||
_batten__subcmd__help__subcmd__doctor_commands() {
    local commands; commands=(
'hooks:Diagnose whether batten is wired on every hook surface of every harness' \
    )
    _describe -t commands 'batten help doctor commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__doctor__subcmd__hooks_commands] )) ||
_batten__subcmd__help__subcmd__doctor__subcmd__hooks_commands() {
    local commands; commands=()
    _describe -t commands 'batten help doctor hooks commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__mcp_commands] )) ||
_batten__subcmd__help__subcmd__mcp_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
    )
    _describe -t commands 'batten help mcp commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__mcp__subcmd__call_commands] )) ||
_batten__subcmd__help__subcmd__mcp__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten help mcp call commands' commands "$@"
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
    )
    _describe -t commands 'batten help perf commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__perf__subcmd__pair_commands] )) ||
_batten__subcmd__help__subcmd__perf__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten help perf pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__policy_commands] )) ||
_batten__subcmd__help__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'hooks:Judge this session'\''s hook output against its declared per-session budget' \
'test:Run each registered module'\''s own \`test_\` rules and report the predicates none exercised' \
'tools:Print the tool names the mediated-call rows decide, one per line' \
'explain:Resolve a verdict token to its class definition and the routes out of it' \
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
(( $+functions[_batten__subcmd__help__subcmd__record_commands] )) ||
_batten__subcmd__help__subcmd__record_commands() {
    local commands; commands=(
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
    )
    _describe -t commands 'batten help record commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__closes_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__forge_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__plan_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__record__subcmd__tool_commands] )) ||
_batten__subcmd__help__subcmd__record__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten help record tool commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__wiring_commands] )) ||
_batten__subcmd__help__subcmd__wiring_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
    )
    _describe -t commands 'batten help wiring commands' commands "$@"
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
(( $+functions[_batten__subcmd__mcp_commands] )) ||
_batten__subcmd__mcp_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mcp commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__call_commands] )) ||
_batten__subcmd__mcp__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp call commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help_commands] )) ||
_batten__subcmd__mcp__subcmd__help_commands() {
    local commands; commands=(
'call:Dispatch one declared method, store the response, and print the declared reduction' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten mcp help commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__call_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__call_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help call commands' commands "$@"
}
(( $+functions[_batten__subcmd__mcp__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__mcp__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten mcp help help commands' commands "$@"
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
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten perf commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help_commands] )) ||
_batten__subcmd__perf__subcmd__help_commands() {
    local commands; commands=(
'pair:Measure this branch and its merge base back to back on one machine, and print both arms as paired records' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten perf help commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__help_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help help commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__help__subcmd__pair_commands] )) ||
_batten__subcmd__perf__subcmd__help__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf help pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__perf__subcmd__pair_commands] )) ||
_batten__subcmd__perf__subcmd__pair_commands() {
    local commands; commands=()
    _describe -t commands 'batten perf pair commands' commands "$@"
}
(( $+functions[_batten__subcmd__policy_commands] )) ||
_batten__subcmd__policy_commands() {
    local commands; commands=(
'budget:Judge the always-loaded instruction set against its declared token budget' \
'hooks:Judge this session'\''s hook output against its declared per-session budget' \
'test:Run each registered module'\''s own \`test_\` rules and report the predicates none exercised' \
'tools:Print the tool names the mediated-call rows decide, one per line' \
'explain:Resolve a verdict token to its class definition and the routes out of it' \
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
(( $+functions[_batten__subcmd__record_commands] )) ||
_batten__subcmd__record_commands() {
    local commands; commands=(
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__closes_commands] )) ||
_batten__subcmd__record__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten record closes commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__forge_commands] )) ||
_batten__subcmd__record__subcmd__forge_commands() {
    local commands; commands=()
    _describe -t commands 'batten record forge commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help_commands] )) ||
_batten__subcmd__record__subcmd__help_commands() {
    local commands; commands=(
'tool:Record a declared tool row'\''s verdict, read as \`<name> <token>\` lines on stdin' \
'forge:Record the forge'\''s check verdicts for one commit, read as \`<check> <conclusion>\` lines on stdin' \
'plan:Record this branch'\''s plan, read as \`<id> <status>\` lines on stdin' \
'closes:Record which rows this branch'\''s pull request body closes, read on stdin' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten record help commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__closes_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__closes_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help closes commands' commands "$@"
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
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__plan_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__help__subcmd__tool_commands] )) ||
_batten__subcmd__record__subcmd__help__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten record help tool commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__plan_commands] )) ||
_batten__subcmd__record__subcmd__plan_commands() {
    local commands; commands=()
    _describe -t commands 'batten record plan commands' commands "$@"
}
(( $+functions[_batten__subcmd__record__subcmd__tool_commands] )) ||
_batten__subcmd__record__subcmd__tool_commands() {
    local commands; commands=()
    _describe -t commands 'batten record tool commands' commands "$@"
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
(( $+functions[_batten__subcmd__wiring_commands] )) ||
_batten__subcmd__wiring_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten wiring commands' commands "$@"
}
(( $+functions[_batten__subcmd__wiring__subcmd__help_commands] )) ||
_batten__subcmd__wiring__subcmd__help_commands() {
    local commands; commands=(
'reclaim:Remove non-batten hook registrations from this host'\''s merged surfaces' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten wiring help commands' commands "$@"
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

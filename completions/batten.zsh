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
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'-J[Emit findings as byte-stable JSON instead of pointer lines]' \
'--json[Emit findings as byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'-J[Emit findings as byte-stable JSON instead of pointer lines]' \
'--json[Emit findings as byte-stable JSON instead of pointer lines]' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(config)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(lint)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
(spec)
_arguments "${_arguments_options[@]}" : \
'--format=[The output format for the spec]: :((json\:"Byte-stable JSON — the agent-facing contract (§6)"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(schema)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
(hook)
_arguments "${_arguments_options[@]}" : \
'--harness=[The harness whose payload to decode and whose decision channel to answer in]: :((claude-code\:"Claude Code'\''s \`PreToolUse\` payload; a deny is returned as the \`hookSpecificOutput.permissionDecision\` JSON object on stdout with exit \`0\` — the channel the production shell guards already use"
exit-code\:"The neutral core contract\: envelope in, decision as exit code out — \`0\` allow, \`2\` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table'\''s, unmodified"))' \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(receipt)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':check -- The check whose conclusion is being recorded:_default' \
&& ret=0
;;
(status)
_arguments "${_arguments_options[@]}" : \
'--strictness=[Raise how strictly gates apply (an override may only tighten policy)]: :((permissive\:"Advisory\: findings are reported without failing the run"
standard\:"The default\: a finding is a violation"
strict\:"Everything \`Standard\` fails on, plus anything advisory"))' \
'--config-from=[Read the committed config from a git ref (e.g. origin/main) instead of the working tree]: :_default' \
'--fail-on-warning[Promote a warn-severity finding to a violation (an override may only turn this on)]' \
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
(lint)
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
(schema)
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
'config:Inspect configuration' \
'spec:Print the tool'\''s own command spec' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten commands' commands "$@"
}
(( $+functions[_batten__subcmd__check_commands] )) ||
_batten__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten check commands' commands "$@"
}
(( $+functions[_batten__subcmd__config_commands] )) ||
_batten__subcmd__config_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config commands' commands "$@"
}
(( $+functions[_batten__subcmd__config__subcmd__help_commands] )) ||
_batten__subcmd__config__subcmd__help_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten config help commands' commands "$@"
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
(( $+functions[_batten__subcmd__enforce_commands] )) ||
_batten__subcmd__enforce_commands() {
    local commands; commands=()
    _describe -t commands 'batten enforce commands' commands "$@"
}
(( $+functions[_batten__subcmd__generate_commands] )) ||
_batten__subcmd__generate_commands() {
    local commands; commands=(
'completions:Emit the shell completion script for one shell' \
'schema:Emit the JSON Schema for batten.toml, derived from the config types' \
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
'schema:Emit the JSON Schema for batten.toml, derived from the config types' \
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
(( $+functions[_batten__subcmd__generate__subcmd__help__subcmd__schema_commands] )) ||
_batten__subcmd__generate__subcmd__help__subcmd__schema_commands() {
    local commands; commands=()
    _describe -t commands 'batten generate help schema commands' commands "$@"
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
'config:Inspect configuration' \
'spec:Print the tool'\''s own command spec' \
'generate:Emit artifacts derived from the command spec, on stdout' \
'hook:Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)' \
'receipt:Verification receipts\: SHA-keyed claims a named check passed, invalidated by git facts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'batten help commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__check_commands] )) ||
_batten__subcmd__help__subcmd__check_commands() {
    local commands; commands=()
    _describe -t commands 'batten help check commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__config_commands] )) ||
_batten__subcmd__help__subcmd__config_commands() {
    local commands; commands=(
'show:Print the effective configuration' \
'lint:Report policy smells in batten.toml (any smell is a violation)' \
    )
    _describe -t commands 'batten help config commands' commands "$@"
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
(( $+functions[_batten__subcmd__help__subcmd__enforce_commands] )) ||
_batten__subcmd__help__subcmd__enforce_commands() {
    local commands; commands=()
    _describe -t commands 'batten help enforce commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate_commands] )) ||
_batten__subcmd__help__subcmd__generate_commands() {
    local commands; commands=(
'completions:Emit the shell completion script for one shell' \
'schema:Emit the JSON Schema for batten.toml, derived from the config types' \
    )
    _describe -t commands 'batten help generate commands' commands "$@"
}
(( $+functions[_batten__subcmd__help__subcmd__generate__subcmd__completions_commands] )) ||
_batten__subcmd__help__subcmd__generate__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'batten help generate completions commands' commands "$@"
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
(( $+functions[_batten__subcmd__hook_commands] )) ||
_batten__subcmd__hook_commands() {
    local commands; commands=()
    _describe -t commands 'batten hook commands' commands "$@"
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

if [ "$funcstack[1]" = "_batten" ]; then
    _batten "$@"
else
    compdef _batten batten
fi

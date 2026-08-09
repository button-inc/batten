# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_batten_global_optspecs
    string join \n strictness= fail-on-warning config-from= h/help V/version
end

function __fish_batten_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_batten_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_batten_using_subcommand
    set -l cmd (__fish_batten_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c batten -n "__fish_batten_needs_command" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_needs_command" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_needs_command" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_needs_command" -s V -l version -d 'Print version'
complete -c batten -n "__fish_batten_needs_command" -f -a "check" -d 'Run the applicable read-only gates against the repository'
complete -c batten -n "__fish_batten_needs_command" -f -a "enforce" -d 'Run every configured rule, including kinds that execute a configured command'
complete -c batten -n "__fish_batten_needs_command" -f -a "config" -d 'Inspect configuration'
complete -c batten -n "__fish_batten_needs_command" -f -a "spec" -d 'Print the tool\'s own command spec'
complete -c batten -n "__fish_batten_needs_command" -f -a "doctor" -d 'Diagnose whether Batten can run in this repository'
complete -c batten -n "__fish_batten_needs_command" -f -a "generate" -d 'Emit artifacts derived from the command spec, on stdout'
complete -c batten -n "__fish_batten_needs_command" -f -a "hook" -d 'Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)'
complete -c batten -n "__fish_batten_needs_command" -f -a "receipt" -d 'Verification receipts: SHA-keyed claims a named check passed, invalidated by git facts'
complete -c batten -n "__fish_batten_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand check" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand check" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand check" -s J -l json -d 'Emit byte-stable JSON instead of pointer lines'
complete -c batten -n "__fish_batten_using_subcommand check" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand check" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand enforce" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand enforce" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand enforce" -s J -l json -d 'Emit byte-stable JSON instead of pointer lines'
complete -c batten -n "__fish_batten_using_subcommand enforce" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand enforce" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -f -a "show" -d 'Print the effective configuration'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -f -a "epoch" -d 'Print the content hash of the governing config surface'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -f -a "lint" -d 'Report policy smells in batten.toml (any smell is a violation)'
complete -c batten -n "__fish_batten_using_subcommand config; and not __fish_seen_subcommand_from show epoch lint help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from show" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from show" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from show" -s J -l json -d 'Emit byte-stable JSON instead of pointer lines'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from show" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from epoch" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from epoch" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from epoch" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from epoch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from lint" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from lint" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from lint" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from lint" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "show" -d 'Print the effective configuration'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "epoch" -d 'Print the content hash of the governing config surface'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "lint" -d 'Report policy smells in batten.toml (any smell is a violation)'
complete -c batten -n "__fish_batten_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand spec" -l format -d 'The output format for the spec' -r -f -a "json\t'Byte-stable JSON — the agent-facing contract (§6)'"
complete -c batten -n "__fish_batten_using_subcommand spec" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand spec" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand spec" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand spec" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand doctor" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand doctor" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand doctor" -s J -l json -d 'Emit byte-stable JSON instead of pointer lines'
complete -c batten -n "__fish_batten_using_subcommand doctor" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -f -a "completions" -d 'Emit the shell completion script for one shell'
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -f -a "schema" -d 'Emit the JSON Schema for batten.toml, derived from the config types'
complete -c batten -n "__fish_batten_using_subcommand generate; and not __fish_seen_subcommand_from completions schema help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from completions" -l shell -d 'The shell whose completion script to emit' -r -f -a "bash\t''
elvish\t''
fish\t''
powershell\t''
zsh\t''"
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from completions" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from completions" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from completions" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from schema" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from schema" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from schema" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from schema" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from help" -f -a "completions" -d 'Emit the shell completion script for one shell'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from help" -f -a "schema" -d 'Emit the JSON Schema for batten.toml, derived from the config types'
complete -c batten -n "__fish_batten_using_subcommand generate; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand hook" -l harness -d 'The harness whose payload to decode and whose decision channel to answer in' -r -f -a "claude-code\t'Claude Code\'s `PreToolUse` payload; a deny is returned as the `hookSpecificOutput.permissionDecision` JSON object on stdout with exit `0` — the channel the production shell guards already use'
exit-code\t'The neutral core contract: envelope in, decision as exit code out — `0` allow, `2` deny (reason on stderr), for any host whose only decision channel is an exit status. Both codes are the §7 table\'s, unmodified'"
complete -c batten -n "__fish_batten_using_subcommand hook" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand hook" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand hook" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand hook" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -f -a "record" -d 'Record that the named check concluded pass against the current HEAD'
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -f -a "status" -d 'Judge the named check\'s recorded receipt against HEAD and origin/main'
complete -c batten -n "__fish_batten_using_subcommand receipt; and not __fish_seen_subcommand_from record status help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from record" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from record" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from record" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from record" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from status" -l strictness -d 'Raise how strictly gates apply (an override may only tighten policy)' -r -f -a "permissive\t'Advisory: findings are reported without failing the run'
standard\t'The default: a finding is a violation'
strict\t'Everything `Standard` fails on, plus anything advisory'"
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from status" -l config-from -d 'Read the committed config from a git ref (e.g. origin/main) instead of the working tree' -r
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from status" -l fail-on-warning -d 'Promote a warn-severity finding to a violation (an override may only turn this on)'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from help" -f -a "record" -d 'Record that the named check concluded pass against the current HEAD'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from help" -f -a "status" -d 'Judge the named check\'s recorded receipt against HEAD and origin/main'
complete -c batten -n "__fish_batten_using_subcommand receipt; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "check" -d 'Run the applicable read-only gates against the repository'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "enforce" -d 'Run every configured rule, including kinds that execute a configured command'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "config" -d 'Inspect configuration'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "spec" -d 'Print the tool\'s own command spec'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "doctor" -d 'Diagnose whether Batten can run in this repository'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "generate" -d 'Emit artifacts derived from the command spec, on stdout'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "hook" -d 'Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "receipt" -d 'Verification receipts: SHA-keyed claims a named check passed, invalidated by git facts'
complete -c batten -n "__fish_batten_using_subcommand help; and not __fish_seen_subcommand_from check enforce config spec doctor generate hook receipt help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "show" -d 'Print the effective configuration'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "epoch" -d 'Print the content hash of the governing config surface'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "lint" -d 'Report policy smells in batten.toml (any smell is a violation)'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from generate" -f -a "completions" -d 'Emit the shell completion script for one shell'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from generate" -f -a "schema" -d 'Emit the JSON Schema for batten.toml, derived from the config types'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from receipt" -f -a "record" -d 'Record that the named check concluded pass against the current HEAD'
complete -c batten -n "__fish_batten_using_subcommand help; and __fish_seen_subcommand_from receipt" -f -a "status" -d 'Judge the named check\'s recorded receipt against HEAD and origin/main'

_batten() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="batten"
                ;;
            batten,check)
                cmd="batten__subcmd__check"
                ;;
            batten,config)
                cmd="batten__subcmd__config"
                ;;
            batten,doctor)
                cmd="batten__subcmd__doctor"
                ;;
            batten,enforce)
                cmd="batten__subcmd__enforce"
                ;;
            batten,exec)
                cmd="batten__subcmd__exec"
                ;;
            batten,generate)
                cmd="batten__subcmd__generate"
                ;;
            batten,help)
                cmd="batten__subcmd__help"
                ;;
            batten,hook)
                cmd="batten__subcmd__hook"
                ;;
            batten,policy)
                cmd="batten__subcmd__policy"
                ;;
            batten,receipt)
                cmd="batten__subcmd__receipt"
                ;;
            batten,spec)
                cmd="batten__subcmd__spec"
                ;;
            batten__subcmd__config,epoch)
                cmd="batten__subcmd__config__subcmd__epoch"
                ;;
            batten__subcmd__config,help)
                cmd="batten__subcmd__config__subcmd__help"
                ;;
            batten__subcmd__config,lint)
                cmd="batten__subcmd__config__subcmd__lint"
                ;;
            batten__subcmd__config,show)
                cmd="batten__subcmd__config__subcmd__show"
                ;;
            batten__subcmd__config__subcmd__help,epoch)
                cmd="batten__subcmd__config__subcmd__help__subcmd__epoch"
                ;;
            batten__subcmd__config__subcmd__help,help)
                cmd="batten__subcmd__config__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__config__subcmd__help,lint)
                cmd="batten__subcmd__config__subcmd__help__subcmd__lint"
                ;;
            batten__subcmd__config__subcmd__help,show)
                cmd="batten__subcmd__config__subcmd__help__subcmd__show"
                ;;
            batten__subcmd__generate,completions)
                cmd="batten__subcmd__generate__subcmd__completions"
                ;;
            batten__subcmd__generate,help)
                cmd="batten__subcmd__generate__subcmd__help"
                ;;
            batten__subcmd__generate,schema)
                cmd="batten__subcmd__generate__subcmd__schema"
                ;;
            batten__subcmd__generate__subcmd__help,completions)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__completions"
                ;;
            batten__subcmd__generate__subcmd__help,help)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__generate__subcmd__help,schema)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__schema"
                ;;
            batten__subcmd__help,check)
                cmd="batten__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__help,config)
                cmd="batten__subcmd__help__subcmd__config"
                ;;
            batten__subcmd__help,doctor)
                cmd="batten__subcmd__help__subcmd__doctor"
                ;;
            batten__subcmd__help,enforce)
                cmd="batten__subcmd__help__subcmd__enforce"
                ;;
            batten__subcmd__help,exec)
                cmd="batten__subcmd__help__subcmd__exec"
                ;;
            batten__subcmd__help,generate)
                cmd="batten__subcmd__help__subcmd__generate"
                ;;
            batten__subcmd__help,help)
                cmd="batten__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__help,hook)
                cmd="batten__subcmd__help__subcmd__hook"
                ;;
            batten__subcmd__help,policy)
                cmd="batten__subcmd__help__subcmd__policy"
                ;;
            batten__subcmd__help,receipt)
                cmd="batten__subcmd__help__subcmd__receipt"
                ;;
            batten__subcmd__help,spec)
                cmd="batten__subcmd__help__subcmd__spec"
                ;;
            batten__subcmd__help__subcmd__config,epoch)
                cmd="batten__subcmd__help__subcmd__config__subcmd__epoch"
                ;;
            batten__subcmd__help__subcmd__config,lint)
                cmd="batten__subcmd__help__subcmd__config__subcmd__lint"
                ;;
            batten__subcmd__help__subcmd__config,show)
                cmd="batten__subcmd__help__subcmd__config__subcmd__show"
                ;;
            batten__subcmd__help__subcmd__generate,completions)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__completions"
                ;;
            batten__subcmd__help__subcmd__generate,schema)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__schema"
                ;;
            batten__subcmd__help__subcmd__policy,budget)
                cmd="batten__subcmd__help__subcmd__policy__subcmd__budget"
                ;;
            batten__subcmd__help__subcmd__receipt,record)
                cmd="batten__subcmd__help__subcmd__receipt__subcmd__record"
                ;;
            batten__subcmd__help__subcmd__receipt,status)
                cmd="batten__subcmd__help__subcmd__receipt__subcmd__status"
                ;;
            batten__subcmd__policy,budget)
                cmd="batten__subcmd__policy__subcmd__budget"
                ;;
            batten__subcmd__policy,help)
                cmd="batten__subcmd__policy__subcmd__help"
                ;;
            batten__subcmd__policy__subcmd__help,budget)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__budget"
                ;;
            batten__subcmd__policy__subcmd__help,help)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__receipt,help)
                cmd="batten__subcmd__receipt__subcmd__help"
                ;;
            batten__subcmd__receipt,record)
                cmd="batten__subcmd__receipt__subcmd__record"
                ;;
            batten__subcmd__receipt,status)
                cmd="batten__subcmd__receipt__subcmd__status"
                ;;
            batten__subcmd__receipt__subcmd__help,help)
                cmd="batten__subcmd__receipt__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__receipt__subcmd__help,record)
                cmd="batten__subcmd__receipt__subcmd__help__subcmd__record"
                ;;
            batten__subcmd__receipt__subcmd__help,status)
                cmd="batten__subcmd__receipt__subcmd__help__subcmd__status"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        batten)
            opts="-q -v -h -V --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help --version check enforce exec config spec doctor generate policy hook receipt help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__check)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help show epoch lint help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__epoch)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__help)
            opts="show epoch lint help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__help__subcmd__epoch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__help__subcmd__lint)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__lint)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__config__subcmd__show)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__doctor)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__enforce)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__exec)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help completions schema help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__completions)
            opts="-q -v -h --shell --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --shell)
                    COMPREPLY=($(compgen -W "bash elvish fish powershell zsh" -- "${cur}"))
                    return 0
                    ;;
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__help)
            opts="completions schema help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__help__subcmd__schema)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__generate__subcmd__schema)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help)
            opts="check enforce exec config spec doctor generate policy hook receipt help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__config)
            opts="show epoch lint"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__config__subcmd__epoch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__config__subcmd__lint)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__config__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__enforce)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__exec)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__generate)
            opts="completions schema"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__generate__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__generate__subcmd__schema)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__hook)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__policy)
            opts="budget"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__policy__subcmd__budget)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__receipt)
            opts="record status"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__receipt__subcmd__record)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__receipt__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__help__subcmd__spec)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__hook)
            opts="-q -v -h --harness --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --harness)
                    COMPREPLY=($(compgen -W "claude-code exit-code" -- "${cur}"))
                    return 0
                    ;;
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__policy)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help budget help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__policy__subcmd__budget)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__policy__subcmd__help)
            opts="budget help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__policy__subcmd__help__subcmd__budget)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__policy__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help record status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__help)
            opts="record status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__help__subcmd__record)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__record)
            opts="-q -v -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__receipt__subcmd__status)
            opts="-J -q -v -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        batten__subcmd__spec)
            opts="-q -v -h --format --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -W "json" -- "${cur}"))
                    return 0
                    ;;
                --strictness)
                    COMPREPLY=($(compgen -W "permissive standard strict" -- "${cur}"))
                    return 0
                    ;;
                --config-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-level)
                    COMPREPLY=($(compgen -W "silent quiet normal verbose debug trace" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _batten -o nosort -o bashdefault -o default batten
else
    complete -F _batten -o bashdefault -o default batten
fi

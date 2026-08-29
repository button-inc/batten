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
            batten,attribution)
                cmd="batten__subcmd__attribution"
                ;;
            batten,baseline)
                cmd="batten__subcmd__baseline"
                ;;
            batten,capture)
                cmd="batten__subcmd__capture"
                ;;
            batten,check)
                cmd="batten__subcmd__check"
                ;;
            batten,claim)
                cmd="batten__subcmd__claim"
                ;;
            batten,commit)
                cmd="batten__subcmd__commit"
                ;;
            batten,config)
                cmd="batten__subcmd__config"
                ;;
            batten,defects)
                cmd="batten__subcmd__defects"
                ;;
            batten,design)
                cmd="batten__subcmd__design"
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
            batten,init)
                cmd="batten__subcmd__init"
                ;;
            batten,lint)
                cmd="batten__subcmd__lint"
                ;;
            batten,override)
                cmd="batten__subcmd__override"
                ;;
            batten,payload)
                cmd="batten__subcmd__payload"
                ;;
            batten,policy)
                cmd="batten__subcmd__policy"
                ;;
            batten,provision)
                cmd="batten__subcmd__provision"
                ;;
            batten,ready)
                cmd="batten__subcmd__ready"
                ;;
            batten,receipt)
                cmd="batten__subcmd__receipt"
                ;;
            batten,semver)
                cmd="batten__subcmd__semver"
                ;;
            batten,spec)
                cmd="batten__subcmd__spec"
                ;;
            batten,state)
                cmd="batten__subcmd__state"
                ;;
            batten,worktree)
                cmd="batten__subcmd__worktree"
                ;;
            batten__subcmd__attribution,check)
                cmd="batten__subcmd__attribution__subcmd__check"
                ;;
            batten__subcmd__attribution,help)
                cmd="batten__subcmd__attribution__subcmd__help"
                ;;
            batten__subcmd__attribution,identity)
                cmd="batten__subcmd__attribution__subcmd__identity"
                ;;
            batten__subcmd__attribution__subcmd__help,check)
                cmd="batten__subcmd__attribution__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__attribution__subcmd__help,help)
                cmd="batten__subcmd__attribution__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__attribution__subcmd__help,identity)
                cmd="batten__subcmd__attribution__subcmd__help__subcmd__identity"
                ;;
            batten__subcmd__capture,find)
                cmd="batten__subcmd__capture__subcmd__find"
                ;;
            batten__subcmd__capture,help)
                cmd="batten__subcmd__capture__subcmd__help"
                ;;
            batten__subcmd__capture,list)
                cmd="batten__subcmd__capture__subcmd__list"
                ;;
            batten__subcmd__capture,prune)
                cmd="batten__subcmd__capture__subcmd__prune"
                ;;
            batten__subcmd__capture,show)
                cmd="batten__subcmd__capture__subcmd__show"
                ;;
            batten__subcmd__capture__subcmd__help,find)
                cmd="batten__subcmd__capture__subcmd__help__subcmd__find"
                ;;
            batten__subcmd__capture__subcmd__help,help)
                cmd="batten__subcmd__capture__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__capture__subcmd__help,list)
                cmd="batten__subcmd__capture__subcmd__help__subcmd__list"
                ;;
            batten__subcmd__capture__subcmd__help,prune)
                cmd="batten__subcmd__capture__subcmd__help__subcmd__prune"
                ;;
            batten__subcmd__capture__subcmd__help,show)
                cmd="batten__subcmd__capture__subcmd__help__subcmd__show"
                ;;
            batten__subcmd__claim,check)
                cmd="batten__subcmd__claim__subcmd__check"
                ;;
            batten__subcmd__claim,help)
                cmd="batten__subcmd__claim__subcmd__help"
                ;;
            batten__subcmd__claim__subcmd__help,check)
                cmd="batten__subcmd__claim__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__claim__subcmd__help,help)
                cmd="batten__subcmd__claim__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__commit,check)
                cmd="batten__subcmd__commit__subcmd__check"
                ;;
            batten__subcmd__commit,help)
                cmd="batten__subcmd__commit__subcmd__help"
                ;;
            batten__subcmd__commit__subcmd__help,check)
                cmd="batten__subcmd__commit__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__commit__subcmd__help,help)
                cmd="batten__subcmd__commit__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__config,deprecations)
                cmd="batten__subcmd__config__subcmd__deprecations"
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
            batten__subcmd__config__subcmd__help,deprecations)
                cmd="batten__subcmd__config__subcmd__help__subcmd__deprecations"
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
            batten__subcmd__defects,add)
                cmd="batten__subcmd__defects__subcmd__add"
                ;;
            batten__subcmd__defects,help)
                cmd="batten__subcmd__defects__subcmd__help"
                ;;
            batten__subcmd__defects,query)
                cmd="batten__subcmd__defects__subcmd__query"
                ;;
            batten__subcmd__defects__subcmd__help,add)
                cmd="batten__subcmd__defects__subcmd__help__subcmd__add"
                ;;
            batten__subcmd__defects__subcmd__help,help)
                cmd="batten__subcmd__defects__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__defects__subcmd__help,query)
                cmd="batten__subcmd__defects__subcmd__help__subcmd__query"
                ;;
            batten__subcmd__design,audit)
                cmd="batten__subcmd__design__subcmd__audit"
                ;;
            batten__subcmd__design,help)
                cmd="batten__subcmd__design__subcmd__help"
                ;;
            batten__subcmd__design__subcmd__help,audit)
                cmd="batten__subcmd__design__subcmd__help__subcmd__audit"
                ;;
            batten__subcmd__design__subcmd__help,help)
                cmd="batten__subcmd__design__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__doctor,help)
                cmd="batten__subcmd__doctor__subcmd__help"
                ;;
            batten__subcmd__doctor,hooks)
                cmd="batten__subcmd__doctor__subcmd__hooks"
                ;;
            batten__subcmd__doctor__subcmd__help,help)
                cmd="batten__subcmd__doctor__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__doctor__subcmd__help,hooks)
                cmd="batten__subcmd__doctor__subcmd__help__subcmd__hooks"
                ;;
            batten__subcmd__generate,completions)
                cmd="batten__subcmd__generate__subcmd__completions"
                ;;
            batten__subcmd__generate,help)
                cmd="batten__subcmd__generate__subcmd__help"
                ;;
            batten__subcmd__generate,hooks)
                cmd="batten__subcmd__generate__subcmd__hooks"
                ;;
            batten__subcmd__generate,man)
                cmd="batten__subcmd__generate__subcmd__man"
                ;;
            batten__subcmd__generate,markdown)
                cmd="batten__subcmd__generate__subcmd__markdown"
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
            batten__subcmd__generate__subcmd__help,hooks)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__hooks"
                ;;
            batten__subcmd__generate__subcmd__help,man)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__man"
                ;;
            batten__subcmd__generate__subcmd__help,markdown)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__markdown"
                ;;
            batten__subcmd__generate__subcmd__help,schema)
                cmd="batten__subcmd__generate__subcmd__help__subcmd__schema"
                ;;
            batten__subcmd__help,attribution)
                cmd="batten__subcmd__help__subcmd__attribution"
                ;;
            batten__subcmd__help,baseline)
                cmd="batten__subcmd__help__subcmd__baseline"
                ;;
            batten__subcmd__help,capture)
                cmd="batten__subcmd__help__subcmd__capture"
                ;;
            batten__subcmd__help,check)
                cmd="batten__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__help,claim)
                cmd="batten__subcmd__help__subcmd__claim"
                ;;
            batten__subcmd__help,commit)
                cmd="batten__subcmd__help__subcmd__commit"
                ;;
            batten__subcmd__help,config)
                cmd="batten__subcmd__help__subcmd__config"
                ;;
            batten__subcmd__help,defects)
                cmd="batten__subcmd__help__subcmd__defects"
                ;;
            batten__subcmd__help,design)
                cmd="batten__subcmd__help__subcmd__design"
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
            batten__subcmd__help,init)
                cmd="batten__subcmd__help__subcmd__init"
                ;;
            batten__subcmd__help,lint)
                cmd="batten__subcmd__help__subcmd__lint"
                ;;
            batten__subcmd__help,override)
                cmd="batten__subcmd__help__subcmd__override"
                ;;
            batten__subcmd__help,payload)
                cmd="batten__subcmd__help__subcmd__payload"
                ;;
            batten__subcmd__help,policy)
                cmd="batten__subcmd__help__subcmd__policy"
                ;;
            batten__subcmd__help,provision)
                cmd="batten__subcmd__help__subcmd__provision"
                ;;
            batten__subcmd__help,ready)
                cmd="batten__subcmd__help__subcmd__ready"
                ;;
            batten__subcmd__help,receipt)
                cmd="batten__subcmd__help__subcmd__receipt"
                ;;
            batten__subcmd__help,semver)
                cmd="batten__subcmd__help__subcmd__semver"
                ;;
            batten__subcmd__help,spec)
                cmd="batten__subcmd__help__subcmd__spec"
                ;;
            batten__subcmd__help,state)
                cmd="batten__subcmd__help__subcmd__state"
                ;;
            batten__subcmd__help,worktree)
                cmd="batten__subcmd__help__subcmd__worktree"
                ;;
            batten__subcmd__help__subcmd__attribution,check)
                cmd="batten__subcmd__help__subcmd__attribution__subcmd__check"
                ;;
            batten__subcmd__help__subcmd__attribution,identity)
                cmd="batten__subcmd__help__subcmd__attribution__subcmd__identity"
                ;;
            batten__subcmd__help__subcmd__capture,find)
                cmd="batten__subcmd__help__subcmd__capture__subcmd__find"
                ;;
            batten__subcmd__help__subcmd__capture,list)
                cmd="batten__subcmd__help__subcmd__capture__subcmd__list"
                ;;
            batten__subcmd__help__subcmd__capture,prune)
                cmd="batten__subcmd__help__subcmd__capture__subcmd__prune"
                ;;
            batten__subcmd__help__subcmd__capture,show)
                cmd="batten__subcmd__help__subcmd__capture__subcmd__show"
                ;;
            batten__subcmd__help__subcmd__claim,check)
                cmd="batten__subcmd__help__subcmd__claim__subcmd__check"
                ;;
            batten__subcmd__help__subcmd__commit,check)
                cmd="batten__subcmd__help__subcmd__commit__subcmd__check"
                ;;
            batten__subcmd__help__subcmd__config,deprecations)
                cmd="batten__subcmd__help__subcmd__config__subcmd__deprecations"
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
            batten__subcmd__help__subcmd__defects,add)
                cmd="batten__subcmd__help__subcmd__defects__subcmd__add"
                ;;
            batten__subcmd__help__subcmd__defects,query)
                cmd="batten__subcmd__help__subcmd__defects__subcmd__query"
                ;;
            batten__subcmd__help__subcmd__design,audit)
                cmd="batten__subcmd__help__subcmd__design__subcmd__audit"
                ;;
            batten__subcmd__help__subcmd__doctor,hooks)
                cmd="batten__subcmd__help__subcmd__doctor__subcmd__hooks"
                ;;
            batten__subcmd__help__subcmd__generate,completions)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__completions"
                ;;
            batten__subcmd__help__subcmd__generate,hooks)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__hooks"
                ;;
            batten__subcmd__help__subcmd__generate,man)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__man"
                ;;
            batten__subcmd__help__subcmd__generate,markdown)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__markdown"
                ;;
            batten__subcmd__help__subcmd__generate,schema)
                cmd="batten__subcmd__help__subcmd__generate__subcmd__schema"
                ;;
            batten__subcmd__help__subcmd__lint,brief)
                cmd="batten__subcmd__help__subcmd__lint__subcmd__brief"
                ;;
            batten__subcmd__help__subcmd__override,request)
                cmd="batten__subcmd__help__subcmd__override__subcmd__request"
                ;;
            batten__subcmd__help__subcmd__override,spend)
                cmd="batten__subcmd__help__subcmd__override__subcmd__spend"
                ;;
            batten__subcmd__help__subcmd__payload,field)
                cmd="batten__subcmd__help__subcmd__payload__subcmd__field"
                ;;
            batten__subcmd__help__subcmd__policy,budget)
                cmd="batten__subcmd__help__subcmd__policy__subcmd__budget"
                ;;
            batten__subcmd__help__subcmd__policy,explain)
                cmd="batten__subcmd__help__subcmd__policy__subcmd__explain"
                ;;
            batten__subcmd__help__subcmd__policy,test)
                cmd="batten__subcmd__help__subcmd__policy__subcmd__test"
                ;;
            batten__subcmd__help__subcmd__policy,tools)
                cmd="batten__subcmd__help__subcmd__policy__subcmd__tools"
                ;;
            batten__subcmd__help__subcmd__provision,apply)
                cmd="batten__subcmd__help__subcmd__provision__subcmd__apply"
                ;;
            batten__subcmd__help__subcmd__provision,status)
                cmd="batten__subcmd__help__subcmd__provision__subcmd__status"
                ;;
            batten__subcmd__help__subcmd__ready,lint)
                cmd="batten__subcmd__help__subcmd__ready__subcmd__lint"
                ;;
            batten__subcmd__help__subcmd__receipt,record)
                cmd="batten__subcmd__help__subcmd__receipt__subcmd__record"
                ;;
            batten__subcmd__help__subcmd__receipt,status)
                cmd="batten__subcmd__help__subcmd__receipt__subcmd__status"
                ;;
            batten__subcmd__help__subcmd__semver,check)
                cmd="batten__subcmd__help__subcmd__semver__subcmd__check"
                ;;
            batten__subcmd__help__subcmd__state,adopt)
                cmd="batten__subcmd__help__subcmd__state__subcmd__adopt"
                ;;
            batten__subcmd__help__subcmd__state,list)
                cmd="batten__subcmd__help__subcmd__state__subcmd__list"
                ;;
            batten__subcmd__help__subcmd__state,migrate)
                cmd="batten__subcmd__help__subcmd__state__subcmd__migrate"
                ;;
            batten__subcmd__help__subcmd__state,record)
                cmd="batten__subcmd__help__subcmd__state__subcmd__record"
                ;;
            batten__subcmd__help__subcmd__worktree,status)
                cmd="batten__subcmd__help__subcmd__worktree__subcmd__status"
                ;;
            batten__subcmd__lint,brief)
                cmd="batten__subcmd__lint__subcmd__brief"
                ;;
            batten__subcmd__lint,help)
                cmd="batten__subcmd__lint__subcmd__help"
                ;;
            batten__subcmd__lint__subcmd__help,brief)
                cmd="batten__subcmd__lint__subcmd__help__subcmd__brief"
                ;;
            batten__subcmd__lint__subcmd__help,help)
                cmd="batten__subcmd__lint__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__override,help)
                cmd="batten__subcmd__override__subcmd__help"
                ;;
            batten__subcmd__override,request)
                cmd="batten__subcmd__override__subcmd__request"
                ;;
            batten__subcmd__override,spend)
                cmd="batten__subcmd__override__subcmd__spend"
                ;;
            batten__subcmd__override__subcmd__help,help)
                cmd="batten__subcmd__override__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__override__subcmd__help,request)
                cmd="batten__subcmd__override__subcmd__help__subcmd__request"
                ;;
            batten__subcmd__override__subcmd__help,spend)
                cmd="batten__subcmd__override__subcmd__help__subcmd__spend"
                ;;
            batten__subcmd__payload,field)
                cmd="batten__subcmd__payload__subcmd__field"
                ;;
            batten__subcmd__payload,help)
                cmd="batten__subcmd__payload__subcmd__help"
                ;;
            batten__subcmd__payload__subcmd__help,field)
                cmd="batten__subcmd__payload__subcmd__help__subcmd__field"
                ;;
            batten__subcmd__payload__subcmd__help,help)
                cmd="batten__subcmd__payload__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__policy,budget)
                cmd="batten__subcmd__policy__subcmd__budget"
                ;;
            batten__subcmd__policy,explain)
                cmd="batten__subcmd__policy__subcmd__explain"
                ;;
            batten__subcmd__policy,help)
                cmd="batten__subcmd__policy__subcmd__help"
                ;;
            batten__subcmd__policy,test)
                cmd="batten__subcmd__policy__subcmd__test"
                ;;
            batten__subcmd__policy,tools)
                cmd="batten__subcmd__policy__subcmd__tools"
                ;;
            batten__subcmd__policy__subcmd__help,budget)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__budget"
                ;;
            batten__subcmd__policy__subcmd__help,explain)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__explain"
                ;;
            batten__subcmd__policy__subcmd__help,help)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__policy__subcmd__help,test)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__test"
                ;;
            batten__subcmd__policy__subcmd__help,tools)
                cmd="batten__subcmd__policy__subcmd__help__subcmd__tools"
                ;;
            batten__subcmd__provision,apply)
                cmd="batten__subcmd__provision__subcmd__apply"
                ;;
            batten__subcmd__provision,help)
                cmd="batten__subcmd__provision__subcmd__help"
                ;;
            batten__subcmd__provision,status)
                cmd="batten__subcmd__provision__subcmd__status"
                ;;
            batten__subcmd__provision__subcmd__help,apply)
                cmd="batten__subcmd__provision__subcmd__help__subcmd__apply"
                ;;
            batten__subcmd__provision__subcmd__help,help)
                cmd="batten__subcmd__provision__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__provision__subcmd__help,status)
                cmd="batten__subcmd__provision__subcmd__help__subcmd__status"
                ;;
            batten__subcmd__ready,help)
                cmd="batten__subcmd__ready__subcmd__help"
                ;;
            batten__subcmd__ready,lint)
                cmd="batten__subcmd__ready__subcmd__lint"
                ;;
            batten__subcmd__ready__subcmd__help,help)
                cmd="batten__subcmd__ready__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__ready__subcmd__help,lint)
                cmd="batten__subcmd__ready__subcmd__help__subcmd__lint"
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
            batten__subcmd__semver,check)
                cmd="batten__subcmd__semver__subcmd__check"
                ;;
            batten__subcmd__semver,help)
                cmd="batten__subcmd__semver__subcmd__help"
                ;;
            batten__subcmd__semver__subcmd__help,check)
                cmd="batten__subcmd__semver__subcmd__help__subcmd__check"
                ;;
            batten__subcmd__semver__subcmd__help,help)
                cmd="batten__subcmd__semver__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__state,adopt)
                cmd="batten__subcmd__state__subcmd__adopt"
                ;;
            batten__subcmd__state,help)
                cmd="batten__subcmd__state__subcmd__help"
                ;;
            batten__subcmd__state,list)
                cmd="batten__subcmd__state__subcmd__list"
                ;;
            batten__subcmd__state,migrate)
                cmd="batten__subcmd__state__subcmd__migrate"
                ;;
            batten__subcmd__state,record)
                cmd="batten__subcmd__state__subcmd__record"
                ;;
            batten__subcmd__state__subcmd__help,adopt)
                cmd="batten__subcmd__state__subcmd__help__subcmd__adopt"
                ;;
            batten__subcmd__state__subcmd__help,help)
                cmd="batten__subcmd__state__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__state__subcmd__help,list)
                cmd="batten__subcmd__state__subcmd__help__subcmd__list"
                ;;
            batten__subcmd__state__subcmd__help,migrate)
                cmd="batten__subcmd__state__subcmd__help__subcmd__migrate"
                ;;
            batten__subcmd__state__subcmd__help,record)
                cmd="batten__subcmd__state__subcmd__help__subcmd__record"
                ;;
            batten__subcmd__worktree,help)
                cmd="batten__subcmd__worktree__subcmd__help"
                ;;
            batten__subcmd__worktree,status)
                cmd="batten__subcmd__worktree__subcmd__status"
                ;;
            batten__subcmd__worktree__subcmd__help,help)
                cmd="batten__subcmd__worktree__subcmd__help__subcmd__help"
                ;;
            batten__subcmd__worktree__subcmd__help,status)
                cmd="batten__subcmd__worktree__subcmd__help__subcmd__status"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        batten)
            opts="-q -v -y -h -V --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help --version check enforce exec capture config lint spec doctor init baseline generate policy commit ready claim semver attribution worktree override provision hook payload receipt defects design state help"
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
        batten__subcmd__attribution)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help check identity help"
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
        batten__subcmd__attribution__subcmd__check)
            opts="-J -q -v -y -h --json --message --harness --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --message)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --harness)
                    COMPREPLY=($(compgen -W "claude-code cursor copilot-cli gemini-cli codex-cli exit-code" -- "${cur}"))
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
        batten__subcmd__attribution__subcmd__help)
            opts="check identity help"
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
        batten__subcmd__attribution__subcmd__help__subcmd__check)
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
        batten__subcmd__attribution__subcmd__help__subcmd__help)
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
        batten__subcmd__attribution__subcmd__help__subcmd__identity)
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
        batten__subcmd__attribution__subcmd__identity)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__baseline)
            opts="-n -q -v -y -h --prune --dry-run --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__capture)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help show find list prune help"
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
        batten__subcmd__capture__subcmd__find)
            opts="-J -q -v -y -h --tool --key-at --raw --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --tool)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-at)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__capture__subcmd__help)
            opts="show find list prune help"
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
        batten__subcmd__capture__subcmd__help__subcmd__find)
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
        batten__subcmd__capture__subcmd__help__subcmd__help)
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
        batten__subcmd__capture__subcmd__help__subcmd__list)
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
        batten__subcmd__capture__subcmd__help__subcmd__prune)
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
        batten__subcmd__capture__subcmd__help__subcmd__show)
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
        batten__subcmd__capture__subcmd__list)
            opts="-J -q -v -y -h --stream --calls --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --stream)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__capture__subcmd__prune)
            opts="-n -q -v -y -h --dry-run --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__capture__subcmd__show)
            opts="-J -q -v -y -h --lines --grep --raw --bytes --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --lines)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__check)
            opts="-J -q -v -y -h --rule --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rule)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__claim)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help check help"
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
        batten__subcmd__claim__subcmd__check)
            opts="-J -q -v -y -h --takeover --bypass-sequence --adopt --adopt-from --issue --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --adopt-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --issue)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__claim__subcmd__help)
            opts="check help"
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
        batten__subcmd__claim__subcmd__help__subcmd__check)
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
        batten__subcmd__claim__subcmd__help__subcmd__help)
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
        batten__subcmd__commit)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help check help"
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
        batten__subcmd__commit__subcmd__check)
            opts="-J -q -v -y -h --json --message --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --message)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__commit__subcmd__help)
            opts="check help"
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
        batten__subcmd__commit__subcmd__help__subcmd__check)
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
        batten__subcmd__commit__subcmd__help__subcmd__help)
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
        batten__subcmd__config)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help show epoch deprecations lint help"
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
        batten__subcmd__config__subcmd__deprecations)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__config__subcmd__epoch)
            opts="-J -q -v -y -h --json --no-cache --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
            opts="show epoch deprecations lint help"
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
        batten__subcmd__config__subcmd__help__subcmd__deprecations)
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
            opts="-J -q -v -y -h --json --host-rules --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --host-rules)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__config__subcmd__show)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__defects)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help query add help"
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
        batten__subcmd__defects__subcmd__add)
            opts="-n -q -v -y -h --dry-run --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__defects__subcmd__help)
            opts="query add help"
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
        batten__subcmd__defects__subcmd__help__subcmd__add)
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
        batten__subcmd__defects__subcmd__help__subcmd__help)
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
        batten__subcmd__defects__subcmd__help__subcmd__query)
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
        batten__subcmd__defects__subcmd__query)
            opts="-J -q -v -y -h --json --class --id --ungated --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --class)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --id)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__design)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help audit help"
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
        batten__subcmd__design__subcmd__audit)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__design__subcmd__help)
            opts="audit help"
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
        batten__subcmd__design__subcmd__help__subcmd__audit)
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
        batten__subcmd__design__subcmd__help__subcmd__help)
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
        batten__subcmd__doctor)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help hooks help"
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
        batten__subcmd__doctor__subcmd__help)
            opts="hooks help"
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
        batten__subcmd__doctor__subcmd__help__subcmd__help)
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
        batten__subcmd__doctor__subcmd__help__subcmd__hooks)
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
        batten__subcmd__doctor__subcmd__hooks)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__enforce)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
            opts="-q -v -y -h --capture-only --tee --jobs --continue-on-error --format --style --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --jobs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "human json jsonl" -- "${cur}"))
                    return 0
                    ;;
                --style)
                    COMPREPLY=($(compgen -W "prefix interleave keep-order replacing timed quiet silent" -- "${cur}"))
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
        batten__subcmd__generate)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help completions hooks man markdown schema help"
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
            opts="-q -v -y -h --shell --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
            opts="completions hooks man markdown schema help"
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
        batten__subcmd__generate__subcmd__help__subcmd__hooks)
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
        batten__subcmd__generate__subcmd__help__subcmd__man)
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
        batten__subcmd__generate__subcmd__help__subcmd__markdown)
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
        batten__subcmd__generate__subcmd__hooks)
            opts="-q -v -y -h --harness --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --harness)
                    COMPREPLY=($(compgen -W "claude-code cursor copilot-cli gemini-cli codex-cli exit-code" -- "${cur}"))
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
        batten__subcmd__generate__subcmd__man)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__generate__subcmd__markdown)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__generate__subcmd__schema)
            opts="-q -v -y -h --surface --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --surface)
                    COMPREPLY=($(compgen -W "authority override policy-input policy-call" -- "${cur}"))
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
        batten__subcmd__help)
            opts="check enforce exec capture config lint spec doctor init baseline generate policy commit ready claim semver attribution worktree override provision hook payload receipt defects design state help"
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
        batten__subcmd__help__subcmd__attribution)
            opts="check identity"
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
        batten__subcmd__help__subcmd__attribution__subcmd__check)
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
        batten__subcmd__help__subcmd__attribution__subcmd__identity)
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
        batten__subcmd__help__subcmd__baseline)
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
        batten__subcmd__help__subcmd__capture)
            opts="show find list prune"
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
        batten__subcmd__help__subcmd__capture__subcmd__find)
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
        batten__subcmd__help__subcmd__capture__subcmd__list)
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
        batten__subcmd__help__subcmd__capture__subcmd__prune)
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
        batten__subcmd__help__subcmd__capture__subcmd__show)
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
        batten__subcmd__help__subcmd__claim)
            opts="check"
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
        batten__subcmd__help__subcmd__claim__subcmd__check)
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
        batten__subcmd__help__subcmd__commit)
            opts="check"
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
        batten__subcmd__help__subcmd__commit__subcmd__check)
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
        batten__subcmd__help__subcmd__config)
            opts="show epoch deprecations lint"
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
        batten__subcmd__help__subcmd__config__subcmd__deprecations)
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
        batten__subcmd__help__subcmd__defects)
            opts="query add"
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
        batten__subcmd__help__subcmd__defects__subcmd__add)
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
        batten__subcmd__help__subcmd__defects__subcmd__query)
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
        batten__subcmd__help__subcmd__design)
            opts="audit"
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
        batten__subcmd__help__subcmd__design__subcmd__audit)
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
            opts="hooks"
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
        batten__subcmd__help__subcmd__doctor__subcmd__hooks)
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
            opts="completions hooks man markdown schema"
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
        batten__subcmd__help__subcmd__generate__subcmd__hooks)
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
        batten__subcmd__help__subcmd__generate__subcmd__man)
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
        batten__subcmd__help__subcmd__generate__subcmd__markdown)
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
        batten__subcmd__help__subcmd__init)
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
        batten__subcmd__help__subcmd__lint)
            opts="brief"
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
        batten__subcmd__help__subcmd__lint__subcmd__brief)
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
        batten__subcmd__help__subcmd__override)
            opts="request spend"
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
        batten__subcmd__help__subcmd__override__subcmd__request)
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
        batten__subcmd__help__subcmd__override__subcmd__spend)
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
        batten__subcmd__help__subcmd__payload)
            opts="field"
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
        batten__subcmd__help__subcmd__payload__subcmd__field)
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
        batten__subcmd__help__subcmd__policy)
            opts="budget test tools explain"
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
        batten__subcmd__help__subcmd__policy__subcmd__explain)
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
        batten__subcmd__help__subcmd__policy__subcmd__test)
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
        batten__subcmd__help__subcmd__policy__subcmd__tools)
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
        batten__subcmd__help__subcmd__provision)
            opts="status apply"
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
        batten__subcmd__help__subcmd__provision__subcmd__apply)
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
        batten__subcmd__help__subcmd__provision__subcmd__status)
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
        batten__subcmd__help__subcmd__ready)
            opts="lint"
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
        batten__subcmd__help__subcmd__ready__subcmd__lint)
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
        batten__subcmd__help__subcmd__semver)
            opts="check"
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
        batten__subcmd__help__subcmd__semver__subcmd__check)
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
        batten__subcmd__help__subcmd__state)
            opts="adopt record migrate list"
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
        batten__subcmd__help__subcmd__state__subcmd__adopt)
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
        batten__subcmd__help__subcmd__state__subcmd__list)
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
        batten__subcmd__help__subcmd__state__subcmd__migrate)
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
        batten__subcmd__help__subcmd__state__subcmd__record)
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
        batten__subcmd__help__subcmd__worktree)
            opts="status"
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
        batten__subcmd__help__subcmd__worktree__subcmd__status)
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
        batten__subcmd__hook)
            opts="-q -v -y -h --harness --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --harness)
                    COMPREPLY=($(compgen -W "claude-code cursor copilot-cli gemini-cli codex-cli exit-code" -- "${cur}"))
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
        batten__subcmd__init)
            opts="-n -q -v -y -h --dry-run --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__lint)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help brief help"
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
        batten__subcmd__lint__subcmd__brief)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__lint__subcmd__help)
            opts="brief help"
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
        batten__subcmd__lint__subcmd__help__subcmd__brief)
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
        batten__subcmd__lint__subcmd__help__subcmd__help)
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
        batten__subcmd__override)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help request spend help"
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
        batten__subcmd__override__subcmd__help)
            opts="request spend help"
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
        batten__subcmd__override__subcmd__help__subcmd__help)
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
        batten__subcmd__override__subcmd__help__subcmd__request)
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
        batten__subcmd__override__subcmd__help__subcmd__spend)
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
        batten__subcmd__override__subcmd__request)
            opts="-q -v -y -h --rule --verdict --subject --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rule)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --verdict)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --subject)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__override__subcmd__spend)
            opts="-q -v -y -h --admission --rule --verdict --subject --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --admission)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rule)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --verdict)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --subject)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__payload)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help field help"
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
        batten__subcmd__payload__subcmd__field)
            opts="-q -v -y -h --harness --name --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --harness)
                    COMPREPLY=($(compgen -W "claude-code cursor copilot-cli gemini-cli codex-cli exit-code" -- "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -W "hook-event-name session-id tool-name command cwd stop-hook-active last-assistant-message transcript-path prompt run-in-background input-id input-state" -- "${cur}"))
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
        batten__subcmd__payload__subcmd__help)
            opts="field help"
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
        batten__subcmd__payload__subcmd__help__subcmd__field)
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
        batten__subcmd__payload__subcmd__help__subcmd__help)
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
        batten__subcmd__policy)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help budget test tools explain help"
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
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__policy__subcmd__explain)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
            opts="budget test tools explain help"
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
        batten__subcmd__policy__subcmd__help__subcmd__explain)
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
        batten__subcmd__policy__subcmd__help__subcmd__test)
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
        batten__subcmd__policy__subcmd__help__subcmd__tools)
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
        batten__subcmd__policy__subcmd__test)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__policy__subcmd__tools)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__provision)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help status apply help"
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
        batten__subcmd__provision__subcmd__apply)
            opts="-n -q -v -y -h --dry-run --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__provision__subcmd__help)
            opts="status apply help"
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
        batten__subcmd__provision__subcmd__help__subcmd__apply)
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
        batten__subcmd__provision__subcmd__help__subcmd__help)
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
        batten__subcmd__provision__subcmd__help__subcmd__status)
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
        batten__subcmd__provision__subcmd__status)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__ready)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help lint help"
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
        batten__subcmd__ready__subcmd__help)
            opts="lint help"
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
        batten__subcmd__ready__subcmd__help__subcmd__help)
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
        batten__subcmd__ready__subcmd__help__subcmd__lint)
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
        batten__subcmd__ready__subcmd__lint)
            opts="-J -q -v -y -h --issue --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --issue)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__receipt)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help record status help"
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
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
            opts="-J -q -v -y -h --key --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key)
                    COMPREPLY=($(compgen -W "head branch named" -- "${cur}"))
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
        batten__subcmd__semver)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help check help"
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
        batten__subcmd__semver__subcmd__check)
            opts="-q -v -y -h --baseline --release-type --package --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --release-type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
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
        batten__subcmd__semver__subcmd__help)
            opts="check help"
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
        batten__subcmd__semver__subcmd__help__subcmd__check)
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
        batten__subcmd__semver__subcmd__help__subcmd__help)
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
        batten__subcmd__spec)
            opts="-q -v -y -h --format --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__state)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help adopt record migrate list help"
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
        batten__subcmd__state__subcmd__adopt)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__state__subcmd__help)
            opts="adopt record migrate list help"
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
        batten__subcmd__state__subcmd__help__subcmd__adopt)
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
        batten__subcmd__state__subcmd__help__subcmd__help)
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
        batten__subcmd__state__subcmd__help__subcmd__list)
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
        batten__subcmd__state__subcmd__help__subcmd__migrate)
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
        batten__subcmd__state__subcmd__help__subcmd__record)
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
        batten__subcmd__state__subcmd__list)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__state__subcmd__migrate)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__state__subcmd__record)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
        batten__subcmd__worktree)
            opts="-q -v -y -h --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help status help"
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
        batten__subcmd__worktree__subcmd__help)
            opts="status help"
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
        batten__subcmd__worktree__subcmd__help__subcmd__help)
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
        batten__subcmd__worktree__subcmd__help__subcmd__status)
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
        batten__subcmd__worktree__subcmd__status)
            opts="-J -q -v -y -h --json --strictness --fail-on-warning --config-from --silent --quiet --verbose --debug --trace --log-level --no-color --no-input --yes --help"
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
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _batten -o nosort -o bashdefault -o default batten
else
    complete -F _batten -o bashdefault -o default batten
fi

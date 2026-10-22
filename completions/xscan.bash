#!/usr/bin/env bash
# XScan bash completion
# Install: source completions/xscan.bash
#          or add to ~/.bashrc

_xscan_commands=(
    scan recon crawl xss workflow
    smart ask research
    tools install models skills take-note memory
    doctor fix auth scope config
    status resume report
    version help
)

_xscan_workflows=(
    xss-deep xss-fast recon-full crawl-deep
    full-audit api-analysis js-analysis
)

_xscan_profiles=(fast balanced deep)

_xscan_report_formats=(terminal html json markdown pdf)

_xscan_tools=(
    katana httpx dnsx amass subfinder nuclei
    ffuf waybackurls dalfox playwright
)

_xscan_models=(qwen3 deepseek-coder mistral llama3 phi3 codellama)

_xscan_help_topics=(
    getting-started architecture workflows tools skills models
    research authentication evidence reports troubleshooting development
    smart concepts/dag concepts/specialists concepts/llm
    concepts/evidence concepts/scope concepts/skills concepts/research
)

_xscan_completefunc() {
    local cur prev words cword
    _init_completion || return

    local cmd=""
    local i
    for (( i=1; i < cword; i++ )); do
        if [[ "${words[i]}" != -* ]]; then
            cmd="${words[i]}"
            break
        fi
    done

    case "$cmd" in
        scan)
            case "$prev" in
                --workflow|-w)  COMPREPLY=( $(compgen -W "${_xscan_workflows[*]}" -- "$cur") ); return ;;
                --profile|-p)   COMPREPLY=( $(compgen -W "${_xscan_profiles[*]}" -- "$cur") ); return ;;
                --format)       COMPREPLY=( $(compgen -W "${_xscan_report_formats[*]}" -- "$cur") ); return ;;
            esac
            COMPREPLY=( $(compgen -W "--workflow --profile --scope --project --resume --no-llm --research --auth --tui --output --format" -- "$cur") )
            ;;
        workflow)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list run inspect" -- "$cur") )
            elif [[ $cword -eq 3 && "${words[2]}" =~ ^(run|inspect)$ ]]; then
                COMPREPLY=( $(compgen -W "${_xscan_workflows[*]}" -- "$cur") )
            fi
            ;;
        tools)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list install check inspect update remove" -- "$cur") )
            elif [[ $cword -eq 3 && "${words[2]}" =~ ^(install|check|inspect|update|remove)$ ]]; then
                COMPREPLY=( $(compgen -W "${_xscan_tools[*]}" -- "$cur") )
            fi
            ;;
        install)
            COMPREPLY=( $(compgen -W "${_xscan_tools[*]}" -- "$cur") )
            ;;
        models)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list use test info" -- "$cur") )
            elif [[ $cword -eq 3 && "${words[2]}" =~ ^(use|test|info)$ ]]; then
                COMPREPLY=( $(compgen -W "${_xscan_models[*]}" -- "$cur") )
            fi
            ;;
        skills)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list install inspect update remove create" -- "$cur") )
            fi
            ;;
        report)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list show generate" -- "$cur") )
            fi
            case "$prev" in
                --format) COMPREPLY=( $(compgen -W "${_xscan_report_formats[*]}" -- "$cur") ); return ;;
            esac
            ;;
        auth)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "login list show refresh export delete" -- "$cur") )
            fi
            ;;
        scope)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "set add show save clear" -- "$cur") )
            fi
            ;;
        config)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "show get set edit reset" -- "$cur") )
            fi
            ;;
        help)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "search topics ${_xscan_help_topics[*]}" -- "$cur") )
            fi
            ;;
        smart)
            COMPREPLY=( $(compgen -W "--plan --confirm --auto --scope --auth" -- "$cur") )
            ;;
        doctor)
            COMPREPLY=( $(compgen -W "--fix --json" -- "$cur") )
            ;;
        "")
            COMPREPLY=( $(compgen -W "${_xscan_commands[*]}" -- "$cur") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--help -h" -- "$cur") )
            ;;
    esac
}

complete -F _xscan_completefunc xscan

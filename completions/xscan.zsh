#compdef xscan
# XScan zsh completion
# Install: place in a directory on $fpath, e.g.:
#   cp completions/xscan.zsh ~/.zsh/completions/_xscan
#   echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
#   autoload -Uz compinit && compinit

local -a _xscan_commands
_xscan_commands=(
    'scan:Run an intelligent security workflow'
    'recon:Run reconnaissance'
    'crawl:Discover URLs and application assets'
    'xss:Run XSS analysis'
    'workflow:Run a predefined DAG workflow'
    'smart:Convert natural language intent into a workflow'
    'ask:Ask questions about the current scan'
    'research:Research external technical information'
    'tools:Manage security tools'
    'install:Install a tool'
    'models:Manage local LLMs'
    'skills:Manage Skills'
    'take-note:Save knowledge or project notes'
    'memory:Search stored memory'
    'doctor:Check XScan environment'
    'fix:Diagnose and repair a problem'
    'auth:Manage browser authentication sessions'
    'scope:Configure authorized scope'
    'config:Manage configuration'
    'status:Show scan status'
    'resume:Resume a scan'
    'report:Generate/view reports'
    'version:Show version'
    'help:Show detailed help'
)

local -a _xscan_workflows
_xscan_workflows=(
    'xss-deep:Deep XSS analysis with taint tracking'
    'xss-fast:Quick XSS scan'
    'recon-full:Comprehensive reconnaissance'
    'crawl-deep:Deep crawl and asset discovery'
    'full-audit:Complete security assessment'
    'api-analysis:REST/GraphQL API analysis'
    'js-analysis:Static JS security analysis'
)

local -a _xscan_profiles
_xscan_profiles=(fast balanced deep)

local -a _xscan_formats
_xscan_formats=(terminal html json markdown pdf)

local -a _xscan_tools
_xscan_tools=(katana httpx dnsx amass subfinder nuclei ffuf waybackurls dalfox playwright)

local -a _xscan_models
_xscan_models=(qwen3 deepseek-coder mistral llama3 phi3 codellama)

local -a _xscan_help_topics
_xscan_help_topics=(
    getting-started architecture workflows tools skills models
    research authentication evidence reports troubleshooting development
    smart 'concepts/dag' 'concepts/specialists' 'concepts/llm'
    'concepts/evidence' 'concepts/scope' 'concepts/skills' 'concepts/research'
)

_xscan() {
    local state line
    typeset -A opt_args

    _arguments \
        '(-h --help)'{-h,--help}'[Show help]' \
        '(-V --version)'{-V,--version}'[Show version]' \
        '1:command:->command' \
        '*::args:->args'

    case $state in
        command)
            _describe 'xscan command' _xscan_commands
            ;;
        args)
            case $line[1] in
                scan)
                    _arguments \
                        '1:target:_hosts' \
                        '--workflow[Workflow]:workflow:( ${_xscan_workflows[@]%%:*} )' \
                        '--profile[Profile]:profile:(fast balanced deep)' \
                        '--scope[Scope]:scope:' \
                        '--project[Project]:project:' \
                        '--resume[Resume interrupted scan]' \
                        '--no-llm[Disable LLM specialists]' \
                        '--research[Allow research nodes]' \
                        '--auth[Auth session]:session:' \
                        '--tui[Launch TUI]' \
                        '--output[Output file]:file:_files' \
                        '--format[Format]:format:(terminal html json markdown pdf)'
                    ;;
                workflow)
                    _arguments \
                        '1:subcommand:(list run inspect)' \
                        '2:workflow:( ${_xscan_workflows[@]%%:*} )' \
                        '3:target:_hosts' \
                        '--profile[Profile]:profile:(fast balanced deep)' \
                        '--format[Format]:format:(terminal dot)'
                    ;;
                tools)
                    _arguments \
                        '1:subcommand:(list install check inspect update remove)' \
                        '2:tool:($_xscan_tools)' \
                        '--all[All tools]'
                    ;;
                install)
                    _arguments '*:tool:($_xscan_tools)'
                    ;;
                models)
                    _arguments \
                        '1:subcommand:(list use test info)' \
                        '2:model:($_xscan_models)'
                    ;;
                skills)
                    _arguments \
                        '1:subcommand:(list install inspect update remove create)'
                    ;;
                help)
                    _arguments \
                        '1:topic:($_xscan_help_topics search topics)' \
                        '2:query:'
                    ;;
                auth)
                    _arguments \
                        '1:subcommand:(login list show refresh export delete)' \
                        '--url[Login URL]:url:' \
                        '--session[Session name]:session:' \
                        '--headless[Headless browser]' \
                        '--format[Export format]:format:(netscape json har)'
                    ;;
                scope)
                    _arguments \
                        '1:subcommand:(set add show save clear)' \
                        '--name[Scope name]:name:'
                    ;;
                config)
                    _arguments \
                        '1:subcommand:(show get set edit reset)'
                    ;;
                report)
                    _arguments \
                        '1:subcommand:(list show generate)' \
                        '2:scan-id:' \
                        '--finding[Finding ID]:id:' \
                        '--format[Format]:format:(terminal html json markdown pdf)' \
                        '--output[Output file]:file:_files'
                    ;;
                smart)
                    _arguments \
                        '1:intent:' \
                        '--plan[Show plan only]' \
                        '--confirm[Confirm before execute]' \
                        '--auto[Auto execute]' \
                        '--scope[Scope]:scope:' \
                        '--auth[Auth session]:session:'
                    ;;
                doctor)
                    _arguments \
                        '--fix[Auto-repair problems]' \
                        '--json[JSON output]'
                    ;;
            esac
            ;;
    esac
}

_xscan "$@"

# XScan fish completion
# Install: cp completions/xscan.fish ~/.config/fish/completions/xscan.fish

# Disable file completion for xscan globally (we provide our own)
complete -c xscan -f

# ─── Top-level commands ────────────────────────────────────────────────────

# Core
complete -c xscan -n '__fish_use_subcommand' -a scan      -d 'Run an intelligent security workflow'
complete -c xscan -n '__fish_use_subcommand' -a recon     -d 'Run reconnaissance'
complete -c xscan -n '__fish_use_subcommand' -a crawl     -d 'Discover URLs and application assets'
complete -c xscan -n '__fish_use_subcommand' -a xss       -d 'Run XSS analysis'
complete -c xscan -n '__fish_use_subcommand' -a workflow  -d 'Run a predefined DAG workflow'
# AI
complete -c xscan -n '__fish_use_subcommand' -a smart     -d 'Natural-language intent → workflow'
complete -c xscan -n '__fish_use_subcommand' -a ask       -d 'Ask questions about the current scan'
complete -c xscan -n '__fish_use_subcommand' -a research  -d 'Research external technical information'
# Management
complete -c xscan -n '__fish_use_subcommand' -a tools     -d 'Manage security tools'
complete -c xscan -n '__fish_use_subcommand' -a install   -d 'Install a tool'
complete -c xscan -n '__fish_use_subcommand' -a models    -d 'Manage local LLMs'
complete -c xscan -n '__fish_use_subcommand' -a skills    -d 'Manage Skills'
complete -c xscan -n '__fish_use_subcommand' -a take-note -d 'Save knowledge or project notes'
complete -c xscan -n '__fish_use_subcommand' -a memory    -d 'Search stored memory'
# System
complete -c xscan -n '__fish_use_subcommand' -a doctor    -d 'Check XScan environment'
complete -c xscan -n '__fish_use_subcommand' -a fix       -d 'Diagnose and repair a problem'
complete -c xscan -n '__fish_use_subcommand' -a auth      -d 'Manage browser authentication sessions'
complete -c xscan -n '__fish_use_subcommand' -a scope     -d 'Configure authorized scope'
complete -c xscan -n '__fish_use_subcommand' -a config    -d 'Manage configuration'
# Results
complete -c xscan -n '__fish_use_subcommand' -a status    -d 'Show scan status'
complete -c xscan -n '__fish_use_subcommand' -a resume    -d 'Resume a scan'
complete -c xscan -n '__fish_use_subcommand' -a report    -d 'Generate/view reports'
# Other
complete -c xscan -n '__fish_use_subcommand' -a version   -d 'Show version'
complete -c xscan -n '__fish_use_subcommand' -a help      -d 'Show detailed help'

# ─── Workflow names (shared helper) ────────────────────────────────────────
set -l _workflows xss-deep xss-fast recon-full crawl-deep full-audit api-analysis js-analysis

# ─── scan options ──────────────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from scan' -l workflow  -d 'Workflow to execute'     -a "$_workflows"
complete -c xscan -n '__fish_seen_subcommand_from scan' -l profile   -d 'Execution profile'        -a 'fast balanced deep'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l scope     -d 'Scope definition'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l project   -d 'Project context'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l resume    -d 'Resume interrupted scan'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l no-llm    -d 'Disable LLM specialists'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l research  -d 'Allow research nodes'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l auth      -d 'Auth session name'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l tui       -d 'Launch TUI dashboard'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l output -s o -d 'Output file'
complete -c xscan -n '__fish_seen_subcommand_from scan' -l format    -d 'Report format'            -a 'terminal html json markdown pdf'

# ─── workflow sub-commands ─────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from workflow' -a 'list'    -d 'List all workflows'
complete -c xscan -n '__fish_seen_subcommand_from workflow' -a 'run'     -d 'Run a workflow'
complete -c xscan -n '__fish_seen_subcommand_from workflow' -a 'inspect' -d 'Show DAG stages'
complete -c xscan -n '__fish_seen_subcommand_from workflow; and __fish_seen_subcommand_from run inspect' -a "$_workflows"

# ─── tools sub-commands ────────────────────────────────────────────────────
set -l _tools katana httpx dnsx amass subfinder nuclei ffuf waybackurls dalfox playwright
complete -c xscan -n '__fish_seen_subcommand_from tools'   -a 'list install check inspect update remove' -d 'Tools sub-command'
complete -c xscan -n '__fish_seen_subcommand_from tools install check inspect update remove' -a "$_tools"
complete -c xscan -n '__fish_seen_subcommand_from install' -a "$_tools" -d 'Tool to install'

# ─── models sub-commands ───────────────────────────────────────────────────
set -l _models qwen3 deepseek-coder mistral llama3 phi3 codellama
complete -c xscan -n '__fish_seen_subcommand_from models' -a 'list use test info' -d 'Models sub-command'
complete -c xscan -n '__fish_seen_subcommand_from models; and __fish_seen_subcommand_from use test info' -a "$_models"

# ─── skills sub-commands ───────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from skills' -a 'list install inspect update remove create' -d 'Skills sub-command'

# ─── smart options ─────────────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from smart' -l plan    -d 'Show plan only'
complete -c xscan -n '__fish_seen_subcommand_from smart' -l confirm -d 'Confirm before execute'
complete -c xscan -n '__fish_seen_subcommand_from smart' -l auto    -d 'Auto execute'
complete -c xscan -n '__fish_seen_subcommand_from smart' -l scope   -d 'Scope override'
complete -c xscan -n '__fish_seen_subcommand_from smart' -l auth    -d 'Auth session'

# ─── doctor options ────────────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from doctor' -l fix  -d 'Auto-repair problems'
complete -c xscan -n '__fish_seen_subcommand_from doctor' -l json -d 'JSON output'

# ─── auth sub-commands ─────────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from auth' -a 'login list show refresh export delete' -d 'Auth sub-command'
complete -c xscan -n '__fish_seen_subcommand_from auth' -l url      -d 'Login URL'
complete -c xscan -n '__fish_seen_subcommand_from auth' -l session  -d 'Session name'
complete -c xscan -n '__fish_seen_subcommand_from auth' -l headless -d 'Headless browser'
complete -c xscan -n '__fish_seen_subcommand_from auth' -l format   -d 'Export format' -a 'netscape json har'

# ─── scope sub-commands ────────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from scope' -a 'set add show save clear' -d 'Scope sub-command'
complete -c xscan -n '__fish_seen_subcommand_from scope' -l name -d 'Named profile'

# ─── report sub-commands ───────────────────────────────────────────────────
complete -c xscan -n '__fish_seen_subcommand_from report' -a 'list show generate' -d 'Report sub-command'
complete -c xscan -n '__fish_seen_subcommand_from report' -l finding -d 'Finding ID'
complete -c xscan -n '__fish_seen_subcommand_from report' -l format  -d 'Format' -a 'terminal html json markdown pdf'
complete -c xscan -n '__fish_seen_subcommand_from report' -l output -s o -d 'Output file'

# ─── help sub-commands / topics ────────────────────────────────────────────
set -l _topics getting-started architecture workflows tools skills models \
    research authentication evidence reports troubleshooting development \
    smart 'concepts/dag' 'concepts/specialists' 'concepts/llm' \
    'concepts/evidence' 'concepts/scope' 'concepts/skills' 'concepts/research'

complete -c xscan -n '__fish_seen_subcommand_from help' -a 'search topics'       -d 'Help sub-command'
complete -c xscan -n '__fish_seen_subcommand_from help' -a "$_topics"            -d 'Help topic'

# ─── Global flags ──────────────────────────────────────────────────────────
complete -c xscan -s h -l help    -d 'Show help'
complete -c xscan -s V -l version -d 'Show version'

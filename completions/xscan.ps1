# XScan PowerShell completion
# Install: Add to your $PROFILE:
#   . "path\to\completions\xscan.ps1"
#   Register-ArgumentCompleter -Native -CommandName xscan -ScriptBlock $XScanCompleter

$XScanCompleter = {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @(
        [PSCustomObject]@{ Name='scan';      Description='Run an intelligent security workflow' }
        [PSCustomObject]@{ Name='recon';     Description='Run reconnaissance' }
        [PSCustomObject]@{ Name='crawl';     Description='Discover URLs and application assets' }
        [PSCustomObject]@{ Name='xss';       Description='Run XSS analysis' }
        [PSCustomObject]@{ Name='workflow';  Description='Run a predefined DAG workflow' }
        [PSCustomObject]@{ Name='smart';     Description='Natural-language intent → workflow' }
        [PSCustomObject]@{ Name='ask';       Description='Ask questions about the current scan' }
        [PSCustomObject]@{ Name='research';  Description='Research external technical information' }
        [PSCustomObject]@{ Name='tools';     Description='Manage security tools' }
        [PSCustomObject]@{ Name='install';   Description='Install a tool' }
        [PSCustomObject]@{ Name='models';    Description='Manage local LLMs' }
        [PSCustomObject]@{ Name='skills';    Description='Manage Skills' }
        [PSCustomObject]@{ Name='take-note'; Description='Save knowledge or project notes' }
        [PSCustomObject]@{ Name='memory';    Description='Search stored memory' }
        [PSCustomObject]@{ Name='doctor';    Description='Check XScan environment' }
        [PSCustomObject]@{ Name='fix';       Description='Diagnose and repair a problem' }
        [PSCustomObject]@{ Name='auth';      Description='Manage browser authentication sessions' }
        [PSCustomObject]@{ Name='scope';     Description='Configure authorized scope' }
        [PSCustomObject]@{ Name='config';    Description='Manage configuration' }
        [PSCustomObject]@{ Name='status';    Description='Show scan status' }
        [PSCustomObject]@{ Name='resume';    Description='Resume a scan' }
        [PSCustomObject]@{ Name='report';    Description='Generate/view reports' }
        [PSCustomObject]@{ Name='version';   Description='Show version' }
        [PSCustomObject]@{ Name='help';      Description='Show detailed help' }
    )

    $workflows = @('xss-deep','xss-fast','recon-full','crawl-deep','full-audit','api-analysis','js-analysis')
    $profiles  = @('fast','balanced','deep')
    $formats   = @('terminal','html','json','markdown','pdf')
    $tools     = @('katana','httpx','dnsx','amass','subfinder','nuclei','ffuf','waybackurls','dalfox','playwright')
    $models    = @('qwen3','deepseek-coder','mistral','llama3','phi3','codellama')
    $helpTopics = @(
        'getting-started','architecture','workflows','tools','skills','models',
        'research','authentication','evidence','reports','troubleshooting','development',
        'smart','concepts/dag','concepts/specialists','concepts/llm',
        'concepts/evidence','concepts/scope','concepts/skills','concepts/research',
        'search','topics'
    )

    # Parse which sub-command is active
    $tokens    = $commandAst.CommandElements
    $subCmd    = $null
    $subSubCmd = $null
    $tokenIdx  = 0
    foreach ($tok in $tokens) {
        $val = $tok.ToString()
        if ($tokenIdx -eq 0) { $tokenIdx++; continue }   # skip 'xscan'
        if (-not $val.StartsWith('-')) {
            if ($null -eq $subCmd) {
                $subCmd = $val
            } elseif ($null -eq $subSubCmd) {
                $subSubCmd = $val
            }
        }
        $tokenIdx++
    }

    # Helper: filter and return completions
    function Complete-Values([string[]]$values) {
        $values | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }

    function Complete-Commands {
        $commands | Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.Name, $_.Name, 'ParameterValue', $_.Description)
        }
    }

    # No sub-command yet → complete commands
    if ($null -eq $subCmd -or ($subCmd -eq $wordToComplete)) {
        return Complete-Commands
    }

    switch ($subCmd) {
        'scan' {
            switch ($wordToComplete) {
                { $_ -like '--workflow*' } { return }  # option value handled below
                default {}
            }
            $prev = ($tokens | Select-Object -Last 2 | Select-Object -First 1).ToString()
            switch ($prev) {
                '--workflow' { return Complete-Values $workflows }
                '-w'         { return Complete-Values $workflows }
                '--profile'  { return Complete-Values $profiles }
                '-p'         { return Complete-Values $profiles }
                '--format'   { return Complete-Values $formats }
            }
            Complete-Values @('--workflow','--profile','--scope','--project','--resume','--no-llm','--research','--auth','--tui','--output','--format')
        }
        'workflow' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('list','run','inspect')
            }
            if ($subSubCmd -in @('run','inspect')) {
                return Complete-Values $workflows
            }
        }
        'tools' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('list','install','check','inspect','update','remove')
            }
            return Complete-Values $tools
        }
        'install' {
            return Complete-Values $tools
        }
        'models' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('list','use','test','info')
            }
            return Complete-Values $models
        }
        'skills' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('list','install','inspect','update','remove','create')
            }
        }
        'auth' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('login','list','show','refresh','export','delete')
            }
            $prev = ($tokens | Select-Object -Last 2 | Select-Object -First 1).ToString()
            if ($prev -eq '--format') { return Complete-Values @('netscape','json','har') }
        }
        'scope' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('set','add','show','save','clear')
            }
        }
        'config' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('show','get','set','edit','reset')
            }
        }
        'report' {
            if ($null -eq $subSubCmd) {
                return Complete-Values @('list','show','generate')
            }
            $prev = ($tokens | Select-Object -Last 2 | Select-Object -First 1).ToString()
            if ($prev -eq '--format') { return Complete-Values $formats }
        }
        'smart' {
            Complete-Values @('--plan','--confirm','--auto','--scope','--auth')
        }
        'doctor' {
            Complete-Values @('--fix','--json')
        }
        'help' {
            return Complete-Values $helpTopics
        }
        'memory' {
            return Complete-Values @('search','list','delete')
        }
        default {
            Complete-Values @('--help','-h')
        }
    }
}

Register-ArgumentCompleter -Native -CommandName xscan -ScriptBlock $XScanCompleter

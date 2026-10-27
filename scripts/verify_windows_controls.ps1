#requires -Version 7.3
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$ExerciseDenials
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSNativeCommandArgumentPassing -eq 'Legacy') { throw 'This verifier requires Standard or Windows native argument passing' }
$configPath = Join-Path $Root 'deployment.json'
$healthPath = Join-Path $Root 'status/health.json'
$config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
if ($config.service_name -cne 'WeirAdmission' -or $config.host_name -cne $env:COMPUTERNAME) { throw 'Unexpected verification target' }
$python = $config.python_executable
$results = [ordered]@{}

function Wait-Health([string]$State, [datetime]$After, [int]$TimeoutSeconds = 180) {
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([datetime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $healthPath) {
            $value = Get-Content -Raw -LiteralPath $healthPath | ConvertFrom-Json
            if ($value.state -eq 'failed' -and ([datetime]$value.heartbeat_at).ToUniversalTime() -gt $After) {
                throw ('Service startup failed: ' + $value.detail)
            }
            if ($value.state -eq $State -and ([datetime]$value.heartbeat_at).ToUniversalTime() -gt $After) { return $value }
        }
        Start-Sleep -Milliseconds 500
    }
    throw ('Service did not report fresh state: ' + $State)
}

function Verify-Live {
    $output = & $python -I -B -m weir.windows_verifier --config $configPath --status $healthPath
    if ($LASTEXITCODE -ne 0) { throw 'Independent live host readback failed' }
    return ($output | ConvertFrom-Json)
}

function Assert-Denied([datetime]$After) {
    $first = Wait-Health 'denied' $After
    $second = Wait-Health 'denied' ([datetime]$first.heartbeat_at).ToUniversalTime()
    if ($second.worker_operations -ne $first.worker_operations) { throw 'Worker was invoked while controls were denied' }
    return @{ state = 'denied'; worker_operations_while_denied = 0; checked_at = $second.heartbeat_at }
}

$started = [datetime]::UtcNow
try {
    $initial = Wait-Health 'admitted' $started.AddSeconds(-60)
    $results.baseline = Verify-Live
    if ($ExerciseDenials) {
        $rule = Get-NetFirewallRule -Name $config.firewall_rule
        $changedAt = [datetime]::UtcNow
        try {
            $rule | Disable-NetFirewallRule
            $results.disabled_firewall = Assert-Denied $changedAt
        } finally { $rule | Enable-NetFirewallRule }
        $null = Wait-Health 'admitted' ([datetime]::UtcNow)

        $changedAt = [datetime]::UtcNow
        try {
            Set-NetFirewallRule -Name $config.firewall_rule -Protocol TCP | Out-Null
            $results.narrowed_firewall = Assert-Denied $changedAt
        } finally { Set-NetFirewallRule -Name $config.firewall_rule -Protocol Any | Out-Null }
        $null = Wait-Health 'admitted' ([datetime]::UtcNow)

        $credentialPath = $config.credentials[0].path
        $originalAcl = Get-Acl -LiteralPath $credentialPath
        $changedAt = [datetime]::UtcNow
        try {
            # Preserving inherited ACEs can retain service read access even after
            # RemoveAccessRuleSpecific. Build the intended admin-only DACL explicitly.
            $restrictedAcl = [Security.AccessControl.FileSecurity]::new()
            $restrictedAcl.SetOwner($originalAcl.GetOwner([Security.Principal.SecurityIdentifier]))
            $restrictedAcl.SetAccessRuleProtection($true, $false)
            foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
                $restrictedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
            }
            Set-Acl -LiteralPath $credentialPath -AclObject $restrictedAcl
            $readback = Get-Acl -LiteralPath $credentialPath
            if (@($readback.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                    Where-Object { $_.IdentityReference.Value -eq $config.service_sid }).Count -ne 0) {
                throw 'Credential denial fixture retained service access'
            }
            $results.inaccessible_credential = Assert-Denied $changedAt
        } finally { Set-Acl -LiteralPath $credentialPath -AclObject $originalAcl }
        $null = Wait-Health 'admitted' ([datetime]::UtcNow)

        $canaryPath = Join-Path $config.base_python_root 'Lib/site-packages/weir/data/windows/acl-canary.txt'
        $originalAcl = Get-Acl -LiteralPath $canaryPath
        $changedAt = [datetime]::UtcNow
        try {
            $weakAcl = Get-Acl -LiteralPath $canaryPath
            $weakAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Write', 'Allow'))
            Set-Acl -LiteralPath $canaryPath -AclObject $weakAcl
            $results.writable_runtime_fixture = Assert-Denied $changedAt
        } finally { Set-Acl -LiteralPath $canaryPath -AclObject $originalAcl }
        $null = Wait-Health 'admitted' ([datetime]::UtcNow)

        $beforeRestart = Verify-Live
        $changedAt = [datetime]::UtcNow
        Stop-Process -Id $beforeRestart.process_binding.supervisor_pid -Force
        # SCM owns the bounded restart policy. Verify exact old process instances.
        Start-Sleep -Milliseconds 800
        $code = 'import json,sys; from weir.browser.windows_process import inspect_process; dead=[]; pairs=json.loads(sys.argv[1]);' + "`n" +
            'for pid,birth in pairs:' + "`n" +
            ' try: dead.append(inspect_process(pid)["created"] != birth)' + "`n" +
            ' except OSError: dead.append(True)' + "`n" + 'print(json.dumps(dead)); sys.exit(0 if all(dead) else 1)'
        $instances = @(@($beforeRestart.worker_pid, $beforeRestart.process_binding.worker_created), @($beforeRestart.descendant_pid, $beforeRestart.descendant_created)) | ConvertTo-Json -Compress
        $deathResult = & $python -I -B -c $code $instances
        if ($LASTEXITCODE -ne 0) { throw 'Supervisor exit left a worker or descendant alive' }
        $results.parent_death = @{ worker_and_descendant_dead = $true }
        $null = Wait-Health 'admitted' $changedAt
        $afterRestart = Verify-Live
        if ($beforeRestart.process_binding.supervisor_created -eq $afterRestart.process_binding.supervisor_created -or
            $beforeRestart.process_binding.worker_created -eq $afterRestart.process_binding.worker_created) { throw 'Restart reused a process binding' }
        $results.restart = @{ new_supervisor_instance = $true; new_worker_instance = $true; old_binding_differs = $true }
    }
    $results.final = Verify-Live
    $report = [ordered]@{ state = 'passed'; started_at = $started.ToString('o'); completed_at = [datetime]::UtcNow.ToString('o');
        action_endpoint_enabled = $false; denial_canaries_exercised = [bool]$ExerciseDenials; checks = $results }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), ($report | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $report | ConvertTo-Json -Depth 12
    exit 0
} catch {
    $report = @{ state = 'failed'; completed_at = [datetime]::UtcNow.ToString('o'); checks = $results;
        reason = $_.Exception.Message; action_endpoint_enabled = $false }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), ($report | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    throw
}

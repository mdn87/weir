[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Apply', 'Verify', 'Rollback')][string]$Mode = 'Prepare',
    [Parameter(Mandatory = $true)][string]$Bundle,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ManifestSha256,
    [string]$Root = (Join-Path $env:ProgramData 'WeirAdmission')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$serviceName = 'WeirAdmission'
$ruleName = 'WeirAdmission-DenyOutbound'
$bundlePath = [IO.Path]::GetFullPath($Bundle)
$rootPath = [IO.Path]::GetFullPath($Root)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'WeirAdmission'))
if ($rootPath -cne $expectedRoot -or [Environment]::MachineName -cne 'MATT') { throw 'This reviewed installer targets 4070pc at ProgramData\WeirAdmission only' }
if ($bundlePath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Bundle must be outside the deployment' }

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Deployment path contains a reparse point' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Invoke-ServiceCommand([string[]]$Arguments) {
    $result = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('SCM command failed: ' + $Arguments[0] + ' (' + $LASTEXITCODE + ')') }
}

function Set-DirectoryPolicy([string]$Path, [string]$ServiceSid, [switch]$Credentials, [switch]$Status) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $serviceRights = $(if ($Status) { 'Modify' } else { 'ReadAndExecute' })
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($ServiceSid), $serviceRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    if (-not $Credentials) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-Runtime([string]$Runtime, [object]$Manifest) {
    $files = @(Get-ChildItem -LiteralPath $Runtime -Recurse -Force -File)
    if ($files.Count -ne $Manifest.files.Count) { throw 'Runtime file count differs from reviewed manifest' }
    $seen = @{}
    foreach ($entry in $Manifest.files) {
        $path = [IO.Path]::GetFullPath((Join-Path $Runtime $entry.path))
        if (-not $path.StartsWith($Runtime + '\', [StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($path)) { throw 'Invalid manifest path' }
        Assert-NoReparse $path
        $seen[$path] = $true
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Runtime hash differs from reviewed manifest' }
    }
}

Assert-NoReparse $rootPath
Assert-NoReparse $bundlePath
$manifestPath = Join-Path $bundlePath 'runtime-manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) { throw 'Bundle manifest hash mismatch' }
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.files.Count -lt 1 -or $manifest.files.Count -gt 20000) { throw 'Invalid runtime manifest' }
$sourceRuntime = Join-Path $bundlePath 'runtime'
Assert-Runtime $sourceRuntime $manifest
$serviceSidText = & "$env:SystemRoot\System32\sc.exe" showsid $serviceName
if ($LASTEXITCODE -ne 0) { throw 'Service identity cannot be resolved' }
$serviceSid = [regex]::Match(($serviceSidText -join "`n"), 'S-1-5-80(?:-\d+){5}').Value
if (-not $serviceSid) { throw 'Service SID is absent' }
if ($Mode -eq 'Prepare') {
    [ordered]@{ state = 'prepared'; host = $env:COMPUTERNAME; root = $rootPath; service = $serviceName;
        service_sid = $serviceSid; manifest_sha256 = $ManifestSha256; runtime_files = $manifest.files.Count;
        action_endpoint_enabled = $false; start_mode = 'Manual'; administrator_required_for_apply = $true } | ConvertTo-Json
    exit 0
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator elevation is required for this concrete host operation' }
$existingService = Get-CimInstance Win32_Service -Filter "Name = 'WeirAdmission'"
$configPath = Join-Path $rootPath 'deployment.json'
$markerPath = Join-Path $rootPath 'installation.json'
if (Test-Path -LiteralPath $rootPath) {
    $rootAcl = Get-Acl -LiteralPath $rootPath
    if ($rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544') -or
        -not $rootAcl.AreAccessRulesProtected -or -not (Test-Path -LiteralPath $markerPath)) { throw 'An unrecognized deployment directory already exists' }
    foreach ($ace in $rootAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -and
            (([int]$ace.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'Existing deployment is writable by an untrusted principal' }
    }
    Assert-NoReparse $markerPath
    $marker = Get-Content -Raw -LiteralPath $markerPath | ConvertFrom-Json
    if ($marker.schema_version -ne 1 -or $marker.root -cne $rootPath -or $marker.service_sid -cne $serviceSid) { throw 'Deployment marker differs' }
}
if ($null -ne $existingService) {
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'An unrecognized service already owns this name' }
    $previous = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
    if ($previous.service_sid -cne $serviceSid -or $previous.service_name -cne $serviceName -or $previous.root -cne $rootPath -or
        -not $existingService.PathName.StartsWith('"' + $rootPath + '\releases\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Existing deployment identity differs' }
}
if ($Mode -eq 'Rollback') {
    if ($null -eq $existingService) { throw 'No recognized service to roll back' }
    Invoke-ServiceCommand @('config', $serviceName, 'start=', 'disabled')
    Stop-Service -Name $serviceName -ErrorAction Stop
    @{ state = 'disabled'; retained = @('runtime', 'credentials', 'firewall-block', 'evidence') } | ConvertTo-Json
    exit 0
}
if ($Mode -eq 'Verify') {
    & (Join-Path $PSScriptRoot 'verify_windows_controls.ps1') -Root $rootPath -OutputPath (Join-Path $bundlePath 'host-acceptance.json')
    exit $LASTEXITCODE
}
if ($null -ne $existingService) {
    Invoke-ServiceCommand @('config', $serviceName, 'start=', 'disabled')
    if ($existingService.State -ne 'Stopped') { Stop-Service -Name $serviceName }
}
try {
    if (-not (Test-Path -LiteralPath $rootPath)) { New-Item -ItemType Directory -Path $rootPath | Out-Null }
    Set-DirectoryPolicy $rootPath $serviceSid
    if (-not (Test-Path -LiteralPath $markerPath)) {
        [IO.File]::WriteAllText($markerPath, (@{ schema_version = 1; root = $rootPath; service_sid = $serviceSid } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        & "$env:SystemRoot\System32\icacls.exe" $markerPath /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Deployment marker ownership could not be secured' }
    }
    foreach ($name in @('releases', 'credentials', 'status', 'history')) {
        $directory = Join-Path $rootPath $name
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        Set-DirectoryPolicy $directory $serviceSid -Credentials:($name -eq 'credentials') -Status:($name -eq 'status')
    }
    $release = Join-Path (Join-Path $rootPath 'releases') $ManifestSha256
    $runtime = Join-Path $release 'runtime'
    if (-not (Test-Path -LiteralPath $runtime)) {
        New-Item -ItemType Directory -Force -Path $release | Out-Null
        Copy-Item -LiteralPath $sourceRuntime -Destination $runtime -Recurse
    }
    Assert-Runtime $runtime $manifest
    $python = Join-Path $runtime 'python.exe'
    & "$env:SystemRoot\System32\icacls.exe" $runtime /reset /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Runtime permissions could not be reset to the protected parent' }
    $containerName = 'Lugos.WeirAdmission'
    $containerSid = & $python -I -B -c "from weir.browser.windows_sandbox import appcontainer_sid; print(appcontainer_sid('Lugos.WeirAdmission'))"
    if ($LASTEXITCODE -ne 0 -or $containerSid -notmatch '^S-1-15-2(?:-\d+){7}$') { throw 'AppContainer SID derivation failed' }
    & "$env:SystemRoot\System32\icacls.exe" $runtime /grant ('*' + $containerSid + ':(OI)(CI)(RX)') /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Runtime AppContainer ACL failed' }
    $sources = @()
    foreach ($caller in @('lugos-mcp', 'fade-weir-authority')) {
        $path = Join-Path (Join-Path $rootPath 'credentials') ($caller + '.token')
        if (-not (Test-Path -LiteralPath $path)) {
            $random = [Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 32
            try { $random.GetBytes($bytes); [IO.File]::WriteAllText($path, [Convert]::ToBase64String($bytes), [Text.UTF8Encoding]::new($false)) }
            finally { [Array]::Clear($bytes, 0, $bytes.Length); $random.Dispose() }
        }
        $sources += [ordered]@{ caller_id = $caller; source_id = ('weir-' + $caller + '-v1'); path = $path }
    }
    if ([IO.File]::ReadAllText($sources[0].path) -ceq [IO.File]::ReadAllText($sources[1].path)) { throw 'Existing caller credentials are not distinct; no credential was rotated' }
    if (Test-Path -LiteralPath $configPath) {
        Copy-Item -LiteralPath $configPath -Destination (Join-Path (Join-Path $rootPath 'history') ('deployment-' + (Get-Date -Format 'yyyyMMdd-HHmmss-ffff') + '.json'))
    }
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $rootPath 'runtime-manifest.json') -Force
    $config = [ordered]@{ schema_version = 1; host_name = $env:COMPUTERNAME; service_name = $serviceName;
        service_sid = $serviceSid; root = $rootPath; python_executable = $python; base_python_root = $runtime;
        firewall_rule = $ruleName; appcontainer_name = $containerName; appcontainer_sid = $containerSid;
        runtime_manifest_sha256 = $ManifestSha256; memory_bytes = 536870912; process_count = 8; credentials = $sources }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    & "$env:SystemRoot\System32\icacls.exe" $rootPath /setowner '*S-1-5-32-544' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Deployment ownership could not be secured' }
    $command = '"' + $python + '" -I -B -m weir.windows_service --config "' + $configPath + '"'
    if ($null -eq $existingService) {
        Invoke-ServiceCommand @('create', $serviceName, 'type=', 'own', 'start=', 'disabled', 'obj=', ('NT SERVICE\' + $serviceName), 'binPath=', $command)
    } else {
        Invoke-ServiceCommand @('config', $serviceName, 'type=', 'own', 'start=', 'disabled', 'obj=', ('NT SERVICE\' + $serviceName), 'binPath=', $command)
    }
    Invoke-ServiceCommand @('sdset', $serviceName, ('O:BAG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;' + $serviceSid + ')'))
    . (Join-Path $runtime 'Lib/site-packages/weir/data/windows/service-policy.ps1')
    [WeirAdmission.ServicePolicy]::Configure($serviceName)
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existingRule) {
        if ($existingRule.Description -cne 'WEIR Batch 7P dedicated service account deny-only egress') { throw 'An unrelated firewall rule already owns this name' }
        $existingRule | Set-NetFirewallRule -Enabled True -Direction Outbound -Action Block -Profile Any -Protocol Any -Program Any -Service Any -LocalAddress Any -RemoteAddress Any -LocalPort Any -RemotePort Any -LocalUser ('D:(A;;CC;;;' + $serviceSid + ')') | Out-Null
    } else {
        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Description 'WEIR Batch 7P dedicated service account deny-only egress' -Enabled True -Direction Outbound -Action Block -Profile Any -Protocol Any -LocalUser ('D:(A;;CC;;;' + $serviceSid + ')') | Out-Null
    }
    Invoke-ServiceCommand @('config', $serviceName, 'start=', 'demand')
    Start-Service -Name $serviceName
    & (Join-Path $PSScriptRoot 'verify_windows_controls.ps1') -Root $rootPath -OutputPath (Join-Path $bundlePath 'host-acceptance.json') -ExerciseDenials
    if ($LASTEXITCODE -ne 0) { throw 'Host acceptance failed' }
} catch {
    # Retain credentials, evidence and firewall protection. Never delete or rotate.
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        & "$env:SystemRoot\System32\sc.exe" config $serviceName start= disabled | Out-Null
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    }
    throw
}

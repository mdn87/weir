#requires -Version 7.3
[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Apply', 'Verify', 'Rollback')][string]$Mode = 'Prepare',
    [string]$Bundle,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ManifestSha256,
    [string]$Root = (Join-Path $env:ProgramData 'WeirAdmission')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSNativeCommandArgumentPassing -eq 'Legacy') { throw 'This installer requires Standard or Windows native argument passing' }
$serviceName = 'WeirAdmission'
$ruleName = 'WeirAdmission-DenyOutbound'
$bundlePath = $null
if ($Mode -ne 'Rollback') {
    if (-not $Bundle -or -not $ManifestSha256) { throw 'Bundle and ManifestSha256 are required for preparation, installation or verification' }
    $bundlePath = [IO.Path]::GetFullPath($Bundle)
}
$rootPath = [IO.Path]::GetFullPath($Root)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'WeirAdmission'))
if ($rootPath -cne $expectedRoot -or [Environment]::MachineName -cne 'MATT') { throw 'This reviewed installer targets 4070pc at ProgramData\WeirAdmission only' }
if ($null -ne $bundlePath -and $bundlePath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Bundle must be outside the deployment' }

function New-ProtectedRoot([string]$Path, [string]$ServiceSid) {
    # CreateDirectoryW installs the owner/DACL atomically and fails if the name exists.
    if (-not ('WeirAdmission.DirectoryCreation' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace WeirAdmission {
  public static class DirectoryCreation {
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string value, int revision, out IntPtr descriptor, IntPtr size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectory(string path, ref Attributes attributes);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    public static void Create(string path, string sddl) {
      IntPtr descriptor;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
      try {
        var attributes = new Attributes { Length=Marshal.SizeOf(typeof(Attributes)), Descriptor=descriptor, Inherit=0 };
        if (!CreateDirectory(path, ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error());
      } finally { LocalFree(descriptor); }
    }
  }
}
'@
    }
    [WeirAdmission.DirectoryCreation]::Create($Path, ('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;' + $ServiceSid + ')(A;OICI;FRFX;;;BU)'))
}

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

function Assert-ProtectedPath([string]$Path, [switch]$Status, [switch]$Credentials) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Existing deployment object has an untrusted owner' }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($Credentials -and $ace.AccessControlType -eq 'Deny') { throw 'Existing credential protection has an unsupported deny ACE' }
        if ($Credentials -and $ace.AccessControlType -eq 'Allow' -and
            $ace.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544', $serviceSid) -and
            (([int]$ace.FileSystemRights -band 0x90000001) -ne 0)) { throw 'Existing credentials may have been exposed; no credential was rotated' }
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -and
            -not ($Status -and $ace.IdentityReference.Value -eq $serviceSid) -and
            (([int]$ace.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'Existing deployment object has an untrusted writer' }
    }
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
    Assert-NoReparse $Runtime
    $items = @(Get-ChildItem -LiteralPath $Runtime -Recurse -Force)
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime contains a reparse point' }
    }
    $files = @($items | Where-Object { -not $_.PSIsContainer })
    if ($files.Count -ne $Manifest.files.Count) { throw 'Runtime file count differs from reviewed manifest' }
    $seen = @{}
    foreach ($entry in $Manifest.files) {
        $path = [IO.Path]::GetFullPath((Join-Path $Runtime $entry.path))
        if (-not $path.StartsWith($Runtime + '\', [StringComparison]::OrdinalIgnoreCase) -or $seen.ContainsKey($path)) { throw 'Invalid manifest path' }
        $seen[$path] = $true
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Runtime hash differs from reviewed manifest' }
    }
}

Assert-NoReparse $rootPath
if ($Mode -ne 'Rollback') {
    Assert-NoReparse $bundlePath
    $manifestPath = Join-Path $bundlePath 'runtime-manifest.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) { throw 'Bundle manifest hash mismatch' }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.files.Count -lt 1 -or $manifest.files.Count -gt 20000) { throw 'Invalid runtime manifest' }
    $sourceRuntime = Join-Path $bundlePath 'runtime'
    Assert-Runtime $sourceRuntime $manifest
}
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
$recognizedRoot = Test-Path -LiteralPath $rootPath
if ($recognizedRoot) {
    $rootAcl = Get-Acl -LiteralPath $rootPath
    if ($rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544') -or
        -not $rootAcl.AreAccessRulesProtected -or -not (Test-Path -LiteralPath $markerPath)) { throw 'An unrecognized deployment directory already exists' }
    foreach ($ace in $rootAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -and
            (([int]$ace.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'Existing deployment is writable by an untrusted principal' }
    }
    Assert-ProtectedPath $markerPath
    $marker = Get-Content -Raw -LiteralPath $markerPath | ConvertFrom-Json
    if ($marker.schema_version -ne 1 -or $marker.root -cne $rootPath -or $marker.service_sid -cne $serviceSid) { throw 'Deployment marker differs' }
}
if ($null -ne $existingService) {
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'An unrecognized service already owns this name' }
    Assert-ProtectedPath $configPath
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
    if (-not $recognizedRoot) { New-ProtectedRoot $rootPath $serviceSid }
    Assert-ProtectedPath $rootPath
    Set-DirectoryPolicy $rootPath $serviceSid
    if (-not (Test-Path -LiteralPath $markerPath)) {
        [IO.File]::WriteAllText($markerPath, (@{ schema_version = 1; root = $rootPath; service_sid = $serviceSid } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        & "$env:SystemRoot\System32\icacls.exe" $markerPath /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Deployment marker ownership could not be secured' }
    }
    foreach ($name in @('releases', 'credentials', 'status', 'history')) {
        $directory = Join-Path $rootPath $name
        if (Test-Path -LiteralPath $directory) { Assert-ProtectedPath $directory -Status:($name -eq 'status') -Credentials:($name -eq 'credentials') }
        else { New-Item -ItemType Directory -Path $directory | Out-Null }
        Set-DirectoryPolicy $directory $serviceSid -Credentials:($name -eq 'credentials') -Status:($name -eq 'status')
    }
    # Every attempt stages a new immutable release. Interrupted copies remain inert.
    $release = Join-Path (Join-Path $rootPath 'releases') ($ManifestSha256 + '-' + [guid]::NewGuid().ToString('N'))
    $runtime = Join-Path $release 'runtime'
    New-Item -ItemType Directory -Path $release | Out-Null
    Set-DirectoryPolicy $release $serviceSid -Credentials
    Copy-Item -LiteralPath $sourceRuntime -Destination $runtime -Recurse
    Assert-Runtime $runtime $manifest
    $python = Join-Path $runtime 'python.exe'
    & "$env:SystemRoot\System32\icacls.exe" $runtime /reset /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Runtime permissions could not be reset to the protected parent' }
    & "$env:SystemRoot\System32\icacls.exe" $release /setowner '*S-1-5-32-544' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Runtime ownership could not be secured before execution' }
    $containerName = 'Lugos.WeirAdmission'
    $containerSid = & $python -I -B -c "from weir.browser.windows_sandbox import appcontainer_sid; print(appcontainer_sid('Lugos.WeirAdmission'))"
    if ($LASTEXITCODE -ne 0 -or $containerSid -notmatch '^S-1-15-2(?:-\d+){7}$') { throw 'AppContainer SID derivation failed' }
    & "$env:SystemRoot\System32\icacls.exe" $runtime /grant ('*' + $containerSid + ':(OI)(CI)(RX)') /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Runtime AppContainer ACL failed' }
    $sources = @()
    foreach ($caller in @('lugos-mcp', 'fade-weir-authority')) {
        $path = Join-Path (Join-Path $rootPath 'credentials') ($caller + '.token')
        if (Test-Path -LiteralPath $path) { Assert-ProtectedPath $path -Credentials }
        else {
            $random = [Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 32
            try { $random.GetBytes($bytes); [IO.File]::WriteAllText($path, [Convert]::ToBase64String($bytes), [Text.UTF8Encoding]::new($false)) }
            finally { [Array]::Clear($bytes, 0, $bytes.Length); $random.Dispose() }
        }
        $sources += [ordered]@{ caller_id = $caller; source_id = ('weir-' + $caller + '-v1'); path = $path }
    }
    if ([IO.File]::ReadAllText($sources[0].path) -ceq [IO.File]::ReadAllText($sources[1].path)) { throw 'Existing caller credentials are not distinct; no credential was rotated' }
    if (Test-Path -LiteralPath $configPath) {
        Assert-ProtectedPath $configPath
        $historyPath = Join-Path (Join-Path $rootPath 'history') ('deployment-' + [guid]::NewGuid().ToString('N') + '.json')
        Copy-Item -LiteralPath $configPath -Destination $historyPath
        & "$env:SystemRoot\System32\icacls.exe" $historyPath /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'History ownership could not be secured' }
    }
    $installedManifest = Join-Path $rootPath 'runtime-manifest.json'
    if (Test-Path -LiteralPath $installedManifest) { Assert-ProtectedPath $installedManifest }
    Copy-Item -LiteralPath $manifestPath -Destination $installedManifest -Force
    $config = [ordered]@{ schema_version = 1; host_name = $env:COMPUTERNAME; service_name = $serviceName;
        service_sid = $serviceSid; root = $rootPath; python_executable = $python; base_python_root = $runtime;
        firewall_rule = $ruleName; appcontainer_name = $containerName; appcontainer_sid = $containerSid;
        runtime_manifest_sha256 = $ManifestSha256; memory_bytes = 536870912; process_count = 8; credentials = $sources }
    $temporaryConfig = Join-Path $rootPath ('deployment-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($temporaryConfig, ($config | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    # Never walk retained releases or service-writable status during elevated repair.
    foreach ($ownedFile in @($temporaryConfig, $installedManifest) + @($sources | ForEach-Object { $_.path })) {
        Assert-NoReparse $ownedFile
        & "$env:SystemRoot\System32\icacls.exe" $ownedFile /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Deployment file ownership could not be secured' }
    }
    if (Test-Path -LiteralPath $configPath) { [IO.File]::Replace($temporaryConfig, $configPath, [NullString]::Value) }
    else { [IO.File]::Move($temporaryConfig, $configPath) }
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

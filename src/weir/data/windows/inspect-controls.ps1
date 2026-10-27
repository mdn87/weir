# Read-only OS inspection. Input is trusted deployment metadata, never credentials.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$config = $request.config
$administrators = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Read-AclRecord([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-Acl -LiteralPath $Path
    $aces = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [ordered]@{ sid = $_.IdentityReference.Value; rights = [int]$_.FileSystemRights;
            allow = ($_.AccessControlType -eq 'Allow');
            inherit_only = (([int]$_.PropagationFlags -band 2) -ne 0) }
    })
    return [ordered]@{ path = $item.FullName; owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
        reparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0); aces = $aces }
}

function Assert-ReadOnly([object]$Record) {
    if ($Record.reparse -or $Record.owner -notin $administrators -or $Record.aces.Count -eq 0) {
        throw 'Untrusted runtime ownership or reparse point'
    }
    foreach ($ace in $Record.aces) {
        if ($ace.allow -and -not $ace.inherit_only -and $ace.sid -notin $administrators -and
            (($ace.rights -band 0x500D0156) -ne 0)) { throw 'Runtime has an untrusted writer' }
    }
}

function Any-Value($Value) {
    if ($null -eq $Value -or [string]$Value -eq '') { return 'Any' }
    return [string]$Value
}

$stage = 'runtime'
try {
    $root = [IO.Path]::GetFullPath($config.root)
    $runtime = [IO.Path]::GetFullPath($config.base_python_root)
    if (-not $runtime.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime is outside deployment' }
    $manifestPath = Join-Path $root 'runtime-manifest.json'
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifestHash -cne $config.runtime_manifest_sha256) { throw 'Runtime manifest changed' }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.files.Count -lt 1 -or $manifest.files.Count -gt 20000) { throw 'Invalid runtime manifest' }
    $requiredPaths = @($root, (Join-Path $root 'deployment.json'), $manifestPath, $config.python_executable, $runtime)
    $intermediate = [IO.Directory]::GetParent($runtime)
    while (-not $intermediate.FullName.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
        $requiredPaths += $intermediate.FullName
        $intermediate = $intermediate.Parent
    }
    $paths = @($requiredPaths | Select-Object -Unique | ForEach-Object { $entry = Read-AclRecord $_; Assert-ReadOnly $entry; $entry })
    $ancestors = @()
    $ancestor = [IO.Directory]::GetParent($root)
    while ($null -ne $ancestor) {
        $ancestors += Read-AclRecord $ancestor.FullName
        $ancestor = $ancestor.Parent
    }
    $actualFiles = @{}
    foreach ($item in Get-ChildItem -LiteralPath $runtime -Force -Recurse) {
        $record = Read-AclRecord $item.FullName
        Assert-ReadOnly $record
        if (-not $item.PSIsContainer) { $actualFiles[$item.FullName] = $true }
    }
    if ($actualFiles.Count -ne $manifest.files.Count) { throw 'Runtime file set changed' }
    $seenFiles = @{}
    foreach ($entry in $manifest.files) {
        $path = [IO.Path]::GetFullPath((Join-Path $runtime $entry.path))
        if (-not $path.StartsWith($runtime + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not $actualFiles.ContainsKey($path) -or $seenFiles.ContainsKey($path)) { throw 'Invalid runtime manifest path' }
        $seenFiles[$path] = $true
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Runtime file changed' }
    }
    $stage = 'credentials'
    $credentials = @($config.credentials | ForEach-Object { Read-AclRecord $_.path })
    $credentialDirectory = Read-AclRecord (Join-Path $root 'credentials')
    Assert-ReadOnly $credentialDirectory
    $stage = 'service'
    $serviceName = [string]$config.service_name
    if ($serviceName -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw 'Invalid service name' }
    $service = Get-CimInstance Win32_Service -Filter ("Name = '" + $serviceName + "'")
    if ($null -eq $service) { throw 'Service is absent' }
    $registry = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName)
    if ($registry.Type -ne 16 -or $registry.Start -ne 3 -or $registry.ServiceSidType -ne 1 -or
        (@($registry.RequiredPrivileges) -join ',') -cne 'SeChangeNotifyPrivilege') { throw 'Service type, start mode, SID or privileges changed' }
    . (Join-Path $PSScriptRoot 'service-policy.ps1')
    $servicePolicy = [WeirAdmission.ServicePolicy]::Read($serviceName)
    if ($servicePolicy.SidType -ne 1 -or ($servicePolicy.RequiredPrivileges -join ',') -cne 'SeChangeNotifyPrivilege' -or
        $servicePolicy.ResetSeconds -ne 86400 -or ($servicePolicy.Actions -join ',') -cne '1,1,0' -or
        ($servicePolicy.Delays -join ',') -cne '5000,30000,0' -or -not $servicePolicy.NonCrashFailures) { throw 'Service recovery or privilege policy changed' }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($servicePolicy.SecurityDescriptor)
    if ($null -eq $descriptor.Owner -or $descriptor.Owner.Value -notin $administrators) { throw 'Untrusted service owner' }
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'Service DACL missing' }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.AceType -ne 'AccessAllowed' -and $ace.AceType -ne 'AccessDenied') { throw 'Unsupported service ACE' }
        if ($ace.AceType -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -notin $administrators -and
            (($ace.AccessMask -band (-bnot 0x0002008D)) -ne 0)) { throw 'Service object has an untrusted controller' }
    }
    $supervisor = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$request.supervisor_pid)
    $worker = $null
    if ($null -ne $request.worker_pid) {
        $worker = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$request.worker_pid)
        if ($null -eq $worker) { throw 'Worker process is absent' }
    }
    $stage = 'firewall'
    $profiles = [ordered]@{}
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore) {
        $profiles[[string]$profile.Name] = ([string]$profile.Enabled -eq 'True')
    }
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $config.firewall_rule
    if (@($rule).Count -ne 1 -or [string]$rule.PrimaryStatus -ne 'OK') { throw 'Effective firewall rule is unavailable' }
    $application = $rule | Get-NetFirewallApplicationFilter
    $security = $rule | Get-NetFirewallSecurityFilter
    $serviceFilter = $rule | Get-NetFirewallServiceFilter
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $interface = $rule | Get-NetFirewallInterfaceFilter
    $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
    if ([string]$security.Encryption -ne 'NotRequired' -or [string]$security.OverrideBlockRules -ne 'False' -or
        [string]$port.IcmpType -ne 'Any' -or [string]$port.DynamicTarget -ne 'Any' -or
        [string]$port.DynamicTransport -ne 'Any') { throw 'Firewall security or transport filter narrowed' }
    if (@($rule.Platforms).Count -gt 0 -or @($rule.RemoteDynamicKeywordAddresses).Count -gt 0 -or
        $rule.PackageFamilyName -or $rule.PolicyAppId -or $rule.Owner) { throw 'Firewall rule has additional restrictions' }
    foreach ($filter in @($application, $security, $serviceFilter, $port, $address, $interface, $interfaceType)) {
        if ($filter.IsNegated) { throw 'Firewall filter is negated' }
    }
    $bypass = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Outbound |
        Get-NetFirewallSecurityFilter | Where-Object { [string]$_.OverrideBlockRules -eq 'True' } | ForEach-Object { $_.InstanceID })
    $loopback = & "$env:SystemRoot\System32\CheckNetIsolation.exe" LoopbackExempt -s
    if ($LASTEXITCODE -ne 0) { throw 'Loopback exemptions unavailable' }
    $exemptions = @([regex]::Matches(($loopback -join "`n"), 'S-1-15-2(?:-\d+){7}') | ForEach-Object { $_.Value })
    $facts = [ordered]@{
        host_name = [Environment]::MachineName;
        service = [ordered]@{ name = $service.Name; state = $service.State; pid = [int]$service.ProcessId;
            account = $service.StartName; start_mode = $service.StartMode; command = $service.PathName };
        supervisor = @{ parent_pid = [int]$supervisor.ParentProcessId };
        worker = $(if ($null -eq $worker) { $null } else { @{ parent_pid = [int]$worker.ParentProcessId } });
        paths = $paths; ancestors = $ancestors; credentials = $credentials;
        closure = @{ manifest_sha256 = $manifestHash; verified_files = $seenFiles.Count };
        loopback_exemptions = $exemptions;
        firewall = [ordered]@{
            services = @{ BFE = [string](Get-Service BFE).Status; MpsSvc = [string](Get-Service MpsSvc).Status };
            profiles = $profiles; bypass_rules = $bypass;
            rule = [ordered]@{
                name = $rule.Name; enabled = ([string]$rule.Enabled -eq 'True'); direction = [string]$rule.Direction;
                action = [string]$rule.Action; profiles = [string]$rule.Profile;
                enforcement = @($rule.CimInstanceProperties['EnforcementStatus'].Value | ForEach-Object { [int]$_ });
                local_user = [string]$security.LocalUsers; remote_user = (Any-Value $security.RemoteUsers);
                remote_machine = (Any-Value $security.RemoteMachines); authentication = [string]$security.Authentication;
                program = (Any-Value $application.AppPath); package = (Any-Value $application.Package);
                service = (Any-Value $serviceFilter.ServiceName); protocol = [string]$port.Protocol;
                local_address = @($address.LocalAddress); remote_address = @($address.RemoteAddress);
                local_port = @($port.LocalPort); remote_port = @($port.RemotePort);
                interface_type = [string]$interfaceType.InterfaceType; interface_alias = @($interface.InterfaceAlias)
            }
        }
    }
    $facts | ConvertTo-Json -Depth 12 -Compress
} catch {
    # Do not return file contents, native command output, paths or credential values.
    [Console]::Error.WriteLine('Windows control inspection denied: ' + $stage)
    exit 1
}

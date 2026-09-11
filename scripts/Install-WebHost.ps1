#Requires -Version 7.2
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RuntimePayload,
    [Parameter(Mandatory)][string]$NodePayload,
    [Parameter(Mandatory)][string]$GuestImage,
    [Parameter(Mandatory)][string]$Certification,
    [Parameter(Mandatory)][string]$ReleasePublicKey,
    [Parameter(Mandatory)][string]$Bootstrap,
    [Parameter(Mandatory)][string]$IdentityPrivateKey,
    [Parameter(Mandatory)][uri]$HeadquartersOrigin,
    [ValidateRange(2,128)][int]$CpuCount = 4,
    [ValidateRange(4096,1048576)][int]$MemoryMb = 16384,
    [ValidateRange(65536,16777216)][int]$DiskMb = 131072,
    [ValidateRange(1024,1048576)][int]$ArtifactCacheMb = 8192
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $HeadquartersOrigin.Scheme -ne 'https' -or $HeadquartersOrigin.AbsolutePath -ne '/' -or $HeadquartersOrigin.UserInfo -or $HeadquartersOrigin.Query -or $HeadquartersOrigin.Fragment) { throw 'An HTTPS Headquarters origin on Windows is required.' }
Import-Module Hyper-V -ErrorAction Stop
function Assert-PlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation paths cannot traverse reparse points.' }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}
foreach ($path in @($RuntimePayload,$NodePayload,$GuestImage,$Certification,$ReleasePublicKey,$Bootstrap,$IdentityPrivateKey)) { Assert-PlainPath $path }
$runtimeSource = (Resolve-Path -LiteralPath $RuntimePayload).Path
$nodeSource = (Resolve-Path -LiteralPath $NodePayload).Path
$nodeVerifier = Join-Path $nodeSource 'CSweet.WebHost.Node.exe'
if (!(Test-Path -LiteralPath $nodeVerifier -PathType Leaf)) { throw 'Publish the Windows Node payload first.' }
# Verification is read-only and must succeed before any service/configuration is created.
& $nodeVerifier verify-release $Certification $ReleasePublicKey $GuestImage $runtimeSource
if ($LASTEXITCODE -ne 0) { throw 'The exact runtime/image release is not independently certified.' }
$bootstrapData = Get-Content -LiteralPath $Bootstrap -Raw | ConvertFrom-Json
if ([Guid]::Parse($bootstrapData.enrollment.id) -eq [Guid]::Empty -or [DateTimeOffset]::Parse($bootstrapData.identityExpiresAt) -le [DateTimeOffset]::UtcNow) { throw 'A current owner-issued enrollment is required.' }
$key = [Security.Cryptography.ECDsa]::Create()
try { $key.ImportFromPem([IO.File]::ReadAllText((Resolve-Path -LiteralPath $IdentityPrivateKey).Path)); $null = $key.ExportParameters($true) }
finally { $key.Dispose() }
function Assert-ProtectedAncestor([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    $writeMask = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($null -ne $item) {
        Assert-PlainPath $item.FullName
        $acl = Get-Acl -LiteralPath $item.FullName
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { throw 'An installation ancestor is not owned by SYSTEM, Administrators, or TrustedInstaller.' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band $writeMask) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { throw 'An installation ancestor allows replacement by an untrusted principal.' }
        }
        $item = $item.Parent
    }
}
foreach ($base in @($env:ProgramFiles,$env:ProgramData)) {
    $candidate = Join-Path $base 'CSweet'
    Assert-ProtectedAncestor $(if (Test-Path -LiteralPath $candidate) { $candidate } else { $base })
}
$programRoot = Join-Path $env:ProgramFiles 'CSweet\WebHost'
$dataRoot = Join-Path $env:ProgramData 'CSweet\WebHost'
if ((Test-Path -LiteralPath $programRoot) -or (Test-Path -LiteralPath $dataRoot) -or (Get-Service -Name 'CSweet.WebHost.*' -ErrorAction SilentlyContinue)) { throw 'This installer is for a fresh host. Drain existing previews and use a reviewed upgrade before replacing an installation.' }
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$nodeAccount = 'NT SERVICE\CSweet.WebHost.Node'
function Protect-Directory([string]$Path, [Security.Principal.SecurityIdentifier]$Reader, [bool]$Writable = $false) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    Assert-PlainPath $Path
    $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetOwner($admins); $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($system,$admins)) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
    if ($null -ne $Reader) { $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }; $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Reader,$rights,'ContainerInherit,ObjectInherit','None','Allow')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
# Restrict newly created shared ancestors too. Do not change pre-existing CSweet parent ACLs silently.
foreach ($parent in @((Split-Path $programRoot),(Split-Path $dataRoot))) {
    if (!(Test-Path -LiteralPath $parent)) { Protect-Directory $parent $null }
    Assert-PlainPath $parent
}
Protect-Directory $programRoot $null; Protect-Directory $dataRoot $null
$runtime = Join-Path $programRoot 'Runtime'; $node = Join-Path $programRoot 'Node'
Protect-Directory $runtime $null; Protect-Directory $node $null
foreach ($source in @(@($runtimeSource,$runtime),@($nodeSource,$node))) {
    foreach ($item in Get-ChildItem -LiteralPath $source[0]) {
        Assert-PlainPath $item.FullName
        if ($item.PSIsContainer) { throw 'Use a flat, framework-dependent Windows publish payload.' }
        Copy-Item -LiteralPath $item.FullName -Destination $source[1]
    }
}
$runtimeExe = Join-Path $runtime 'CSweet.WebHost.RuntimeHost.exe'; $nodeExe = Join-Path $node 'CSweet.WebHost.Node.exe'
& sc.exe create 'CSweet.WebHost.RuntimeHost' binPath= ('"' + $runtimeExe + '"') start= disabled obj= LocalSystem
if ($LASTEXITCODE -ne 0) { throw 'Runtime service registration failed.' }
& sc.exe create 'CSweet.WebHost.Node' binPath= ('"' + $nodeExe + '" run') start= disabled obj= $nodeAccount depend= 'CSweet.WebHost.RuntimeHost'
if ($LASTEXITCODE -ne 0) { throw 'Node service registration failed. The runtime remains disabled.' }
$nodeSid = ([Security.Principal.NTAccount]::new($nodeAccount)).Translate([Security.Principal.SecurityIdentifier])
# Parent traversal is read-only; only the dedicated Node state directory is writable by Node.
Protect-Directory $programRoot $nodeSid; Protect-Directory $node $nodeSid; Protect-Directory $dataRoot $nodeSid
$protected = Join-Path $dataRoot 'Protected'; $nodeState = Join-Path $dataRoot 'NodeState'
Protect-Directory $protected $null; Protect-Directory $nodeState $nodeSid $true
$state = Join-Path $protected 'State'; $cache = Join-Path $protected 'Artifacts'
Protect-Directory $state $null; Protect-Directory $cache $null
$imagePath = Join-Path $protected 'product.vhdx'; $certificatePath = Join-Path $protected 'release.json'
Copy-Item -LiteralPath $GuestImage -Destination $imagePath; Copy-Item -LiteralPath $Certification -Destination $certificatePath
$identityPath = Join-Path $dataRoot 'node-identity.pem'; Copy-Item -LiteralPath $IdentityPrivateKey -Destination $identityPath
$release = (Get-Content -LiteralPath $certificatePath -Raw | ConvertFrom-Json).certificateJson | ConvertFrom-Json
$runtimeConfig = @{
    enrollment=$bootstrapData.enrollment; nodeSid=$nodeSid.Value
    provider=@{stateRoot=$state;guestImagePath=$imagePath;guestImageDigest=$release.guestImageDigest;artifactMediaRoot=$cache;runtimePayloadRoot=$runtime;
        certificationPath=$certificatePath;certificationPublicKeyBase64=(Get-Content -LiteralPath $ReleasePublicKey -Raw).Trim();
        hostCapacity=@{cpuCount=$CpuCount;memoryMb=$MemoryMb;diskMb=$DiskMb;maximumProcesses=4096;maximumLogBytes=33554432}; maximumArtifactCacheBytes=[long]$ArtifactCacheMb*1MB}
}
$runtimeConfig | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $dataRoot 'runtime-host.json')
@{headquartersOrigin=$HeadquartersOrigin.AbsoluteUri.TrimEnd('/');bootstrap=$bootstrapData;identityPrivateKeyPath=$identityPath;stateRoot=$nodeState} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $dataRoot 'node.json')
foreach ($installedRoot in @($programRoot,$dataRoot)) {
    foreach ($installedFile in Get-ChildItem -LiteralPath $installedRoot -File -Recurse) {
        Assert-PlainPath $installedFile.FullName
        $fileAcl = Get-Acl -LiteralPath $installedFile.FullName; $fileAcl.SetOwner($admins)
        Set-Acl -LiteralPath $installedFile.FullName -AclObject $fileAcl
    }
}
foreach ($service in @('CSweet.WebHost.RuntimeHost','CSweet.WebHost.Node')) {
    & sc.exe failure $service reset= 86400 actions= 'restart/1000/restart/5000/restart/10000'
    if ($LASTEXITCODE -ne 0) { throw 'Service recovery setup failed; services remain disabled.' }
    & sc.exe failureflag $service 1
    if ($LASTEXITCODE -ne 0) { throw 'Service recovery setup failed; services remain disabled.' }
}
# Only this dedicated Hyper-V socket service is registered. Product VMs have no network adapter.
$socketKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\00000aca-facb-11e6-bd58-64006a7986d3'
if (!(Test-Path -LiteralPath $socketKey)) { $null = New-Item -Path $socketKey -Force }
$null = New-ItemProperty -LiteralPath $socketKey -Name ElementName -Value 'CSweet Product Guest v1' -PropertyType String -Force
& sc.exe config 'CSweet.WebHost.RuntimeHost' start= auto
if ($LASTEXITCODE -ne 0) { throw 'Runtime service configuration failed.' }
& sc.exe config 'CSweet.WebHost.Node' start= delayed-auto
if ($LASTEXITCODE -ne 0) { throw 'Node service configuration failed.' }
Write-Output 'Installed. Review the protected configuration and start CSweet.WebHost.RuntimeHost, then CSweet.WebHost.Node. No product workload has been launched.'

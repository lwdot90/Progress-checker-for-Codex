<#
Development artifact inspector and staged installation candidate.
No marketplace/profile updates, executable launches, approvals, or state removal.
The current archive is unqualified: Install deliberately refuses activation.
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Install', 'Remove')][string]$Action = 'Validate',
    [string]$Archive,
    [string]$ArchiveSha256,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'ProgressCheckerDevelopment\plugin')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This candidate requires native Windows.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Assert-SafeDirectory([string]$Path) {
    $canonical = [IO.Path]::GetFullPath($Path)
    if ($canonical.StartsWith('\\')) { throw 'Remote and device path destinations are unsupported.' }
    $cursor = $canonical
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path components are unsupported.' }
            if (-not $item.PSIsContainer) { throw 'Installation ancestor must be a directory.' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $canonical
}
function Assert-Pe([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'Expected PE executable.' }
        $stream.Position = 60
        $offset = $reader.ReadUInt32()
        if ($offset -gt $stream.Length - 6) { throw 'PE header outside file.' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Expected native Windows x86_64 PE executable.' }
    } finally { $reader.Dispose(); $stream.Dispose() }
}
$destinationPath = Assert-SafeDirectory $Destination
# Dedicated development location; never remove installed marketplaces or state.
$developmentBase = Assert-SafeDirectory (Join-Path $env:LOCALAPPDATA 'ProgressCheckerDevelopment')
if (-not $destinationPath.StartsWith($developmentBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Destination must remain below the dedicated ProgressCheckerDevelopment directory.'
}
if ($Action -eq 'Remove') {
    if (-not (Test-Path -LiteralPath $destinationPath)) { return }
    $marker = Join-Path $destinationPath '.development-install.json'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'Refusing to remove an unrecognized directory.' }
    $receipt = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($receipt.schema_version -ne 1 -or $receipt.destination -ne $destinationPath -or $receipt.kind -ne 'unqualified-development-install') {
        throw 'Invalid development installation marker.'
    }
    $quarantine = $destinationPath + '.removed-' + [Guid]::NewGuid().ToString('N')
    [IO.Directory]::Move($destinationPath, $quarantine)
    Remove-Item -LiteralPath $quarantine -Recurse -Force
    Write-Output 'Development files removed. Checker evidence/state was not accessed.'
    return
}
if (-not $Archive -or $ArchiveSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Supply Archive and its independently obtained SHA-256.' }
$archivePath = [IO.Path]::GetFullPath($Archive)
$archiveItem = Get-Item -LiteralPath $archivePath -Force
if ($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or $archiveItem.Length -gt 1GB) { throw 'Archive is reparse-linked or exceeds 1 GiB.' }
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $ArchiveSha256) { throw 'Archive SHA-256 mismatch.' }
$parent = [IO.Path]::GetDirectoryName($destinationPath)
[IO.Directory]::CreateDirectory($parent) | Out-Null
$staging = Join-Path $parent ('.pc-stage-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
try {
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $total = [long]0
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName.Replace('/', '\')
            if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or ($relative.Split('\') -contains '..') -or ($relative.Split('\') -contains '.')) { throw 'Unsafe ZIP entry path.' }
            foreach ($component in $relative.Split('\')) {
                if ($component -and ($component -match '[. ]$' -or $component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)')) { throw 'Ambiguous Windows ZIP entry name.' }
            }
            if (-not $seen.Add($relative)) { throw 'Duplicate ZIP entry.' }
            if ((($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000) { throw 'ZIP symlink entries are unsupported.' }
            $total += $entry.Length
            if ($entry.Length -gt 256MB -or $total -gt 1GB -or $seen.Count -gt 20000) { throw 'ZIP extraction limit exceeded.' }
            $target = [IO.Path]::GetFullPath((Join-Path $staging $relative))
            if (-not $target.StartsWith($staging + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'ZIP entry escapes staging.' }
            if ($relative.EndsWith('\')) { [IO.Directory]::CreateDirectory($target) | Out-Null; continue }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            $source = $entry.Open(); $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew)
            try {
                $buffer = [byte[]]::new(65536); $written = [long]0
                while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $count
                    if ($written -gt $entry.Length -or $written -gt 256MB) { throw 'ZIP entry actual size exceeds declared/bounded size.' }
                    $output.Write($buffer, 0, $count)
                }
                if ($written -ne $entry.Length) { throw 'ZIP entry length mismatch.' }
            } finally { $output.Dispose(); $source.Dispose() }
        }
    } finally { $zip.Dispose() }
    $roots = @(Get-ChildItem -LiteralPath $staging -Force)
    if ($roots.Count -ne 1 -or -not $roots[0].PSIsContainer) { throw 'Expected one archive package directory.' }
    $package = $roots[0].FullName
    $checksumPath = Join-Path $package 'checksums.json'
    $checksums = Get-Content -LiteralPath $checksumPath -Raw | ConvertFrom-Json
    $files = @(Get-ChildItem -LiteralPath $package -File -Recurse -Force)
    $expected = @($checksums.PSObject.Properties)
    if ($files.Count -ne $expected.Count + 1) { throw 'Unexpected package file count.' }
    foreach ($property in $expected) {
        $path = [IO.Path]::GetFullPath((Join-Path $package $property.Name))
        if (-not $path.StartsWith($package + '\', [StringComparison]::OrdinalIgnoreCase) -or $property.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Unsafe checksum entry.' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $property.Value) { throw 'Package file checksum mismatch.' }
    }
    $status = Get-Content -LiteralPath (Join-Path $package 'support-status.json') -Raw | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath (Join-Path $package 'plugin\plugin.json') -Raw | ConvertFrom-Json
    if ($status.platform -ne 'windows-x86_64' -or $status.version -ne $manifest.version) { throw 'Native package platform/version mismatch.' }
    foreach ($name in @('progress-checker.exe', 'progress-checker-mcp.exe', 'checker-global.exe')) {
        Assert-Pe (Join-Path $package ('plugin\bin\' + $name))
    }
    if ($Action -eq 'Install') {
        # Candidate safety gate: metadata versions are not native executable/runtime
        # qualification. Implement qualified bounded version probing and reviewed
        # activation before enabling atomic stage->destination / rollback updates.
        throw 'Installation is unavailable: native runtime/version/ACL qualification and reviewed activation are incomplete. No existing installation was replaced.'
    }
    [pscustomobject]@{ archive_sha256 = $ArchiveSha256.ToLowerInvariant(); version = $manifest.version;
        integrity_validated = $true; binary_runtime_version_verified = $false; qualified = $false;
        installation_enabled = $false; state_accessed = $false } | ConvertTo-Json
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}

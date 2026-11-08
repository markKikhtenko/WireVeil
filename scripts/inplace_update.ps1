param(
    [Parameter(Mandatory = $true)][string] $InstallRoot,
    [Parameter(Mandatory = $true)][string] $PayloadRoot,
    [Parameter(Mandatory = $true)][string] $BackupRoot,
    [Parameter(Mandatory = $true)][string] $ResultPath,
    [Parameter(Mandatory = $true)][int] $ParentPid,
    [Parameter(Mandatory = $true)][string] $NewVersion,
    [switch] $Elevated,
    [switch] $NoRestart
)

$ErrorActionPreference = "Stop"

function Write-UpdateResult([string] $status, [string] $message, [int] $verifiedFiles = 0) {
    @{
        Status = $status
        Message = $message
        InstalledPath = $script:resolvedInstallRoot
        BackupPath = $script:resolvedBackupRoot
        VerifiedFiles = $verifiedFiles
        Timestamp = (Get-Date).ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

function Get-Sha256([string] $path) {
    $stream = [IO.File]::OpenRead($path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "")
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Get-FileManifest {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [string] $Prefix = ""
    )

    foreach ($child in Get-ChildItem -LiteralPath $Root) {
        $relativePath = if ($Prefix) {
            Join-Path $Prefix $child.Name
        }
        else {
            $child.Name
        }
        if ($child.PSIsContainer) {
            Get-FileManifest -Root $child.FullName -Prefix $relativePath
        }
        else {
            [pscustomobject]@{
                FullName = $child.FullName
                RelativePath = $relativePath
            }
        }
    }
}

function Start-WireVeil([string] $executable) {
    if ($NoRestart) {
        return
    }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        return
    }
    if ($Elevated) {
        Start-Process -FilePath (Join-Path $env:WINDIR "explorer.exe") -ArgumentList ('"' + $executable + '"')
    }
    else {
        Start-Process -FilePath $executable
    }
}

$script:resolvedInstallRoot = ""
$script:resolvedBackupRoot = ""
$movedNames = [System.Collections.Generic.List[string]]::new()
$installedNames = [System.Collections.Generic.List[string]]::new()
$replaceNames = @()
$stageRoot = ""
$replacementCompleted = $false

try {
    if ($NewVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Invalid update version: $NewVersion"
    }

    $script:resolvedInstallRoot = (Resolve-Path -LiteralPath $InstallRoot).Path
    $resolvedPayloadRoot = (Resolve-Path -LiteralPath $PayloadRoot).Path
    $expectedExecutable = Join-Path $script:resolvedInstallRoot "WireVeilChecker.exe"
    if (-not (Test-Path -LiteralPath $expectedExecutable -PathType Leaf)) {
        throw "WireVeilChecker.exe was not found in the install directory."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayloadRoot "WireVeilChecker.exe") -PathType Leaf)) {
        throw "WireVeilChecker.exe was not found in the verified update payload."
    }
    foreach ($runtime in @("sing-box.exe", "mihomo.exe", "libcronet.dll")) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayloadRoot "_internal\$runtime") -PathType Leaf)) {
            throw "Required runtime is missing from the verified update payload: $runtime"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayloadRoot "_internal\scripts\inplace_update.ps1") -PathType Leaf)) {
        throw "The next-version update helper is missing from the verified update payload."
    }

    $localAppData = [Environment]::GetFolderPath("LocalApplicationData").TrimEnd("\")
    $backupParent = [IO.Path]::GetFullPath((Join-Path $localAppData "WireVeil Checker\update-backups"))
    $script:resolvedBackupRoot = [IO.Path]::GetFullPath($BackupRoot)
    $temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd("\")
    $normalBackup = $script:resolvedBackupRoot.StartsWith($backupParent + "\", [System.StringComparison]::OrdinalIgnoreCase)
    $testBackup = $NoRestart -and $script:resolvedBackupRoot.StartsWith($temporaryParent + "\", [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $normalBackup -and -not $testBackup) {
        throw "Refusing to use an unexpected backup path: $script:resolvedBackupRoot"
    }
    if (Test-Path -LiteralPath $script:resolvedBackupRoot) {
        throw "Update backup path already exists: $script:resolvedBackupRoot"
    }

    $stageRoot = Join-Path $script:resolvedInstallRoot ".wireveil-update-$NewVersion"
    if (Test-Path -LiteralPath $stageRoot) {
        throw "Update staging path already exists: $stageRoot"
    }
    New-Item -ItemType Directory -Path $stageRoot | Out-Null

    $payloadChildren = @(Get-ChildItem -LiteralPath $resolvedPayloadRoot)
    if ($payloadChildren.Count -eq 0) {
        throw "The verified update payload is empty."
    }
    foreach ($payloadChild in $payloadChildren) {
        if ($payloadChild.Name -like "unins000*") {
            throw "The update payload must not replace the uninstaller."
        }
        Copy-Item -LiteralPath $payloadChild.FullName -Destination $stageRoot -Recurse -Force
    }

    $sourceFiles = @(Get-FileManifest -Root $resolvedPayloadRoot)
    foreach ($sourceFile in $sourceFiles) {
        $relative = $sourceFile.RelativePath
        $stagedFile = Join-Path $stageRoot $relative
        if (-not (Test-Path -LiteralPath $stagedFile -PathType Leaf)) {
            throw "Staged file is missing: $relative"
        }
        $sourceHash = Get-Sha256 $sourceFile.FullName
        $stagedHash = Get-Sha256 $stagedFile
        if ($sourceHash -ne $stagedHash) {
            throw "Staged file checksum mismatch: $relative"
        }
    }

    $deadline = (Get-Date).AddSeconds(60)
    do {
        $parent = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
        if ($null -eq $parent) {
            break
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    if ($null -ne (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) {
        throw "WireVeil Checker did not close before the update timeout."
    }

    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($script:resolvedBackupRoot)) -Force | Out-Null
    New-Item -ItemType Directory -Path $script:resolvedBackupRoot | Out-Null
    $replaceNames = @($payloadChildren | ForEach-Object { $_.Name })
    try {
        foreach ($name in $replaceNames) {
            $currentPath = Join-Path $script:resolvedInstallRoot $name
            if (Test-Path -LiteralPath $currentPath) {
                $resolvedCurrent = (Resolve-Path -LiteralPath $currentPath).Path
                if (-not $resolvedCurrent.StartsWith($script:resolvedInstallRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Refusing to move an unexpected path: $resolvedCurrent"
                }
                Move-Item -LiteralPath $resolvedCurrent -Destination $script:resolvedBackupRoot
                $movedNames.Add($name)
            }
        }

        foreach ($name in $replaceNames) {
            $stagedPath = Join-Path $stageRoot $name
            if (Test-Path -LiteralPath $stagedPath) {
                Move-Item -LiteralPath $stagedPath -Destination $script:resolvedInstallRoot
                $installedNames.Add($name)
            }
        }
        Remove-Item -LiteralPath $stageRoot -Force

        foreach ($sourceFile in $sourceFiles) {
            $relative = $sourceFile.RelativePath
            $installedFile = Join-Path $script:resolvedInstallRoot $relative
            if (-not (Test-Path -LiteralPath $installedFile -PathType Leaf)) {
                throw "Installed file is missing: $relative"
            }
            $sourceHash = Get-Sha256 $sourceFile.FullName
            $installedHash = Get-Sha256 $installedFile
            if ($sourceHash -ne $installedHash) {
                throw "Installed file checksum mismatch: $relative"
            }
        }
        $replacementCompleted = $true
    }
    catch {
        foreach ($name in $installedNames) {
            $newPath = Join-Path $script:resolvedInstallRoot $name
            if (Test-Path -LiteralPath $newPath) {
                $resolvedNew = (Resolve-Path -LiteralPath $newPath).Path
                if ($resolvedNew.StartsWith($script:resolvedInstallRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
                    Remove-Item -LiteralPath $resolvedNew -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        foreach ($name in $movedNames) {
            $backupPath = Join-Path $script:resolvedBackupRoot $name
            if (Test-Path -LiteralPath $backupPath) {
                Move-Item -LiteralPath $backupPath -Destination $script:resolvedInstallRoot -ErrorAction SilentlyContinue
            }
        }
        throw
    }

    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A4C81415-8612-49AB-9EC8-23D63FC1D134}_is1"
    $registryWarning = ""
    try {
        if (Test-Path -LiteralPath $uninstallKey) {
            $uninstallEntry = Get-ItemProperty -LiteralPath $uninstallKey
            $registeredLocation = [string] $uninstallEntry.InstallLocation
            if ($registeredLocation -and $registeredLocation.TrimEnd("\") -ieq $script:resolvedInstallRoot) {
                Set-ItemProperty -LiteralPath $uninstallKey -Name "DisplayName" -Value "WireVeil Checker $NewVersion"
                Set-ItemProperty -LiteralPath $uninstallKey -Name "DisplayVersion" -Value $NewVersion
            }
        }
    }
    catch {
        $registryWarning = " Registry metadata was not updated: $($_.Exception.Message)"
    }

    Write-UpdateResult "ok" ("WireVeil Checker was updated in place." + $registryWarning) $sourceFiles.Count
    Start-WireVeil (Join-Path $script:resolvedInstallRoot "WireVeilChecker.exe")
}
catch {
    if (-not $replacementCompleted -and $script:resolvedInstallRoot -and $script:resolvedBackupRoot) {
        foreach ($name in $installedNames) {
            $newPath = Join-Path $script:resolvedInstallRoot $name
            if (Test-Path -LiteralPath $newPath) {
                Remove-Item -LiteralPath $newPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        foreach ($name in $movedNames) {
            $backupPath = Join-Path $script:resolvedBackupRoot $name
            if (Test-Path -LiteralPath $backupPath) {
                Move-Item -LiteralPath $backupPath -Destination $script:resolvedInstallRoot -ErrorAction SilentlyContinue
            }
        }
    }
    if ($stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-UpdateResult "error" $_.Exception.Message
    Start-WireVeil (Join-Path $script:resolvedInstallRoot "WireVeilChecker.exe")
    exit 1
}

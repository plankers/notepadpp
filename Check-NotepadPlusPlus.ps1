<#
.SYNOPSIS
    Checks Notepad++ executables for valid digital signatures and verifies
    against official GitHub releases.

.DESCRIPTION
    Verifies the Authenticode digital signature of notepad++.exe, checks that
    it's signed by the legitimate publisher with a valid certificate chain,
    and compares the file hash against the official release from GitHub.

.PARAMETER Path
    Path(s) to notepad++.exe file(s) to check. Accepts multiple paths.

.PARAMETER SkipGitHubCheck
    Skip downloading and comparing against GitHub releases (for offline use).

.EXAMPLE
    .\Check-NotepadPlusPlus.ps1 -Path "C:\Program Files\Notepad++\notepad++.exe"

.EXAMPLE
    .\Check-NotepadPlusPlus.ps1 -Path "C:\Program Files\Notepad++\notepad++.exe", "D:\Tools\npp\notepad++.exe"

.NOTES
    Legitimate Notepad++ executables are signed by "Notepad++" (Don Ho).
    A compromised binary may have no signature, an invalid signature,
    or be signed by a different entity.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string[]]$Path,

    [switch]$SkipGitHubCheck
)

$ErrorActionPreference = "Stop"

# Known legitimate signers for Notepad++
$legitimateSigners = @(
    "Notepad++",
    "Don Ho"
)

# Cache for downloaded official hashes (version -> hash)
$script:officialHashCache = @{}

# Function to get the official hash from GitHub
function Get-OfficialHash {
    param(
        [string]$Version,
        [string]$FilePath
    )

    # Determine architecture from PE header
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)

        # Notepad++ naming: no suffix for 32-bit, .x64. for 64-bit, .arm64. for ARM
        $archSuffix = switch ($machine) {
            0x014c { "" }         # IMAGE_FILE_MACHINE_I386 (32-bit, no suffix)
            0x8664 { ".x64" }     # IMAGE_FILE_MACHINE_AMD64
            0xAA64 { ".arm64" }   # IMAGE_FILE_MACHINE_ARM64
            default { ".x64" }    # Default to x64
        }
    }
    catch {
        $archSuffix = ".x64"
    }

    # Return cached hash if we already downloaded this version
    $cacheKey = "$Version$archSuffix"
    if ($script:officialHashCache.ContainsKey($cacheKey)) {
        return $script:officialHashCache[$cacheKey]
    }

    $tag = "v$Version"

    # Check if 7-Zip is available for extracting installer
    $7zPath = $null
    $7zLocations = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
        "C:\7-Zip\7z.exe"
    )
    foreach ($loc in $7zLocations) {
        if (Test-Path $loc) {
            $7zPath = $loc
            break
        }
    }

    $tempDir = Join-Path $env:TEMP "npp-verify-$Version$archSuffix"
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    # Try MSI first (easy to extract), then NSIS installer with 7-Zip
    # Notepad++ naming: npp.8.9.1.Installer.x64.msi (64-bit) or npp.8.9.1.Installer.msi (32-bit)
    $msiName = "npp.$Version.Installer$archSuffix.msi"
    $installerName = "npp.$Version.Installer$archSuffix.exe"

    $downloadAttempts = @(
        @{ Name = $msiName; Type = "msi" }
    )
    if ($7zPath) {
        $downloadAttempts += @{ Name = $installerName; Type = "7z" }
    }

    foreach ($attempt in $downloadAttempts) {
        $url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/$tag/$($attempt.Name)"
        $tempFile = Join-Path $env:TEMP $attempt.Name

        try {
            Write-Host "  Fetching $($attempt.Name)... " -ForegroundColor Gray -NoNewline

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing -ErrorAction Stop

            Write-Host "extracting... " -ForegroundColor Gray -NoNewline

            switch ($attempt.Type) {
                "msi" {
                    $msiExec = Start-Process -FilePath "msiexec.exe" -ArgumentList "/a `"$tempFile`" /qn TARGETDIR=`"$tempDir`"" -Wait -PassThru -NoNewWindow
                    if ($msiExec.ExitCode -ne 0) {
                        Write-Host "failed" -ForegroundColor Yellow
                        continue
                    }
                }
                "7z" {
                    $null = & $7zPath x $tempFile -o"$tempDir" -y 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "failed" -ForegroundColor Yellow
                        continue
                    }
                }
            }

            $officialExe = Get-ChildItem -Path $tempDir -Filter "notepad++.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

            if ($officialExe) {
                Write-Host "done" -ForegroundColor Gray
                $hash = (Get-FileHash $officialExe.FullName -Algorithm SHA256).Hash.ToLower()
                Write-Host "  Extracted to: $tempDir" -ForegroundColor Gray
                Write-Host "  Official SHA256: $hash" -ForegroundColor Gray
                $script:officialHashCache[$cacheKey] = $hash

                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                return $hash
            }
            else {
                Write-Host "exe not found" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "failed ($($_.Exception.Message))" -ForegroundColor Yellow
        }
        finally {
            if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
        }
    }

    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    return $null
}

# Function to analyze a file's digital signature and compare to official release
function Analyze-NotepadFile {
    param([string]$FilePath)

    $sigStatus = "UNKNOWN"
    $chainStatus = "N/A"
    $gitHubStatus = "SKIPPED"
    $signerName = ""
    $fileHash = ""

    try {
        $fileInfo = Get-Item $FilePath
        $versionInfo = $fileInfo.VersionInfo
        $version = $versionInfo.ProductVersion
        $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()

        Write-Host "$FilePath" -ForegroundColor White
        Write-Host "  Version: $version | SHA256: $fileHash" -ForegroundColor Gray
        Write-Host "  Checking signature... " -ForegroundColor Gray -NoNewline

        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        $sigResult = ""

        if ($sig.Status -eq "Valid") {
            $signerName = $sig.SignerCertificate.Subject
            $isLegitimate = $legitimateSigners | Where-Object { $signerName -match [regex]::Escape($_) }

            if ($isLegitimate) {
                Write-Host "valid (Notepad++), checking chain... " -ForegroundColor Gray -NoNewline
            }
            else {
                Write-Host "valid but WRONG SIGNER" -ForegroundColor Red
                $sigStatus = "SUSPICIOUS"
                $sigResult = "SUSPICIOUS"
            }

            if ($isLegitimate) {
                # Validate certificate chain
                $chainStatus = "VALID"
                try {
                    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                    $chainValid = $chain.Build($sig.SignerCertificate)

                    if (-not $chainValid -or $chain.ChainStatus.Count -gt 0) {
                        foreach ($status in $chain.ChainStatus) {
                            switch ($status.Status) {
                                "Revoked" { $chainStatus = "REVOKED" }
                                { $_ -in "RevocationStatusUnknown", "OfflineRevocation" } { if ($chainStatus -ne "REVOKED") { $chainStatus = "UNKNOWN" } }
                                "NotTimeValid" { if ($chainStatus -eq "VALID") { $chainStatus = "EXPIRED" } }
                                "UntrustedRoot" { if ($chainStatus -eq "VALID") { $chainStatus = "UNTRUSTED" } }
                                default { if ($chainStatus -eq "VALID") { $chainStatus = "WARNING" } }
                            }
                        }
                    }
                    $chain.Dispose()
                }
                catch { $chainStatus = "ERROR" }

                if ($chainStatus -eq "REVOKED") {
                    Write-Host "REVOKED!" -ForegroundColor Red
                    $sigStatus = "REVOKED"
                    $sigResult = "REVOKED"
                }
                elseif ($chainStatus -eq "VALID") {
                    Write-Host "ok" -ForegroundColor Gray
                    $sigStatus = "GOOD"
                    $sigResult = "GOOD"
                }
                else {
                    Write-Host "$chainStatus" -ForegroundColor Yellow
                    $sigStatus = "GOOD"
                    $sigResult = "GOOD (chain: $chainStatus)"
                }
            }
        }
        else {
            Write-Host "$($sig.Status)" -ForegroundColor Red
            $sigStatus = $sig.Status.ToString().ToUpper()
            $sigResult = $sigStatus
        }

        # GitHub comparison
        $gitHubResult = ""
        if (-not $SkipGitHubCheck -and $version) {
            $officialHash = Get-OfficialHash -Version $version -FilePath $FilePath
            if ($officialHash) {
                if ($fileHash -eq $officialHash) {
                    $gitHubStatus = "MATCH"
                    $gitHubResult = "MATCH"
                }
                else {
                    $gitHubStatus = "MISMATCH"
                    $gitHubResult = "MISMATCH"
                }
            }
            else {
                $gitHubStatus = "UNAVAILABLE"
                $gitHubResult = "UNAVAILABLE"
            }
        }

        # Final result
        $color = "Green"
        $result = "VERIFIED"
        if ($sigStatus -eq "REVOKED") {
            $color = "Red"; $result = "REVOKED - DO NOT TRUST"
            $script:badCount++
        }
        elseif ($sigStatus -ne "GOOD") {
            $color = "Red"; $result = "FAILED"
            $script:badCount++
        }
        elseif ($gitHubStatus -eq "MISMATCH") {
            $color = "Red"; $result = "HASH MISMATCH"
            $script:badCount++
        }
        elseif ($gitHubStatus -eq "UNAVAILABLE") {
            $color = "Yellow"; $result = "OK (GitHub unavailable)"
            $script:goodCount++
        }
        else {
            $script:goodCount++
        }

        $statusLine = "  Result: Signature=$sigResult"
        if ($gitHubResult) { $statusLine += ", GitHub=$gitHubResult" }
        $statusLine += " => $result"
        Write-Host $statusLine -ForegroundColor $color

        return [PSCustomObject]@{
            Path = $FilePath
            SignatureStatus = $sigStatus
            ChainStatus = $chainStatus
            GitHubStatus = $gitHubStatus
            Signer = $signerName
            ProductVersion = $version
            SHA256 = $fileHash
        }
    }
    catch {
        Write-Host "$FilePath" -ForegroundColor White
        Write-Host "  ERROR: $_" -ForegroundColor Red
        $script:badCount++
        return [PSCustomObject]@{
            Path = $FilePath
            SignatureStatus = "ERROR"
            ChainStatus = "ERROR"
            GitHubStatus = "ERROR"
            Signer = ""
            ProductVersion = $null
            SHA256 = ""
        }
    }
}

$results = @()
$goodCount = 0
$badCount = 0

Write-Host "Notepad++ Security Checker" -ForegroundColor Cyan
if ($SkipGitHubCheck) {
    Write-Host "(GitHub comparison disabled)" -ForegroundColor Yellow
}
Write-Host ""

# Analyze each provided path
foreach ($filePath in $Path) {
    if (-not (Test-Path $filePath)) {
        Write-Host "File not found: $filePath" -ForegroundColor Red
        Write-Host ""
        continue
    }

    $result = Analyze-NotepadFile -FilePath $filePath
    $results += $result
    Write-Host ""
}

if ($results.Count -eq 0) {
    Write-Host "No valid files to analyze." -ForegroundColor Yellow
    exit 1
}

# Summary
Write-Host ""
if ($badCount -gt 0) {
    Write-Host "FAILED: $badCount file(s) did not pass verification" -ForegroundColor Red
    Write-Host "Download fresh copy from https://notepad-plus-plus.org/downloads/" -ForegroundColor Yellow
}
elseif ($goodCount -gt 0) {
    Write-Host "OK: All files verified" -ForegroundColor Green
}

# Return results for programmatic use
$results

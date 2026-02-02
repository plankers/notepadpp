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

    # Try MSI first (easy to extract), then portable zip, then installer with 7-Zip
    # Notepad++ naming: npp.8.9.1.Installer.x64.msi (64-bit) or npp.8.9.1.Installer.msi (32-bit)
    $msiName = "npp.$Version.Installer$archSuffix.msi"
    $portableName = "npp.$Version.portable$archSuffix.zip"
    $installerName = "npp.$Version.Installer$archSuffix.exe"

    $downloadAttempts = @(
        @{ Name = $msiName; Type = "msi" },
        @{ Name = $portableName; Type = "zip" }
    )
    if ($7zPath) {
        $downloadAttempts += @{ Name = $installerName; Type = "7z" }
    }

    foreach ($attempt in $downloadAttempts) {
        $url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/$tag/$($attempt.Name)"
        $tempFile = Join-Path $env:TEMP $attempt.Name

        try {
            Write-Host "  Downloading official release from GitHub..." -ForegroundColor Gray
            Write-Host "    URL: $url" -ForegroundColor DarkGray

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing -ErrorAction Stop

            # Extract based on type
            switch ($attempt.Type) {
                "msi" {
                    Write-Host "    Extracting MSI..." -ForegroundColor DarkGray
                    $msiExec = Start-Process -FilePath "msiexec.exe" -ArgumentList "/a `"$tempFile`" /qn TARGETDIR=`"$tempDir`"" -Wait -PassThru -NoNewWindow
                    if ($msiExec.ExitCode -ne 0) {
                        Write-Host "    MSI extraction failed (exit code $($msiExec.ExitCode)), trying next option..." -ForegroundColor Yellow
                        continue
                    }
                }
                "zip" {
                    Expand-Archive -Path $tempFile -DestinationPath $tempDir -Force
                }
                "7z" {
                    Write-Host "    Extracting with 7-Zip..." -ForegroundColor DarkGray
                    $null = & $7zPath x $tempFile -o"$tempDir" -y 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "    7-Zip extraction failed, trying next option..." -ForegroundColor Yellow
                        continue
                    }
                }
            }

            # Search for notepad++.exe (MSI extracts to a subdirectory)
            $officialExe = Get-ChildItem -Path $tempDir -Filter "notepad++.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

            if ($officialExe) {
                $hash = (Get-FileHash $officialExe.FullName -Algorithm SHA256).Hash.ToLower()
                $script:officialHashCache[$cacheKey] = $hash

                # Cleanup
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                return $hash
            }
            else {
                Write-Host "    notepad++.exe not found in archive, trying next option..." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "    Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        finally {
            if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
        }
    }

    # Cleanup on failure
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Host "    Could not download or extract official release" -ForegroundColor Yellow
    return $null
}

# Function to analyze a file's digital signature and compare to official release
function Analyze-NotepadFile {
    param([string]$FilePath)

    Write-Host "File: $FilePath" -ForegroundColor White

    $sigStatus = "UNKNOWN"
    $chainStatus = "N/A"
    $gitHubStatus = "SKIPPED"
    $signerName = ""
    $fileHash = ""

    try {
        # Get file details first
        $fileInfo = Get-Item $FilePath
        $versionInfo = $fileInfo.VersionInfo
        $version = $versionInfo.ProductVersion

        Write-Host "  File Version: $($versionInfo.FileVersion)" -ForegroundColor Gray
        Write-Host "  Product Version: $version" -ForegroundColor Gray
        Write-Host "  Last Modified: $($fileInfo.LastWriteTime)" -ForegroundColor Gray
        Write-Host "  Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray

        # Compute hash
        $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
        Write-Host "  SHA256: $fileHash" -ForegroundColor Gray

        # Check digital signature
        Write-Host ""
        Write-Host "  [Signature Check]" -ForegroundColor Cyan
        $sig = Get-AuthenticodeSignature -FilePath $FilePath

        Write-Host "  Signature Status: $($sig.Status)" -ForegroundColor Gray

        if ($sig.Status -eq "Valid") {
            $signerName = $sig.SignerCertificate.Subject
            Write-Host "  Signer: $signerName" -ForegroundColor Gray

            # Check if signer is legitimate
            $isLegitimate = $false
            foreach ($legitSigner in $legitimateSigners) {
                if ($signerName -match [regex]::Escape($legitSigner)) {
                    $isLegitimate = $true
                    break
                }
            }

            # Validate certificate chain with online revocation check
            Write-Host "  Checking certificate chain with CA..." -ForegroundColor Gray
            $chainStatus = "VALID"
            $chainStatusDetails = @()

            try {
                $cert = $sig.SignerCertificate
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

                $chainValid = $chain.Build($cert)

                if ($chainValid -and $chain.ChainStatus.Count -eq 0) {
                    Write-Host "  Certificate Chain: VALID (not revoked)" -ForegroundColor Green
                }
                else {
                    foreach ($status in $chain.ChainStatus) {
                        $chainStatusDetails += $status.Status.ToString()

                        if ($status.Status -eq "Revoked") {
                            Write-Host "  Certificate Chain: REVOKED - Certificate has been revoked by CA!" -ForegroundColor Red
                            $chainStatus = "REVOKED"
                        }
                        elseif ($status.Status -eq "RevocationStatusUnknown" -or $status.Status -eq "OfflineRevocation") {
                            Write-Host "  Certificate Chain: WARNING - Could not check revocation status (offline/unavailable)" -ForegroundColor Yellow
                            if ($chainStatus -ne "REVOKED") { $chainStatus = "UNKNOWN" }
                        }
                        elseif ($status.Status -eq "NotTimeValid") {
                            Write-Host "  Certificate Chain: WARNING - Certificate has expired" -ForegroundColor Yellow
                            if ($chainStatus -eq "VALID") { $chainStatus = "EXPIRED" }
                        }
                        elseif ($status.Status -eq "UntrustedRoot") {
                            Write-Host "  Certificate Chain: WARNING - Untrusted root CA" -ForegroundColor Yellow
                            if ($chainStatus -eq "VALID") { $chainStatus = "UNTRUSTED" }
                        }
                        else {
                            Write-Host "  Certificate Chain: WARNING - $($status.Status): $($status.StatusInformation)" -ForegroundColor Yellow
                            if ($chainStatus -eq "VALID") { $chainStatus = "WARNING" }
                        }
                    }
                }

                $chain.Dispose()
            }
            catch {
                Write-Host "  Certificate Chain: ERROR - Could not validate: $_" -ForegroundColor Yellow
                $chainStatus = "ERROR"
            }

            # Determine signature status based on signer and chain
            if ($isLegitimate -and $chainStatus -eq "VALID") {
                Write-Host "  Result: GOOD - Valid signature from legitimate Notepad++ publisher, chain verified" -ForegroundColor Green
                $sigStatus = "GOOD"
            }
            elseif ($isLegitimate -and $chainStatus -eq "REVOKED") {
                Write-Host "  Result: BAD - Certificate has been REVOKED!" -ForegroundColor Red
                $sigStatus = "REVOKED"
            }
            elseif ($isLegitimate -and ($chainStatus -eq "UNKNOWN" -or $chainStatus -eq "ERROR")) {
                Write-Host "  Result: LIKELY OK - Valid signature, but could not verify chain online" -ForegroundColor Yellow
                $sigStatus = "GOOD"  # Still count as good since signature itself is valid
            }
            elseif ($isLegitimate) {
                Write-Host "  Result: WARNING - Valid signature but chain has issues ($chainStatus)" -ForegroundColor Yellow
                $sigStatus = "GOOD"  # Still count as good since signature is from legitimate signer
            }
            else {
                Write-Host "  Result: SUSPICIOUS - Valid signature but NOT from Notepad++ publisher!" -ForegroundColor Red
                $sigStatus = "SUSPICIOUS"
            }
        }
        elseif ($sig.Status -eq "NotSigned") {
            Write-Host "  Result: BAD - File is NOT digitally signed" -ForegroundColor Red
            $sigStatus = "NOT SIGNED"
        }
        elseif ($sig.Status -eq "HashMismatch") {
            Write-Host "  Result: BAD - Signature INVALID (file has been modified!)" -ForegroundColor Red
            $sigStatus = "TAMPERED"
        }
        else {
            Write-Host "  Result: BAD - Signature problem: $($sig.Status)" -ForegroundColor Red
            $sigStatus = "INVALID"
        }

        # GitHub comparison
        if (-not $SkipGitHubCheck) {
            Write-Host ""
            Write-Host "  [GitHub Release Check]" -ForegroundColor Cyan

            if ($version) {
                $officialHash = Get-OfficialHash -Version $version -FilePath $FilePath

                if ($officialHash) {
                    Write-Host "  Official Hash: $officialHash" -ForegroundColor Gray

                    if ($fileHash -eq $officialHash) {
                        Write-Host "  Result: MATCH - File matches official GitHub release" -ForegroundColor Green
                        $gitHubStatus = "MATCH"
                    }
                    else {
                        Write-Host "  Result: MISMATCH - File differs from official GitHub release!" -ForegroundColor Red
                        $gitHubStatus = "MISMATCH"
                    }
                }
                else {
                    Write-Host "  Result: Could not verify (download failed or version not found)" -ForegroundColor Yellow
                    $gitHubStatus = "UNAVAILABLE"
                }
            }
            else {
                Write-Host "  Result: Could not determine version" -ForegroundColor Yellow
                $gitHubStatus = "UNAVAILABLE"
            }
        }

        # Overall determination
        Write-Host ""
        if ($sigStatus -eq "REVOKED") {
            Write-Host "  OVERALL: CERTIFICATE REVOKED - DO NOT TRUST" -ForegroundColor White -BackgroundColor DarkRed
            $script:badCount++
        }
        elseif ($sigStatus -eq "GOOD" -and ($gitHubStatus -eq "MATCH" -or $gitHubStatus -eq "SKIPPED")) {
            Write-Host "  OVERALL: VERIFIED" -ForegroundColor Green -BackgroundColor DarkGreen
            $script:goodCount++
        }
        elseif ($sigStatus -eq "GOOD" -and $gitHubStatus -eq "UNAVAILABLE") {
            Write-Host "  OVERALL: LIKELY OK (signature valid, GitHub check unavailable)" -ForegroundColor Yellow
            $script:goodCount++
        }
        else {
            Write-Host "  OVERALL: POTENTIALLY COMPROMISED" -ForegroundColor White -BackgroundColor DarkRed
            $script:badCount++
        }

        return [PSCustomObject]@{
            Path = $FilePath
            SignatureStatus = $sigStatus
            ChainStatus = $chainStatus
            GitHubStatus = $gitHubStatus
            Signer = $signerName
            FileVersion = $versionInfo.FileVersion
            ProductVersion = $version
            LastModified = $fileInfo.LastWriteTime
            SizeBytes = $fileInfo.Length
            SHA256 = $fileHash
        }
    }
    catch {
        Write-Host "  ERROR: Could not analyze file - $_" -ForegroundColor Red
        $script:badCount++
        return [PSCustomObject]@{
            Path = $FilePath
            SignatureStatus = "ERROR"
            ChainStatus = "ERROR"
            GitHubStatus = "ERROR"
            Signer = ""
            FileVersion = $null
            ProductVersion = $null
            LastModified = $null
            SizeBytes = $null
            SHA256 = ""
        }
    }
}

$results = @()
$goodCount = 0
$badCount = 0

Write-Host "Notepad++ Security Checker" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Verifying digital signatures, certificate chain, and comparing against official GitHub releases" -ForegroundColor Gray
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
Write-Host "=" * 80
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 80
Write-Host "VERIFIED/OK: $goodCount" -ForegroundColor Green
Write-Host "POTENTIALLY COMPROMISED: $badCount" -ForegroundColor $(if ($badCount -gt 0) { "Red" } else { "Gray" })
Write-Host ""

# Show table of results
Write-Host "Results:" -ForegroundColor Cyan
$results | Format-Table -Property @(
    @{Label="Path"; Expression={$_.Path}; Width=40},
    @{Label="Signature"; Expression={$_.SignatureStatus}; Width=11},
    @{Label="Chain"; Expression={$_.ChainStatus}; Width=10},
    @{Label="GitHub"; Expression={$_.GitHubStatus}; Width=11},
    @{Label="Version"; Expression={$_.ProductVersion}; Width=10}
) -Wrap

if ($badCount -gt 0) {
    Write-Host "WARNING: Some files failed verification!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Recommended actions:" -ForegroundColor Yellow
    Write-Host "  1. Do not run unverified executables" -ForegroundColor Yellow
    Write-Host "  2. Download a fresh copy from https://notepad-plus-plus.org/downloads/" -ForegroundColor Yellow
    Write-Host "  3. If you suspect compromise, scan with antivirus and check for other IOCs" -ForegroundColor Yellow
}
else {
    Write-Host "All found copies passed verification." -ForegroundColor Green
}

# Return results for programmatic use
$results

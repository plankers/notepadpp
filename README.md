A PowerShell script to verify the integrity of Notepad++ installations by checking digital signatures, certificate chain validity, and comparing against official GitHub releases.

## Background

In December 2024, compromised versions of Notepad++ were discovered being distributed through unofficial channels. This tool helps verify that your Notepad++ installation is legitimate and hasn't been tampered with.

## Features

- **Digital Signature Verification**: Checks that the executable is signed by the legitimate Notepad++ publisher (Don Ho)
- **Certificate Chain Validation**: Verifies the signing certificate against the CA with online revocation checking (CRL/OCSP)
- **GitHub Release Comparison**: Downloads the official release from GitHub and compares SHA256 hashes
- **PE Header Analysis**: Automatically detects executable architecture (x86, x64, ARM64) to download the correct official release

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Internet connection (for GitHub comparison and certificate revocation checks)
- Optional: 7-Zip installed (for extracting NSIS installers if MSI is unavailable)

## Usage

```powershell
# Check a single file
.\Check-NotepadPlusPlus.ps1 -Path "C:\Program Files\Notepad++\notepad++.exe"

# Check multiple files
.\Check-NotepadPlusPlus.ps1 -Path "C:\Program Files\Notepad++\notepad++.exe", "D:\Tools\npp\notepad++.exe"

# Skip GitHub comparison (offline mode)
.\Check-NotepadPlusPlus.ps1 -Path "C:\Program Files\Notepad++\notepad++.exe" -SkipGitHubCheck

# Pipeline input
Get-ChildItem -Path C:\ -Recurse -Filter "notepad++.exe" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName |
    .\Check-NotepadPlusPlus.ps1
```

## Output

The script checks each file and reports:

| Check | Status Values |
|-------|---------------|
| **Signature** | `GOOD`, `SUSPICIOUS`, `NOT SIGNED`, `TAMPERED`, `REVOKED`, `INVALID` |
| **Chain** | `VALID`, `REVOKED`, `EXPIRED`, `UNTRUSTED`, `UNKNOWN`, `ERROR` |
| **GitHub** | `MATCH`, `MISMATCH`, `UNAVAILABLE`, `SKIPPED` |

### Overall Verdicts

- **VERIFIED**: Valid signature from legitimate publisher + matches official GitHub release
- **LIKELY OK**: Valid signature, but GitHub check unavailable
- **CERTIFICATE REVOKED**: The signing certificate has been revoked by the CA
- **POTENTIALLY COMPROMISED**: Failed signature or GitHub hash mismatch

## How It Works

1. **Signature Check**: Uses `Get-AuthenticodeSignature` to verify the Authenticode signature and checks that the signer matches "Notepad++" or "Don Ho"

2. **Certificate Chain Validation**: Builds the certificate chain with online revocation checking enabled to verify the certificate hasn't been revoked

3. **GitHub Comparison**:
   - Detects the executable's version from file metadata
   - Detects architecture from PE header
   - Downloads the matching official release (tries MSI first, then portable ZIP, then NSIS installer with 7-Zip)
   - Extracts `notepad++.exe` and compares SHA256 hashes

## Limitations

- The GitHub comparison requires the exact version to be available as a release
- Very old versions may not be available on GitHub
- Certificate revocation checks require internet connectivity
- MSI extraction requires administrative privileges in some cases

## License

MIT License

## Disclaimer

This repository and the documents within is intended to provide general guidance. The information contained in this document is for educational and informational purposes only. This repository is not intended to provide advice and is provided “AS IS.” The publisher makes no claims, promises, or guarantees about the accuracy, completeness, or adequacy of the information contained herein. Organizations should engage appropriate legal, business, technical, and audit expertise within their specific organization for review of requirements and effectiveness of implementations.

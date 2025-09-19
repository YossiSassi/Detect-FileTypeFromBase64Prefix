<#
# my first POC: simple b64 common prefixes detector
# Reading the first N bytes (e.g. 32) is enough
$fs = [System.IO.File]::OpenRead("C:\windows\system32\calc.exe")
$buf = New-Object byte[] 32;
$read = $fs.Read($buf, 0, $buf.Length);
$fs.Close();
$B64 = [Convert]::ToBase64String($buf,0,$read)
--> compare b64 to json...
#>

<#
.SYNOPSIS
  Detect likely file types by signature (hex/ASCII) and show Base64 prefix

.DESCRIPTION
  - Loads a JSON signature map (file_signatures.json)
  - Reads minimal bytes to test each signature at its offset
  - Shows matched signature names and a short Base64 prefix for each file
  - Can export results to CSV or JSON

.EXAMPLE
  # Basic usage - scan current directory
  .\Detect-FileTypeFromBase64Prefix.ps1

.EXAMPLE
  # Export to CSV
  .\Detect-FileTypeFromBase64Prefix.ps1 -Path C:\Downloads -Recurse -ExportCsv .\filetypes.csv

.NOTES
  Version: 1.0
  Comments: yossis@protonmail.com (1nTh35h311)
#>

param(
    #[Parameter(Mandatory=$true)]
    [string]$Path = ".\",

    [string]$SignatureJson = ".\file_Signatures.json",

    [switch]$Recurse,

    [int]$ReadBytes = 64,   # number of leading bytes to read (increased to cover offsets)
    [int]$Base64PrefixChars = 24,

    [string]$ExportCsv = $null,
    [string]$ExportJson = $null
)

if (-not (Test-Path $SignatureJson)) {
    Write-Error "Signature JSON not found at path: $SignatureJson"
    return
}

# Load signatures
$signatures = Get-Content -Raw -Path $SignatureJson | ConvertFrom-Json

# Compute required maximum bytes to read (consider offsets + sig length)
$maxNeeded = 0
foreach ($s in $signatures) {
    $sigLen = 0
    if ($s.sigHex) { $sigLen = ([regex]::Matches($s.sigHex, '..')).Count }
    elseif ($s.sigAscii) { $sigLen = [System.Text.Encoding]::ASCII.GetByteCount($s.sigAscii) }
    $needed = [int]$s.offset + $sigLen
    if ($needed -gt $maxNeeded) { $maxNeeded = $needed }
}
$readSize = [int][Math]::Max($ReadBytes, $maxNeeded)

# Helper: byte array to hex string (upper, no spaces)
function Bytes-ToHex([byte[]]$b) {
    if (-not $b) { return "" }
    ($b | ForEach-Object { $_.ToString("X2") }) -join ''
}

# Helper: read first N bytes (but also allow offsets inside file)
function Read-FilePrefix([string]$file, [int]$count) {
    $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $buf = New-Object byte[] $count
        $read = $fs.Read($buf, 0, $count)
        if ($read -lt $count) { $buf = $buf[0..($read-1)] }
        return ,@($buf)  # wrap to ensure array (could be empty)
    } finally {
        $fs.Close()
        $fs.Dispose()
    }
}

# Enumerate files
$files = if ($Recurse) { Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue } else { Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue }

$results = @()

foreach ($f in $files) {
    try {
        $bytes = Read-FilePrefix -file $f.FullName -count $readSize
        if (-not $bytes) { continue }

        $hexAll = Bytes-ToHex $bytes
        # base64 prefix from the raw bytes read
        $b64 = [Convert]::ToBase64String($bytes)
        $b64Prefix = if ($b64.Length -le $Base64PrefixChars) { $b64 } else { $b64.Substring(0, $Base64PrefixChars) }

        $matches = @()

        foreach ($s in $signatures) {
            $offset = [int]$s.offset
            if ($s.sigHex) {
                $sigHex = ($s.sigHex -replace '\s','').ToUpper()
                $sigLen = $sigHex.Length
                $startPos = $offset * 2
                if ($hexAll.Length -ge ($startPos + $sigLen)) {
                    $substr = $hexAll.Substring($startPos, $sigLen)
                    if ($substr -ieq $sigHex) {
                        $matches += $s.name
                        continue
                    }
                }
            }
            if ($s.sigAscii) {
                # handle escape sequences like \u007F in JSON by interpreting them
                $sigAscii = $s.sigAscii
                $sigBytes = [System.Text.Encoding]::ASCII.GetBytes($sigAscii)
                $sigHex = Bytes-ToHex $sigBytes
                $sigLen = $sigHex.Length
                $startPos = $offset * 2
                if ($hexAll.Length -ge ($startPos + $sigLen)) {
                    $substr = $hexAll.Substring($startPos, $sigLen)
                    if ($substr -ieq $sigHex) {
                        $matches += $s.name
                        continue
                    }
                }
            }
        }

        $detected = if ($matches.Count -gt 0) { ($matches -join '; ') } else { 'Unknown' }

        $obj = [PSCustomObject]@{
            Path        = $f.FullName
            SizeBytes   = $f.Length
            Detected    = $detected
            Base64Pref  = $b64Prefix
        }
        $results += $obj

        Write-Host ("{0,-60} {1,10}  {2,-20}  {3}" -f $f.Name, $f.Length, $detected, $b64Prefix)
    } catch {
        Write-Warning "Failed to inspect $($f.FullName): $_"
    }
}

# Exports
if ($ExportJson) {
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding UTF8;
    Write-Host "Exported JSON to $ExportJson" -ForegroundColor Cyan
}
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8;
    Write-Host "Exported CSV to $ExportCsv" -ForegroundColor Cyan
}
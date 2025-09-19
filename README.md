## Detect-FileTypeFromBase64Prefix
###  Detect likely file types by signature (hex/ASCII) and show Base64 prefix
- Loads a JSON signature map (file_signatures.json)
- Reads minimal bytes to test each signature at its offset
- Shows matched signature names and a short Base64 prefix for each file
- Can export results to CSV or JSON


### .PARAMETERS
Path - The folder path to scan. default to current directory.

SignatureJson - Path to the json file with prefix signatures. Default is current directory, e.g. ".\file_Signatures.json",

Recurse - a switch parameter. performs recursive detection on all files in the given path.

ReadBytes - number of leading bytes to read (increased to cover offsets). default to 64.

Base64PrefixChars = default to 24. although ~10 to 18 should be ok.

ExportCsv - Path to exported CSV results file, e.g. c:\temp\filetypes.csv

ExportJson = Path to exported JSON results file, e.g. c:\temp\filetypes.json

### .EXAMPLE 1
#### Basic usage - scan current directory
```
.\Detect-FileTypeFromBase64Prefix.ps1
```

### .EXAMPLE 2
#### Scan c:\downloads recursively, and export result to CSV
```
.\Detect-FileTypeFromBase64Prefix.ps1 -Path C:\Downloads -Recurse -ExportCsv .\filetypes.csv
```

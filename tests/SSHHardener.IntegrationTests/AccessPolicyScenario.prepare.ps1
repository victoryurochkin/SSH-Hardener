param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/access-policy'))
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../src/SSHHardener.Profiles/AccessPolicyScripts.cs') -Raw
$match = [regex]::Match($source, '(?s)internal const string AccessPolicyPython = """\r?\n(.*?)\r?\n        """;')
if (-not $match.Success) { throw 'The production AccessPolicyPython constant was not found.' }
$code = (($match.Groups[1].Value -replace "`r", '') -split "`n" | ForEach-Object {
    if (-not $_.StartsWith('        ')) { throw 'Unexpected C# raw-string indentation.' }
    $_.Substring(8)
}) -join "`n"
$destination = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $destination -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $destination 'access-policy.py'), $code + "`n", [Text.UTF8Encoding]::new($false))
Write-Output "Exported the actual production access helper to $destination"

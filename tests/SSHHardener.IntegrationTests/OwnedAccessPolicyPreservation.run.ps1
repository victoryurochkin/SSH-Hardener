param([string]$ArtifactDirectory = (Join-Path $PSScriptRoot '../../artifacts/owned-access-preservation'))
$ErrorActionPreference = 'Stop'
$repoDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixtureDirectory = [IO.Path]::GetFullPath($ArtifactDirectory)
if (-not $fixtureDirectory.StartsWith((Join-Path $repoDirectory 'artifacts') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture output must be inside this repository artifacts directory.'
}
& (Join-Path $PSScriptRoot 'AccessPolicyScenario.prepare.ps1') -OutputDirectory $fixtureDirectory
$fixtureLinux = (& wsl -d Ubuntu --exec wslpath -a $fixtureDirectory.Replace('\', '/')).Trim()
$testLinux = (& wsl -d Ubuntu --exec wslpath -a (Join-Path $PSScriptRoot 'OwnedAccessPolicyPreservation.fixture.py').Replace('\', '/')).Trim()
$containerName = 'sshhardener-preserve-fixture-' + [Guid]::NewGuid().ToString('N')
if ($containerName -notmatch '\Asshhardener-preserve-fixture-[a-f0-9]{32}\z') { throw 'Invalid container name.' }
& wsl -d Ubuntu --exec docker run --rm --network none --name $containerName `
    --mount "type=bind,src=$fixtureLinux/access-policy.py,dst=/probe/access-policy.py,readonly" `
    --mount "type=bind,src=$testLinux,dst=/probe/preservation.py,readonly" `
    --entrypoint python3 sshhardener-access-policy:local /probe/preservation.py 2>&1 | Tee-Object -FilePath (Join-Path $fixtureDirectory 'results.txt')
if ($LASTEXITCODE -ne 0) { throw 'Owned access policy preservation acceptance failed.' }

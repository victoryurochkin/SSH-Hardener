param([string]$ArtifactDirectory = (Join-Path $PSScriptRoot '../../artifacts/framed-transport'))
$ErrorActionPreference = 'Stop'
$repoDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixtureDirectory = [IO.Path]::GetFullPath($ArtifactDirectory)
if (-not $fixtureDirectory.StartsWith((Join-Path $repoDirectory 'artifacts') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture output must be a child of this repository artifacts directory.'
}
[IO.Directory]::CreateDirectory($fixtureDirectory) | Out-Null
$testProject = Join-Path $PSScriptRoot 'SSHHardener.IntegrationTests.csproj'
$testDll = Join-Path $PSScriptRoot 'bin/Debug/net10.0-windows/SSHHardener.IntegrationTests.dll'
& dotnet build $testProject --no-restore --nologo
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
if (-not (Test-Path -LiteralPath (Join-Path $fixtureDirectory 'fixture.ppk'))) {
    & dotnet $testDll --prepare-framed-transport $fixtureDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic key preparation failed.' }
}
$fixtureLinux = (& wsl -d Ubuntu --exec wslpath -a $fixtureDirectory.Replace('\', '/')).Trim()
$serverLinux = (& wsl -d Ubuntu --exec wslpath -a (Join-Path $PSScriptRoot 'FramedTransportScenario.server.sh').Replace('\', '/')).Trim()
$containerName = 'sshhardener-framed-fixture-' + [Guid]::NewGuid().ToString('N')
if ($containerName -notmatch '\Asshhardener-framed-fixture-[a-f0-9]{32}\z') { throw 'Invalid container name.' }
try {
    & wsl -d Ubuntu --exec docker run --detach --name $containerName --publish '127.0.0.1::2222' `
        --mount "type=bind,src=$serverLinux,dst=/probe/server.sh,readonly" `
        --mount "type=bind,src=$fixtureLinux/fixture.ppk.pub,dst=/probe/fixture.pub,readonly" `
        --entrypoint /bin/sh sshhardener-access-policy:local /probe/server.sh | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Disposable Docker fixture failed to start.' }
    $binding = (& wsl -d Ubuntu --exec docker port $containerName 2222/tcp).Trim()
    if ($binding -notmatch '\A127\.0\.0\.1:(\d+)\z') { throw 'Fixture must bind loopback only.' }
    $port = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $probe = [Net.Sockets.TcpClient]::new()
        try { if ($probe.ConnectAsync('127.0.0.1', $port).Wait(200)) { $ready = $probe.Connected; if ($ready) { break } } } catch { }
        finally { $probe.Dispose() }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { throw 'Disposable fixture did not become ready.' }
    & wsl -d Ubuntu --exec docker cp "${containerName}:/etc/ssh/ssh_host_ed25519_key.pub" "$fixtureLinux/host.pub" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not copy fixture public host key.' }
    & dotnet $testDll --verify-framed-transport $fixtureDirectory $port
    if ($LASTEXITCODE -ne 0) { throw 'Framed transport integration failed.' }
} finally {
    & wsl -d Ubuntu --exec docker logs $containerName 2>&1 | Set-Content -LiteralPath (Join-Path $fixtureDirectory 'server.log')
    & wsl -d Ubuntu --exec docker rm -f $containerName | Out-Null
}

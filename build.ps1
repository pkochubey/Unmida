$ErrorActionPreference = 'Stop'
$previousGoOs = $env:GOOS
$previousGoArch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
Push-Location $PSScriptRoot
try {
    $env:GOOS = 'windows'
    $env:CGO_ENABLED = '0'
    $env:GOARCH = '386'
    go build -trimpath -o Unmida32.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Unmida32 build failed' }
    $env:GOARCH = 'amd64'
    go build -trimpath -o Unmida64.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Unmida64 build failed' }
} finally {
    $env:GOOS = $previousGoOs
    $env:GOARCH = $previousGoArch
    $env:CGO_ENABLED = $previousCgo
    Pop-Location
}

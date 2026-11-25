$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path bin | Out-Null
    go build -o bin/sp-client.exe ./cmd/sp-client
    go build -o bin/sp-server.exe ./cmd/sp-server
    Write-Host "built: bin\sp-client.exe, bin\sp-server.exe"
} finally {
    Pop-Location
}

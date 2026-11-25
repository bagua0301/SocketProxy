@echo off
setlocal
cd /d "%~dp0.."
if not exist bin mkdir bin
go build -o bin\sp-client.exe ./cmd/sp-client || exit /b 1
go build -o bin\sp-server.exe ./cmd/sp-server || exit /b 1
echo built: bin\sp-client.exe, bin\sp-server.exe

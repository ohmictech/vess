# Vess local testnet — launches 3 nodes that mine and gossip.
# Run from the workspace root (cargo build first).
#
# Usage: .\run-testnet.ps1

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "=== Vess Local Testnet ===" -ForegroundColor Cyan
Write-Host ""

# Kill any existing vess-node processes
Get-Process vess-node -ErrorAction SilentlyContinue | Stop-Process -Force

# Start 3 nodes on different ports, each mining
Write-Host "Starting node 1 on :9876..." -ForegroundColor Green
Start-Process -NoNewWindow cargo -ArgumentList "run","--release","-p","vess-node","--","--listen","0.0.0.0:9876","--mine"

Start-Sleep -Seconds 2

Write-Host "Starting node 2 on :9877 (bootstrapping from node 1)..." -ForegroundColor Green
Start-Process -NoNewWindow cargo -ArgumentList "run","--release","-p","vess-node","--","--listen","0.0.0.0:9877","--mine","--bootstrap","127.0.0.1:9876"

Start-Sleep -Seconds 2

Write-Host "Starting node 3 on :9878 (bootstrapping from node 1)..." -ForegroundColor Green
Start-Process -NoNewWindow cargo -ArgumentList "run","--release","-p","vess-node","--","--listen","0.0.0.0:9878","--mine","--bootstrap","127.0.0.1:9876"

Write-Host ""
Write-Host "Testnet running! Nodes:" -ForegroundColor Cyan
Write-Host "  Node 1: 127.0.0.1:9876" -ForegroundColor Yellow
Write-Host "  Node 2: 127.0.0.1:9877" -ForegroundColor Yellow
Write-Host "  Node 3: 127.0.0.1:9878" -ForegroundColor Yellow
Write-Host ""
Write-Host "Wallet usage:" -ForegroundColor Cyan
Write-Host "  cargo run -p vess-wallet -- connect 127.0.0.1:9876" -ForegroundColor White
Write-Host "  cargo run -p vess-wallet -- balance" -ForegroundColor White
Write-Host "  cargo run -p vess-wallet -- import ../vess-db" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop all nodes." -ForegroundColor Red

try {
    while ($true) { Start-Sleep -Seconds 10 }
} finally {
    Get-Process vess-node -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "Nodes stopped." -ForegroundColor Cyan
}

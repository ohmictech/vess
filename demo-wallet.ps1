# Vess wallet demo — imports treasure chest, consolidates, makes a payment.
# Requires a running testnet (.\run-testnet.ps1).

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$wallet_exe = "cargo run --release -p vess-wallet --"
$node_db = "$root\vess-db"  # Node 1's LMDB

Write-Host "=== Vess Wallet Demo ===" -ForegroundColor Cyan
Write-Host ""

# 1. Import treasure chest from node 1
Write-Host "[1/4] Importing treasure chest from node..." -ForegroundColor Green
Invoke-Expression "$wallet_exe --import `"$node_db`"" 2>$null
Write-Host ""

# 2. Check balance
Write-Host "[2/4] Checking balance..." -ForegroundColor Green
$balance = Invoke-Expression "$wallet_exe --balance" 2>$null
Write-Host "Balance: $balance VESS"
Write-Host ""

# 3. Consolidate
Write-Host "[3/4] Consolidating UTXOs..." -ForegroundColor Green
Invoke-Expression "$wallet_exe --consolidate" 2>$null
Write-Host ""

# 4. Generate invoice and pay it (self-pay demo)
Write-Host "[4/4] Self-payment demo..." -ForegroundColor Green
$invoice = Invoke-Expression "$wallet_exe --invoice 1" 2>$null
Write-Host "Invoice: $invoice"
Invoke-Expression "$wallet_exe --pay `"$invoice`"" 2>$null
Write-Host ""

Write-Host "Demo complete! Final balance:" -ForegroundColor Cyan
Invoke-Expression "$wallet_exe --balance" 2>$null

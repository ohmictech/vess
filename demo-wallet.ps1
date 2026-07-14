# Vess wallet demo — imports treasure chest, exports a payment OOB, submits and syncs.
# Requires a running testnet (.\run-testnet.ps1).

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$wallet_exe = "cargo run --release -p vess-wallet --"
$node_db = "$root\vess-db"  # Node 1's LMDB

Write-Host "=== Vess Wallet Demo ===" -ForegroundColor Cyan
Write-Host ""

# 1. Import treasure chest from node 1
Write-Host "[1/5] Importing treasure chest from node..." -ForegroundColor Green
Invoke-Expression "$wallet_exe --import `"$node_db`"" 2>$null
Write-Host ""

# 2. Check balance
Write-Host "[2/5] Checking balance..." -ForegroundColor Green
$balance = Invoke-Expression "$wallet_exe --balance" 2>$null
Write-Host "Balance: $balance VESS"
Write-Host ""

# 3. Consolidate (connects to node, merges UTXOs)
Write-Host "[3/5] Consolidating UTXOs..." -ForegroundColor Green
Invoke-Expression "$wallet_exe --consolidate" 2>$null
Write-Host ""

# 4. Generate invoice and export payment OOB (self-pay demo)
Write-Host "[4/5] Self-payment (OOB flow)..." -ForegroundColor Green
$invoice = Invoke-Expression "$wallet_exe --invoice 1" 2>$null
Write-Host "Invoice: $invoice"
# Export the payment blob (payer side — does NOT submit)
Invoke-Expression "$wallet_exe --export `"$invoice`" --out payment.vess" 2>$null
Write-Host ""

# 5. Submit the payment (receiver side) and sync
Write-Host "[5/5] Submitting and syncing..." -ForegroundColor Green
Invoke-Expression "$wallet_exe --submit payment.vess" 2>$null
Invoke-Expression "$wallet_exe --sync" 2>$null
Write-Host ""

Write-Host "Demo complete! Final balance:" -ForegroundColor Cyan
Invoke-Expression "$wallet_exe --balance" 2>$null

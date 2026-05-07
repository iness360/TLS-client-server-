# benchmark.ps1 — Measure TLS handshake latency for all three modes

$runs = 20
$results = @()

Write-Host "Starting benchmark ($runs runs per mode)..." -ForegroundColor Cyan

foreach ($mode in @("classical", "pq", "hybrid")) {

    $port = switch ($mode) {
        "classical" { 4430 }
        "pq"        { 4431 }
        "hybrid"    { 4432 }
    }

    $server = "pq-server-$mode"
    $curvesArg = if ($mode -eq "pq") { "--curves mlkem768" } else { "" }

    Write-Host "Testing $mode on port $port..." -ForegroundColor Yellow

    for ($i = 1; $i -le $runs; $i++) {
        $time = docker run --rm --network pq-tls-demo_pqnet `
            -v "${PWD}/certs/${mode}:/certs:ro" `
            openquantumsafe/curl curl -s -o /dev/null `
            -w "%{time_appconnect}" `
            --cacert /certs/ca.crt `
            $curvesArg.Split(" ") `
            --connect-to "localhost:${port}:${server}:${port}" `
            "https://localhost:${port}" 2>$null

        $ms = [math]::Round([double]$time * 1000, 2)
        $results += [PSCustomObject]@{ mode=$mode; run=$i; time_ms=$ms }
        Write-Host "  Run $i : ${ms} ms"
    }
}

# Save to CSV
$results | Export-Csv -Path "results\latency_raw.csv" -NoTypeInformation
Write-Host ""
Write-Host "Done! Results saved to results\latency_raw.csv" -ForegroundColor Green

# Show summary
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
foreach ($mode in @("classical", "pq", "hybrid")) {
    $modeData = $results | Where-Object { $_.mode -eq $mode }
    $avg = [math]::Round(($modeData | Measure-Object -Property time_ms -Average).Average, 2)
    Write-Host "$mode average: ${avg} ms"
}
# ── AUTO OPEN DASHBOARD ─────────────────────────────
$dashboardPath = (Resolve-Path "dashboard\index.html").Path
Start-Process $dashboardPath
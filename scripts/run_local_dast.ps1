param([int]$DownloadWaitMinutes = 30)

$repositoryPath = Split-Path -Parent $PSScriptRoot
$reportPath = Join-Path $repositoryPath 'evidence\zap-local'
New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
$deadline = (Get-Date).AddMinutes($DownloadWaitMinutes)
$scannerImage = $null
while ((Get-Date) -lt $deadline) {
    foreach ($candidate in @('zaproxy/zap-stable:latest', 'ghcr.io/zaproxy/zaproxy:stable')) {
        $null = & docker image inspect $candidate 2>$null
        if ($LASTEXITCODE -eq 0) {
            $scannerImage = $candidate
            break
        }
    }
    if ($scannerImage) { break }
    Start-Sleep -Seconds 5
}
if (-not $scannerImage) { throw 'ZAP image download did not finish within the allowed time.' }

$response = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/' -UseBasicParsing -TimeoutSec 15
if ($response.StatusCode -ne 200) { throw 'PyGoat is not ready for scanning.' }

$mount = $reportPath + ':/zap/wrk:rw'
& docker run --rm --name devsecops-lab5-zap --network devsecops-lab5-net `
    -v $mount $scannerImage zap-baseline.py `
    -t http://web:8000/ -m 1 -T 10 `
    -r zap-report.html -J zap-report.json -w zap-report.md 2>&1 |
    Tee-Object -FilePath (Join-Path $reportPath 'scan.log')
$scanStatus = $LASTEXITCODE
Set-Content -LiteralPath (Join-Path $reportPath 'exit-code.txt') -Value $scanStatus
if ($scanStatus -gt 2) { throw "ZAP execution failed with code $scanStatus" }
if (-not (Test-Path -LiteralPath (Join-Path $reportPath 'zap-report.json'))) {
    throw 'ZAP did not generate its JSON report.'
}
& python (Join-Path $PSScriptRoot 'summarize_zap.py') (Join-Path $reportPath 'zap-report.json') |
    Out-File -LiteralPath (Join-Path $reportPath 'summary.md') -Encoding utf8
& python (Join-Path $PSScriptRoot 'build_lab_report.py')
Write-Output 'Local DAST finished and the English report was updated.'

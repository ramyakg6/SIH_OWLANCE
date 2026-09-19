# OwLance - start backend and frontend together (Windows / PowerShell)
#
#   .\run.ps1
#
# Backend  -> http://127.0.0.1:8000   (API docs at /docs)
# Frontend -> http://localhost:5173

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> Starting backend on http://127.0.0.1:8000" -ForegroundColor Cyan
$backend = Start-Process -PassThru -NoNewWindow -FilePath "powershell" -ArgumentList @(
  "-NoProfile", "-Command",
  "cd '$PSScriptRoot\backend'; " +
  "if (-not (Test-Path .venv)) { python -m venv .venv }; " +
  ".\.venv\Scripts\Activate.ps1; " +
  "pip install -q -r requirements.txt; " +
  "uvicorn app.main:app --host 127.0.0.1 --port 8000"
)

Write-Host "    waiting for backend" -NoNewline
for ($i = 0; $i -lt 40; $i++) {
  try {
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2 | Out-Null
    Write-Host " - up." -ForegroundColor Green
    break
  } catch {
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 1
  }
}

Write-Host "==> Starting frontend on http://localhost:5173" -ForegroundColor Cyan
if (-not (Test-Path node_modules)) {
  npm install --no-audit --no-fund
}

try {
  npm run dev -- --host
} finally {
  Write-Host "`nShutting down..." -ForegroundColor Yellow
  if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
}

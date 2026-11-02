<#
  Cuidarte+ · Orquestador de pruebas QA (Windows PowerShell)
  ISY1102 · EP3 · Matías Alejandro Araos Urra

  Uso (desde la raíz del repositorio, con Docker Desktop iniciado):
    powershell -ExecutionPolicy Bypass -File QA\scripts\ejecutar-qa.ps1

  Genera evidencias en QA\reports\ (txt, json, md). Toma capturas de la terminal tras cada bloque.
#>
$ErrorActionPreference = "Continue"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root
New-Item -ItemType Directory -Force -Path "QA\reports" | Out-Null
$stamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

function Titulo($t) { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }

Titulo "0. Entorno"
"Fecha: $(Get-Date)" | Tee-Object -FilePath "QA\reports\entorno.txt"
docker --version | Tee-Object -FilePath "QA\reports\entorno.txt" -Append
docker compose version | Tee-Object -FilePath "QA\reports\entorno.txt" -Append
node --version | Tee-Object -FilePath "QA\reports\entorno.txt" -Append

Titulo "1. Levantar stack (docker compose up -d --build)"
docker compose up -d --build 2>&1 | Tee-Object -FilePath "QA\reports\docker-up.txt"
Start-Sleep -Seconds 15
docker compose ps 2>&1 | Tee-Object -FilePath "QA\reports\docker-ps.txt"     # [CAPTURA 1]

Titulo "2. Smoke test (ciclo 1)"
try { (Invoke-WebRequest -UseBasicParsing http://localhost:4444/).Content | Tee-Object -FilePath "QA\reports\smoke.txt" } catch { "API no responde: $_" | Tee-Object -FilePath "QA\reports\smoke.txt" }
try { "Frontend HTTP " + (Invoke-WebRequest -UseBasicParsing http://localhost:3333/).StatusCode | Tee-Object -FilePath "QA\reports\smoke.txt" -Append } catch { "Frontend no responde" }

Titulo "3. Auditoria estatica propia (SAST)"
node QA\static\sast-scan.mjs 2>&1 | Tee-Object -FilePath "QA\reports\sast-consola.txt"   # [CAPTURA 2]

Titulo "4. Pruebas dinamicas (28 casos)"
node QA\tests\run-api-tests.mjs 2>&1 | Tee-Object -FilePath "QA\reports\pruebas-consola.txt"   # [CAPTURA 3 y 4]

Titulo "5. Evidencia en base de datos"
Get-Content QA\sql\evidencia-bd.sql | docker exec -i cuidarteplus-postgres-ev psql -U postgres -d cuidarteplus 2>&1 | Tee-Object -FilePath "QA\reports\evidencia-bd.txt"   # [CAPTURA 5]

Titulo "6. Analisis de dependencias (SCA) - npm audit"
Push-Location BACKEND;  npm audit --omit=dev --json 2>$null | Out-File -Encoding utf8 "..\QA\reports\npm-audit-backend.json";  npm audit --omit=dev 2>&1 | Tee-Object -FilePath "..\QA\reports\npm-audit-backend.txt"; Pop-Location
Push-Location FRONTEND; npm audit --json 2>$null | Out-File -Encoding utf8 "..\QA\reports\npm-audit-frontend.json"; npm audit 2>&1 | Tee-Object -FilePath "..\QA\reports\npm-audit-frontend.txt"; Pop-Location   # [CAPTURA 6]

Titulo "7. ESLint (frontend, configuracion del proyecto)"
Push-Location FRONTEND
if (-not (Test-Path node_modules)) { npm ci 2>&1 | Out-Null }
npx eslint . -f json -o ..\QA\reports\eslint-frontend.json 2>&1 | Out-Null
npx eslint . 2>&1 | Tee-Object -FilePath "..\QA\reports\eslint-frontend.txt"   # [CAPTURA 7]
Pop-Location

Titulo "8. Semgrep (SAST) via Docker"
docker run --rm -v "${root}:/src" semgrep/semgrep semgrep --config p/javascript --config p/owasp-top-ten --config /src/QA/static/semgrep-cuidarte.yml /src/BACKEND/src /src/FRONTEND/src --json -o /src/QA/reports/semgrep.json 2>&1 | Tee-Object -FilePath "QA\reports\semgrep-consola.txt"

Titulo "9. Trivy: vulnerabilidades de imagenes y secretos"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --scanners vuln cuidarteplus-ev-cuidarteplus-backend-ev 2>&1 | Tee-Object -FilePath "QA\reports\trivy-backend.txt"   # [CAPTURA 8]
docker run --rm -v "${root}:/src" aquasec/trivy:latest fs --scanners secret,misconfig /src 2>&1 | Tee-Object -FilePath "QA\reports\trivy-fs.txt"

Titulo "Listo"
Write-Host "Evidencias en QA\reports. Envia resultados-pruebas.json, sast-resultados.json, npm-audit-*.txt y trivy-*.txt para consolidar el informe." -ForegroundColor Green

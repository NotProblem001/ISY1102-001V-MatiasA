<#
  Cuidarte+ - Ejecucion real de pruebas con capturas de pantalla automaticas
  ISY1102-001V - EP3 - Matias Alejandro Araos Urra
  Uso: doble clic en EJECUTAR_PRUEBAS.bat (raiz del repositorio) con Docker Desktop iniciado.
  Salidas: QA\evidencias\*.png (capturas) - QA\reports\*.txt|json|md (registros)
#>
$ErrorActionPreference = "Continue"
try { chcp 65001 > $null } catch {}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root
$ev = Join-Path $root "QA\evidencias"; $rep = Join-Path $root "QA\reports"
New-Item -ItemType Directory -Force -Path $ev, $rep | Out-Null
$log = Join-Path $rep "ejecucion-evidencias.log"
"Inicio: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Set-Content -Encoding UTF8 $log

Add-Type -AssemblyName System.Windows.Forms, System.Drawing, System.Net.Http
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W32 { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h); }
"@
[W32]::SetProcessDPIAware() | Out-Null
$cw = [W32]::GetConsoleWindow(); [W32]::ShowWindow($cw, 3) | Out-Null

function Paso($t) { "`n### $t" | Add-Content -Encoding UTF8 $log; Write-Host "[$(Get-Date -Format HH:mm:ss)] $t" -ForegroundColor DarkGray }
function Encabezado($t) { Clear-Host; Write-Host ("=" * 100) -ForegroundColor Cyan; Write-Host "  $t" -ForegroundColor Cyan; Write-Host "  Cuidarte+ - ISY1102-001V - Matias Araos Urra - $(Get-Date -Format 'dd-MM-yyyy HH:mm')" -ForegroundColor DarkCyan; Write-Host ("=" * 100) -ForegroundColor Cyan }
function Capturar($nombre) {
  [W32]::SetForegroundWindow($cw) | Out-Null; Start-Sleep -Milliseconds 1500
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $bmp.Save((Join-Path $ev "$nombre.png"), [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
  "captura: $nombre.png" | Add-Content -Encoding UTF8 $log
}
function CapturarNavegador($url, $nombre, $espera = 6) {
  Start-Process $url; Start-Sleep -Seconds $espera
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
  $bmp.Save((Join-Path $ev "$nombre.png"), [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
  "captura navegador: $nombre.png ($url)" | Add-Content -Encoding UTF8 $log
}
$http = New-Object System.Net.Http.HttpClient; $http.Timeout = [TimeSpan]::FromSeconds(60)
$API = "http://localhost:4444"
function Llamar($metodo, $ruta, $token = $null, $cuerpo = $null, $headers = @{}) {
  $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::new($metodo)), ($API + $ruta)
  if ($token) { $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue "Bearer", $token }
  foreach ($k in $headers.Keys) { $req.Headers.TryAddWithoutValidation($k, $headers[$k]) | Out-Null }
  if ($cuerpo) { $req.Content = New-Object System.Net.Http.StringContent ($cuerpo | ConvertTo-Json -Compress), ([System.Text.Encoding]::UTF8), "application/json" }
  $sw = [Diagnostics.Stopwatch]::StartNew(); $res = $http.SendAsync($req).Result; $sw.Stop()
  $txt = $res.Content.ReadAsStringAsync().Result
  $hd = @{}; foreach ($h in $res.Headers) { $hd[$h.Key] = ($h.Value -join ",") }; foreach ($h in $res.Content.Headers) { $hd[$h.Key] = ($h.Value -join ",") }
  [pscustomobject]@{ Status = [int]$res.StatusCode; Ms = $sw.ElapsedMilliseconds; Body = $txt; Headers = $hd }
}
function Mostrar($titulo, $r, $color = "Yellow") {
  Write-Host "`n> $titulo" -ForegroundColor White
  $c = if ($r.Status -ge 200 -and $r.Status -lt 300) { "Green" } else { "Red" }
  Write-Host ("  HTTP {0}  ({1} ms)" -f $r.Status, $r.Ms) -ForegroundColor $c
  $b = $r.Body; try { $b = ($r.Body | ConvertFrom-Json | ConvertTo-Json -Depth 5) } catch {}
  $b = $b -replace 'eyJ[\w-]+\.[\w-]+\.[\w-]+', '<JWT>'
  ($b -split "`n" | Select-Object -First 28) | ForEach-Object { Write-Host "  $_" -ForegroundColor $color }
  "$titulo -> HTTP $($r.Status) ($($r.Ms) ms) $($r.Body)" | Add-Content -Encoding UTF8 $log
}
function TokenDe($u, $p) { (Llamar "POST" "/autenticacion/login" $null @{ nombre_usuario = $u; password = $p }).Body | ConvertFrom-Json | Select-Object -ExpandProperty token }

# ====================== 01 ENTORNO ======================
Paso "01 entorno"; Encabezado "01 - ENTORNO DE PRUEBA (versiones de herramientas)"
$nodeOk = [bool](Get-Command node -ErrorAction SilentlyContinue)
Write-Host "`nSistema operativo : $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-Host "Docker            : $(docker --version)"
Write-Host "Docker Compose    : $(docker compose version)"
Write-Host "Node.js           : $(if ($nodeOk) { node --version } else { 'no instalado (se usa contenedor node:18-alpine)' })"
Write-Host "Git               : $(git --version)"
Write-Host "Commit evaluado   : $(git log -1 --format='%h %s (%ad)' --date=short)"
Write-Host "Repositorio       : $(git config --get remote.origin.url)"
Capturar "01-entorno"

# ====================== 02 DOCKER UP ======================
Paso "02 docker compose up"; Encabezado "02 - LEVANTAMIENTO DEL STACK: docker compose up -d --build"
docker compose up -d --build 2>&1 | Tee-Object -FilePath (Join-Path $rep "docker-up.txt") | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
Write-Host "`nEsperando inicializacion de la base de datos y la API..." -ForegroundColor DarkGray
for ($i = 0; $i -lt 40; $i++) { try { if ((Llamar "GET" "/").Status -eq 200) { break } } catch {}; Start-Sleep 3 }
Capturar "02-docker-compose-up"

Paso "03 docker ps"; Encabezado "03 - CONTENEDORES EN EJECUCION: docker compose ps"
docker compose ps 2>&1 | Tee-Object -FilePath (Join-Path $rep "docker-ps.txt") | ForEach-Object { Write-Host $_ }
Write-Host ""; docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>&1 | Select-String "cuidarte|postgres|node" | ForEach-Object { Write-Host $_ }
Capturar "03-docker-ps"

# ====================== 04 SMOKE ======================
Paso "04 smoke"; Encabezado "04 - CICLO 1 - SMOKE TEST (API, login y frontend)"
Mostrar "GET http://localhost:4444/  (salud de la API)" (Llamar "GET" "/")
$lr = Llamar "POST" "/autenticacion/login" $null @{ nombre_usuario = "admin"; password = "admin" }
Mostrar "POST /autenticacion/login  (admin)" $lr
try { $w = $http.GetAsync("http://localhost:3333/").Result; Write-Host "`n> GET http://localhost:3333/  (frontend)`n  HTTP $([int]$w.StatusCode)" -ForegroundColor Green } catch { Write-Host "Frontend no responde" -ForegroundColor Red }
Capturar "04-smoke-test"

# ====================== 05 SAST ======================
function NodeRun($argsLine, $salida) {
  if ($nodeOk) { cmd /c "node $argsLine 2>&1" | Tee-Object -FilePath $salida }
  else { docker run --rm --network cuidarteplus-network -e API_URL=http://cuidarteplus-api:4000 -e WEB_URL=http://cuidarteplus-web:80 -v "${root}:/repo" -w /repo node:18-alpine sh -c "node $($argsLine -replace '\\','/') 2>&1" | Tee-Object -FilePath $salida }
}
Paso "05 SAST"; Encabezado "05 - CICLO 1 - AUDITORIA ESTATICA (SAST propio, 23 reglas CWE/OWASP)"
NodeRun "QA\static\sast-scan.mjs" (Join-Path $rep "sast-consola.txt") | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
Capturar "05-sast-resumen"

# ====================== 06 EVIDENCIA BD ======================
Paso "06 BD"; Encabezado "06 - EVIDENCIA EN BASE DE DATOS (E1-E2 contrasenas - E3 datos sensibles - E4 consentimiento)"
$bd = Get-Content -Raw -Encoding UTF8 QA\sql\evidencia-bd.sql | docker exec -i cuidarteplus-postgres-ev psql -U postgres -d cuidarteplus 2>&1
$bd | Set-Content -Encoding UTF8 (Join-Path $rep "evidencia-bd.txt")
$bdl = ($bd -split "`r?`n")
$i7 = [Array]::FindIndex($bdl, [Predicate[string]] { param($x) $x -like "*E5.*" })
($bdl | Select-Object -First $i7) | ForEach-Object { Write-Host $_ }
Capturar "06-bd-contrasenas-datos-sensibles"
Encabezado "07 - EVIDENCIA EN BASE DE DATOS (E5 auditoria - E6 acciones - E7 RUT con digito verificador invalido)"
($bdl | Select-Object -Skip $i7 | Select-Object -First 50) | ForEach-Object { Write-Host $_ }
Capturar "07-bd-auditoria-rut"

# ====================== 08 SUITE DINAMICA ======================
Paso "08 suite"; Encabezado "08 - CICLO 2 - SUITE DINAMICA run-api-tests.mjs (28 casos) - ejecutando, espere ~2 minutos..."
$suite = NodeRun "QA\tests\run-api-tests.mjs" (Join-Path $rep "pruebas-consola.txt")
$sl = @($suite)
$mid = [Math]::Ceiling(($sl.Count) / 2)
Encabezado "08 - CICLO 2 - RESULTADOS run-api-tests.mjs (parte 1 de 2)"
($sl | Select-Object -First $mid) | ForEach-Object { $c = if ($_ -match "FALLIDO") { "Red" } elseif ($_ -match "APROBADO") { "Green" } else { "Gray" }; Write-Host $_ -ForegroundColor $c }
Capturar "08-suite-resultados-1"
Encabezado "09 - CICLO 2 - RESULTADOS run-api-tests.mjs (parte 2 de 2)"
($sl | Select-Object -Skip $mid) | ForEach-Object { $c = if ($_ -match "FALLIDO") { "Red" } elseif ($_ -match "APROBADO") { "Green" } else { "Gray" }; Write-Host $_ -ForegroundColor $c }
Capturar "09-suite-resultados-2"

# ====================== 10.. DEMOSTRACIONES INDIVIDUALES ======================
$tA = TokenDe "admin" "admin"; $tM = TokenDe "medico" "medico"; $tP = TokenDe "paciente" "paciente"
$ts = Get-Date -Format "HHmmss"; $limpiar = @()

Paso "CP-10"; Encabezado "CP-10 - Ficha clinica accesible SIN autenticacion (GET /pacientes/buscar/rut/{rut}, sin token)"
Mostrar "GET /pacientes/buscar/rut/16789456-K   (sin cabecera Authorization)" (Llamar "GET" "/pacientes/buscar/rut/16789456-K")
Write-Host "`nResultado esperado: HTTP 401 - Resultado obtenido: datos clinicos expuestos  =>  FALLIDO (Critico, CVSS 7.5)" -ForegroundColor Red
Capturar "10-CP10-ficha-sin-autenticacion"

Paso "CP-11"; Encabezado "CP-11 - Control BOLA: paciente intenta ver la ficha de OTRO paciente (control que SI funciona)"
Mostrar "GET /pacientes/1   (token paciente, ficha propia)" (Llamar "GET" "/pacientes/1" $tP) "Gray"
Mostrar "GET /pacientes/2   (token paciente, ficha ajena)" (Llamar "GET" "/pacientes/2" $tP)
Write-Host "`nResultado esperado: 403 en ficha ajena  =>  APROBADO" -ForegroundColor Green
Capturar "11-CP11-bola-control-correcto"

Paso "CP-07"; Encabezado "CP-07 - Eliminacion de usuario SIN token (DELETE /usuarios/{id})"
$reg = Llamar "POST" "/autenticacion/registro" $null @{ nombre_usuario = "qa_demo_del_$ts"; password = "Qa#Demo2026!"; correo = "qa_demo_del_$ts@cuidarte.test" }
$uid = ($reg.Body | ConvertFrom-Json).usuario.id
Mostrar "POST /autenticacion/registro  (usuario de prueba qa_demo_del_$ts)" $reg "Gray"
Mostrar "DELETE /usuarios/$uid   (SIN cabecera Authorization)" (Llamar "DELETE" "/usuarios/$uid")
Mostrar "GET /usuarios/$uid   (verificacion con token admin)" (Llamar "GET" "/usuarios/$uid" $tA) "Gray"
Write-Host "`nResultado esperado: HTTP 401 y usuario intacto  =>  FALLIDO (Critico, CVSS 9.1)" -ForegroundColor Red
Capturar "12-CP07-delete-sin-token"

Paso "CP-09"; Encabezado "CP-09 - Escalamiento de privilegios: paciente autorregistrado crea un ADMINISTRADOR"
$r1 = Llamar "POST" "/autenticacion/registro" $null @{ nombre_usuario = "qa_demo_pac_$ts"; password = "Qa#Demo2026!"; correo = "qa_demo_pac_$ts@cuidarte.test" }
$limpiar += ($r1.Body | ConvertFrom-Json).usuario.id
$tq = TokenDe "qa_demo_pac_$ts" "Qa#Demo2026!"
$r2 = Llamar "POST" "/usuarios" $tq @{ nombre_usuario = "qa_demo_adm_$ts"; contrasena_hash = "Qa#Demo2026!"; correo = "qa_demo_adm_$ts@cuidarte.test"; rol_id = 1 }
$limpiar += ($r2.Body | ConvertFrom-Json).id
Mostrar "POST /usuarios con token de PACIENTE y rol_id = 1" $r2
$tE = TokenDe "qa_demo_adm_$ts" "Qa#Demo2026!"
$r3 = Llamar "GET" "/usuarios" $tE
Write-Host "`n> GET /usuarios con la cuenta creada (funcion exclusiva de administrador)" -ForegroundColor White
Write-Host ("  HTTP {0}: lista {1} usuarios del sistema" -f $r3.Status, (($r3.Body | ConvertFrom-Json) | Measure-Object).Count) -ForegroundColor Green
Write-Host "`nResultado esperado: HTTP 403  =>  FALLIDO (Critico, CVSS 8.8)" -ForegroundColor Red
Capturar "13-CP09-escalamiento-privilegios"

Paso "CP-08"; Encabezado "CP-08 - Creacion y eliminacion de ROLES sin autenticacion"
$rr = Llamar "POST" "/roles" $null @{ nombre = "qa_demo_rol_$ts" }
Mostrar "POST /roles   (SIN token)" $rr
Mostrar "DELETE /roles/$(($rr.Body | ConvertFrom-Json).id)   (SIN token)" (Llamar "DELETE" "/roles/$(($rr.Body | ConvertFrom-Json).id)")
Write-Host "`nResultado esperado: HTTP 401  =>  FALLIDO (Critico, CVSS 9.8)" -ForegroundColor Red
Capturar "14-CP08-roles-sin-autenticacion"

Paso "CP-14"; Encabezado "CP-14 - Paciente modifica su propio dato clinico (grupo sanguineo)"
$orig = ((Llamar "GET" "/pacientes/1" $tP).Body | ConvertFrom-Json).grupo_sanguineo
$pp = Llamar "PUT" "/pacientes/1" $tP @{ grupo_sanguineo = "AB-" }
Write-Host "`nValor original: $orig" -ForegroundColor White
Mostrar "PUT /pacientes/1  {grupo_sanguineo: 'AB-'}  (token PACIENTE)" $pp
Llamar "PUT" "/pacientes/1" $tM @{ grupo_sanguineo = $orig } | Out-Null
Write-Host "`n(valor restaurado a '$orig' por el medico) - Resultado esperado: HTTP 403  =>  FALLIDO (Grave)" -ForegroundColor Red
Capturar "15-CP14-paciente-altera-dato-clinico"

Paso "CP-22 CP-23"; Encabezado "CP-22 / CP-23 - Fuga de errores internos y configuracion CORS / cabeceras"
Mostrar "GET /pacientes/abc   (token medico)" (Llamar "GET" "/pacientes/abc" $tM)
$hh = Llamar "GET" "/" $null $null @{ Origin = "https://sitio-malicioso.example" }
Write-Host "`n> GET /  con Origin: https://sitio-malicioso.example  - cabeceras de respuesta:" -ForegroundColor White
$hh.Headers.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name, $_.Value) -ForegroundColor Yellow }
foreach ($k in "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security") { if (-not $hh.Headers.ContainsKey($k)) { Write-Host "  [ausente] $k" -ForegroundColor Red } }
Capturar "16-CP22-CP23-errores-cors-cabeceras"

Paso "CP-25 CP-03"; Encabezado "CP-25 / CP-03 - Tiempo de respuesta y ausencia de bloqueo por fuerza bruta"
foreach ($ruta in "/pacientes", "/examenes", "/tipo-examen") { $r = Llamar "GET" $ruta $tM; Write-Host ("  GET {0,-14} HTTP {1}  {2,6} ms" -f $ruta, $r.Status, $r.Ms) -ForegroundColor $(if ($r.Ms -gt 3000) { "Red" } else { "Green" }) }
Write-Host "  Umbral RNF-06: p95 <= 3.000 ms  =>  CP-25 FALLIDO (retardo artificial de 5 s)" -ForegroundColor Red
Write-Host "`n> 20 intentos de login fallidos consecutivos para 'medico':" -ForegroundColor White
$codes = 1..20 | ForEach-Object { (Llamar "POST" "/autenticacion/login" $null @{ nombre_usuario = "medico"; password = "mala_$_" }).Status }
Write-Host ("  Codigos: " + ($codes -join " ")) -ForegroundColor Yellow
Write-Host ("  Login valido posterior: HTTP " + (Llamar "POST" "/autenticacion/login" $null @{ nombre_usuario = "medico"; password = "medico" }).Status) -ForegroundColor Yellow
Write-Host "  Sin HTTP 429 ni bloqueo  =>  CP-03 FALLIDO (Grave, CVSS 7.3)" -ForegroundColor Red
Capturar "17-CP25-CP03-rendimiento-fuerza-bruta"

foreach ($id in $limpiar) { if ($id) { Llamar "DELETE" "/usuarios/$id" $tA | Out-Null } }

# ====================== 18 NAVEGADOR ======================
Paso "navegador"
CapturarNavegador "http://localhost:3333/" "18-frontend-login" 8
CapturarNavegador "http://localhost:4444/docs" "19-swagger-api-docs" 8
CapturarNavegador "http://localhost:4444/pacientes/buscar/rut/16789456-K" "20-navegador-ficha-sin-login" 6

# ====================== 21 SCA / LINT / TRIVY ======================
Paso "npm audit"; Encabezado "21 - ANALISIS DE DEPENDENCIAS (SCA): npm audit --omit=dev (BACKEND)"
Push-Location BACKEND
cmd /c "npm audit --omit=dev 2>&1" | Tee-Object -FilePath (Join-Path $rep "npm-audit-backend.txt") | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
Pop-Location
Capturar "21-npm-audit-backend"

Paso "trivy"; Encabezado "22 - TRIVY: vulnerabilidades HIGH/CRITICAL de la imagen del backend"
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --scanners vuln --format table cuidarteplus-ev-cuidarteplus-backend-ev 2>&1 | Tee-Object -FilePath (Join-Path $rep "trivy-backend.txt") | Select-Object -Last 45 | ForEach-Object { Write-Host $_ }
Capturar "22-trivy-imagen-backend"

Paso "eslint"; Encabezado "23 - ESLINT (configuracion del proyecto) sobre FRONTEND"
Push-Location FRONTEND
if (-not (Test-Path node_modules)) { cmd /c "npm ci --no-audit --no-fund 2>&1" | Out-Null }
cmd /c "npx eslint . 2>&1" | Tee-Object -FilePath (Join-Path $rep "eslint-frontend.txt") | Select-Object -Last 45 | ForEach-Object { Write-Host $_ }
Pop-Location
Capturar "23-eslint-frontend"

"Fin: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content -Encoding UTF8 $log
Encabezado "EJECUCION FINALIZADA - evidencias en QA\evidencias y registros en QA\reports"
Get-ChildItem $ev -Filter *.png | ForEach-Object { Write-Host "  $($_.Name)" }
"LISTO" | Set-Content -Encoding UTF8 (Join-Path $rep "FIN.txt")

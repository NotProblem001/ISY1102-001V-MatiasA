# QA · Cuidarte+ — Evaluación Parcial N°3 (ISY1102-001V)

Autor: Matías Alejandro Araos Urra · Ingeniería de Software (Desarrollo de Software)

Esta carpeta contiene los scripts de prueba, las reglas de análisis estático y las consultas de evidencia usadas en el *Informe de seguridad y calidad*. **No modifica el código de la aplicación.**

```
QA/
├── README.md                     ← este archivo
├── scripts/ejecutar-qa.ps1       ← orquestador Windows (ejecuta todo y guarda evidencias)
├── static/sast-scan.mjs          ← auditoría estática propia (23 reglas · CWE/OWASP/ISO 25010) — sin dependencias
├── static/semgrep-cuidarte.yml   ← reglas Semgrep personalizadas
├── tests/run-api-tests.mjs       ← 28 casos de prueba dinámicos (CP-01…CP-28) — sin dependencias
├── sql/evidencia-bd.sql          ← consultas de solo lectura (contraseñas, datos sensibles, RUT, auditoría)
├── ci/github-actions-qa.yml      ← propuesta de pipeline CI (no activado)
└── reports/                      ← salidas generadas (json/md/txt)
```

## Requisitos
- Docker Desktop (para levantar el stack del caso) · Node.js ≥ 18 en el equipo (sólo para ejecutar los scripts; no se instalan paquetes).

## Ejecución rápida (PowerShell, en `C:\Workspace\ISY1102-001V-MatiasA`)
```powershell
docker compose up -d --build
node QA\static\sast-scan.mjs
node QA\tests\run-api-tests.mjs
Get-Content QA\sql\evidencia-bd.sql | docker exec -i cuidarteplus-postgres-ev psql -U postgres -d cuidarteplus
```
O todo de una vez (incluye npm audit, ESLint, Semgrep y Trivy vía Docker):
```powershell
powershell -ExecutionPolicy Bypass -File QA\scripts\ejecutar-qa.ps1
```

## Capturas sugeridas para el informe (alta legibilidad: zoom 125 %, tema claro)
| # | Qué capturar | Sección del informe |
|---|---|---|
| 1 | `docker compose ps` con los 3 contenedores *running/healthy* | 3.4 / 5.1 |
| 2 | Tabla de resumen de `sast-scan.mjs` | 3.4 / 5.3 |
| 3 | Consola de `run-api-tests.mjs` (lista ✔/✘) | 5.1 |
| 4 | `QA/reports/resultados-pruebas.md` abierto en VS Code (vista previa) | 5.2 |
| 5 | Salida de `evidencia-bd.sql` (E1, E2, E7) | 5.2 (CP-05) |
| 6 | Postman/Swagger `GET /pacientes/buscar/rut/16789456-K` **sin token** → 200 con datos clínicos | 5.2 (CP-10) |
| 7 | Postman `DELETE /usuarios/{id}` **sin token** → 200 `{deleted:true}` | 5.2 (CP-07) |
| 8 | Login en `http://localhost:3333` + DevTools › Application › Local Storage con el token | 5.2 (S13) |
| 9 | `npm audit` backend (multer < 2.0.0) | 5.3 |

## Datos de prueba
Usuarios semilla del caso: `admin/admin`, `medico/medico`, `paciente/paciente` (paciente ID 1, RUT 11111111-1).
La suite crea registros con prefijo `qa_` y los elimina al terminar. El único residuo es un evento de auditoría marcado `[QA]` (CP-20), porque la API no expone borrado de auditoría.

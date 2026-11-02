# Resultados SAST — Cuidarte+

Fecha: 2026-11-02T17:09:51.743Z

| Métrica | Valor |
|---|---|
| archivos_analizados | 82 |
| loc_backend | 2256 |
| loc_frontend | 7680 |
| endpoints | 32 |
| endpoints_publicos_por_diseno | 4 |
| endpoints_sin_control_efectivo | 7 |
| cc_max | 22 |
| cc_promedio | 7.9 |

## Resumen por severidad

| Severidad | Hallazgos |
|---|---|
| Crítica | 17 |
| Alta | 14 |
| Media | 61 |
| Baja | 8 |
| Info | 0 |

## Inventario de endpoints

| Método | Ruta | Autenticación | CC aprox. | Archivo:línea |
|---|---|---|---|---|
| POST | /auditoria | Sí | 6 | BACKEND/src/routes/audit.js:19 |
| GET | /auditoria | Sí | 6 | BACKEND/src/routes/audit.js:46 |
| POST | /autenticacion/login | No | 8 | BACKEND/src/routes/auth.js:10 |
| POST | /autenticacion/registro | No | 12 | BACKEND/src/routes/auth.js:71 |
| POST | /documentos | Sí | 8 | BACKEND/src/routes/documentos.js:66 |
| GET | /documentos/examen/:examen_id | Sí | 9 | BACKEND/src/routes/documentos.js:121 |
| GET | /documentos/:id | Sí | 12 | BACKEND/src/routes/documentos.js:184 |
| DELETE | /documentos/:id | Sí | 6 | BACKEND/src/routes/documentos.js:263 |
| POST | /examenes | Sí | 9 | BACKEND/src/routes/examenes.js:46 |
| GET | /examenes | Sí | 9 | BACKEND/src/routes/examenes.js:99 |
| GET | /examenes/:id | Sí | 10 | BACKEND/src/routes/examenes.js:179 |
| GET | /examenes/paciente/:paciente_id | Sí | 9 | BACKEND/src/routes/examenes.js:262 |
| PUT | /examenes/:id | Sí | 9 | BACKEND/src/routes/examenes.js:330 |
| DELETE | /examenes/:id | Sí | 6 | BACKEND/src/routes/examenes.js:396 |
| POST | /pacientes | Sí | 22 | BACKEND/src/routes/pacientes.js:48 |
| GET | /pacientes | Sí | 4 | BACKEND/src/routes/pacientes.js:145 |
| GET | /pacientes/:id | Sí | 12 | BACKEND/src/routes/pacientes.js:173 |
| GET | /pacientes/buscar/rut/:rut | No | 4 | BACKEND/src/routes/pacientes.js:249 |
| PUT | /pacientes/:id | Sí | 17 | BACKEND/src/routes/pacientes.js:276 |
| DELETE | /pacientes/:id | Sí | 6 | BACKEND/src/routes/pacientes.js:387 |
| POST | /roles | Parcial | 4 | BACKEND/src/routes/roles.js:18 |
| GET | /roles | No | 3 | BACKEND/src/routes/roles.js:36 |
| GET | /roles/:id | No | 4 | BACKEND/src/routes/roles.js:46 |
| PUT | /roles/:id | Parcial | 5 | BACKEND/src/routes/roles.js:57 |
| DELETE | /roles/:id | Parcial | 5 | BACKEND/src/routes/roles.js:76 |
| GET | /tipo-examen | No | 3 | BACKEND/src/routes/tipo-examen.js:6 |
| GET | /tipo-examen/:id | No | 4 | BACKEND/src/routes/tipo-examen.js:22 |
| POST | /usuarios | Sí | 9 | BACKEND/src/routes/users.js:23 |
| GET | /usuarios | Sí | 10 | BACKEND/src/routes/users.js:74 |
| GET | /usuarios/:id | Sí | 12 | BACKEND/src/routes/users.js:140 |
| PUT | /usuarios/:id | Sí | 5 | BACKEND/src/routes/users.js:246 |
| DELETE | /usuarios/:id | Parcial | 5 | BACKEND/src/routes/users.js:571 |

## Hallazgos

| Regla | Severidad | CWE | OWASP | Archivo:línea | Evidencia |
|---|---|---|---|---|---|
| S03 | Crítica | CWE-256 / CWE-916 | A02:2021 | BACKEND/src/routes/auth.js:21 | `if (user.contrasena !== password) {` |
| S03 | Crítica | CWE-256 / CWE-916 | A02:2021 | BACKEND/src/routes/auth.js:110 | `"INSERT INTO usuarios (nombre_usuario, contrasena, correo) VALUES ($1, $2, $3) RETURNING id, nombre_usuario, correo, created_at",` |
| S03 | Crítica | CWE-256 / CWE-916 | A02:2021 | BACKEND/src/routes/users.js:36 | `"INSERT INTO usuarios (nombre_usuario, contrasena, correo) VALUES ($1, $2, $3) RETURNING id, nombre_usuario, correo, created_at",` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/pacientes.js:249 | `GET /pacientes/buscar/rut/:rut — no invoca getUserFromAuthHeader/requireRole` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/roles.js:18 | `POST /roles — decodifica el token pero no rechaza solicitudes anónimas` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/roles.js:36 | `GET /roles — no invoca getUserFromAuthHeader/requireRole` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/roles.js:46 | `GET /roles/:id — no invoca getUserFromAuthHeader/requireRole` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/roles.js:57 | `PUT /roles/:id — decodifica el token pero no rechaza solicitudes anónimas` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/roles.js:76 | `DELETE /roles/:id — decodifica el token pero no rechaza solicitudes anónimas` |
| S04 | Crítica | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/routes/users.js:571 | `DELETE /usuarios/:id — decodifica el token pero no rechaza solicitudes anónimas` |
| S05 | Crítica | CWE-696 / CWE-862 | A01:2021 | BACKEND/src/routes/roles.js:18 | `POST /roles — ejecuta pool.query('INSERT INTO roles (nombre) VALUES ($1) RETURNING… antes de leer el token` |
| S05 | Crítica | CWE-696 / CWE-862 | A01:2021 | BACKEND/src/routes/roles.js:57 | `PUT /roles/:id — ejecuta pool.query('UPDATE roles SET nombre=$1 WHERE id=$2 RETURNING… antes de leer el token` |
| S05 | Crítica | CWE-696 / CWE-862 | A01:2021 | BACKEND/src/routes/roles.js:76 | `DELETE /roles/:id — ejecuta pool.query('DELETE FROM roles WHERE id=$1 RETURNING *', [req… antes de leer el token` |
| S05 | Crítica | CWE-696 / CWE-862 | A01:2021 | BACKEND/src/routes/users.js:571 | `DELETE /usuarios/:id — ejecuta pool.query( "DELETE FROM usuarios WHERE id=$1 RETURNI… antes de leer el token` |
| S15 | Crítica | CWE-1392 / CWE-521 | A07:2021 | BACKEND/sql/dump-cuidarteplus.sql:288 | `INSERT INTO public.usuarios OVERRIDING SYSTEM VALUE VALUES (1, 'admin', '****', 'admin@cuidarteplus.com');` |
| S15 | Crítica | CWE-1392 / CWE-521 | A07:2021 | BACKEND/sql/dump-cuidarteplus.sql:289 | `INSERT INTO public.usuarios OVERRIDING SYSTEM VALUE VALUES (2, 'medico', '****', 'medico@cuidarteplus.com');` |
| S15 | Crítica | CWE-1392 / CWE-521 | A07:2021 | BACKEND/sql/dump-cuidarteplus.sql:290 | `INSERT INTO public.usuarios OVERRIDING SYSTEM VALUE VALUES (3, 'paciente', '****', 'paciente@cuidarteplus.com');` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/db.js:6 | `"postgres://postgres:****@localhost:5432/cuidarteplus";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/audit.js:6 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/auth.js:8 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/documentos.js:7 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/examenes.js:8 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/pacientes.js:9 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/roles.js:5 | `const JWT_SECRET = process.env.JWT_SECRET \|\| 'inseguro';` |
| S01 | Alta | CWE-798 | A07:2021 / API2:2023 | BACKEND/src/routes/users.js:8 | `const JWT_SECRET = process.env.JWT_SECRET \|\| "inseguro";` |
| S02 | Alta | CWE-538 / CWE-798 | A05:2021 | .env:1 | `Archivo versionado en Git: .env` |
| S02 | Alta | CWE-538 / CWE-798 | A05:2021 | BACKEND/.env:1 | `Archivo versionado en Git: BACKEND/.env` |
| S02 | Alta | CWE-538 / CWE-798 | A05:2021 | FRONTEND/.env:1 | `Archivo versionado en Git: FRONTEND/.env` |
| S02 | Alta | CWE-538 / CWE-798 | A05:2021 | README.md:30 | `1. JWT_SECRET: '0d1d81…' Llave utilizada para cifrar y generar los tokens de sesión` |
| S09 | Alta | CWE-307 | A07:2021 / API4:2023 | BACKEND/src/routes/auth.js:10 | `router.post("/login", …) sin express-rate-limit ni bloqueo por intentos` |
| S23 | Alta | CWE-359 | A04:2021 | FRONTEND/src/pages/auth/Register.jsx:1 | `El formulario de registro no solicita aceptación de Política de Privacidad ni consentimiento expreso` |
| S04 | Media | CWE-306 / CWE-862 | A01:2021 / API5:2023 | BACKEND/src/app.js:43 | `app.use("/files/documentos", express.static(uploadsDir))` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/audit.js:41 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/audit.js:107 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/auth.js:67 | `.json({ error: "Error en login", glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/auth.js:163 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/documentos.js:115 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/documentos.js:178 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/documentos.js:257 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/documentos.js:295 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:93 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:173 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:256 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:324 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:390 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/examenes.js:428 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:139 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:167 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:243 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:270 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:381 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/pacientes.js:419 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/roles.js:32 | `res.status(500).json({ error: 'Error al crear rol', glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/roles.js:42 | `res.status(500).json({ error: 'Error al listar roles', glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/roles.js:53 | `res.status(500).json({ error: 'Error al obtener rol', glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/roles.js:72 | `res.status(500).json({ error: 'Error al actualizar rol', glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/roles.js:90 | `res.status(500).json({ error: 'Error al eliminar rol', glosa: err.message \|\| err.toString() });` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/tipo-examen.js:16 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/tipo-examen.js:37 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:69 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:135 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:241 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:278 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:432 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:566 | `glosa: err.message \|\| err.toString(),` |
| S06 | Media | CWE-209 | A05:2021 | BACKEND/src/routes/users.js:594 | `glosa: err.message \|\| err.toString(),` |
| S10 | Media | CWE-1050 | API4:2023 | BACKEND/src/routes/documentos.js:66 | `router.post("/", delayMiddleware(5000), upload.single("documento"), async (req, res) => {` |
| S10 | Media | CWE-1050 | API4:2023 | BACKEND/src/routes/examenes.js:46 | `router.post("/", delayMiddleware(5000), validate(examenMedicoSchema), async (req, res) => {` |
| S10 | Media | CWE-1050 | API4:2023 | BACKEND/src/routes/examenes.js:99 | `router.get("/", delayMiddleware(5000), async (req, res) => {` |
| S10 | Media | CWE-1050 | API4:2023 | BACKEND/src/routes/examenes.js:330 | `router.put("/:id", delayMiddleware(5000), validate(updateExamenMedicoSchema), async (req, res) => {` |
| S10 | Media | CWE-1050 | API4:2023 | BACKEND/src/routes/pacientes.js:145 | `router.get("/", delayMiddleware(5000), async (req, res) => {` |
| S11 | Media | CWE-915 | A04:2021 / API3:2023 | BACKEND/src/middleware/validate.js:5 | `await schema.validate(data, { abortEarly: false, stripUnknown: true }); // resultado descartado` |
| S12 | Media | CWE-532 | A09:2021 | BACKEND/src/routes/pacientes.js:124 | `'PACIENTES_CREAR: creó paciente ${primer_nombre} ${apellido_paterno} (RUT: ${rut})',` |
| S13 | Media | CWE-922 | A07:2021 | FRONTEND/src/context/AuthContext.jsx:41 | `localStorage.setItem("token", newToken);` |
| S16 | Media | CWE-521 | A07:2021 | BACKEND/src/validations/auth.js:24 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S16 | Media | CWE-521 | A07:2021 | BACKEND/src/validations/empresa_usuarios.js:21 | `.min(6, "La contraseña debe tener al menos 6 caracteres")` |
| S16 | Media | CWE-521 | A07:2021 | BACKEND/src/validations/users.js:12 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S16 | Media | CWE-521 | A07:2021 | BACKEND/src/validations/users.js:33 | `.min(6, "La contraseña debe tener al menos 6 caracteres")` |
| S16 | Media | CWE-521 | A07:2021 | FRONTEND/src/pages/auth/Register.jsx:20 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S16 | Media | CWE-521 | A07:2021 | FRONTEND/src/pages/usuarios/UsuariosTabCreate.jsx:35 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S16 | Media | CWE-521 | A07:2021 | FRONTEND/src/validations/auth.js:29 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S16 | Media | CWE-521 | A07:2021 | FRONTEND/src/validations/users.js:15 | `.min(6, "La contraseña debe tener al menos 6 caracteres"),` |
| S17 | Media | CWE-1104 / CWE-250 | A06:2021 | BACKEND/Dockerfile:1 | `FROM node:18-alpine (Node.js 18 sin soporte desde 30-04-2025)` |
| S17 | Media | CWE-1104 / CWE-250 | A06:2021 | BACKEND/Dockerfile:1 | `No se define USER no privilegiado: el proceso corre como root` |
| S18 | Media | CWE-1068 | A05:2021 | BACKEND/Dockerfile:14 | `COPY uploads/ ./uploads/  ← BACKEND/uploads/ no existe en un clon limpio` |
| S19 | Media | CWE-434 | A04:2021 | BACKEND/src/routes/documentos.js:22 | `if (allowedMimes.includes(file.mimetype)) {` |
| S22 | Media | CWE-1286 | A04:2021 | BACKEND/src/validations/auth.js:32 | `.matches(/^([0-9]{1,2}(\.[0-9]{3})*-[0-9kK]\|[0-9]+-[0-9kK])$/, "El RUT debe tener formato válido (ej: 12.345.678-9 o` |
| S22 | Media | CWE-1286 | A04:2021 | BACKEND/src/validations/pacientes.js:8 | `.matches(/^([0-9]{1,2}(\.[0-9]{3})*-[0-9kK]\|[0-9]+-[0-9kK])$/, "El RUT debe tener formato válido (ej: 12.345.678-9 o` |
| S22 | Media | CWE-1286 | A04:2021 | BACKEND/src/validations/pacientes.js:99 | `.matches(/^([0-9]{1,2}(\.[0-9]{3})*-[0-9kK]\|[0-9]+-[0-9kK])$/, "El RUT debe tener formato válido (ej: 12.345.678-9 o` |
| S22 | Media | CWE-1286 | A04:2021 | FRONTEND/src/pages/auth/Register.jsx:28 | `.matches(/^([0-9]{1,2}(\.[0-9]{3})*-[0-9kK]\|[0-9]+-[0-9kK])$/, "El RUT debe tener formato válido (ej: 12.345.678-9 o` |
| S22 | Media | CWE-1286 | A04:2021 | FRONTEND/src/validations/pacientes.js:7 | `.matches(/^([0-9]{1,2}(\.[0-9]{3})*-[0-9kK]\|[0-9]+-[0-9kK])$/, "El RUT debe tener formato válido (ej: 12.345.678-9 o` |
| S23 | Media | CWE-359 | A04:2021 | FRONTEND/src/pages/informacion/PoliticaPrivacidad.jsx:1 | `Sin referencia a Ley 19.628 / 21.719 / 20.584 ni a responsable del tratamiento` |
| S07 | Baja | CWE-942 | A05:2021 | BACKEND/src/app.js:21 | `app.use(cors());` |
| S08 | Baja | CWE-693 | A05:2021 | BACKEND/src/app.js:1 | `No se registra helmet() ni cabeceras CSP/X-Frame-Options/X-Content-Type-Options` |
| S08 | Baja | CWE-693 | A05:2021 | FRONTEND/nginx.conf:1 | `nginx no define CSP, X-Frame-Options ni X-Content-Type-Options` |
| S14 | Baja | CWE-113 | A03:2021 | BACKEND/src/routes/documentos.js:249 | `"Content-Disposition",       'attachment; filename="${documento.nombre_archivo}"'     );` |
| S20 | Baja | CWE-1041 | A04:2021 | BACKEND/src/routes/audit.js, BACKEND/src/routes/documentos.js, BACKEND/src/routes/examenes.js, BACKEND/src/routes/pacientes.js, BACKEND/src/routes/roles.js, BACKEND/src/routes/users.js:0 | `getUserFromAuthHeader() definida 6 veces; requireRole() 3 veces` |
| S21 | Baja | CWE-489 | A05:2021 | BACKEND/Dockerfile:20 | `EXPOSE 3000` |
| S21 | Baja | CWE-489 | A05:2021 | BACKEND/src/app.js:23 | `app.use(morgan("dev"));` |
| S21 | Baja | CWE-489 | A05:2021 | BACKEND/src/app.js:38 | `app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapi));` |

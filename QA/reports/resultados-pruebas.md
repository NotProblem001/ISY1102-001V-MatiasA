# Bitácora de ejecución — Cuidarte+

- Ejecutor: Matías Alejandro Araos Urra
- Inicio: 02-11-2026, 2:09:56 p. m.
- API: http://localhost:4444 · Web: http://localhost:3333 · Node v24.15.0 · Windows_NT 10.0.26300

| Total | Ejecutados | Aprobados | Fallidos | Bloqueados | % aprobación |
|---|---|---|---|---|---|
| 28 | 28 | 11 | 17 | 0 | 39.3% |

| ID | Caso | Req. | Tipo | Estado | Severidad | Resultado obtenido |
|---|---|---|---|---|---|---|
| CP-01 | Inicio de sesión con credenciales válidas por rol | RF-01 | Funcional | APROBADO | — | Los 3 perfiles obtienen token con rol correcto y vigencia de 7200 s |
| CP-02 | Rechazo de credenciales inválidas con mensaje genérico | RF-01 / RNF-02 | Seguridad | APROBADO | — | Ambos casos HTTP 401 «Credenciales inválidas» |
| CP-03 | Protección contra fuerza bruta en el inicio de sesión | RNF-05 / RNF-02 | Seguridad | FALLIDO | Grave | 20 intentos fallidos sin bloqueo (códigos: 401); login posterior HTTP 200; 0 intentos fallidos auditados |
| CP-04 | Registro de paciente rechaza RUT con dígito verificador inválido | RF-02 / RN-01 | Funcional / Normativo | FALLIDO | Moderado | RUT 21392536-1 (DV correcto 9) aceptado: HTTP 201 |
| CP-05 | Contraseñas almacenadas con hash robusto (bcrypt/argon2) | RNF-02 / RL-01 | Seguridad / Normativo | FALLIDO | Crítico | 6 de 6 contraseñas en texto plano; 3 iguales al nombre de usuario |
| CP-06 | Política de contraseñas robusta en el registro | RNF-02 | Seguridad | FALLIDO | Moderado | Contraseña «123456» aceptada (HTTP 201) |
| CP-07 | Eliminación de usuarios exige autenticación de administrador | RF-03 / RNF-01 | Seguridad | FALLIDO | Crítico | Usuario 5 eliminado sin autenticación (HTTP 200; verificación posterior HTTP 404) |
| CP-08 | Gestión de roles restringida a administradores | RF-03 / RNF-01 | Seguridad | FALLIDO | Crítico | Rol creado (HTTP 201) y eliminado (HTTP 200) sin autenticación |
| CP-09 | Paciente no puede crear usuarios ni asignar rol administrador | RF-03 / RNF-01 | Seguridad | FALLIDO | Crítico | Paciente autorregistrado creó «qa_esc_mvzil40c» con rol admin (HTTP 201); el nuevo usuario lista todos los usuarios (HTTP 200) |
| CP-10 | Ficha clínica no es accesible sin autenticación (búsqueda por RUT) | RL-01 / RL-02 / RNF-01 | Seguridad / Normativo | FALLIDO | Crítico | HTTP 200 sin token; expone 6 campos sensibles (grupo_sanguineo, alergias, enfermedades_cronicas, discapacidades, direccion, telefono) |
| CP-11 | Paciente no puede acceder a la ficha de otro paciente (BOLA) | RN-02 / RL-02 | Seguridad | APROBADO | — | Propia: 200 · Ajena: 403 · Exámenes ajenos: 403 |
| CP-12 | Paciente visualiza únicamente sus propios exámenes | RF-07 / RN-02 | Funcional / Seguridad | APROBADO | — | 0 exámenes, 0 ajenos (tiempo 5009 ms) |
| CP-13 | Médico registra paciente válido y el sistema valida datos obligatorios | RF-04 / RNF-08 | Funcional | APROBADO | — | Alta 201; fecha futura rechazada 400 «no puede ser futura» |
| CP-14 | Paciente no puede alterar sus datos clínicos (integridad de ficha) | RF-04 / RL-02 | Seguridad / Normativo | FALLIDO | Grave | Paciente cambió grupo sanguíneo O+ → AB- (HTTP 200); valor restaurado por médico |
| CP-15 | Médico registra examen médico y queda auditado | RF-05 / RF-08 | Funcional | APROBADO | — | Examen ID 2 creado (tiempo 5008 ms) |
| CP-16 | Carga de documento PDF a un examen | RF-06 | Funcional | APROBADO | — | Documento cargado (201) y listado |
| CP-17 | Rechazo de archivo ejecutable con MIME falsificado | RF-06 / RNF-05 | Seguridad | FALLIDO | Moderado | Archivo .exe (cabecera MZ) aceptado como PDF y almacenado |
| CP-18 | Paciente no puede descargar documentos de otro paciente | RF-07 / RL-02 | Seguridad | APROBADO | — | Descarga ajena denegada (403) |
| CP-19 | Auditoría registra eventos y sólo el administrador la consulta | RF-08 | Funcional / Seguridad | APROBADO | — | 19 eventos; LOGIN y EXAMENES_CREAR presentes; médico 403 |
| CP-20 | Usuarios no administradores no pueden insertar eventos de auditoría arbitrarios | RF-08 / RL-03 | Seguridad / Normativo | FALLIDO | Moderado | Paciente insertó evento «USUARIOS_ELIMINAR» (HTTP 201) |
| CP-21 | Trazabilidad de accesos de lectura a fichas clínicas | RL-02 / RL-03 | Normativo | FALLIDO | Moderado | Lectura de ficha ID 2 no generó evento (eventos nuevos: 1) |
| CP-22 | Manejo de errores sin exponer detalles internos | RNF-04 | Seguridad | FALLIDO | Moderado | HTTP 500 con mensaje interno del motor de BD |
| CP-23 | Configuración segura de CORS y cabeceras HTTP | RNF-05 | Seguridad | FALLIDO | Leve | ACAO: * · X-Powered-By: Express · API sin x-content-type-options, x-frame-options, content-security-policy · Web sin x-content-type-options, x-frame-options, content-security-policy |
| CP-24 | Rechazo de tokens manipulados (alg=none y firma con secreto por defecto) | RNF-03 | Seguridad | APROBADO | — | Ambos tokens rechazados (HTTP 401). JWT_SECRET de entorno está activo. |
| CP-25 | Tiempo de respuesta de consultas principales | RNF-06 | Rendimiento | FALLIDO | Moderado | p95 /pacientes=5039 ms · p95 /examenes=5017 ms · p95 /tipo-examen (sin delay)=13 ms · POST /examenes=5008 ms |
| CP-26 | Consulta del catálogo de tipos de examen | RF-09 | Funcional | APROBADO | — | 86 tipos de examen |
| CP-27 | Despliegue reproducible desde un clon limpio del repositorio | RNF-07 | Portabilidad (ISO 25010) | FALLIDO | Moderado | Dockerfile ejecuta «COPY uploads/» pero BACKEND/uploads/ no está versionado (falla en clon limpio) · Imagen base node:18-alpine sin soporte (EOL 30-04-2025) · Contenedor se ejecuta como root |
| CP-28 | Consentimiento informado y política de privacidad conforme a ley chilena | RL-01 | Normativo | FALLIDO | Grave | Formulario de registro sin casilla de consentimiento ni enlace a la política · Política de privacidad sin referencia a Ley 19.628 / 21.719 / 20.584 |

## Evidencia HTTP por caso

### CP-01 — Inicio de sesión con credenciales válidas por rol

- Esperado: HTTP 200 y JWT con rol correcto para admin, médico y paciente; expiración ≤ 2 h
- Obtenido: Los 3 perfiles obtienen token con rol correcto y vigencia de 7200 s

```
POST /autenticacion/login → HTTP 200 (9 ms) {"token":"<JWT>"}
claims admin: usuarioId=1 rolNombre=admin pacienteId=null exp-iat=7200s
POST /autenticacion/login → HTTP 200 (6 ms) {"token":"<JWT>"}
claims medico: usuarioId=2 rolNombre=medico pacienteId=null exp-iat=7200s
POST /autenticacion/login → HTTP 200 (7 ms) {"token":"<JWT>"}
claims paciente: usuarioId=3 rolNombre=paciente pacienteId=1 exp-iat=7200s
```

### CP-02 — Rechazo de credenciales inválidas con mensaje genérico

- Esperado: HTTP 401 con mensaje idéntico para usuario inexistente y contraseña incorrecta (sin enumeración)
- Obtenido: Ambos casos HTTP 401 «Credenciales inválidas»

```
POST /autenticacion/login → HTTP 401 (3 ms) {"error":"Credenciales inválidas"}
POST /autenticacion/login → HTTP 401 (3 ms) {"error":"Credenciales inválidas"}
```

### CP-03 — Protección contra fuerza bruta en el inicio de sesión

- Esperado: Tras ≤ 10 intentos fallidos consecutivos: HTTP 429 o bloqueo temporal, y registro del intento en auditoría
- Obtenido: 20 intentos fallidos sin bloqueo (códigos: 401); login posterior HTTP 200; 0 intentos fallidos auditados
- Referencia: CWE-307 / API2:2023 · CVSS 7.3

```
Códigos: 401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401,401
POST /autenticacion/login → HTTP 200 (6 ms) {"token":"<JWT>"}
```

### CP-04 — Registro de paciente rechaza RUT con dígito verificador inválido

- Esperado: HTTP 400 «RUT inválido» cuando el DV no corresponde (módulo 11)
- Obtenido: RUT 21392536-1 (DV correcto 9) aceptado: HTTP 201
- Referencia: CWE-1286

```
POST /autenticacion/registro → HTTP 201 (7 ms) {"message":"Usuario registrado exitosamente","usuario":{"id":"4","nombre_usuario":"qa_rut_mvzil40c","correo":"qa_rut_mvzil40c@cuidarte.test","created_at"
```

### CP-05 — Contraseñas almacenadas con hash robusto (bcrypt/argon2)

- Esperado: 0 contraseñas en texto plano en la tabla usuarios
- Obtenido: 6 de 6 contraseñas en texto plano; 3 iguales al nombre de usuario
- Referencia: CWE-256 / A02:2021 · Ley 19.628 art. 11

```
docker exec cuidarteplus-postgres-ev psql … → total/texto_plano/igual_usuario = 6/6/3
```

### CP-06 — Política de contraseñas robusta en el registro

- Esperado: HTTP 400 ante contraseñas triviales (≥ 12 caracteres, mezcla de tipos, no listadas como comunes)
- Obtenido: Contraseña «123456» aceptada (HTTP 201)
- Referencia: CWE-521 · CVSS 4.8

```
POST /autenticacion/registro → HTTP 201 (5 ms) {"message":"Usuario registrado exitosamente","usuario":{"id":"5","nombre_usuario":"qa_debil_mvzil40c","correo":"qa_debil_mvzil40c@cuidarte.test","created_at":"2026-11-02T17:10:16.948Z"}}
```

### CP-07 — Eliminación de usuarios exige autenticación de administrador

- Esperado: HTTP 401 al invocar DELETE /usuarios/{id} sin token; el usuario no se elimina
- Obtenido: Usuario 5 eliminado sin autenticación (HTTP 200; verificación posterior HTTP 404)
- Referencia: CWE-306 · CVSS 9.1

```
DELETE /usuarios/5 → HTTP 200 (3 ms) {"deleted":true}
GET /usuarios/5 → HTTP 404 (3 ms) {"error":"No encontrado"}
```

### CP-08 — Gestión de roles restringida a administradores

- Esperado: HTTP 401 al crear o eliminar roles sin token
- Obtenido: Rol creado (HTTP 201) y eliminado (HTTP 200) sin autenticación
- Referencia: CWE-306 / API5:2023 · CVSS 9.8

```
POST /roles → HTTP 201 (3 ms) {"id":"4","nombre":"qa_rol_mvzil40c"}
DELETE /roles/4 → HTTP 200 (3 ms) {"deleted":true}
```

### CP-09 — Paciente no puede crear usuarios ni asignar rol administrador

- Esperado: HTTP 403 al invocar POST /usuarios con token de paciente
- Obtenido: Paciente autorregistrado creó «qa_esc_mvzil40c» con rol admin (HTTP 201); el nuevo usuario lista todos los usuarios (HTTP 200)
- Referencia: CWE-269 / API5:2023 · CVSS 8.8

```
POST /autenticacion/registro → HTTP 201 (4 ms) {"message":"Usuario registrado exitosamente","usuario":{"id":"6","nombre_
POST /usuarios → HTTP 201 (4 ms) {"id":"7","nombre_usuario":"qa_esc_mvzil40c","correo":"qa_esc_mvzil40c@cuidarte.test","created_at":"2026-11-02T17:10:16.968Z"}
GET /usuarios → HTTP 200 (3 ms) [{"id":"7","nombre_usuario":"qa_esc_mvzil40c","correo":"qa_esc_mvzil40c@cuidarte.test","created_at":"2026-11-02T17:10:16.968Z"},
```

### CP-10 — Ficha clínica no es accesible sin autenticación (búsqueda por RUT)

- Esperado: HTTP 401 al consultar /pacientes/buscar/rut/{rut} sin token
- Obtenido: HTTP 200 sin token; expone 6 campos sensibles (grupo_sanguineo, alergias, enfermedades_cronicas, discapacidades, direccion, telefono)
- Referencia: CWE-306 / API1:2023 · CVSS 7.5 · Ley 19.628 art. 11

```
GET /pacientes/buscar/rut/23672761-0 → HTTP 200 (2 ms) {"id":"21","rut":"23672761-0","primer_nombre":"Qa","apellido_paterno":"Prueba","apellido_materno":null,"fecha_nacimiento":"1990-05-10T00:00:00.000Z","sexo":"F","nacionalidad":null,"estado_civil":null,"emai
```

### CP-11 — Paciente no puede acceder a la ficha de otro paciente (BOLA)

- Esperado: HTTP 403 al solicitar /pacientes/{id} ajeno; HTTP 200 para su propia ficha
- Obtenido: Propia: 200 · Ajena: 403 · Exámenes ajenos: 403

```
GET /pacientes/1 → HTTP 200 (7 ms) {"id":"1","rut":"11111111-1","primer_nombre":"Juan","apellido_paterno":"Pérez","apell
GET /pacientes/2 → HTTP 403 (4 ms) {"error":"No autorizado","glosa":"Solo puede ver sus propios datos"}
GET /examenes/paciente/2 → HTTP 403 (3 ms) {"error":"No autorizado","glosa":"Solo puede ver sus propios exámenes"}
```

### CP-12 — Paciente visualiza únicamente sus propios exámenes

- Esperado: Todos los exámenes listados pertenecen al paciente autenticado
- Obtenido: 0 exámenes, 0 ajenos (tiempo 5009 ms)

```
GET /examenes → HTTP 200 (5009 ms) []
```

### CP-13 — Médico registra paciente válido y el sistema valida datos obligatorios

- Esperado: HTTP 201 con RUT válido; HTTP 400 con mensajes en español si la fecha de nacimiento es futura
- Obtenido: Alta 201; fecha futura rechazada 400 «no puede ser futura»

```
POST /pacientes → HTTP 201 (7 ms) {"id":"21","rut":"23672761-0","primer_nombre":"Qa","apellido_paterno":"Prueba","apellido_materno":null,"fecha_nacimiento":"1990-05-10T00:00:00.000Z","sexo":"F","nacio
POST /pacientes → HTTP 400 (3 ms) {"error":"Error de validación","glosa":"Los datos proporcionados no son válidos","detalles":[{"field":"fecha_nacimiento","message":"La fecha de nacimiento no puede ser futura"}]}
```

### CP-14 — Paciente no puede alterar sus datos clínicos (integridad de ficha)

- Esperado: HTTP 403 cuando un paciente modifica campos clínicos (grupo sanguíneo, alergias, enfermedades)
- Obtenido: Paciente cambió grupo sanguíneo O+ → AB- (HTTP 200); valor restaurado por médico
- Referencia: CWE-639 / API3:2023 · CVSS 6.5

```
PUT /pacientes/1 → HTTP 200 (6 ms) {"id":"1","rut":"11111111-1","primer_nombre":"Juan","apellido_paterno":"Pérez","apellido_materno":"Gómez","fecha_nacimiento":"1985-03-14T00:00:00.000Z","sexo":"M","n
PUT /pacientes/1 → HTTP 200 (5 ms) {"id":"1","rut":"11111111-1","primer_nombre":"Juan","apellido_paterno":"Pérez","apell
```

### CP-15 — Médico registra examen médico y queda auditado

- Esperado: HTTP 201 con examen asociado al paciente y evento EXAMENES_CREAR en auditoría
- Obtenido: Examen ID 2 creado (tiempo 5008 ms)

```
POST /examenes → HTTP 201 (5008 ms) {"id":"2","tipo_examen_medico_id":"37","paciente_id":"2","diagnosis":"[QA] Control","tratamiento":"[QA]","observaciones":"[QA] prueba automatizada","notas":null,"created_at":"2026-11-0
```

### CP-16 — Carga de documento PDF a un examen

- Esperado: HTTP 201 y documento listado en /documentos/examen/{id}
- Obtenido: Documento cargado (201) y listado

```
POST /documentos → HTTP 201 (5015 ms) {"documento":{"id":"2","nombre_archivo":"qa_resultado.pdf","created_at":"2026-11-02T17:10:11.901Z"}}
GET /documentos/examen/2 → HTTP 200 (5 ms) [{"id":"2","nombre_archivo":"qa_resultado.pdf","created_at":"2026-11-02T17:10:11.901Z"}]
```

### CP-17 — Rechazo de archivo ejecutable con MIME falsificado

- Esperado: HTTP 400: el servidor valida firma/contenido (magic bytes) y extensión, no sólo el Content-Type del cliente
- Obtenido: Archivo .exe (cabecera MZ) aceptado como PDF y almacenado
- Referencia: CWE-434 · CVSS 4.8

```
POST /documentos → HTTP 201 (5007 ms) {"documento":{"id":"3","nombre_archivo":"qa_resultado.exe","created_at":"2026-11-02T17:10:16.914Z"}}
```

### CP-18 — Paciente no puede descargar documentos de otro paciente

- Esperado: HTTP 403 al descargar /documentos/{id} perteneciente a otro paciente
- Obtenido: Descarga ajena denegada (403)

```
GET /documentos/2 → HTTP 403 (7 ms) {"error":"No autorizado","glosa":"Solo puede ver sus propios documentos"}
```

### CP-19 — Auditoría registra eventos y sólo el administrador la consulta

- Esperado: Admin: HTTP 200 con eventos LOGIN y EXAMENES_CREAR; médico: HTTP 403
- Obtenido: 19 eventos; LOGIN y EXAMENES_CREAR presentes; médico 403

```
GET /auditoria → HTTP 200 (2 ms) [{"id":"20","usuario_id":null,"accion":"ROLES_ELIMINAR: eliminó rol ID 4","fecha_hora":"2026-11-02T17:10:16.982Z","nombre_usuar
GET /auditoria → HTTP 403 (2 ms) {"error":"No autorizado","glosa":"Solo los administradores pueden ver los registros de auditoría"}
```

### CP-20 — Usuarios no administradores no pueden insertar eventos de auditoría arbitrarios

- Esperado: HTTP 403: la bitácora sólo se escribe desde el servidor (no repudio)
- Obtenido: Paciente insertó evento «USUARIOS_ELIMINAR» (HTTP 201)
- Referencia: CWE-117 / A09:2021 · CVSS 4.3

```
POST /auditoria → HTTP 201 (3 ms) {"id":"21","usuario_id":"3","accion":"USUARIOS_ELIMINAR: [QA] evento falsificado por paciente","fecha_hora":"2026-11-02T17:10:16.990Z"}
```

### CP-21 — Trazabilidad de accesos de lectura a fichas clínicas

- Esperado: Cada lectura de ficha (GET /pacientes/{id}) genera evento con usuario, paciente y fecha
- Obtenido: Lectura de ficha ID 2 no generó evento (eventos nuevos: 1)
- Referencia: ISO 27001 A.8.15 · Ley 20.584 art. 13

```
GET /pacientes/2 → HTTP 200 (3 ms) {"id":"2","rut":"16789456-K","primer_nombre":"María","apellido_pa
GET /auditoria → HTTP 200 (2 ms) [{"id":"21","usuario_id":"3","accion":"USUARIOS_ELIMINAR: [QA] evento falsificado por paciente","fecha_hora":"2026-11-02T17:10:
```

### CP-22 — Manejo de errores sin exponer detalles internos

- Esperado: HTTP 400/404 con mensaje genérico; sin texto de PostgreSQL ni trazas
- Obtenido: HTTP 500 con mensaje interno del motor de BD
- Referencia: CWE-209 · CVSS 4.3

```
GET /pacientes/abc → HTTP 500 (4 ms) {"error":"Error al obtener paciente","glosa":"invalid input syntax for type bigint: \"abc\""}
```

### CP-23 — Configuración segura de CORS y cabeceras HTTP

- Esperado: CORS restringido al dominio del frontend; cabeceras X-Content-Type-Options, X-Frame-Options/CSP presentes; sin X-Powered-By
- Obtenido: ACAO: * · X-Powered-By: Express · API sin x-content-type-options, x-frame-options, content-security-policy · Web sin x-content-type-options, x-frame-options, content-security-policy
- Referencia: CWE-942 / CWE-693 · CVSS 3.1

```
GET / (Origin externo) → cabeceras: {"access-control-allow-origin":"*","connection":"keep-alive","content-length":"37","content-type":"application/json; charset=utf-8","date":"Mon, 02 Nov 2026 17:10:17 GMT","etag":"W/\"25-JEn3xOhLDvVDZdesdoxyGakXh6s\"","keep-alive":"timeout=5","x-powered-by":"Express"}
GET http://localhost:3333/ → HTTP 200; cabeceras: accept-ranges, connection, content-length, content-type, date, etag, last-modified, server
```

### CP-24 — Rechazo de tokens manipulados (alg=none y firma con secreto por defecto)

- Esperado: HTTP 401 ante token sin firma y ante token firmado con el secreto de respaldo 'inseguro'
- Obtenido: Ambos tokens rechazados (HTTP 401). JWT_SECRET de entorno está activo.

```
GET /usuarios → HTTP 401 (4 ms) {"error":"No autorizado","glosa":"Token inválido"}
GET /usuarios → HTTP 401 (3 ms) {"error":"No autorizado","glosa":"Token inválido"}
```

### CP-25 — Tiempo de respuesta de consultas principales

- Esperado: p95 ≤ 3000 ms en GET /pacientes y GET /examenes con 5 solicitudes concurrentes
- Obtenido: p95 /pacientes=5039 ms · p95 /examenes=5017 ms · p95 /tipo-examen (sin delay)=13 ms · POST /examenes=5008 ms
- Referencia: ISO/IEC 25010 – Comportamiento temporal

```
{"pacientes":[5022,5026,5027,5029,5039],"examenes":[5007,5008,5008,5008,5017],"tipo_examen":[6,7,8,8,9,10,10,10,12,13]}
```

### CP-26 — Consulta del catálogo de tipos de examen

- Esperado: HTTP 200 y lista no vacía ordenada por nombre
- Obtenido: 86 tipos de examen

```
GET /tipo-examen → HTTP 200 (4 ms) [{"id":"37","nombre":"Anticuerpos antitiroideos"},{"id":"53","nombre":"Antígeno prostático específico (PSA)"},{"id":"30","nom
```

### CP-27 — Despliegue reproducible desde un clon limpio del repositorio

- Esperado: docker compose build finaliza sin errores en un clon limpio; imagen base con soporte vigente
- Obtenido: Dockerfile ejecuta «COPY uploads/» pero BACKEND/uploads/ no está versionado (falla en clon limpio) · Imagen base node:18-alpine sin soporte (EOL 30-04-2025) · Contenedor se ejecuta como root
- Referencia: CWE-1104 / CWE-250

```
BACKEND/Dockerfile: FROM node:18-alpine; git ls-files BACKEND/uploads → «vacío»
```

### CP-28 — Consentimiento informado y política de privacidad conforme a ley chilena

- Esperado: El registro exige aceptar la política (casilla no premarcada) y la política identifica responsable, finalidad y Ley 19.628/21.719/20.584
- Obtenido: Formulario de registro sin casilla de consentimiento ni enlace a la política · Política de privacidad sin referencia a Ley 19.628 / 21.719 / 20.584
- Referencia: Ley 21.719 (consentimiento para datos sensibles)

```
FRONTEND/src/pages/auth/Register.jsx
FRONTEND/src/pages/informacion/PoliticaPrivacidad.jsx
```

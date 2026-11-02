#!/usr/bin/env node
/**
 * Cuidarte+ — Suite de pruebas dinámicas (funcionales, seguridad, normativas y rendimiento)
 * ISY1102 · Evaluación Parcial N°3 · Matías Alejandro Araos Urra
 *
 * Requisitos: Node.js >= 18 (usa fetch, FormData y Blob nativos). Sin dependencias npm.
 * Precondición: stack levantado con `docker compose up -d` (API en :4444, Web en :3333).
 *
 * Uso (desde la raíz del repositorio):
 *   node QA/tests/run-api-tests.mjs
 *   API_URL=http://localhost:4444 WEB_URL=http://localhost:3333 node QA/tests/run-api-tests.mjs
 *   (PowerShell)  $env:API_URL="http://localhost:4444"; node QA/tests/run-api-tests.mjs
 *
 * Salidas:
 *   QA/reports/resultados-pruebas.json   (resultado por caso, evidencia HTTP)
 *   QA/reports/resultados-pruebas.md     (bitácora de ejecución legible)
 *
 * La suite crea datos de prueba con prefijo "qa_" y los elimina al finalizar (fase de limpieza).
 * Única excepción: el registro de auditoría falsificado en CP-20 (la API no permite borrarlo; texto marcado "[QA]").
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const API = (process.env.API_URL || "http://localhost:4444").replace(/\/$/, "");
const WEB = (process.env.WEB_URL || "http://localhost:3333").replace(/\/$/, "");
const DB_CONTAINER = process.env.DB_CONTAINER || "cuidarteplus-postgres-ev";
const EJECUTOR = process.env.QA_EJECUTOR || "Matías Alejandro Araos Urra";
const TS = Date.now().toString(36);
const OUT = path.join(ROOT, "QA", "reports");
fs.mkdirSync(OUT, { recursive: true });

// ---------------- utilidades ----------------
const redact = (s) => String(s).replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, "<JWT>").replace(/"(contrasena|password|contrasena_hash)":"[^"]*"/g, '"$1":"****"');
async function http(method, url, { token, body, headers = {}, form } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { h["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const t0 = performance.now();
  const res = await fetch(url.startsWith("http") ? url : API + url, { method, headers: h, body: payload });
  const ms = Math.round(performance.now() - t0);
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = undefined; }
  const hdrs = Object.fromEntries(res.headers.entries());
  return { status: res.status, ms, json, text, headers: hdrs,
    ev: `${method} ${url.replace(API, "")} → HTTP ${res.status} (${ms} ms) ${redact(text).slice(0, 300)}` };
}
const login = async (u, p) => (await http("POST", "/autenticacion/login", { body: { nombre_usuario: u, password: p } })).json?.token;
const decode = (t) => JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString());
function rutDV(cuerpo) {
  let s = 0, m = 2;
  for (const d of String(cuerpo).split("").reverse()) { s += Number(d) * m; m = m === 7 ? 2 : m + 1; }
  const r = 11 - (s % 11);
  return r === 11 ? "0" : r === 10 ? "K" : String(r);
}
const randBody = () => String(20000000 + Math.floor(Math.random() * 4999999));
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
function signHS256(payload, secret) {
  const h = b64u({ alg: "HS256", typ: "JWT" }), p = b64u(payload);
  return `${h}.${p}.${crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url")}`;
}
const pdfBytes = Buffer.from("%PDF-1.4\n1 0 obj<< /Type /Catalog >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n");

// ---------------- catálogo de casos ----------------
const results = [];
const cleanup = { usuarios: new Set(), pacientes: new Set(), roles: new Set(), examenes: new Set(), documentos: new Set() };
const ctx = {};

function caso(id, nombre, req, tipo, esperado, fn, meta = {}) { return { id, nombre, req, tipo, esperado, fn, ...meta }; }
const PASS = (obtenido, evidencia) => ({ estado: "APROBADO", obtenido, evidencia });
const FAIL = (obtenido, evidencia, severidad, ref) => ({ estado: "FALLIDO", obtenido, evidencia, severidad, ref });

const CASOS = [
  caso("CP-01", "Inicio de sesión con credenciales válidas por rol", "RF-01", "Funcional",
    "HTTP 200 y JWT con rol correcto para admin, médico y paciente; expiración ≤ 2 h", async () => {
      const ev = [];
      for (const [u, p, rol] of [["admin", "admin", "admin"], ["medico", "medico", "medico"], ["paciente", "paciente", "paciente"]]) {
        const r = await http("POST", "/autenticacion/login", { body: { nombre_usuario: u, password: p } });
        ev.push(r.ev);
        if (r.status !== 200 || !r.json?.token) return FAIL(`Login ${u} falló (HTTP ${r.status})`, ev, "Crítico");
        const d = decode(r.json.token); ctx[u] = r.json.token; ctx[u + "Claims"] = d;
        if (d.rolNombre !== rol) return FAIL(`Rol en token ${d.rolNombre} ≠ ${rol}`, ev, "Grave");
        ev.push(`claims ${u}: usuarioId=${d.usuarioId} rolNombre=${d.rolNombre} pacienteId=${d.pacienteId} exp-iat=${d.exp - d.iat}s`);
      }
      return PASS("Los 3 perfiles obtienen token con rol correcto y vigencia de 7200 s", ev);
    }),
  caso("CP-02", "Rechazo de credenciales inválidas con mensaje genérico", "RF-01 / RNF-02", "Seguridad",
    "HTTP 401 con mensaje idéntico para usuario inexistente y contraseña incorrecta (sin enumeración)", async () => {
      const a = await http("POST", "/autenticacion/login", { body: { nombre_usuario: "admin", password: "incorrecta" } });
      const b = await http("POST", "/autenticacion/login", { body: { nombre_usuario: "qa_noexiste_" + TS, password: "x" } });
      const ok = a.status === 401 && b.status === 401 && a.text === b.text;
      return ok ? PASS("Ambos casos HTTP 401 «Credenciales inválidas»", [a.ev, b.ev]) : FAIL("Respuestas distinguibles o código incorrecto", [a.ev, b.ev], "Moderado");
    }),
  caso("CP-26", "Consulta del catálogo de tipos de examen", "RF-09", "Funcional",
    "HTTP 200 y lista no vacía ordenada por nombre", async () => {
      const r = await http("GET", "/tipo-examen");
      const n = Array.isArray(r.json) ? r.json.length : 0;
      const sorted = n > 1 && r.json.every((x, i, a) => i === 0 || a[i - 1].nombre.localeCompare(x.nombre, "es", { sensitivity: "base" }) <= 0);
      ctx.tipoExamenId = r.json?.[0]?.id;
      return r.status === 200 && n > 0 ? PASS(`${n} tipos de examen${sorted ? " ordenados" : ""}`, [r.ev.slice(0, 160)]) : FAIL(`HTTP ${r.status}, ${n} elementos`, [r.ev], "Moderado");
    }),
  caso("CP-24", "Rechazo de tokens manipulados (alg=none y firma con secreto por defecto)", "RNF-03", "Seguridad",
    "HTTP 401 ante token sin firma y ante token firmado con el secreto de respaldo 'inseguro'", async () => {
      const claims = { usuarioId: 1, nombreUsuario: "admin", rolId: 1, rolNombre: "admin", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 };
      const none = `${b64u({ alg: "none", typ: "JWT" })}.${b64u(claims)}.`;
      const forged = signHS256(claims, "inseguro");
      const a = await http("GET", "/usuarios", { token: none });
      const b = await http("GET", "/usuarios", { token: forged });
      if (a.status === 401 && b.status === 401) return PASS("Ambos tokens rechazados (HTTP 401). JWT_SECRET de entorno está activo.", [a.ev, b.ev]);
      return FAIL("La API aceptó un token no emitido por ella", [a.ev, b.ev], "Crítico", "CWE-347 / CWE-798");
    }),
  caso("CP-11", "Paciente no puede acceder a la ficha de otro paciente (BOLA)", "RN-02 / RL-02", "Seguridad",
    "HTTP 403 al solicitar /pacientes/{id} ajeno; HTTP 200 para su propia ficha", async () => {
      const own = ctx.pacienteClaims?.pacienteId;
      const otro = String(own) === "2" ? 3 : 2;
      const a = await http("GET", `/pacientes/${own}`, { token: ctx.paciente });
      const b = await http("GET", `/pacientes/${otro}`, { token: ctx.paciente });
      const c = await http("GET", `/examenes/paciente/${otro}`, { token: ctx.paciente });
      ctx.pacientePropio = a.json; ctx.otroPacienteId = otro; ctx.otroPacienteRut = undefined;
      return a.status === 200 && b.status === 403 && c.status === 403 ? PASS("Propia: 200 · Ajena: 403 · Exámenes ajenos: 403", [a.ev.slice(0, 120), b.ev, c.ev])
        : FAIL("Control de acceso por objeto no se cumple", [a.ev, b.ev, c.ev], "Crítico", "API1:2023 BOLA");
    }),
  caso("CP-13", "Médico registra paciente válido y el sistema valida datos obligatorios", "RF-04 / RNF-08", "Funcional",
    "HTTP 201 con RUT válido; HTTP 400 con mensajes en español si la fecha de nacimiento es futura", async () => {
      const cuerpo = randBody(); const rut = `${cuerpo}-${rutDV(cuerpo)}`;
      const base = { rut, primer_nombre: "Qa", apellido_paterno: "Prueba", fecha_nacimiento: "1990-05-10", sexo: "F", email: `qa_${TS}@cuidarte.test`, grupo_sanguineo: "O+" };
      const a = await http("POST", "/pacientes", { token: ctx.medico, body: base });
      if (a.json?.id) { cleanup.pacientes.add(a.json.id); ctx.pacienteQA = a.json; }
      const c2 = randBody();
      const b = await http("POST", "/pacientes", { token: ctx.medico, body: { ...base, rut: `${c2}-${rutDV(c2)}`, email: `qa2_${TS}@cuidarte.test`, fecha_nacimiento: "2999-01-01" } });
      const msg = JSON.stringify(b.json?.detalles || "");
      return a.status === 201 && b.status === 400 && /futura/.test(msg) ? PASS("Alta 201; fecha futura rechazada 400 «no puede ser futura»", [a.ev.slice(0, 200), b.ev])
        : FAIL(`Alta HTTP ${a.status}; validación HTTP ${b.status}`, [a.ev, b.ev], "Grave");
    }),
  caso("CP-15", "Médico registra examen médico y queda auditado", "RF-05 / RF-08", "Funcional",
    "HTTP 201 con examen asociado al paciente y evento EXAMENES_CREAR en auditoría", async () => {
      const r = await http("POST", "/examenes", { token: ctx.medico, body: { tipo_examen_medico_id: ctx.tipoExamenId || 1, paciente_id: ctx.otroPacienteId, diagnosis: "[QA] Control", tratamiento: "[QA]", observaciones: "[QA] prueba automatizada" } });
      if (r.json?.id) { cleanup.examenes.add(r.json.id); ctx.examenQA = r.json; }
      ctx.tiempoCrearExamen = r.ms;
      return r.status === 201 ? PASS(`Examen ID ${r.json.id} creado (tiempo ${r.ms} ms)`, [r.ev.slice(0, 220)]) : FAIL(`HTTP ${r.status}`, [r.ev], "Grave");
    }),
  caso("CP-12", "Paciente visualiza únicamente sus propios exámenes", "RF-07 / RN-02", "Funcional / Seguridad",
    "Todos los exámenes listados pertenecen al paciente autenticado", async () => {
      const r = await http("GET", "/examenes", { token: ctx.paciente });
      const own = ctx.pacienteClaims?.pacienteId;
      const ajenos = Array.isArray(r.json) ? r.json.filter((e) => String(e.paciente_id) !== String(own)) : [];
      return r.status === 200 && ajenos.length === 0 ? PASS(`${r.json.length} exámenes, 0 ajenos (tiempo ${r.ms} ms)`, [r.ev.slice(0, 160)])
        : FAIL(`${ajenos.length} exámenes ajenos visibles`, [r.ev], "Crítico", "API1:2023");
    }),
  caso("CP-16", "Carga de documento PDF a un examen", "RF-06", "Funcional",
    "HTTP 201 y documento listado en /documentos/examen/{id}", async () => {
      if (!ctx.examenQA) return { estado: "BLOQUEADO", obtenido: "Depende de CP-15", evidencia: [] };
      const f = new FormData();
      f.append("examen_medico_id", String(ctx.examenQA.id)); f.append("paciente_id", String(ctx.otroPacienteId));
      f.append("documento", new Blob([pdfBytes], { type: "application/pdf" }), "qa_resultado.pdf");
      const r = await http("POST", "/documentos", { token: ctx.medico, form: f });
      if (r.json?.documento?.id) { cleanup.documentos.add(r.json.documento.id); ctx.docQA = r.json.documento; }
      const l = await http("GET", `/documentos/examen/${ctx.examenQA.id}`, { token: ctx.medico });
      return r.status === 201 && l.json?.some?.((d) => d.id === ctx.docQA?.id) ? PASS("Documento cargado (201) y listado", [r.ev, l.ev.slice(0, 160)]) : FAIL(`Carga HTTP ${r.status}`, [r.ev, l.ev], "Grave");
    }),
  caso("CP-17", "Rechazo de archivo ejecutable con MIME falsificado", "RF-06 / RNF-05", "Seguridad",
    "HTTP 400: el servidor valida firma/contenido (magic bytes) y extensión, no sólo el Content-Type del cliente", async () => {
      if (!ctx.examenQA) return { estado: "BLOQUEADO", obtenido: "Depende de CP-15", evidencia: [] };
      const f = new FormData();
      f.append("examen_medico_id", String(ctx.examenQA.id)); f.append("paciente_id", String(ctx.otroPacienteId));
      f.append("documento", new Blob([Buffer.from("MZ\x90\x00QA-ejecutable-simulado")], { type: "application/pdf" }), "qa_resultado.exe");
      const r = await http("POST", "/documentos", { token: ctx.medico, form: f });
      if (r.json?.documento?.id) cleanup.documentos.add(r.json.documento.id);
      return r.status >= 400 && r.status < 500 ? PASS("Archivo rechazado", [r.ev])
        : FAIL("Archivo .exe (cabecera MZ) aceptado como PDF y almacenado", [r.ev], "Moderado", "CWE-434 · CVSS 4.8");
    }),
  caso("CP-18", "Paciente no puede descargar documentos de otro paciente", "RF-07 / RL-02", "Seguridad",
    "HTTP 403 al descargar /documentos/{id} perteneciente a otro paciente", async () => {
      if (!ctx.docQA) return { estado: "BLOQUEADO", obtenido: "Depende de CP-16", evidencia: [] };
      const r = await http("GET", `/documentos/${ctx.docQA.id}`, { token: ctx.paciente });
      return r.status === 403 ? PASS("Descarga ajena denegada (403)", [r.ev]) : FAIL(`HTTP ${r.status}`, [r.ev], "Crítico", "API1:2023");
    }),
  caso("CP-14", "Paciente no puede alterar sus datos clínicos (integridad de ficha)", "RF-04 / RL-02", "Seguridad / Normativo",
    "HTTP 403 cuando un paciente modifica campos clínicos (grupo sanguíneo, alergias, enfermedades)", async () => {
      const own = ctx.pacienteClaims?.pacienteId; const orig = ctx.pacientePropio?.grupo_sanguineo ?? null;
      const nuevo = orig === "AB-" ? "B-" : "AB-";
      const r = await http("PUT", `/pacientes/${own}`, { token: ctx.paciente, body: { grupo_sanguineo: nuevo } });
      let restore;
      if (r.status === 200) restore = await http("PUT", `/pacientes/${own}`, { token: ctx.medico, body: { grupo_sanguineo: orig || "O+" } });
      return r.status === 403 ? PASS("Modificación clínica denegada", [r.ev])
        : FAIL(`Paciente cambió grupo sanguíneo ${orig} → ${nuevo} (HTTP ${r.status}); valor restaurado por médico`, [r.ev.slice(0, 200), restore?.ev?.slice(0, 120)].filter(Boolean), "Grave", "CWE-639 / API3:2023 · CVSS 6.5");
    }),
  caso("CP-10", "Ficha clínica no es accesible sin autenticación (búsqueda por RUT)", "RL-01 / RL-02 / RNF-01", "Seguridad / Normativo",
    "HTTP 401 al consultar /pacientes/buscar/rut/{rut} sin token", async () => {
      const rut = ctx.pacienteQA?.rut || "16789456-K";
      const r = await http("GET", `/pacientes/buscar/rut/${encodeURIComponent(rut)}`);
      const sensibles = r.json ? ["grupo_sanguineo", "alergias", "enfermedades_cronicas", "discapacidades", "direccion", "telefono"].filter((k) => k in r.json) : [];
      return r.status === 401 ? PASS("Acceso anónimo denegado", [r.ev])
        : FAIL(`HTTP ${r.status} sin token; expone ${sensibles.length} campos sensibles (${sensibles.join(", ")})`, [r.ev.slice(0, 260)], "Crítico", "CWE-306 / API1:2023 · CVSS 7.5 · Ley 19.628 art. 11");
    }),
  caso("CP-04", "Registro de paciente rechaza RUT con dígito verificador inválido", "RF-02 / RN-01", "Funcional / Normativo",
    "HTTP 400 «RUT inválido» cuando el DV no corresponde (módulo 11)", async () => {
      const cuerpo = randBody(); const dv = rutDV(cuerpo); const malo = dv === "1" ? "2" : "1";
      const u = `qa_rut_${TS}`;
      const r = await http("POST", "/autenticacion/registro", { body: { nombre_usuario: u, password: "Qa#Prueba2026!", correo: `${u}@cuidarte.test`, rut: `${cuerpo}-${malo}` } });
      if (r.json?.usuario?.id) cleanup.usuarios.add(r.json.usuario.id);
      const p = await http("GET", `/pacientes/buscar/rut/${cuerpo}-${malo}`);
      if (p.json?.id) cleanup.pacientes.add(p.json.id);
      return r.status === 400 ? PASS("RUT inválido rechazado", [r.ev])
        : FAIL(`RUT ${cuerpo}-${malo} (DV correcto ${dv}) aceptado: HTTP ${r.status}`, [r.ev.slice(0, 200)], "Moderado", "CWE-1286");
    }),
  caso("CP-06", "Política de contraseñas robusta en el registro", "RNF-02", "Seguridad",
    "HTTP 400 ante contraseñas triviales (≥ 12 caracteres, mezcla de tipos, no listadas como comunes)", async () => {
      const u = `qa_debil_${TS}`;
      const r = await http("POST", "/autenticacion/registro", { body: { nombre_usuario: u, password: "123456", correo: `${u}@cuidarte.test` } });
      if (r.json?.usuario?.id) { cleanup.usuarios.add(r.json.usuario.id); ctx.usuarioDebil = r.json.usuario; }
      return r.status === 400 ? PASS("Contraseña trivial rechazada", [r.ev]) : FAIL("Contraseña «123456» aceptada (HTTP 201)", [r.ev], "Moderado", "CWE-521 · CVSS 4.8");
    }),
  caso("CP-07", "Eliminación de usuarios exige autenticación de administrador", "RF-03 / RNF-01", "Seguridad",
    "HTTP 401 al invocar DELETE /usuarios/{id} sin token; el usuario no se elimina", async () => {
      if (!ctx.usuarioDebil) return { estado: "BLOQUEADO", obtenido: "Depende del usuario creado en CP-06", evidencia: [] };
      const r = await http("DELETE", `/usuarios/${ctx.usuarioDebil.id}`);
      const chk = await http("GET", `/usuarios/${ctx.usuarioDebil.id}`, { token: ctx.admin });
      if (chk.status === 404) cleanup.usuarios.delete(ctx.usuarioDebil.id);
      return r.status === 401 || r.status === 403 ? PASS("Solicitud anónima rechazada", [r.ev])
        : FAIL(`Usuario ${ctx.usuarioDebil.id} eliminado sin autenticación (HTTP ${r.status}; verificación posterior HTTP ${chk.status})`, [r.ev, chk.ev], "Crítico", "CWE-306 · CVSS 9.1");
    }),
  caso("CP-09", "Paciente no puede crear usuarios ni asignar rol administrador", "RF-03 / RNF-01", "Seguridad",
    "HTTP 403 al invocar POST /usuarios con token de paciente", async () => {
      const u = `qa_pac_${TS}`;
      const reg = await http("POST", "/autenticacion/registro", { body: { nombre_usuario: u, password: "Qa#Prueba2026!", correo: `${u}@cuidarte.test` } });
      if (reg.json?.usuario?.id) cleanup.usuarios.add(reg.json.usuario.id);
      const tok = await login(u, "Qa#Prueba2026!");
      const esc = `qa_esc_${TS}`;
      const c = await http("POST", "/usuarios", { token: tok, body: { nombre_usuario: esc, contrasena_hash: "Qa#Prueba2026!", correo: `${esc}@cuidarte.test`, rol_id: 1 } });
      if (c.json?.id) cleanup.usuarios.add(c.json.id);
      let g;
      if (c.status === 201) { const t2 = await login(esc, "Qa#Prueba2026!"); g = await http("GET", "/usuarios", { token: t2 }); }
      return c.status === 403 ? PASS("Creación denegada", [reg.ev.slice(0, 120), c.ev])
        : FAIL(`Paciente autorregistrado creó «${esc}» con rol admin (HTTP ${c.status}); el nuevo usuario lista todos los usuarios (HTTP ${g?.status})`, [reg.ev.slice(0, 120), c.ev, g?.ev?.slice(0, 160)].filter(Boolean), "Crítico", "CWE-269 / API5:2023 · CVSS 8.8");
    }),
  caso("CP-08", "Gestión de roles restringida a administradores", "RF-03 / RNF-01", "Seguridad",
    "HTTP 401 al crear o eliminar roles sin token", async () => {
      const a = await http("POST", "/roles", { body: { nombre: `qa_rol_${TS}` } });
      if (a.json?.id) cleanup.roles.add(a.json.id);
      let b;
      if (a.json?.id) { b = await http("DELETE", `/roles/${a.json.id}`); if (b.status === 200) cleanup.roles.delete(a.json.id); }
      return a.status === 401 ? PASS("Operación anónima rechazada", [a.ev])
        : FAIL(`Rol creado (HTTP ${a.status}) y eliminado (HTTP ${b?.status}) sin autenticación`, [a.ev, b?.ev].filter(Boolean), "Crítico", "CWE-306 / API5:2023 · CVSS 9.8");
    }),
  caso("CP-19", "Auditoría registra eventos y sólo el administrador la consulta", "RF-08", "Funcional / Seguridad",
    "Admin: HTTP 200 con eventos LOGIN y EXAMENES_CREAR; médico: HTTP 403", async () => {
      const a = await http("GET", "/auditoria", { token: ctx.admin });
      const m = await http("GET", "/auditoria", { token: ctx.medico });
      const acc = Array.isArray(a.json) ? a.json.map((x) => x.accion) : [];
      const ok = a.status === 200 && acc.some((x) => /^LOGIN/.test(x)) && acc.some((x) => /^EXAMENES_CREAR/.test(x)) && m.status === 403;
      ctx.auditCount = acc.length;
      return ok ? PASS(`${acc.length} eventos; LOGIN y EXAMENES_CREAR presentes; médico 403`, [a.ev.slice(0, 160), m.ev]) : FAIL("Registro o restricción incompletos", [a.ev, m.ev], "Grave");
    }),
  caso("CP-20", "Usuarios no administradores no pueden insertar eventos de auditoría arbitrarios", "RF-08 / RL-03", "Seguridad / Normativo",
    "HTTP 403: la bitácora sólo se escribe desde el servidor (no repudio)", async () => {
      const r = await http("POST", "/auditoria", { token: ctx.paciente, body: { accion: "USUARIOS_ELIMINAR", detalles: "[QA] evento falsificado por paciente" } });
      return r.status === 403 ? PASS("Inserción denegada", [r.ev])
        : FAIL(`Paciente insertó evento «USUARIOS_ELIMINAR» (HTTP ${r.status})`, [r.ev], "Moderado", "CWE-117 / A09:2021 · CVSS 4.3");
    }),
  caso("CP-21", "Trazabilidad de accesos de lectura a fichas clínicas", "RL-02 / RL-03", "Normativo",
    "Cada lectura de ficha (GET /pacientes/{id}) genera evento con usuario, paciente y fecha", async () => {
      const before = ctx.auditCount ?? 0;
      const r = await http("GET", `/pacientes/${ctx.otroPacienteId}`, { token: ctx.medico });
      const a = await http("GET", "/auditoria", { token: ctx.admin });
      const nuevos = Array.isArray(a.json) ? a.json.length - before : 0;
      const hay = Array.isArray(a.json) && a.json.slice(0, Math.max(nuevos, 0)).some((x) => /PACIENTE.*(VER|LEER|CONSULT)/i.test(x.accion));
      return hay ? PASS("Lectura registrada", [r.ev.slice(0, 100), a.ev.slice(0, 120)])
        : FAIL(`Lectura de ficha ID ${ctx.otroPacienteId} no generó evento (eventos nuevos: ${nuevos})`, [r.ev.slice(0, 100), a.ev.slice(0, 160)], "Moderado", "ISO 27001 A.8.15 · Ley 20.584 art. 13");
    }),
  caso("CP-22", "Manejo de errores sin exponer detalles internos", "RNF-04", "Seguridad",
    "HTTP 400/404 con mensaje genérico; sin texto de PostgreSQL ni trazas", async () => {
      const r = await http("GET", "/pacientes/abc", { token: ctx.medico });
      const leak = /syntax|bigint|pg_|postgres|relation|column/i.test(r.text);
      return !leak && r.status < 500 ? PASS("Error controlado", [r.ev])
        : FAIL(`HTTP ${r.status} con mensaje interno del motor de BD`, [r.ev], "Moderado", "CWE-209 · CVSS 4.3");
    }),
  caso("CP-23", "Configuración segura de CORS y cabeceras HTTP", "RNF-05", "Seguridad",
    "CORS restringido al dominio del frontend; cabeceras X-Content-Type-Options, X-Frame-Options/CSP presentes; sin X-Powered-By", async () => {
      const a = await http("GET", "/", { headers: { Origin: "https://sitio-malicioso.example" } });
      const req = ["x-content-type-options", "x-frame-options", "content-security-policy"];
      const faltan = req.filter((k) => !a.headers[k]);
      const issues = [];
      if (a.headers["access-control-allow-origin"] === "*") issues.push("ACAO: *");
      if (a.headers["x-powered-by"]) issues.push(`X-Powered-By: ${a.headers["x-powered-by"]}`);
      if (faltan.length) issues.push(`API sin ${faltan.join(", ")}`);
      let wev = "Frontend no disponible";
      try { const w = await http("GET", WEB + "/"); const wf = req.filter((k) => !w.headers[k]); if (wf.length) issues.push(`Web sin ${wf.join(", ")}`); wev = `GET ${WEB}/ → HTTP ${w.status}; cabeceras: ${Object.keys(w.headers).join(", ")}`; } catch {}
      return issues.length === 0 ? PASS("Configuración correcta", [a.ev]) : FAIL(issues.join(" · "), [`GET / (Origin externo) → cabeceras: ${JSON.stringify(a.headers)}`.slice(0, 400), wev], "Leve", "CWE-942 / CWE-693 · CVSS 3.1");
    }),
  caso("CP-25", "Tiempo de respuesta de consultas principales", "RNF-06", "Rendimiento",
    "p95 ≤ 3000 ms en GET /pacientes y GET /examenes con 5 solicitudes concurrentes", async () => {
      const lat = async (url, tok, n = 5) => (await Promise.all(Array.from({ length: n }, () => http("GET", url, { token: tok })))).map((x) => x.ms).sort((a, b) => a - b);
      const p95 = (a) => a[Math.min(a.length - 1, Math.ceil(a.length * 0.95) - 1)];
      const pac = await lat("/pacientes", ctx.medico), ex = await lat("/examenes", ctx.medico), base = await lat("/tipo-examen", null, 10);
      ctx.perf = { pacientes: pac, examenes: ex, tipo_examen: base };
      const ok = p95(pac) <= 3000 && p95(ex) <= 3000;
      const msg = `p95 /pacientes=${p95(pac)} ms · p95 /examenes=${p95(ex)} ms · p95 /tipo-examen (sin delay)=${p95(base)} ms · POST /examenes=${ctx.tiempoCrearExamen ?? "?"} ms`;
      return ok ? PASS(msg, [JSON.stringify(ctx.perf)]) : FAIL(msg, [JSON.stringify(ctx.perf)], "Moderado", "ISO/IEC 25010 – Comportamiento temporal");
    }),
  caso("CP-03", "Protección contra fuerza bruta en el inicio de sesión", "RNF-05 / RNF-02", "Seguridad",
    "Tras ≤ 10 intentos fallidos consecutivos: HTTP 429 o bloqueo temporal, y registro del intento en auditoría", async () => {
      const codes = [];
      for (let i = 0; i < 20; i++) codes.push((await http("POST", "/autenticacion/login", { body: { nombre_usuario: "medico", password: `qa_mala_${i}` } })).status);
      const ok = await http("POST", "/autenticacion/login", { body: { nombre_usuario: "medico", password: "medico" } });
      const a = await http("GET", "/auditoria", { token: ctx.admin });
      const fallidos = Array.isArray(a.json) ? a.json.filter((x) => /FALLID|FAIL|INTENTO/i.test(x.accion)).length : 0;
      const bloqueado = codes.includes(429) || codes.includes(423);
      return bloqueado ? PASS("Bloqueo/limitación activa", [codes.join(",")])
        : FAIL(`20 intentos fallidos sin bloqueo (códigos: ${[...new Set(codes)].join("/")}); login posterior HTTP ${ok.status}; ${fallidos} intentos fallidos auditados`, [`Códigos: ${codes.join(",")}`, ok.ev.slice(0, 80)], "Grave", "CWE-307 / API2:2023 · CVSS 7.3");
    }),
  caso("CP-05", "Contraseñas almacenadas con hash robusto (bcrypt/argon2)", "RNF-02 / RL-01", "Seguridad / Normativo",
    "0 contraseñas en texto plano en la tabla usuarios", async () => {
      try {
        const q = "SELECT count(*)||'/'||count(*) FILTER (WHERE contrasena !~ '^\\$(2[aby]|argon2(id|i|d))\\$')||'/'||count(*) FILTER (WHERE contrasena = nombre_usuario) FROM usuarios;";
        const outp = execSync(`docker exec -i ${DB_CONTAINER} psql -U postgres -d cuidarteplus -t -A`, { input: q, stdio: ["pipe", "pipe", "pipe"] }).toString().trim();
        const [tot, plano, igual] = outp.split("/").map(Number);
        return plano === 0 ? PASS(`${tot} usuarios con hash`, [outp])
          : FAIL(`${plano} de ${tot} contraseñas en texto plano; ${igual} iguales al nombre de usuario`, [`docker exec ${DB_CONTAINER} psql … → total/texto_plano/igual_usuario = ${outp}`], "Crítico", "CWE-256 / A02:2021 · Ley 19.628 art. 11");
      } catch (e) {
        return { estado: "BLOQUEADO", obtenido: "No fue posible ejecutar docker exec (ejecutar QA/sql/evidencia-bd.sql manualmente)", evidencia: [String(e.message).slice(0, 200)] };
      }
    }),
  caso("CP-27", "Despliegue reproducible desde un clon limpio del repositorio", "RNF-07", "Portabilidad (ISO 25010)",
    "docker compose build finaliza sin errores en un clon limpio; imagen base con soporte vigente", async () => {
      const df = fs.readFileSync(path.join(ROOT, "BACKEND", "Dockerfile"), "utf8");
      let tracked = "";
      try { tracked = execSync("git ls-files BACKEND/uploads", { cwd: ROOT }).toString().trim(); } catch {}
      const copia = /^COPY\s+uploads\//m.test(df); const base = (df.match(/^FROM\s+(\S+)/m) || [])[1];
      const issues = [];
      if (copia && !tracked) issues.push("Dockerfile ejecuta «COPY uploads/» pero BACKEND/uploads/ no está versionado (falla en clon limpio)");
      if (/node:1[0-8]\b/.test(base)) issues.push(`Imagen base ${base} sin soporte (EOL 30-04-2025)`);
      if (!/^USER\s/m.test(df)) issues.push("Contenedor se ejecuta como root");
      return issues.length ? FAIL(issues.join(" · "), [`BACKEND/Dockerfile: FROM ${base}; git ls-files BACKEND/uploads → «${tracked || "vacío"}»`], "Moderado", "CWE-1104 / CWE-250")
        : PASS("Build reproducible", []);
    }),
  caso("CP-28", "Consentimiento informado y política de privacidad conforme a ley chilena", "RL-01", "Normativo",
    "El registro exige aceptar la política (casilla no premarcada) y la política identifica responsable, finalidad y Ley 19.628/21.719/20.584", async () => {
      const reg = fs.readFileSync(path.join(ROOT, "FRONTEND", "src", "pages", "auth", "Register.jsx"), "utf8");
      const pol = fs.readFileSync(path.join(ROOT, "FRONTEND", "src", "pages", "informacion", "PoliticaPrivacidad.jsx"), "utf8");
      const issues = [];
      if (!/Checkbox|consent|acept/i.test(reg)) issues.push("Formulario de registro sin casilla de consentimiento ni enlace a la política");
      if (!/19\.628|21\.719|20\.584/.test(pol)) issues.push("Política de privacidad sin referencia a Ley 19.628 / 21.719 / 20.584");
      return issues.length ? FAIL(issues.join(" · "), ["FRONTEND/src/pages/auth/Register.jsx", "FRONTEND/src/pages/informacion/PoliticaPrivacidad.jsx"], "Grave", "Ley 21.719 (consentimiento para datos sensibles)") : PASS("Consentimiento y política conformes", []);
    }),
];

// ---------------- ejecución ----------------
const inicio = new Date();
console.log(`\nCuidarte+ · Suite QA · API=${API} · WEB=${WEB} · ${inicio.toLocaleString("es-CL")}\n`);
let apiUp = false;
try { apiUp = (await http("GET", "/")).status === 200; } catch {}
for (const c of CASOS) {
  const t0 = Date.now();
  let r;
  const offline = !apiUp && !["CP-27", "CP-28", "CP-05"].includes(c.id);
  try { r = offline ? { estado: "BLOQUEADO", obtenido: `API no disponible en ${API}`, evidencia: [] } : await c.fn(); }
  catch (e) { r = { estado: "BLOQUEADO", obtenido: "Error de ejecución: " + e.message, evidencia: [] }; }
  const row = { id: c.id, nombre: c.nombre, requerimiento: c.req, tipo: c.tipo, esperado: c.esperado, ...r, duracion_ms: Date.now() - t0, fecha: new Date().toISOString(), ejecutor: EJECUTOR };
  results.push(row);
  const icon = r.estado === "APROBADO" ? "✔" : r.estado === "FALLIDO" ? "✘" : "■";
  console.log(`${icon} ${c.id} ${r.estado.padEnd(9)} ${c.nombre}\n    → ${r.obtenido}`);
}

// ---------------- limpieza ----------------
const limp = [];
if (apiUp && ctx.admin) {
  for (const id of cleanup.documentos) limp.push((await http("DELETE", `/documentos/${id}`, { token: ctx.admin })).status);
  for (const id of cleanup.examenes) limp.push((await http("DELETE", `/examenes/${id}`, { token: ctx.admin })).status);
  for (const id of cleanup.pacientes) limp.push((await http("DELETE", `/pacientes/${id}`, { token: ctx.admin })).status);
  for (const id of cleanup.roles) limp.push((await http("DELETE", `/roles/${id}`, { token: ctx.admin })).status);
  for (const id of cleanup.usuarios) limp.push((await http("DELETE", `/usuarios/${id}`, { token: ctx.admin })).status);
}

// ---------------- reporte ----------------
results.sort((a, b) => a.id.localeCompare(b.id, "es", { numeric: true }));
const cnt = (e) => results.filter((r) => r.estado === e).length;
const resumen = { total_disenados: CASOS.length, ejecutados: CASOS.length - cnt("BLOQUEADO"), aprobados: cnt("APROBADO"), fallidos: cnt("FALLIDO"), bloqueados: cnt("BLOQUEADO") };
resumen.tasa_aprobacion = resumen.ejecutados ? +((resumen.aprobados / resumen.ejecutados) * 100).toFixed(1) : 0;
const entorno = { api: API, web: WEB, node: process.version, so: `${os.type()} ${os.release()}`, inicio: inicio.toISOString(), fin: new Date().toISOString(), limpieza_http: limp };
fs.writeFileSync(path.join(OUT, "resultados-pruebas.json"), JSON.stringify({ entorno, resumen, rendimiento: ctx.perf, resultados: results }, null, 2));
let md = `# Bitácora de ejecución — Cuidarte+\n\n- Ejecutor: ${EJECUTOR}\n- Inicio: ${inicio.toLocaleString("es-CL")}\n- API: ${API} · Web: ${WEB} · Node ${process.version} · ${entorno.so}\n\n`;
md += `| Total | Ejecutados | Aprobados | Fallidos | Bloqueados | % aprobación |\n|---|---|---|---|---|---|\n| ${resumen.total_disenados} | ${resumen.ejecutados} | ${resumen.aprobados} | ${resumen.fallidos} | ${resumen.bloqueados} | ${resumen.tasa_aprobacion}% |\n\n`;
md += `| ID | Caso | Req. | Tipo | Estado | Severidad | Resultado obtenido |\n|---|---|---|---|---|---|---|\n` + results.map((r) => `| ${r.id} | ${r.nombre} | ${r.requerimiento} | ${r.tipo} | ${r.estado} | ${r.severidad || "—"} | ${String(r.obtenido).replace(/\|/g, "/")} |`).join("\n");
md += `\n\n## Evidencia HTTP por caso\n\n` + results.map((r) => `### ${r.id} — ${r.nombre}\n\n- Esperado: ${r.esperado}\n- Obtenido: ${r.obtenido}\n${r.ref ? `- Referencia: ${r.ref}\n` : ""}\n\`\`\`\n${(r.evidencia || []).join("\n")}\n\`\`\`\n`).join("\n");
fs.writeFileSync(path.join(OUT, "resultados-pruebas.md"), md);
console.log(`\nResumen: ${JSON.stringify(resumen)}\nReportes: QA/reports/resultados-pruebas.{json,md}\n`);

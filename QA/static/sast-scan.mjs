#!/usr/bin/env node
/**
 * Cuidarte+ — Auditoría estática (SAST) sin dependencias externas
 * ISY1102 · Evaluación Parcial N°3 · Matías Alejandro Araos Urra
 *
 * Uso (desde la raíz del repositorio):
 *   node QA/static/sast-scan.mjs
 *
 * Requisitos: Node.js >= 18. No instala paquetes ni requiere red.
 * Salida: QA/reports/sast-resultados.json y QA/reports/sast-resultados.md
 *
 * Cada regla está mapeada a CWE, OWASP Top 10:2021, OWASP API Security Top 10:2023
 * e ISO/IEC 25010:2023. Las reglas son heurísticas (expresiones regulares y análisis
 * de bloques de rutas Express); los hallazgos deben confirmarse con revisión manual
 * y con las pruebas dinámicas de QA/tests/run-api-tests.mjs.
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const OUT_DIR = path.join(ROOT, "QA", "reports");
fs.mkdirSync(OUT_DIR, { recursive: true });

const IGNORE_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", "QA"]);
const EXT = new Set([".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".conf", ".sql", ".md", ".env", ""]);

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORE_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (EXT.has(path.extname(e.name)) || e.name.startsWith(".env") || e.name === "Dockerfile") acc.push(p);
  }
  return acc;
}
const rel = (p) => path.relative(ROOT, p).split(path.sep).join("/");
const files = walk(ROOT);
const read = (p) => fs.readFileSync(p, "utf8");
const lineOf = (text, idx) => text.slice(0, idx).split("\n").length;

const findings = [];
function add(rule, file, line, evidence, extra = {}) {
  findings.push({ rule: rule.id, titulo: rule.titulo, severidad: rule.severidad, cwe: rule.cwe, owasp: rule.owasp,
    iso25010: rule.iso, archivo: file, linea: line, evidencia: String(evidence).trim().slice(0, 220), ...extra });
}

const RULES = {
  S01: { id: "S01", titulo: "Secreto JWT con valor por defecto inseguro (fallback hardcodeado)", severidad: "Alta", cwe: "CWE-798", owasp: "A07:2021 / API2:2023", iso: "Seguridad – Autenticidad" },
  S02: { id: "S02", titulo: "Archivo .env / secreto versionado en el repositorio", severidad: "Alta", cwe: "CWE-538 / CWE-798", owasp: "A05:2021", iso: "Seguridad – Confidencialidad" },
  S03: { id: "S03", titulo: "Contraseña almacenada/comparada en texto plano (sin hash)", severidad: "Crítica", cwe: "CWE-256 / CWE-916", owasp: "A02:2021", iso: "Seguridad – Confidencialidad" },
  S04: { id: "S04", titulo: "Endpoint sin verificación de autenticación/autorización", severidad: "Crítica", cwe: "CWE-306 / CWE-862", owasp: "A01:2021 / API5:2023", iso: "Seguridad – Confidencialidad/Integridad" },
  S05: { id: "S05", titulo: "Autorización evaluada después de ejecutar la operación", severidad: "Crítica", cwe: "CWE-696 / CWE-862", owasp: "A01:2021", iso: "Seguridad – Integridad" },
  S06: { id: "S06", titulo: "Exposición de mensajes internos de error al cliente", severidad: "Media", cwe: "CWE-209", owasp: "A05:2021", iso: "Seguridad – Confidencialidad" },
  S07: { id: "S07", titulo: "CORS abierto a cualquier origen", severidad: "Baja", cwe: "CWE-942", owasp: "A05:2021", iso: "Seguridad" },
  S08: { id: "S08", titulo: "Ausencia de cabeceras de seguridad HTTP (helmet / CSP)", severidad: "Baja", cwe: "CWE-693", owasp: "A05:2021", iso: "Seguridad" },
  S09: { id: "S09", titulo: "Login sin limitación de intentos (rate limiting / bloqueo)", severidad: "Alta", cwe: "CWE-307", owasp: "A07:2021 / API4:2023", iso: "Seguridad – Autenticidad" },
  S10: { id: "S10", titulo: "Retardo artificial en rutas productivas (delay middleware)", severidad: "Media", cwe: "CWE-1050", owasp: "API4:2023", iso: "Eficiencia de desempeño – Comportamiento temporal" },
  S11: { id: "S11", titulo: "Validación no aplica datos saneados (stripUnknown descartado) → asignación masiva", severidad: "Media", cwe: "CWE-915", owasp: "A04:2021 / API3:2023", iso: "Seguridad – Integridad" },
  S12: { id: "S12", titulo: "Dato personal (RUT) escrito en registro de auditoría/log", severidad: "Media", cwe: "CWE-532", owasp: "A09:2021", iso: "Seguridad – Confidencialidad" },
  S13: { id: "S13", titulo: "Token de sesión almacenado en localStorage", severidad: "Media", cwe: "CWE-922", owasp: "A07:2021", iso: "Seguridad – Confidencialidad" },
  S14: { id: "S14", titulo: "Cabecera Content-Disposition con nombre de archivo sin sanear", severidad: "Baja", cwe: "CWE-113", owasp: "A03:2021", iso: "Seguridad – Integridad" },
  S15: { id: "S15", titulo: "Credenciales por defecto en datos semilla (usuario = contraseña)", severidad: "Crítica", cwe: "CWE-1392 / CWE-521", owasp: "A07:2021", iso: "Seguridad – Autenticidad" },
  S16: { id: "S16", titulo: "Política de contraseñas débil (mínimo 6 caracteres, sin complejidad)", severidad: "Media", cwe: "CWE-521", owasp: "A07:2021", iso: "Seguridad – Autenticidad" },
  S17: { id: "S17", titulo: "Imagen base con runtime fuera de soporte (Node.js 18 EOL) / contenedor ejecuta como root", severidad: "Media", cwe: "CWE-1104 / CWE-250", owasp: "A06:2021", iso: "Mantenibilidad / Flexibilidad" },
  S18: { id: "S18", titulo: "Dockerfile copia directorio no versionado (build no reproducible desde clon limpio)", severidad: "Media", cwe: "CWE-1068", owasp: "A05:2021", iso: "Flexibilidad – Instalabilidad" },
  S19: { id: "S19", titulo: "Validación de tipo de archivo basada sólo en MIME declarado por el cliente", severidad: "Media", cwe: "CWE-434", owasp: "A04:2021", iso: "Seguridad – Integridad" },
  S20: { id: "S20", titulo: "Código duplicado: verificación de token replicada por módulo (sin middleware común)", severidad: "Baja", cwe: "CWE-1041", owasp: "A04:2021", iso: "Mantenibilidad – Modularidad" },
  S21: { id: "S21", titulo: "Documentación/Swagger y logging de desarrollo expuestos en producción", severidad: "Baja", cwe: "CWE-489", owasp: "A05:2021", iso: "Seguridad" },
  S22: { id: "S22", titulo: "Validación de RUT sólo por formato (sin dígito verificador módulo 11)", severidad: "Media", cwe: "CWE-1286", owasp: "A04:2021", iso: "Adecuación funcional – Corrección" },
  S23: { id: "S23", titulo: "Registro sin consentimiento explícito para datos sensibles de salud", severidad: "Alta", cwe: "CWE-359", owasp: "A04:2021", iso: "Seguridad / Cumplimiento (Ley 19.628 – 21.719)" },
};

const byRel = Object.fromEntries(files.map((f) => [rel(f), f]));
const src = (r) => (byRel[r] ? read(byRel[r]) : "");

// ---------- Reglas por patrón línea a línea ----------
for (const f of files) {
  const r = rel(f);
  const text = read(f);
  const lines = text.split("\n");
  const isCode = /\.(m?js|jsx|cjs)$/.test(r);
  lines.forEach((ln, i) => {
    const n = i + 1;
    if (isCode && /JWT_SECRET\s*=\s*process\.env\.JWT_SECRET\s*\|\|\s*["'`][^"'`]+["'`]/.test(ln)) add(RULES.S01, r, n, ln);
    if (isCode && /postgres:\/\/[^:\s]+:[^@\s]+@/.test(ln)) add(RULES.S01, r, n, ln.replace(/:[^:@\s]+@/, ":****@"), { nota: "Cadena de conexión con contraseña embebida" });
    if (r.endsWith("README.md") && /JWT_SECRET:\s*`[0-9a-f]{16,}`/.test(ln)) add(RULES.S02, r, n, ln.replace(/[0-9a-f]{12,}/, (m) => m.slice(0, 6) + "…"));
    if (isCode && /\.contrasena\s*!==?\s*password/.test(ln)) add(RULES.S03, r, n, ln);
    if (isCode && /INSERT INTO usuarios \(nombre_usuario, contrasena/.test(ln)) add(RULES.S03, r, n, ln, { nota: "La contraseña se inserta sin derivación (bcrypt/argon2)" });
    if (isCode && /glosa:\s*err\.message/.test(ln)) add(RULES.S06, r, n, ln);
    if (isCode && /app\.use\(cors\(\)\)/.test(ln)) add(RULES.S07, r, n, ln);
    if (isCode && /delayMiddleware\(\d+\)/.test(ln) && /router\.(get|post|put|delete)/.test(ln)) add(RULES.S10, r, n, ln);
    if (isCode && /RUT:\s*\$\{rut\}/.test(ln)) add(RULES.S12, r, n, ln);
    if (isCode && /localStorage\.setItem\(["']token["']/.test(ln)) add(RULES.S13, r, n, ln);
    if (isCode && /Content-Disposition/.test(ln)) {
      const ctx = lines.slice(i, i + 3).join(" ");
      if (/filename="\$\{[^}]+\}"/.test(ctx)) add(RULES.S14, r, n, ctx);
    }
    if (isCode && /\.min\(6,\s*["']La contraseña/.test(ln)) add(RULES.S16, r, n, ln);
    if (isCode && /swaggerUi\.setup|morgan\(["']dev["']\)/.test(ln)) add(RULES.S21, r, n, ln);
    if (isCode && /allowedMimes\.includes\(file\.mimetype\)/.test(ln)) add(RULES.S19, r, n, ln);
    if (isCode && /\.matches\(\/\^\(\[0-9\]\{1,2\}/.test(ln)) add(RULES.S22, r, n, ln.slice(0, 120));
    if (r.endsWith(".sql") && /INSERT INTO public\.usuarios .*VALUES \(\d+, '([^']+)', '\1'/.test(ln)) add(RULES.S15, r, n, ln.replace(/'([^']+)', '\1'/, "'$1', '****'"));
  });
}

// ---------- S02: archivos .env versionados ----------
try {
  const tracked = execSync("git ls-files", { cwd: ROOT }).toString().split("\n").filter(Boolean);
  for (const t of tracked) if (/(^|\/)\.env(\.|$)/.test(t)) add(RULES.S02, t, 1, "Archivo versionado en Git: " + t);
  // S18: uploads no versionado pero copiado en Dockerfile
  const df = src("BACKEND/Dockerfile");
  const m = df.match(/^COPY\s+uploads\/.*$/m);
  if (m && !tracked.some((t) => t.startsWith("BACKEND/uploads/"))) add(RULES.S18, "BACKEND/Dockerfile", lineOf(df, m.index), m[0] + "  ← BACKEND/uploads/ no existe en un clon limpio");
} catch {
  findings.push({ rule: "INFO", titulo: "git no disponible: S02/S18 no evaluadas", severidad: "Info" });
}

// ---------- S17: imagen base EOL / root ----------
{
  const df = src("BACKEND/Dockerfile");
  const m = df.match(/^FROM\s+node:(\d+)[^\s]*/m);
  if (m && Number(m[1]) < 20) add(RULES.S17, "BACKEND/Dockerfile", lineOf(df, m.index), m[0] + " (Node.js 18 sin soporte desde 30-04-2025)");
  if (df && !/^USER\s+/m.test(df)) add(RULES.S17, "BACKEND/Dockerfile", 1, "No se define USER no privilegiado: el proceso corre como root");
  const ex = df.match(/^EXPOSE\s+(\d+)/m);
  if (ex && ex[1] !== "4000") add({ ...RULES.S21, id: "S21", titulo: "EXPOSE del Dockerfile no coincide con el puerto real (PORT=4000)" }, "BACKEND/Dockerfile", lineOf(df, ex.index), ex[0]);
}

// ---------- S08 / S09: controles ausentes a nivel de aplicación ----------
{
  const app = src("BACKEND/src/app.js");
  const pkg = src("BACKEND/package.json");
  if (app && !/helmet/.test(app + pkg)) add(RULES.S08, "BACKEND/src/app.js", 1, "No se registra helmet() ni cabeceras CSP/X-Frame-Options/X-Content-Type-Options");
  if (app && !/rate-?limit|express-slow-down/i.test(app + pkg)) add(RULES.S09, "BACKEND/src/routes/auth.js", 10, "router.post(\"/login\", …) sin express-rate-limit ni bloqueo por intentos");
  const ng = src("FRONTEND/nginx.conf");
  if (ng && !/add_header\s+(Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)/.test(ng)) add(RULES.S08, "FRONTEND/nginx.conf", 1, "nginx no define CSP, X-Frame-Options ni X-Content-Type-Options");
  if (app && /express\.static\(uploadsDir\)/.test(app)) add({ ...RULES.S04, severidad: "Media", titulo: "Directorio de documentos servido estáticamente sin autenticación" }, "BACKEND/src/app.js", lineOf(app, app.indexOf("express.static(uploadsDir)")), "app.use(\"/files/documentos\", express.static(uploadsDir))");
}

// ---------- S11: middleware de validación ----------
{
  const v = src("BACKEND/src/middleware/validate.js");
  if (/stripUnknown:\s*true/.test(v) && !/req\[source\]\s*=/.test(v)) add(RULES.S11, "BACKEND/src/middleware/validate.js", lineOf(v, v.indexOf("stripUnknown")), "await schema.validate(data, { abortEarly: false, stripUnknown: true }); // resultado descartado");
}

// ---------- S23: consentimiento en registro ----------
{
  const reg = src("FRONTEND/src/pages/auth/Register.jsx");
  if (reg && !/consent|acept|politica-privacidad|Checkbox/i.test(reg)) add(RULES.S23, "FRONTEND/src/pages/auth/Register.jsx", 1, "El formulario de registro no solicita aceptación de Política de Privacidad ni consentimiento expreso");
  const pp = src("FRONTEND/src/pages/informacion/PoliticaPrivacidad.jsx");
  if (pp && !/19\.628|21\.719|20\.584/.test(pp)) add({ ...RULES.S23, severidad: "Media", titulo: "Política de privacidad no identifica marco legal chileno aplicable" }, "FRONTEND/src/pages/informacion/PoliticaPrivacidad.jsx", 1, "Sin referencia a Ley 19.628 / 21.719 / 20.584 ni a responsable del tratamiento");
}

// ---------- S04/S05: análisis de bloques de rutas Express ----------
const routeInventory = [];
const routeFiles = files.filter((f) => /BACKEND\/src\/routes\/.*\.js$/.test(rel(f)));
for (const f of routeFiles) {
  const r = rel(f);
  const text = read(f);
  const appSrc = src("BACKEND/src/app.js");
  const varName = (appSrc.match(new RegExp(`const\\s+(\\w+)\\s*=\\s*require\\(["']\\./routes/${path.basename(r, ".js")}["']\\)`)) || [])[1];
  const mount = (varName && (appSrc.match(new RegExp(`app\\.use\\(["']([^"']+)["'],\\s*${varName}\\)`)) || [])[1]) || "/" + path.basename(r, ".js");
  const re = /router\.(get|post|put|delete)\(\s*["'`]([^"'`]+)["'`]/g;
  const starts = [];
  let m;
  while ((m = re.exec(text))) starts.push({ method: m[1].toUpperCase(), sub: m[2], idx: m.index });
  starts.forEach((s, k) => {
    let block = text.slice(s.idx, k + 1 < starts.length ? starts[k + 1].idx : text.length);
    const helper = block.search(/\n(async\s+)?function\s+\w+\s*\(|\nmodule\.exports/);
    if (helper > 0) block = block.slice(0, helper);
    const authIdx = block.search(/getUserFromAuthHeader\(req\)|requireRole\(req/);
    const firstMutation = block.search(/pool\.query\(\s*["'`](DELETE|UPDATE|INSERT)/);
    const hasAuth = authIdx >= 0;
    const enforces = /status\(401\)|authCheck\.error/.test(block);
    // complejidad ciclomática aproximada (McCabe): 1 + puntos de decisión
    const decisions = (block.match(/\bif\s*\(|\belse if\b|\?[^.:]|&&|\|\||\bcase\b|\bcatch\b|\bfor\s*\(|\bwhile\s*\(/g) || []).length;
    const fullPath = (mount + (s.sub === "/" ? "" : s.sub)).replace(/\/+/g, "/");
    const line = lineOf(text, s.idx);
    const isPublic = /^\/autenticacion\/(login|registro)$/.test(fullPath) || /^\/tipo-examen/.test(fullPath);
    const item = { publico_por_diseno: isPublic, metodo: s.method, ruta: fullPath, archivo: r, linea: line, autenticacion: hasAuth && enforces ? "Sí" : hasAuth ? "Parcial" : "No", cc_aprox: 1 + decisions };
    routeInventory.push(item);
    const isPublicByDesign = /^\/autenticacion\/(login|registro)$/.test(fullPath) || /^\/tipo-examen/.test(fullPath);
    if (!hasAuth && !isPublicByDesign) add(RULES.S04, r, line, `${s.method} ${fullPath} — no invoca getUserFromAuthHeader/requireRole`);
    else if (hasAuth && !enforces && !isPublicByDesign) add(RULES.S04, r, line, `${s.method} ${fullPath} — decodifica el token pero no rechaza solicitudes anónimas`);
    if (hasAuth && firstMutation >= 0 && firstMutation < authIdx) add(RULES.S05, r, line, `${s.method} ${fullPath} — ejecuta ${block.slice(firstMutation, firstMutation + 60).replace(/\s+/g, " ")}… antes de leer el token`);
  });
}
// duplicación de lógica de autenticación
{
  const dups = routeFiles.filter((f) => /function getUserFromAuthHeader/.test(read(f))).map(rel);
  if (dups.length > 1) add(RULES.S20, dups.join(", "), 0, `getUserFromAuthHeader() definida ${dups.length} veces; requireRole() ${routeFiles.filter((f) => /function requireRole/.test(read(f))).length} veces`);
}

// ---------- Métricas ----------
const codeFiles = files.filter((f) => /\.(m?js|jsx)$/.test(f) && !/\.config\./.test(f));
const loc = (dir) => codeFiles.filter((f) => rel(f).startsWith(dir)).reduce((a, f) => a + read(f).split("\n").filter((l) => l.trim() && !/^\s*(\/\/|\*|\/\*)/.test(l)).length, 0);
const metrics = {
  fecha: new Date().toISOString(),
  archivos_analizados: files.length,
  loc_backend: loc("BACKEND/src"),
  loc_frontend: loc("FRONTEND/src"),
  endpoints: routeInventory.length,
  endpoints_publicos_por_diseno: routeInventory.filter((x) => x.publico_por_diseno).length,
  endpoints_sin_control_efectivo: routeInventory.filter((x) => !x.publico_por_diseno && x.autenticacion !== "Sí").length,
  cc_max: Math.max(...routeInventory.map((x) => x.cc_aprox)),
  cc_promedio: +(routeInventory.reduce((a, x) => a + x.cc_aprox, 0) / routeInventory.length).toFixed(1),
};
const sevOrder = { "Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Info": 4 };
findings.sort((a, b) => (sevOrder[a.severidad] - sevOrder[b.severidad]) || a.rule.localeCompare(b.rule) || String(a.archivo).localeCompare(String(b.archivo)) || a.linea - b.linea);
const resumen = Object.fromEntries(Object.keys(sevOrder).map((s) => [s, findings.filter((f) => f.severidad === s).length]));
const porRegla = Object.values(findings.reduce((acc, f) => { (acc[f.rule] ||= { regla: f.rule, titulo: RULES[f.rule]?.titulo || f.titulo, severidad: f.severidad, ocurrencias: 0 }).ocurrencias++; return acc; }, {}));

const out = { herramienta: "sast-scan.mjs (Cuidarte+ QA)", metrics, resumen, porRegla, routeInventory, findings };
fs.writeFileSync(path.join(OUT_DIR, "sast-resultados.json"), JSON.stringify(out, null, 2));

let md = `# Resultados SAST — Cuidarte+\n\nFecha: ${metrics.fecha}\n\n`;
md += `| Métrica | Valor |\n|---|---|\n` + Object.entries(metrics).filter(([k]) => k !== "fecha").map(([k, v]) => `| ${k} | ${v} |`).join("\n") + "\n\n";
md += `## Resumen por severidad\n\n| Severidad | Hallazgos |\n|---|---|\n` + Object.entries(resumen).map(([k, v]) => `| ${k} | ${v} |`).join("\n") + "\n\n";
md += `## Inventario de endpoints\n\n| Método | Ruta | Autenticación | CC aprox. | Archivo:línea |\n|---|---|---|---|---|\n` + routeInventory.map((x) => `| ${x.metodo} | ${x.ruta} | ${x.autenticacion} | ${x.cc_aprox} | ${x.archivo}:${x.linea} |`).join("\n") + "\n\n";
md += `## Hallazgos\n\n| Regla | Severidad | CWE | OWASP | Archivo:línea | Evidencia |\n|---|---|---|---|---|---|\n` + findings.map((f) => `| ${f.rule} | ${f.severidad} | ${f.cwe || ""} | ${f.owasp || ""} | ${f.archivo}:${f.linea ?? ""} | \`${String(f.evidencia || f.titulo).replace(/\|/g, "\\|").replace(/`/g, "'")}\` |`).join("\n") + "\n";
fs.writeFileSync(path.join(OUT_DIR, "sast-resultados.md"), md);

console.log("\n=== SAST Cuidarte+ ===");
console.table(metrics);
console.table(resumen);
console.table(porRegla);
console.log(`Detalle: QA/reports/sast-resultados.md (${findings.length} hallazgos)`);

-- Cuidarte+ · Evidencias a nivel de base de datos (solo lectura)
-- Ejecutar con Docker:
--   docker exec -i cuidarteplus-postgres-ev psql -U postgres -d cuidarteplus < QA/sql/evidencia-bd.sql
-- Ninguna consulta modifica datos. Las contraseñas se enmascaran en la salida.

\echo '== E1. Almacenamiento de contraseñas (CP-05 / RNF-02) =='
SELECT u.id,
       u.nombre_usuario,
       left(u.contrasena, 2) || repeat('*', greatest(length(u.contrasena) - 2, 0)) AS contrasena_enmascarada,
       length(u.contrasena) AS largo,
       CASE WHEN u.contrasena ~ '^\$(2[aby]|argon2(id|i|d))\$' THEN 'HASH' ELSE 'TEXTO PLANO' END AS formato,
       (u.contrasena = u.nombre_usuario) AS igual_a_usuario
FROM usuarios u ORDER BY u.id;

\echo '== E2. Resumen de formato de contraseñas =='
SELECT count(*) AS total_usuarios,
       count(*) FILTER (WHERE contrasena !~ '^\$(2[aby]|argon2(id|i|d))\$') AS en_texto_plano,
       count(*) FILTER (WHERE contrasena = nombre_usuario) AS contrasena_igual_usuario
FROM usuarios;

\echo '== E3. Datos sensibles de salud almacenados sin cifrado a nivel de columna (RL-01) =='
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'pacientes'
  AND column_name IN ('rut','grupo_sanguineo','alergias','enfermedades_cronicas','discapacidades','observaciones_medicas_generales')
ORDER BY ordinal_position;

SELECT count(*) AS pacientes,
       count(*) FILTER (WHERE enfermedades_cronicas IS NOT NULL AND enfermedades_cronicas <> 'Ninguna') AS con_enfermedad_cronica_legible,
       count(*) FILTER (WHERE alergias IS NOT NULL AND alergias <> 'Ninguna') AS con_alergias_legibles
FROM pacientes;

\echo '== E4. Ausencia de campos de consentimiento / base de licitud (RL-01) =='
SELECT count(*) AS columnas_consentimiento
FROM information_schema.columns
WHERE table_schema = 'public' AND (column_name ILIKE '%consent%' OR column_name ILIKE '%acepta%' OR column_name ILIKE '%licitud%');

\echo '== E5. Integridad de la auditoría: sin protección contra modificación (RL-03) =='
SELECT count(*) AS triggers_en_auditoria
FROM information_schema.triggers WHERE event_object_table = 'auditoria';
SELECT grantee, privilege_type FROM information_schema.role_table_grants
WHERE table_name = 'auditoria' ORDER BY grantee, privilege_type;

\echo '== E6. Distribución de acciones auditadas (¿se registran lecturas de fichas?) =='
SELECT split_part(accion, ':', 1) AS tipo_accion, count(*) AS eventos
FROM auditoria GROUP BY 1 ORDER BY 2 DESC;

\echo '== E7. RUT de pacientes que no cumplen dígito verificador módulo 11 (RN-01) =='
WITH r AS (
  SELECT id, rut, split_part(rut, '-', 1) AS cuerpo, upper(split_part(rut, '-', 2)) AS dv FROM pacientes
), calc AS (
  SELECT id, rut, dv,
         11 - (SELECT sum((substr(reverse(cuerpo), i, 1))::int * (2 + ((i - 1) % 6)))
               FROM generate_series(1, length(cuerpo)) AS i) % 11 AS d
  FROM r WHERE cuerpo ~ '^[0-9]+$'
)
SELECT id, rut,
       CASE d WHEN 11 THEN '0' WHEN 10 THEN 'K' ELSE d::text END AS dv_correcto,
       dv AS dv_registrado
FROM calc
WHERE dv <> CASE d WHEN 11 THEN '0' WHEN 10 THEN 'K' ELSE d::text END
ORDER BY id;

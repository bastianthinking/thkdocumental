-- =====================================================================
-- Control Documental · Migración 006 · Visor del historial de thinking-knowledge
--
--  · Tabla materiales: un registro por manual o QRG de la bóveda, con su
--    historial de versiones. La llena tools/historial.py --subir (en el
--    repo thinking-knowledge) con la clave service_role; la app solo lee.
--  · Acceso sin roles: puede leer cualquier persona con sesión iniciada y
--    correo @thinking.cl verificado (entra con un link a su correo).
--
-- No borra las tablas del flujo de aprobación anterior: eso va en la 007,
-- después de revisar si tienen datos.
-- Ejecutar en Supabase → SQL Editor (idempotente).
-- =====================================================================


-- ─── 1. TABLA MATERIALES ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.materiales (
    id            text PRIMARY KEY,          -- código del manual o id interno de la QRG
    codigo        text NOT NULL DEFAULT '',  -- MN-ESC-0XX (vacío en las QRG)
    nombre        text NOT NULL,
    tipo          text NOT NULL,             -- Manual | QRG
    marca         text NOT NULL DEFAULT '',  -- BHP Verde | BHP Naranjo | Contract Support | Thinking
    version       text NOT NULL DEFAULT '—',
    fecha_version date,
    publicacion   text NOT NULL DEFAULT '',  -- Publicado | Sin publicar
    en_revision   boolean NOT NULL DEFAULT false,  -- hay una versión nueva en 03. En Revisión
    al_dia        text NOT NULL DEFAULT '',  -- Al día | Cambios pendientes | Por revisar
    descripcion   text NOT NULL DEFAULT '',
    archivo       text NOT NULL DEFAULT '',  -- ruta relativa en Version Editables
    versiones     jsonb NOT NULL DEFAULT '[]'::jsonb,  -- [{version, fecha, cambios}], la más nueva primero
    sincronizado  date
);


-- ─── 2. ¿ES UNA CUENTA @thinking.cl VERIFICADA? ──────────────────────
-- SECURITY DEFINER para leer auth.users; exige el correo confirmado, así
-- nadie puede registrarse con un @thinking.cl ajeno y leer los datos.
CREATE OR REPLACE FUNCTION public.es_thinking()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, auth
AS $$
    SELECT EXISTS (
        SELECT 1 FROM auth.users u
        WHERE u.id = auth.uid()
          AND lower(u.email) LIKE '%@thinking.cl'
          AND u.email_confirmed_at IS NOT NULL
    );
$$;

REVOKE ALL ON FUNCTION public.es_thinking() FROM public, anon;
GRANT EXECUTE ON FUNCTION public.es_thinking() TO authenticated;


-- ─── 3. LECTURA SOLO PARA @thinking.cl ───────────────────────────────
ALTER TABLE public.materiales ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS materiales_select ON public.materiales;
CREATE POLICY materiales_select ON public.materiales FOR SELECT TO authenticated
USING (public.es_thinking());
-- Sin políticas de escritura: solo la clave service_role (el script) modifica la tabla.

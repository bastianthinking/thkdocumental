-- =====================================================================
-- Control Documental · Migración 002
-- Catálogos editables por el owner: Tipo, Alcance y Repositorio
--
-- Ejecutar UNA VEZ en Supabase → SQL Editor (idempotente).
-- =====================================================================

CREATE TABLE IF NOT EXISTS public.catalog_options (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category    text NOT NULL CHECK (category IN ('tipo', 'alcance', 'repositorio')),
    value       text NOT NULL CHECK (length(trim(value)) > 0),
    sort_order  int  NOT NULL DEFAULT 0,
    active      boolean NOT NULL DEFAULT true,   -- inactivo: no se ofrece en documentos nuevos
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (category, value)
);

-- Valores que hoy estaban fijos en el código
INSERT INTO public.catalog_options (category, value, sort_order) VALUES
    ('tipo', 'Manual', 1), ('tipo', 'Procedimiento', 2), ('tipo', 'Capacitación', 3),
    ('tipo', 'QRG', 4), ('tipo', 'Video', 5),
    ('alcance', 'Contratista', 1), ('alcance', 'Empleados', 2),
    ('alcance', 'Transversal', 3), ('alcance', 'Thinking', 4),
    ('repositorio', 'Contract Support', 1), ('repositorio', 'PMG Center', 2),
    ('repositorio', 'Reportabilidad HSS', 3), ('repositorio', 'Rutinas HSS', 4),
    ('repositorio', 'Contract Data Center', 5)
ON CONFLICT (category, value) DO NOTHING;

-- Valores usados en documentos existentes que no estén en la lista anterior
INSERT INTO public.catalog_options (category, value, sort_order)
SELECT DISTINCT c.category, c.value, 99
FROM (
    SELECT 'tipo' AS category, tipo AS value FROM public.documents
    UNION SELECT 'alcance', alcance FROM public.documents
    UNION SELECT 'repositorio', repositorio FROM public.documents
) c
WHERE nullif(trim(c.value), '') IS NOT NULL
ON CONFLICT (category, value) DO NOTHING;

-- RLS: cualquier usuario con rol lee; solo owner administra
ALTER TABLE public.catalog_options ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS catalog_select ON public.catalog_options;
DROP POLICY IF EXISTS catalog_insert ON public.catalog_options;
DROP POLICY IF EXISTS catalog_update ON public.catalog_options;
DROP POLICY IF EXISTS catalog_delete ON public.catalog_options;

CREATE POLICY catalog_select ON public.catalog_options FOR SELECT TO authenticated
USING (public.app_user_role() IS NOT NULL);
CREATE POLICY catalog_insert ON public.catalog_options FOR INSERT TO authenticated
WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY catalog_update ON public.catalog_options FOR UPDATE TO authenticated
USING (public.app_user_role() = 'owner') WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY catalog_delete ON public.catalog_options FOR DELETE TO authenticated
USING (public.app_user_role() = 'owner');

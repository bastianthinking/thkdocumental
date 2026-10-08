-- =====================================================================
-- Control Documental · Migración 005 · Ajustes ISO 9001:2015 (cláusula 7.5)
--
--  · Historial de versiones publicadas (document_versions) con motivo del cambio
--  · Registros protegidos: solo se eliminan borradores sin historial
--  · Código de documento único
--  · Revisión periódica registrada (reemplaza "Renovar mantención")
--  · Archivar / Obsoleto con comentario obligatorio (retiro del repositorio)
--  · Aprobación por excepción del owner, con justificación obligatoria
--  · Revisor puede ser el mismo elaborador; aprobador sigue siendo distinto
--  · Publicar exige link al PDF y número de versión no publicado antes
--
-- Ejecutar DESPUÉS de 004, en Supabase → SQL Editor (idempotente).
-- =====================================================================


-- ─── 1. COLUMNAS NUEVAS ──────────────────────────────────────────────
ALTER TABLE public.documents
    ADD COLUMN IF NOT EXISTS motivo_cambio    text,   -- motivo de la versión en curso
    ADD COLUMN IF NOT EXISTS ultima_revision  date;   -- última revisión periódica


-- ─── 2. HISTORIAL DE VERSIONES PUBLICADAS ────────────────────────────
CREATE TABLE IF NOT EXISTS public.document_versions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id      uuid NOT NULL REFERENCES public.documents(id) ON DELETE RESTRICT,
    version          text NOT NULL,
    link             text,                 -- PDF de esa versión
    publicado        date NOT NULL,
    aprobado_por     text,                 -- correo de quien aprobó
    motivo_cambio    text,
    snapshot         jsonb NOT NULL,       -- copia completa del documento al publicar
    published_by     uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    published_email  text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, version)
);

CREATE INDEX IF NOT EXISTS idx_document_versions_doc
    ON public.document_versions (document_id, created_at DESC);

ALTER TABLE public.document_versions ENABLE ROW LEVEL SECURITY;

-- Versiones anteriores solo para owner y revisor/aprobador:
-- los viewers ven únicamente la versión vigente (evita uso de obsoletos).
DROP POLICY IF EXISTS versions_select ON public.document_versions;
CREATE POLICY versions_select ON public.document_versions FOR SELECT TO authenticated
USING (public.app_user_role() IN ('owner', 'aprobador')
       AND EXISTS (SELECT 1 FROM public.documents d WHERE d.id = document_id));

-- Los documentos ya publicados antes de esta migración quedan como su primera versión registrada
INSERT INTO public.document_versions
    (document_id, version, link, publicado, aprobado_por, motivo_cambio, snapshot, published_email)
SELECT d.id,
       coalesce(nullif(trim(d.version), ''), 's/v'),
       d.data ->> 'link',
       coalesce(d.publicado, current_date),
       nullif(d.aprobador, ''),
       'Registro inicial (documento vigente antes del historial de versiones)',
       to_jsonb(d),
       'migración 005'
FROM public.documents d
WHERE d.estado = 'Publicado'
ON CONFLICT (document_id, version) DO NOTHING;


-- ─── 3. REGISTROS PROTEGIDOS ─────────────────────────────────────────
-- El historial de aprobaciones ya no se borra en cascada
ALTER TABLE public.document_approvals DROP CONSTRAINT IF EXISTS document_approvals_document_id_fkey;
ALTER TABLE public.document_approvals
    ADD CONSTRAINT document_approvals_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE RESTRICT;

-- Solo se eliminan borradores que nunca entraron al flujo; lo demás se archiva
DROP POLICY IF EXISTS documents_delete ON public.documents;
CREATE POLICY documents_delete ON public.documents FOR DELETE TO authenticated
USING (
    public.app_user_role() = 'owner'
    AND estado = 'Borrador'
    AND NOT EXISTS (SELECT 1 FROM public.document_approvals a WHERE a.document_id = documents.id)
    AND NOT EXISTS (SELECT 1 FROM public.document_versions  v WHERE v.document_id = documents.id)
);


-- ─── 4. CÓDIGO ÚNICO ─────────────────────────────────────────────────
-- Si hay códigos duplicados no se crea el índice: se listan para corregirlos y volver a correr.
DO $$
DECLARE v_dup text;
BEGIN
    SELECT string_agg(codigo, ', ') INTO v_dup
    FROM (
        SELECT lower(trim(codigo)) AS codigo
        FROM public.documents
        WHERE nullif(trim(codigo), '') IS NOT NULL
        GROUP BY lower(trim(codigo))
        HAVING count(*) > 1
    ) d;

    IF v_dup IS NULL THEN
        CREATE UNIQUE INDEX IF NOT EXISTS ux_documents_codigo ON public.documents (lower(trim(codigo)));
    ELSE
        RAISE NOTICE 'Códigos duplicados (corrígelos y vuelve a correr este script): %', v_dup;
    END IF;
END $$;


-- ─── 5. SEGREGACIÓN: solo aprobador ≠ elaborador ─────────────────────
CREATE OR REPLACE FUNCTION public.documents_guard_segregacion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.elaborador_id IS NOT NULL AND NEW.aprobador_id = NEW.elaborador_id THEN
        RAISE EXCEPTION 'El aprobador no puede ser el mismo elaborador (si es necesario, un owner puede aprobar por excepción)';
    END IF;
    RETURN NEW;
END $$;


-- Integridad: en un documento publicado no se cambian el PDF ni la versión
-- (eso solo ocurre vía "Nueva versión", que pasa de nuevo por aprobación)
CREATE OR REPLACE FUNCTION public.documents_guard_publicado()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.estado = 'Publicado'
       AND coalesce(current_setting('app.doc_transition', true), 'off') <> 'on'
       AND (NEW.version IS DISTINCT FROM OLD.version
            OR (NEW.data ->> 'link') IS DISTINCT FROM (OLD.data ->> 'link')) THEN
        RAISE EXCEPTION 'Documento publicado: para cambiar el PDF o la versión crea una "Nueva versión"';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_documents_guard_publicado ON public.documents;
CREATE TRIGGER trg_documents_guard_publicado
    BEFORE UPDATE ON public.documents
    FOR EACH ROW EXECUTE FUNCTION public.documents_guard_publicado();


-- ─── 6. FLUJO ────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.doc_transition(
    p_doc_id  uuid,
    p_action  text,
    p_comment text DEFAULT NULL,
    p_version text DEFAULT NULL
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    v_doc       public.documents%ROWTYPE;
    v_role      text := public.app_user_role();
    v_uid       uuid := auth.uid();
    v_email     text := auth.jwt() ->> 'email';
    v_to        text;
    v_comment   text := nullif(trim(coalesce(p_comment, '')), '');
    v_aprobador text;
BEGIN
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'Sin acceso a la aplicación';
    END IF;

    SELECT * INTO v_doc FROM public.documents WHERE id = p_doc_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Documento no encontrado';
    END IF;

    CASE p_action
        WHEN 'enviar_revision' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede enviar al flujo'; END IF;
            IF v_doc.estado NOT IN ('Borrador', 'Observado') THEN
                RAISE EXCEPTION 'Solo se envían documentos en Borrador u Observado';
            END IF;
            IF v_doc.aprobador_id IS NULL THEN RAISE EXCEPTION 'Asigna un aprobador antes de enviar'; END IF;
            v_to := CASE WHEN v_doc.revisor_id IS NULL THEN 'En aprobación' ELSE 'En revisión' END;

        WHEN 'aprobar_revision' THEN
            IF v_doc.estado <> 'En revisión' THEN RAISE EXCEPTION 'El documento no está en revisión'; END IF;
            IF v_doc.revisor_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el revisor asignado'; END IF;
            v_to := 'En aprobación';

        WHEN 'observar' THEN
            IF NOT (
                (v_doc.estado = 'En revisión'   AND v_doc.revisor_id   = v_uid) OR
                (v_doc.estado = 'En aprobación' AND v_doc.aprobador_id = v_uid) OR
                (v_doc.estado IN ('En revisión', 'En aprobación') AND v_role = 'owner')
            ) THEN
                RAISE EXCEPTION 'No tienes este documento pendiente';
            END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Las observaciones son obligatorias'; END IF;
            v_to := 'Observado';

        WHEN 'aprobar' THEN
            IF v_doc.estado <> 'En aprobación' THEN RAISE EXCEPTION 'El documento no está en aprobación'; END IF;
            IF v_doc.aprobador_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el aprobador asignado'; END IF;
            IF v_doc.elaborador_id = v_uid THEN
                RAISE EXCEPTION 'No puedes aprobar un documento que elaboraste (usa aprobación por excepción)';
            END IF;
            v_to := 'Aprobado';

        -- Owner aprueba saltándose el flujo; queda registrado con justificación
        WHEN 'aprobar_owner' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede aprobar por excepción'; END IF;
            IF v_doc.estado NOT IN ('Borrador', 'Observado', 'En revisión', 'En aprobación') THEN
                RAISE EXCEPTION 'El documento no está pendiente de aprobación';
            END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'La justificación de la excepción es obligatoria'; END IF;
            v_to := 'Aprobado';

        WHEN 'publicar' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede publicar'; END IF;
            IF v_doc.estado <> 'Aprobado' THEN RAISE EXCEPTION 'Solo se publican documentos aprobados'; END IF;
            v_to := 'Publicado';

        WHEN 'carga_historica' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede hacer carga histórica'; END IF;
            IF v_doc.estado <> 'Borrador' THEN RAISE EXCEPTION 'La carga histórica parte desde Borrador'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica quién y cuándo aprobó el documento'; END IF;
            v_to := 'Publicado';

        WHEN 'nueva_version' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede crear una nueva versión'; END IF;
            IF v_doc.estado NOT IN ('Publicado', 'Aprobado') THEN
                RAISE EXCEPTION 'Solo se versionan documentos aprobados o publicados';
            END IF;
            IF nullif(trim(coalesce(p_version, '')), '') IS NULL THEN RAISE EXCEPTION 'Indica la nueva versión'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica el motivo del cambio'; END IF;
            IF EXISTS (SELECT 1 FROM public.document_versions
                       WHERE document_id = p_doc_id AND version = trim(p_version)) THEN
                RAISE EXCEPTION 'La versión % ya fue publicada; usa otro número', trim(p_version);
            END IF;
            v_to := 'Borrador';

        -- Revisión periódica: el documento sigue vigente sin cambios
        WHEN 'revision_periodica' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner registra revisiones periódicas'; END IF;
            IF v_doc.estado <> 'Publicado' THEN RAISE EXCEPTION 'Solo aplica a documentos publicados'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica la conclusión de la revisión'; END IF;
            v_to := 'Publicado';

        WHEN 'archivar' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede archivar'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica el motivo y confirma el retiro del repositorio'; END IF;
            v_to := 'Archivado';

        WHEN 'obsoleto' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede marcar obsoleto'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica el motivo y confirma el retiro del repositorio'; END IF;
            v_to := 'Obsoleto';

        ELSE
            RAISE EXCEPTION 'Acción no válida: %', p_action;
    END CASE;

    -- Publicar exige el PDF y un número de versión no usado antes
    IF v_to = 'Publicado' AND p_action <> 'revision_periodica' THEN
        IF nullif(trim(coalesce(v_doc.data ->> 'link', '')), '') IS NULL THEN
            RAISE EXCEPTION 'Registra el link al PDF de la versión aprobada antes de publicar';
        END IF;
        IF nullif(trim(coalesce(v_doc.version, '')), '') IS NULL THEN
            RAISE EXCEPTION 'Indica el número de versión antes de publicar';
        END IF;
        IF EXISTS (SELECT 1 FROM public.document_versions
                   WHERE document_id = p_doc_id AND version = trim(v_doc.version)) THEN
            RAISE EXCEPTION 'La versión % ya fue publicada; crea una nueva versión', trim(v_doc.version);
        END IF;
    END IF;

    PERFORM set_config('app.doc_transition', 'on', true);

    UPDATE public.documents
    SET estado          = v_to,
        version         = CASE WHEN p_action = 'nueva_version' THEN trim(p_version) ELSE version END,
        motivo_cambio   = CASE WHEN p_action = 'nueva_version' THEN v_comment ELSE motivo_cambio END,
        publicado       = CASE WHEN v_to = 'Publicado' AND p_action <> 'revision_periodica'
                               THEN current_date ELSE publicado END,
        ultima_revision = CASE WHEN p_action = 'revision_periodica' THEN current_date ELSE ultima_revision END,
        updated_at      = now()
    WHERE id = p_doc_id;

    PERFORM set_config('app.doc_transition', 'off', true);

    INSERT INTO public.document_approvals
        (document_id, version, action, from_estado, to_estado, user_id, user_email, comment)
    VALUES
        (p_doc_id,
         CASE WHEN p_action = 'nueva_version' THEN trim(p_version) ELSE v_doc.version END,
         p_action, v_doc.estado, v_to, v_uid, v_email, v_comment);

    -- Cada publicación queda como versión registrada (con copia del documento)
    IF v_to = 'Publicado' AND p_action <> 'revision_periodica' THEN
        SELECT user_email INTO v_aprobador
        FROM public.document_approvals
        WHERE document_id = p_doc_id AND action IN ('aprobar', 'aprobar_owner', 'carga_historica')
        ORDER BY created_at DESC
        LIMIT 1;

        INSERT INTO public.document_versions
            (document_id, version, link, publicado, aprobado_por, motivo_cambio,
             snapshot, published_by, published_email)
        SELECT d.id, trim(d.version), d.data ->> 'link', current_date, v_aprobador,
               coalesce(d.motivo_cambio, 'Versión inicial'), to_jsonb(d), v_uid, v_email
        FROM public.documents d
        WHERE d.id = p_doc_id;
    END IF;

    INSERT INTO public.audit_log (document_id, action, user_id, user_email, changes)
    VALUES (p_doc_id, p_action, v_uid, v_email,
            jsonb_build_object('name', v_doc.name, 'estado', v_to, 'comentario', v_comment));

    RETURN v_to;
END $$;

REVOKE ALL ON FUNCTION public.doc_transition(uuid, text, text, text) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.doc_transition(uuid, text, text, text) TO authenticated;

-- =====================================================================
-- Control Documental · Migración 004
-- Área solicitante (con aprobador por defecto), elaborador como usuario,
-- revisor opcional y segregación de funciones (nadie aprueba lo que elaboró).
--
-- Ejecutar UNA VEZ en Supabase → SQL Editor (idempotente).
-- Requiere haber corrido 001, 002 y 003.
-- =====================================================================


-- ─── 1. CATÁLOGO DE ÁREAS ────────────────────────────────────────────
ALTER TABLE public.catalog_options DROP CONSTRAINT IF EXISTS catalog_options_category_check;
ALTER TABLE public.catalog_options
    ADD CONSTRAINT catalog_options_category_check
    CHECK (category IN ('tipo', 'alcance', 'repositorio', 'area'));

-- Aprobador sugerido al elegir el área en un documento (configurable en la app)
ALTER TABLE public.catalog_options
    ADD COLUMN IF NOT EXISTS default_aprobador_id uuid REFERENCES auth.users(id) ON DELETE SET NULL;

INSERT INTO public.catalog_options (category, value, sort_order) VALUES
    ('area', 'Data Ops', 1),
    ('area', 'Soporte', 2),
    ('area', 'Extract', 3),
    ('area', 'Proyectos', 4),
    ('area', 'Comunicaciones y Administración', 5)
ON CONFLICT (category, value) DO NOTHING;


-- ─── 2. DOCUMENTS: área y elaborador como usuario ────────────────────
ALTER TABLE public.documents
    ADD COLUMN IF NOT EXISTS area           text,
    ADD COLUMN IF NOT EXISTS elaborador_id  uuid REFERENCES auth.users(id) ON DELETE SET NULL;


-- ─── 3. SEGREGACIÓN: revisor y aprobador distintos del elaborador ────
CREATE OR REPLACE FUNCTION public.documents_guard_segregacion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.elaborador_id IS NOT NULL THEN
        IF NEW.revisor_id = NEW.elaborador_id THEN
            RAISE EXCEPTION 'El revisor no puede ser el mismo elaborador del documento';
        END IF;
        IF NEW.aprobador_id = NEW.elaborador_id THEN
            RAISE EXCEPTION 'El aprobador no puede ser el mismo elaborador del documento';
        END IF;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_documents_guard_segregacion ON public.documents;
CREATE TRIGGER trg_documents_guard_segregacion
    BEFORE INSERT OR UPDATE ON public.documents
    FOR EACH ROW EXECUTE FUNCTION public.documents_guard_segregacion();


-- ─── 4. FLUJO: revisor opcional ──────────────────────────────────────
-- Igual a la versión de 001, salvo:
--   · enviar_revision exige solo aprobador; sin revisor va directo a "En aprobación"
--   · aprobar / aprobar_revision rechazan al elaborador (defensa adicional)
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
    v_doc     public.documents%ROWTYPE;
    v_role    text := public.app_user_role();
    v_uid     uuid := auth.uid();
    v_email   text := auth.jwt() ->> 'email';
    v_to      text;
    v_comment text := nullif(trim(coalesce(p_comment, '')), '');
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
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede enviar a revisión'; END IF;
            IF v_doc.estado NOT IN ('Borrador', 'Observado') THEN
                RAISE EXCEPTION 'Solo se envían a revisión documentos en Borrador u Observado';
            END IF;
            IF v_doc.aprobador_id IS NULL THEN
                RAISE EXCEPTION 'Asigna un aprobador antes de enviar';
            END IF;
            v_to := CASE WHEN v_doc.revisor_id IS NULL THEN 'En aprobación' ELSE 'En revisión' END;

        WHEN 'aprobar_revision' THEN
            IF v_doc.estado <> 'En revisión' THEN RAISE EXCEPTION 'El documento no está en revisión'; END IF;
            IF v_doc.revisor_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el revisor asignado'; END IF;
            IF v_doc.elaborador_id = v_uid THEN RAISE EXCEPTION 'No puedes revisar un documento que elaboraste'; END IF;
            v_to := 'En aprobación';

        WHEN 'observar' THEN
            IF NOT (
                (v_doc.estado = 'En revisión'   AND v_doc.revisor_id   = v_uid) OR
                (v_doc.estado = 'En aprobación' AND v_doc.aprobador_id = v_uid)
            ) THEN
                RAISE EXCEPTION 'No tienes este documento pendiente';
            END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Las observaciones son obligatorias'; END IF;
            v_to := 'Observado';

        WHEN 'aprobar' THEN
            IF v_doc.estado <> 'En aprobación' THEN RAISE EXCEPTION 'El documento no está en aprobación'; END IF;
            IF v_doc.aprobador_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el aprobador asignado'; END IF;
            IF v_doc.elaborador_id = v_uid THEN RAISE EXCEPTION 'No puedes aprobar un documento que elaboraste'; END IF;
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
            v_to := 'Borrador';

        WHEN 'archivar' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede archivar'; END IF;
            v_to := 'Archivado';

        WHEN 'obsoleto' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede marcar obsoleto'; END IF;
            v_to := 'Obsoleto';

        ELSE
            RAISE EXCEPTION 'Acción no válida: %', p_action;
    END CASE;

    PERFORM set_config('app.doc_transition', 'on', true);

    UPDATE public.documents
    SET estado     = v_to,
        version    = CASE WHEN p_action = 'nueva_version' THEN trim(p_version) ELSE version END,
        publicado  = CASE WHEN v_to = 'Publicado' THEN current_date ELSE publicado END,
        updated_at = now()
    WHERE id = p_doc_id;

    PERFORM set_config('app.doc_transition', 'off', true);

    INSERT INTO public.document_approvals
        (document_id, version, action, from_estado, to_estado, user_id, user_email, comment)
    VALUES
        (p_doc_id,
         CASE WHEN p_action = 'nueva_version' THEN trim(p_version) ELSE v_doc.version END,
         p_action, v_doc.estado, v_to, v_uid, v_email, v_comment);

    INSERT INTO public.audit_log (document_id, action, user_id, user_email, changes)
    VALUES (p_doc_id, p_action, v_uid, v_email,
            jsonb_build_object('name', v_doc.name, 'estado', v_to, 'comentario', v_comment));

    RETURN v_to;
END $$;

REVOKE ALL ON FUNCTION public.doc_transition(uuid, text, text, text) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.doc_transition(uuid, text, text, text) TO authenticated;

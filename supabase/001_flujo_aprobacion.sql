-- =====================================================================
-- Control Documental · Migración 001
-- Rol aprobador + flujo de aprobación + trazabilidad + RLS + auto-alta viewer
--
-- Ejecutar UNA VEZ en Supabase → SQL Editor (es idempotente: se puede
-- volver a correr sin duplicar nada).
--
-- ⚠️ La sección 6 ELIMINA las políticas RLS actuales de documents,
--    audit_log y user_roles y las reemplaza por las de este archivo.
--    Antes de correr, revisa/respalda las actuales en
--    Authentication → Policies.
-- =====================================================================


-- ─── 1. ROLES: permitir 'aprobador' ──────────────────────────────────
-- user_roles.role puede ser texto con CHECK o un ENUM; se cubren ambos casos.
DO $$
DECLARE
    v_type  text;
    v_udt   text;
    v_con   record;
BEGIN
    SELECT data_type, udt_name INTO v_type, v_udt
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'user_roles' AND column_name = 'role';

    IF v_type = 'USER-DEFINED' THEN
        EXECUTE format('ALTER TYPE %I ADD VALUE IF NOT EXISTS %L', v_udt, 'aprobador');
    ELSE
        FOR v_con IN
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'public.user_roles'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%role%'
        LOOP
            EXECUTE format('ALTER TABLE public.user_roles DROP CONSTRAINT %I', v_con.conname);
        END LOOP;
        ALTER TABLE public.user_roles
            ADD CONSTRAINT user_roles_role_check CHECK (role IN ('owner', 'aprobador', 'viewer'));
    END IF;
END $$;


-- ─── 2. DOCUMENTS: nuevos estados y asignación por usuario ───────────
ALTER TABLE public.documents
    ADD COLUMN IF NOT EXISTS revisor_id   uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS aprobador_id uuid REFERENCES auth.users(id) ON DELETE SET NULL;

-- Un borrador todavía no tiene fecha de publicación
ALTER TABLE public.documents ALTER COLUMN publicado DROP NOT NULL;

-- estado puede ser texto con CHECK o un ENUM; se agregan los estados nuevos.
-- NOT VALID: no revalida filas antiguas, pero sí controla todo lo nuevo.
DO $$
DECLARE
    v_type text;
    v_udt  text;
    v_val  text;
    v_con  record;
BEGIN
    SELECT data_type, udt_name INTO v_type, v_udt
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'documents' AND column_name = 'estado';

    IF v_type = 'USER-DEFINED' THEN
        FOREACH v_val IN ARRAY ARRAY['Borrador', 'En revisión', 'Observado', 'En aprobación',
                                     'Aprobado', 'Publicado', 'Archivado', 'Obsoleto'] LOOP
            EXECUTE format('ALTER TYPE %I ADD VALUE IF NOT EXISTS %L', v_udt, v_val);
        END LOOP;
    ELSE
        FOR v_con IN
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'public.documents'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%estado%'
        LOOP
            EXECUTE format('ALTER TABLE public.documents DROP CONSTRAINT %I', v_con.conname);
        END LOOP;
        ALTER TABLE public.documents
            ADD CONSTRAINT documents_estado_check CHECK (estado IN (
                'Borrador', 'En revisión', 'Observado', 'En aprobación',
                'Aprobado', 'Publicado', 'Archivado', 'Obsoleto'
            )) NOT VALID;
    END IF;
END $$;

-- Si audit_log.action tiene un CHECK con las acciones antiguas, se elimina
-- (doc_transition registra acciones nuevas: aprobar, observar, publicar, ...)
DO $$
DECLARE v_con record;
BEGIN
    FOR v_con IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'public.audit_log'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) ILIKE '%action%'
    LOOP
        EXECUTE format('ALTER TABLE public.audit_log DROP CONSTRAINT %I', v_con.conname);
    END LOOP;
END $$;


-- ─── 3. TRAZABILIDAD DE APROBACIONES ─────────────────────────────────
CREATE TABLE IF NOT EXISTS public.document_approvals (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id  uuid NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
    version      text,
    action       text NOT NULL,          -- enviar_revision, aprobar_revision, observar, aprobar, publicar, ...
    from_estado  text,
    to_estado    text NOT NULL,
    user_id      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    user_email   text,
    comment      text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_document_approvals_doc
    ON public.document_approvals (document_id, created_at DESC);


-- ─── 4. HELPERS ──────────────────────────────────────────────────────
-- Rol del usuario autenticado (SECURITY DEFINER: evita recursión de RLS)
CREATE OR REPLACE FUNCTION public.app_user_role()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
    SELECT role::text FROM public.user_roles WHERE user_id = auth.uid() LIMIT 1;
$$;

-- Devuelve el rol del usuario; si no tiene y su correo es @thinking.cl,
-- lo da de alta como viewer (así no hay que crear cuentas a mano).
CREATE OR REPLACE FUNCTION public.ensure_my_role()
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    v_role  text;
    v_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
BEGIN
    IF auth.uid() IS NULL THEN
        RETURN NULL;
    END IF;

    v_role := public.app_user_role();

    IF v_role IS NULL AND v_email LIKE '%@thinking.cl' THEN
        INSERT INTO public.user_roles (user_id, email, role)
        VALUES (auth.uid(), v_email, 'viewer');
        v_role := 'viewer';
    END IF;

    RETURN v_role;
END $$;


-- ─── 5. MÁQUINA DE ESTADOS ───────────────────────────────────────────
-- Única vía para cambiar documents.estado. Valida rol, estado de origen
-- y asignación, y deja registro en document_approvals y audit_log.
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
        -- PMG envía a revisión (desde borrador o tras observaciones)
        WHEN 'enviar_revision' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede enviar a revisión'; END IF;
            IF v_doc.estado NOT IN ('Borrador', 'Observado') THEN
                RAISE EXCEPTION 'Solo se envían a revisión documentos en Borrador u Observado';
            END IF;
            IF v_doc.revisor_id IS NULL OR v_doc.aprobador_id IS NULL THEN
                RAISE EXCEPTION 'Asigna revisor y aprobador antes de enviar a revisión';
            END IF;
            v_to := 'En revisión';

        -- Revisor: ¿Aprueba la revisión? SI
        WHEN 'aprobar_revision' THEN
            IF v_doc.estado <> 'En revisión' THEN RAISE EXCEPTION 'El documento no está en revisión'; END IF;
            IF v_doc.revisor_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el revisor asignado'; END IF;
            v_to := 'En aprobación';

        -- Revisor o aprobador: NO → vuelve a elaboración con observaciones
        WHEN 'observar' THEN
            IF NOT (
                (v_doc.estado = 'En revisión'   AND v_doc.revisor_id   = v_uid) OR
                (v_doc.estado = 'En aprobación' AND v_doc.aprobador_id = v_uid)
            ) THEN
                RAISE EXCEPTION 'No tienes este documento pendiente';
            END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Las observaciones son obligatorias'; END IF;
            v_to := 'Observado';

        -- Aprobador: aprobación final
        WHEN 'aprobar' THEN
            IF v_doc.estado <> 'En aprobación' THEN RAISE EXCEPTION 'El documento no está en aprobación'; END IF;
            IF v_doc.aprobador_id IS DISTINCT FROM v_uid THEN RAISE EXCEPTION 'No eres el aprobador asignado'; END IF;
            v_to := 'Aprobado';

        -- PMG publica en repositorios (solo lo aprobado)
        WHEN 'publicar' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede publicar'; END IF;
            IF v_doc.estado <> 'Aprobado' THEN RAISE EXCEPTION 'Solo se publican documentos aprobados'; END IF;
            v_to := 'Publicado';

        -- Documento aprobado fuera de la app (carga de catálogo existente)
        WHEN 'carga_historica' THEN
            IF v_role <> 'owner' THEN RAISE EXCEPTION 'Solo un owner puede hacer carga histórica'; END IF;
            IF v_doc.estado <> 'Borrador' THEN RAISE EXCEPTION 'La carga histórica parte desde Borrador'; END IF;
            IF v_comment IS NULL THEN RAISE EXCEPTION 'Indica quién y cuándo aprobó el documento'; END IF;
            v_to := 'Publicado';

        -- Nueva versión de un documento vigente: vuelve a Borrador
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

    -- Marca la transacción para que el trigger permita el cambio de estado
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

-- Bloquea cambios de estado fuera de doc_transition() y fuerza Borrador al crear
CREATE OR REPLACE FUNCTION public.documents_guard_estado()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.estado := 'Borrador';
    ELSIF NEW.estado IS DISTINCT FROM OLD.estado
          AND coalesce(current_setting('app.doc_transition', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'El estado solo cambia a través del flujo de aprobación';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_documents_guard_estado ON public.documents;
CREATE TRIGGER trg_documents_guard_estado
    BEFORE INSERT OR UPDATE ON public.documents
    FOR EACH ROW EXECUTE FUNCTION public.documents_guard_estado();

REVOKE ALL ON FUNCTION public.doc_transition(uuid, text, text, text) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.doc_transition(uuid, text, text, text) TO authenticated;
REVOKE ALL ON FUNCTION public.ensure_my_role() FROM public, anon;
GRANT EXECUTE ON FUNCTION public.ensure_my_role() TO authenticated;


-- ─── 6. RLS ──────────────────────────────────────────────────────────
-- Se eliminan las políticas existentes de estas tablas y se recrean.
DO $$
DECLARE v_pol record;
BEGIN
    FOR v_pol IN
        SELECT schemaname, tablename, policyname FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename IN ('documents', 'audit_log', 'user_roles', 'document_approvals')
    LOOP
        EXECUTE format('DROP POLICY %I ON %I.%I', v_pol.policyname, v_pol.schemaname, v_pol.tablename);
    END LOOP;
END $$;

ALTER TABLE public.documents          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_approvals ENABLE ROW LEVEL SECURITY;

-- documents: owner ve todo; aprobador ve publicados + los asignados; viewer solo publicados
CREATE POLICY documents_select ON public.documents FOR SELECT TO authenticated
USING (
    public.app_user_role() = 'owner'
    OR (public.app_user_role() IS NOT NULL AND estado = 'Publicado')
    OR revisor_id = auth.uid()
    OR aprobador_id = auth.uid()
);
CREATE POLICY documents_insert ON public.documents FOR INSERT TO authenticated
WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY documents_update ON public.documents FOR UPDATE TO authenticated
USING (public.app_user_role() = 'owner') WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY documents_delete ON public.documents FOR DELETE TO authenticated
USING (public.app_user_role() = 'owner');

-- document_approvals: lectura para quien puede ver el documento; escritura solo vía doc_transition()
CREATE POLICY approvals_select ON public.document_approvals FOR SELECT TO authenticated
USING (EXISTS (SELECT 1 FROM public.documents d WHERE d.id = document_id));

-- audit_log: solo owner lee; cada usuario inserta a su nombre
CREATE POLICY audit_select ON public.audit_log FOR SELECT TO authenticated
USING (public.app_user_role() = 'owner');
CREATE POLICY audit_insert ON public.audit_log FOR INSERT TO authenticated
WITH CHECK (public.app_user_role() IS NOT NULL AND user_id = auth.uid());

-- user_roles: cada uno ve su fila; owner ve y administra todas
CREATE POLICY roles_select ON public.user_roles FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.app_user_role() = 'owner');
CREATE POLICY roles_insert ON public.user_roles FOR INSERT TO authenticated
WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY roles_update ON public.user_roles FOR UPDATE TO authenticated
USING (public.app_user_role() = 'owner') WITH CHECK (public.app_user_role() = 'owner');
CREATE POLICY roles_delete ON public.user_roles FOR DELETE TO authenticated
USING (public.app_user_role() = 'owner' AND user_id <> auth.uid());

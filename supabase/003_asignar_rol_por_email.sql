-- =====================================================================
-- Control Documental · Migración 003
-- Asignar rol a un usuario que ya tiene cuenta en Supabase Auth
-- (p. ej. se le quitó el acceso, o entró antes por otro medio).
--
-- Ejecutar UNA VEZ en Supabase → SQL Editor (idempotente).
-- =====================================================================

-- Devuelve true si el correo existe en auth.users y se le asignó el rol;
-- false si no existe (en ese caso la app crea la cuenta con create-user).
CREATE OR REPLACE FUNCTION public.assign_role_by_email(p_email text, p_role text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    v_user_id uuid;
    v_email   text := lower(trim(p_email));
BEGIN
    IF public.app_user_role() IS DISTINCT FROM 'owner' THEN
        RAISE EXCEPTION 'Solo un owner puede asignar roles';
    END IF;
    IF p_role NOT IN ('owner', 'aprobador', 'viewer') THEN
        RAISE EXCEPTION 'Rol no válido: %', p_role;
    END IF;

    SELECT id INTO v_user_id FROM auth.users WHERE lower(email) = v_email LIMIT 1;
    IF v_user_id IS NULL THEN
        RETURN false;
    END IF;

    UPDATE public.user_roles SET role = p_role, email = v_email WHERE user_id = v_user_id;
    IF NOT FOUND THEN
        INSERT INTO public.user_roles (user_id, email, role) VALUES (v_user_id, v_email, p_role);
    END IF;

    RETURN true;
END $$;

REVOKE ALL ON FUNCTION public.assign_role_by_email(text, text) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.assign_role_by_email(text, text) TO authenticated;

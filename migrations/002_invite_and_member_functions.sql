-- =====================================================================
-- Phase B / Migration 002
-- Creates: SECURITY DEFINER functions for invite + member management.
-- Depends on: Migration 001 (org_invites table, is_org_admin predicate)
-- Rollback: see bottom of file
--
-- Naming convention: all functions in `private` schema, EXECUTE revoked
-- from PUBLIC, granted to `authenticated` (or `anon, authenticated` for
-- preview_invite which is called by unauthenticated invite landings).
-- =====================================================================


-- ---------------------------------------------------------------------
-- create_org_invite — admin creates a new invite. Caller then reads back
-- the token from the row (or via a follow-up fetch by id) and triggers
-- the send-invite Edge Function to deliver email.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.create_org_invite(
  p_org_id uuid,
  p_email  text,
  p_role   public.app_role
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_token   text;
  v_id      uuid;
BEGIN
  -- Guard: must be admin of this org
  IF NOT private.is_org_admin(p_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not an admin of org %', p_org_id
      USING ERRCODE = '42501';
  END IF;

  -- Guard: role must be one of the known app roles (enum gives us this for free,
  -- but be explicit about disallowing nulls or unexpected casts at the boundary)
  IF p_role IS NULL THEN
    RAISE EXCEPTION 'invalid_argument: role must be one of admin | moderator | user'
      USING ERRCODE = '22023';
  END IF;

  -- Soft-revoke any existing open invite for (org_id, email) so the unique
  -- partial index org_invites_org_email_active_idx doesn't conflict.
  UPDATE public.org_invites
     SET revoked_at = now()
   WHERE org_id = p_org_id
     AND lower(email::text) = lower(p_email)
     AND accepted_at IS NULL
     AND revoked_at  IS NULL;

  -- Generate a 32-byte base64url token (pgcrypto's gen_random_bytes available in Supabase)
  v_token := translate(encode(gen_random_bytes(32), 'base64'), '+/=', '-_');

  INSERT INTO public.org_invites (org_id, email, role, token, created_by)
       VALUES (p_org_id, p_email::citext, p_role, v_token, auth.uid())
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.create_org_invite(uuid, text, public.app_role) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.create_org_invite(uuid, text, public.app_role) TO authenticated;

COMMENT ON FUNCTION private.create_org_invite(uuid, text, public.app_role) IS
  'Phase B: admin-only invite creation. Returns invite id. Soft-revokes any prior open invite for (org_id, email).';


-- ---------------------------------------------------------------------
-- revoke_org_invite — admin revokes an outstanding invite.
-- Idempotent: revoking an already-revoked invite is a no-op.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.revoke_org_invite(p_invite_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_org_id     uuid;
  v_accepted   timestamptz;
  v_revoked    timestamptz;
BEGIN
  SELECT org_id, accepted_at, revoked_at
    INTO v_org_id, v_accepted, v_revoked
    FROM public.org_invites
   WHERE id = p_invite_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'not_found: invite %', p_invite_id USING ERRCODE = '02000';
  END IF;

  IF NOT private.is_org_admin(v_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not an admin of the invite''s org'
      USING ERRCODE = '42501';
  END IF;

  IF v_accepted IS NOT NULL THEN
    RAISE EXCEPTION 'conflict: invite already accepted' USING ERRCODE = '23000';
  END IF;

  IF v_revoked IS NOT NULL THEN
    RETURN;  -- idempotent
  END IF;

  UPDATE public.org_invites SET revoked_at = now() WHERE id = p_invite_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.revoke_org_invite(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.revoke_org_invite(uuid) TO authenticated;


-- ---------------------------------------------------------------------
-- preview_invite — public RPC called by the /invite/[token] landing page
-- BEFORE the invitee signs in. Returns ONLY safe fields, never the token
-- or internal ids. Reveals only enough for the page to render the right
-- state machine.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.preview_invite(p_token text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_org_id      uuid;
  v_org_name    text;
  v_role        public.app_role;
  v_email       text;
  v_expires_at  timestamptz;
  v_accepted_at timestamptz;
  v_revoked_at  timestamptz;
  v_status      text;
BEGIN
  SELECT org_id, role, email::text, expires_at, accepted_at, revoked_at
    INTO v_org_id, v_role, v_email, v_expires_at, v_accepted_at, v_revoked_at
    FROM public.org_invites
   WHERE token = p_token;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'not_found');
  END IF;

  -- Resolve org name from public.organizations (confirmed via PostgREST 2026-05-21:
  -- columns id, name, created_at; sample row { id: '00000000-...-0001', name: 'Demo Hospital' }).
  SELECT name INTO v_org_name FROM public.organizations WHERE id = v_org_id;

  IF v_revoked_at IS NOT NULL THEN
    v_status := 'revoked';
  ELSIF v_accepted_at IS NOT NULL THEN
    v_status := 'accepted';
  ELSIF v_expires_at < now() THEN
    v_status := 'expired';
  ELSE
    v_status := 'valid';
  END IF;

  RETURN jsonb_build_object(
    'status',     v_status,
    'org_name',   v_org_name,
    'role',       v_role,
    'email',      v_email,
    'expires_at', v_expires_at
  );
END;
$$;

REVOKE EXECUTE ON FUNCTION private.preview_invite(text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.preview_invite(text) TO anon, authenticated;

COMMENT ON FUNCTION private.preview_invite(text) IS
  'Phase B: returns minimal invite preview for the public /invite/[token] page. Never returns token, org_id, or invitee identity.';


-- ---------------------------------------------------------------------
-- accept_org_invite — the invitee accepts. Called AFTER they sign in
-- with the email the invite was sent to. Idempotent on re-accept; will
-- upsert the org_members row if the user is already a member.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.accept_org_invite(p_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_invite_id   uuid;
  v_org_id      uuid;
  v_role        public.app_role;
  v_invite_email text;
  v_auth_email  text;
  v_expires_at  timestamptz;
  v_accepted_at timestamptz;
  v_revoked_at  timestamptz;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'unauthenticated: sign in before accepting an invite' USING ERRCODE = '42501';
  END IF;

  -- Lock the invite row to prevent double-accept races
  SELECT id, org_id, role, email::text, expires_at, accepted_at, revoked_at
    INTO v_invite_id, v_org_id, v_role, v_invite_email, v_expires_at, v_accepted_at, v_revoked_at
    FROM public.org_invites
   WHERE token = p_token
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'not_found: invite' USING ERRCODE = '02000';
  END IF;

  IF v_revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'revoked: invite has been revoked' USING ERRCODE = '22023';
  END IF;

  IF v_expires_at < now() THEN
    RAISE EXCEPTION 'expired: invite has expired' USING ERRCODE = '22023';
  END IF;

  -- Get the auth user's email
  SELECT email INTO v_auth_email FROM auth.users WHERE id = auth.uid();

  IF v_auth_email IS NULL OR lower(v_auth_email) <> lower(v_invite_email) THEN
    RAISE EXCEPTION 'email_mismatch: signed-in email does not match the invitee' USING ERRCODE = '42501';
  END IF;

  -- If already accepted, return idempotently
  IF v_accepted_at IS NOT NULL THEN
    RETURN jsonb_build_object('org_id', v_org_id, 'role', v_role, 'already_accepted', true);
  END IF;

  -- Insert/update org_members. We don't trust the schema definition here;
  -- adapt the columns if your org_members table includes more (e.g. joined_at).
  INSERT INTO public.org_members (user_id, org_id, role)
       VALUES (auth.uid(), v_org_id, v_role)
  ON CONFLICT (user_id, org_id)
    DO UPDATE SET role = EXCLUDED.role;

  UPDATE public.org_invites
     SET accepted_at = now()
   WHERE id = v_invite_id;

  RETURN jsonb_build_object('org_id', v_org_id, 'role', v_role, 'already_accepted', false);
END;
$$;

REVOKE EXECUTE ON FUNCTION private.accept_org_invite(text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.accept_org_invite(text) TO authenticated;


-- ---------------------------------------------------------------------
-- change_member_role — admin promotes/demotes a member.
-- Guards: caller is admin; cannot self-demote if last admin; cannot
-- demote the last admin in the org.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.change_member_role(
  p_user_id  uuid,
  p_org_id   uuid,
  p_new_role public.app_role
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_current_role  public.app_role;
  v_admin_count   int;
BEGIN
  IF NOT private.is_org_admin(p_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not admin of org %', p_org_id USING ERRCODE = '42501';
  END IF;

  IF p_new_role IS NULL THEN
    RAISE EXCEPTION 'invalid_argument: new role required' USING ERRCODE = '22023';
  END IF;

  SELECT role
    INTO v_current_role
    FROM public.org_members
   WHERE user_id = p_user_id AND org_id = p_org_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'not_found: user is not a member of this org' USING ERRCODE = '02000';
  END IF;

  IF v_current_role = p_new_role THEN
    RETURN;  -- idempotent no-op
  END IF;

  -- Last-admin guard: if the target is currently an admin AND would be
  -- demoted, check that the org has at least one other admin.
  IF v_current_role = 'admin' AND p_new_role <> 'admin' THEN
    SELECT COUNT(*) INTO v_admin_count
      FROM public.org_members
     WHERE org_id = p_org_id AND role = 'admin' AND user_id <> p_user_id;

    IF v_admin_count = 0 THEN
      RAISE EXCEPTION 'last_admin: cannot demote the only admin of this org' USING ERRCODE = '23000';
    END IF;
  END IF;

  -- Self-demotion lockout is implicitly covered by the last-admin guard,
  -- but reject explicitly to give the user a clearer error if they're the
  -- only admin trying to demote themselves.
  IF p_user_id = auth.uid()
     AND v_current_role = 'admin'
     AND p_new_role <> 'admin'
     AND v_admin_count = 0 THEN
    RAISE EXCEPTION 'self_demotion_lockout: would leave you without admin access' USING ERRCODE = '23000';
  END IF;

  UPDATE public.org_members
     SET role = p_new_role
   WHERE user_id = p_user_id AND org_id = p_org_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.change_member_role(uuid, uuid, public.app_role) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.change_member_role(uuid, uuid, public.app_role) TO authenticated;


-- ---------------------------------------------------------------------
-- remove_org_member — admin removes another member from the org.
-- Guards: caller is admin; cannot remove self; cannot remove last admin.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.remove_org_member(
  p_user_id uuid,
  p_org_id  uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_role         public.app_role;
  v_admin_count  int;
BEGIN
  IF NOT private.is_org_admin(p_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not admin of org %', p_org_id USING ERRCODE = '42501';
  END IF;

  IF p_user_id = auth.uid() THEN
    RAISE EXCEPTION 'self_removal: cannot remove yourself; ask another admin' USING ERRCODE = '23000';
  END IF;

  SELECT role INTO v_role
    FROM public.org_members
   WHERE user_id = p_user_id AND org_id = p_org_id;

  IF NOT FOUND THEN
    RETURN;  -- idempotent: nothing to remove
  END IF;

  IF v_role = 'admin' THEN
    SELECT COUNT(*) INTO v_admin_count
      FROM public.org_members
     WHERE org_id = p_org_id AND role = 'admin' AND user_id <> p_user_id;

    IF v_admin_count = 0 THEN
      RAISE EXCEPTION 'last_admin: cannot remove the only admin of this org' USING ERRCODE = '23000';
    END IF;
  END IF;

  DELETE FROM public.org_members
   WHERE user_id = p_user_id AND org_id = p_org_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.remove_org_member(uuid, uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.remove_org_member(uuid, uuid) TO authenticated;


-- ---------------------------------------------------------------------
-- ROLLBACK (paste in SQL editor to revert):
-- ---------------------------------------------------------------------
-- DROP FUNCTION private.remove_org_member(uuid, uuid);
-- DROP FUNCTION private.change_member_role(uuid, uuid, public.app_role);
-- DROP FUNCTION private.accept_org_invite(text);
-- DROP FUNCTION private.preview_invite(text);
-- DROP FUNCTION private.revoke_org_invite(uuid);
-- DROP FUNCTION private.create_org_invite(uuid, text, public.app_role);

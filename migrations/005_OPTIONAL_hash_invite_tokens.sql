-- =====================================================================
-- Phase B / Migration 005 — OPTIONAL
-- Hash org_invites.token at rest for defense in depth against DB read leaks
-- (e.g., compromised backup, accidental log dump). Without this, the live
-- token sits readable in the row (admins-only via RLS, but still).
--
-- Apply ONLY if you want hashing. The plaintext v1 (Migrations 001+002) is
-- functionally correct without this; the token is already unguessable and
-- the RLS gate is admins-only.
--
-- This migration (in order):
--   1. Adds token_hash column (sha256 hex of the token)
--   2. Backfills hashes from any existing plaintext tokens
--   3. Adds a unique index on token_hash; drops plaintext token column
--   4. Replaces create_org_invite to return { invite_id, token } to the
--      caller and store only the hash in the DB
--   5. Replaces preview_invite and accept_org_invite to look up by hash
--
-- After applying, the Edge Function (send-invite/index.ts) needs ONE small
-- change: read the `token` field from the create_org_invite RPC return
-- value (now jsonb { invite_id, token }) instead of SELECTing it from
-- org_invites (which no longer stores plaintext).
--
-- Rollback: see bottom of file.
-- Depends on: Migrations 001, 002
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Schema change
-- ---------------------------------------------------------------------
-- pgcrypto provides digest(); already enabled in Supabase by default.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.org_invites
  ADD COLUMN IF NOT EXISTS token_hash text;

-- Backfill: hash any existing tokens
UPDATE public.org_invites
   SET token_hash = encode(digest(token, 'sha256'), 'hex')
 WHERE token_hash IS NULL AND token IS NOT NULL;

ALTER TABLE public.org_invites
  ALTER COLUMN token_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS org_invites_token_hash_idx
  ON public.org_invites (token_hash);

-- Drop the plaintext token column NOW, before the function replacements
-- below. The new function bodies must not reference `token`, and dropping
-- it here forces a clear error if any of them accidentally do (caught at
-- function-creation time on a strict DB, or at first call otherwise).
-- (The old org_invites_token_idx is dropped automatically with the column.)
ALTER TABLE public.org_invites DROP COLUMN IF EXISTS token;

-- ---------------------------------------------------------------------
-- 2. Replace create_org_invite — now returns both id and token; token is
--    stored only as hash on the row.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.create_org_invite(
  p_org_id uuid,
  p_email  text,
  p_role   public.app_role
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_token  text;
  v_hash   text;
  v_id     uuid;
BEGIN
  IF NOT private.is_org_admin(p_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not an admin of org %', p_org_id USING ERRCODE = '42501';
  END IF;
  IF p_role IS NULL THEN
    RAISE EXCEPTION 'invalid_argument: role required' USING ERRCODE = '22023';
  END IF;

  UPDATE public.org_invites
     SET revoked_at = now()
   WHERE org_id = p_org_id
     AND lower(email::text) = lower(p_email)
     AND accepted_at IS NULL
     AND revoked_at  IS NULL;

  v_token := translate(encode(gen_random_bytes(32), 'base64'), '+/=', '-_');
  v_hash  := encode(digest(v_token, 'sha256'), 'hex');

  INSERT INTO public.org_invites (org_id, email, role, token_hash, created_by)
       VALUES (p_org_id, p_email::citext, p_role, v_hash, auth.uid())
  RETURNING id INTO v_id;

  RETURN jsonb_build_object('invite_id', v_id, 'token', v_token);
END;
$$;

REVOKE EXECUTE ON FUNCTION private.create_org_invite(uuid, text, public.app_role) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.create_org_invite(uuid, text, public.app_role) TO authenticated;

COMMENT ON FUNCTION private.create_org_invite(uuid, text, public.app_role) IS
  'Phase B (hashed-token variant): returns { invite_id, token }. Token returned ONCE; only the hash is stored. Caller must capture token immediately for email delivery.';


-- ---------------------------------------------------------------------
-- 3. Replace preview_invite — lookup by hash
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.preview_invite(p_token text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_hash         text;
  v_org_id       uuid;
  v_org_name     text;
  v_role         public.app_role;
  v_email        text;
  v_expires_at   timestamptz;
  v_accepted_at  timestamptz;
  v_revoked_at   timestamptz;
  v_status       text;
BEGIN
  v_hash := encode(digest(p_token, 'sha256'), 'hex');

  SELECT org_id, role, email::text, expires_at, accepted_at, revoked_at
    INTO v_org_id, v_role, v_email, v_expires_at, v_accepted_at, v_revoked_at
    FROM public.org_invites
   WHERE token_hash = v_hash;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'not_found');
  END IF;

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


-- ---------------------------------------------------------------------
-- 4. Replace accept_org_invite — lookup by hash, row-locked
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.accept_org_invite(p_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_hash         text;
  v_invite_id    uuid;
  v_org_id       uuid;
  v_role         public.app_role;
  v_invite_email text;
  v_auth_email   text;
  v_expires_at   timestamptz;
  v_accepted_at  timestamptz;
  v_revoked_at   timestamptz;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'unauthenticated: sign in before accepting an invite' USING ERRCODE = '42501';
  END IF;

  v_hash := encode(digest(p_token, 'sha256'), 'hex');

  SELECT id, org_id, role, email::text, expires_at, accepted_at, revoked_at
    INTO v_invite_id, v_org_id, v_role, v_invite_email, v_expires_at, v_accepted_at, v_revoked_at
    FROM public.org_invites
   WHERE token_hash = v_hash
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

  SELECT email INTO v_auth_email FROM auth.users WHERE id = auth.uid();
  IF v_auth_email IS NULL OR lower(v_auth_email) <> lower(v_invite_email) THEN
    RAISE EXCEPTION 'email_mismatch: signed-in email does not match the invitee' USING ERRCODE = '42501';
  END IF;

  IF v_accepted_at IS NOT NULL THEN
    RETURN jsonb_build_object('org_id', v_org_id, 'role', v_role, 'already_accepted', true);
  END IF;

  INSERT INTO public.org_members (user_id, org_id, role)
       VALUES (auth.uid(), v_org_id, v_role)
  ON CONFLICT (user_id, org_id)
    DO UPDATE SET role = EXCLUDED.role;

  UPDATE public.org_invites SET accepted_at = now() WHERE id = v_invite_id;

  RETURN jsonb_build_object('org_id', v_org_id, 'role', v_role, 'already_accepted', false);
END;
$$;

REVOKE EXECUTE ON FUNCTION private.accept_org_invite(text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.accept_org_invite(text) TO authenticated;


COMMENT ON COLUMN public.org_invites.token_hash IS
  'SHA-256 hex of the plaintext invite token. Plaintext is returned ONCE by create_org_invite and is never stored.';


-- ---------------------------------------------------------------------
-- 5. Edge Function + UI compatibility — already handled
-- ---------------------------------------------------------------------
-- After applying this migration, the create_org_invite RPC returns
-- { invite_id, token } (jsonb) instead of a uuid. The shipped scaffolds
-- in this project are already forward-compatible:
--
--   - edge-functions/send-invite/index.ts detects PGRST204 / missing-
--     column errors when SELECTing the (now-dropped) token column and
--     reads token from the request body instead.
--   - ui-scaffolds/settings/members.tsx has an `inviteResultToEdgeBody`
--     helper that handles both shapes: uuid string (pre-005) and
--     { invite_id, token } object (post-005).
--
-- So you can apply this migration without manual code edits on either
-- side. The only behavioral difference users will see is that admins
-- can no longer recover an invite token by re-reading the DB row; the
-- token only exists in the email that was sent. To "resend" an invite,
-- use the Resend button in /settings/members, which generates a fresh
-- token (the old one is soft-revoked by create_org_invite's idempotent
-- guard).


-- ---------------------------------------------------------------------
-- ROLLBACK (revert hashed-token upgrade, return to plaintext v1):
-- ---------------------------------------------------------------------
-- ALTER TABLE public.org_invites ADD COLUMN token text;
-- -- NOTE: cannot recover plaintext tokens from hashes; existing rows will
-- -- have empty token strings. Outstanding invites would need to be revoked
-- -- and reissued.
-- DROP INDEX IF EXISTS org_invites_token_hash_idx;
-- ALTER TABLE public.org_invites DROP COLUMN token_hash;
-- -- Then re-apply the create_org_invite / accept_org_invite / preview_invite
-- -- bodies from migration 002.

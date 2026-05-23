-- =====================================================================
-- Phase B / Migration 001
-- Creates: private.is_org_admin predicate + public.org_invites table + RLS
-- Depends on: Phase A objects (private.has_role, private.is_org_member, app_role enum)
-- Rollback: see bottom of file
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Predicate: private.is_org_admin(uuid) -> bool
--    Returns true iff the current user has the 'admin' app role AND is
--    a member of the given org. Used by RLS policies on org_invites
--    and (in migration 003) on metric_audit_log.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION private.is_org_admin(p_org_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    private.has_role(auth.uid(), 'admin'::public.app_role)
    AND private.is_org_member(p_org_id);
$$;

REVOKE EXECUTE ON FUNCTION private.is_org_admin(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION private.is_org_admin(uuid) TO authenticated;

COMMENT ON FUNCTION private.is_org_admin(uuid) IS
  'Phase B: predicate used by RLS. True iff auth.uid() is admin AND a member of the given org.';

-- ---------------------------------------------------------------------
-- 2. citext extension for case-insensitive email
-- ---------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------
-- 3. Table: public.org_invites
--    Mutations only via SECURITY DEFINER functions (migration 002).
-- ---------------------------------------------------------------------

CREATE TABLE public.org_invites (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid        NOT NULL,
  email        citext      NOT NULL,
  role         public.app_role NOT NULL,
  token        text        NOT NULL,
  expires_at   timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  accepted_at  timestamptz,
  revoked_at   timestamptz,
  created_by   uuid        NOT NULL REFERENCES auth.users(id),
  created_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.org_invites IS 'Phase B: pending and historical invites. Mutations only via SECURITY DEFINER functions in migration 002.';
COMMENT ON COLUMN public.org_invites.token IS 'Unguessable 32-byte base64url string. Stored plaintext for v1; consider hashing at rest in a future hardening pass.';

-- Indexes
CREATE UNIQUE INDEX org_invites_token_idx
  ON public.org_invites (token);

-- One active (not accepted, not revoked) invite per (org_id, email) at a time
CREATE UNIQUE INDEX org_invites_org_email_active_idx
  ON public.org_invites (org_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Drives the admin "pending invites" list
CREATE INDEX org_invites_org_pending_idx
  ON public.org_invites (org_id)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- ---------------------------------------------------------------------
-- 4. RLS policies on org_invites
-- ---------------------------------------------------------------------

ALTER TABLE public.org_invites ENABLE ROW LEVEL SECURITY;

-- SELECT: admins see invites for their own org
CREATE POLICY "org_invites_select_admin"
  ON public.org_invites
  AS PERMISSIVE
  FOR SELECT
  TO authenticated
  USING (private.is_org_admin(org_id));

-- INSERT/UPDATE/DELETE: RESTRICTIVE deny for all clients (mutations only via SECURITY DEFINER)
CREATE POLICY "org_invites_insert_deny"
  ON public.org_invites
  AS RESTRICTIVE
  FOR INSERT
  TO authenticated, anon
  WITH CHECK (false);

CREATE POLICY "org_invites_update_deny"
  ON public.org_invites
  AS RESTRICTIVE
  FOR UPDATE
  TO authenticated, anon
  USING (false);

CREATE POLICY "org_invites_delete_deny"
  ON public.org_invites
  AS RESTRICTIVE
  FOR DELETE
  TO authenticated, anon
  USING (false);

-- Defense in depth: revoke direct write grants. RLS is the real gate but this
-- adds another layer in case a future policy is added by mistake.
REVOKE INSERT, UPDATE, DELETE ON public.org_invites FROM authenticated, anon, PUBLIC;
GRANT  SELECT                 ON public.org_invites TO authenticated;

-- ---------------------------------------------------------------------
-- ROLLBACK (paste in SQL editor to revert):
-- ---------------------------------------------------------------------
-- DROP TABLE  public.org_invites;
-- DROP FUNCTION private.is_org_admin(uuid);
-- (citext extension can stay; harmless if unused.)

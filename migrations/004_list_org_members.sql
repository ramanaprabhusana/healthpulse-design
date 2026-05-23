-- =====================================================================
-- Phase B / Migration 004
-- Helper RPC: public.list_org_members(p_org_id uuid)
-- Returns members of an org with their auth.users.email joined in.
-- Needed by the /settings/members and /settings/audit pages, which can't
-- read auth.users directly (it's privileged).
--
-- Depends on: Migration 001 (is_org_admin predicate); Phase A org_members table.
-- Rollback: see bottom of file.
-- =====================================================================

CREATE OR REPLACE FUNCTION public.list_org_members(p_org_id uuid)
RETURNS TABLE (
  user_id   uuid,
  email     text,
  role      public.app_role,
  joined_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- Authorization: caller must be an admin of the requested org.
  -- The audit viewer also calls this to build the actor email lookup, so
  -- admins-only is the right gate (matches the admin-only audit SELECT).
  IF NOT private.is_org_admin(p_org_id) THEN
    RAISE EXCEPTION 'forbidden: caller is not an admin of org %', p_org_id
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
    SELECT
      om.user_id,
      u.email::text  AS email,
      om.role,
      om.created_at  AS joined_at
    FROM public.org_members om
    JOIN auth.users u ON u.id = om.user_id
    WHERE om.org_id = p_org_id
    ORDER BY om.created_at DESC;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.list_org_members(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.list_org_members(uuid) TO authenticated;

COMMENT ON FUNCTION public.list_org_members(uuid) IS
  'Phase B: admin-only listing of org members with emails. SECURITY DEFINER lets us cross the public→auth boundary without exposing auth.users directly.';

-- ---------------------------------------------------------------------
-- NOTE on the `created_at` column:
-- Assumes org_members has a `created_at timestamptz` column, matching the
-- Supabase convention used elsewhere in this schema (org_invites,
-- metric_audit_log, health_metrics, organizations all have created_at).
-- If your actual column is named differently (e.g. `joined_at`), swap
-- both occurrences in the SELECT above and the function will work as-is.
-- ---------------------------------------------------------------------

-- ---------------------------------------------------------------------
-- ROLLBACK (paste in SQL editor to revert):
-- ---------------------------------------------------------------------
-- DROP FUNCTION public.list_org_members(uuid);

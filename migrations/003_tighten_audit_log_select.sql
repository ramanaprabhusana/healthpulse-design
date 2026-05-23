-- =====================================================================
-- Phase B / Migration 003
-- Tighten metric_audit_log SELECT from any org member to admins only.
-- Depends on: Migration 001 (is_org_admin predicate)
-- Rollback: see bottom of file
--
-- BEFORE running this:
--   - Communicate to existing moderators/users that they will lose
--     audit-log visibility. The new /settings/audit page (Phase B
--     Migration step 7) is admin-only.
--   - If you decide moderators should retain self-audit (rows where
--     user_id = auth.uid()), swap the USING expression for the
--     commented-out variant near the bottom.
-- =====================================================================

-- Drop whichever PERMISSIVE SELECT policy is currently on metric_audit_log,
-- regardless of its name. RAISE NOTICE prints what got dropped to the SQL
-- editor output so you can confirm only the expected policy was removed.
--
-- Why this approach: the Phase A policy name may differ across environments
-- (Lovable's auto-generated names vs. our preferred convention). The DO
-- block makes this migration idempotent and name-agnostic — re-running it
-- is a no-op once audit_select_admin already exists.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT policyname
      FROM pg_policies
     WHERE schemaname = 'public'
       AND tablename  = 'metric_audit_log'
       AND cmd        = 'SELECT'
       AND permissive = 'PERMISSIVE'
       AND policyname <> 'audit_select_admin'       -- don't drop the new one if re-running
       AND policyname <> 'audit_select_admin_or_self' -- nor the optional variant
  LOOP
    RAISE NOTICE 'Phase B / 003: dropping existing PERMISSIVE SELECT policy: %', r.policyname;
    EXECUTE format('DROP POLICY %I ON public.metric_audit_log', r.policyname);
  END LOOP;
END $$;

-- New: admins only. Drop-then-create makes this migration safely re-runnable.
DROP POLICY IF EXISTS "audit_select_admin" ON public.metric_audit_log;
CREATE POLICY "audit_select_admin"
  ON public.metric_audit_log
  AS PERMISSIVE
  FOR SELECT
  TO authenticated
  USING (private.is_org_admin(org_id));

COMMENT ON POLICY "audit_select_admin" ON public.metric_audit_log IS
  'Phase B: tightened from is_org_member to is_org_admin. Non-admin org members can no longer browse audit history.';

-- ---------------------------------------------------------------------
-- Variant: admins OR self-audit (uncomment if you decide moderators
-- should be able to see their own actions but not others'):
-- ---------------------------------------------------------------------
-- DROP POLICY IF EXISTS "audit_select_admin" ON public.metric_audit_log;
-- CREATE POLICY "audit_select_admin_or_self"
--   ON public.metric_audit_log
--   AS PERMISSIVE
--   FOR SELECT
--   TO authenticated
--   USING (private.is_org_admin(org_id) OR user_id = auth.uid());

-- ---------------------------------------------------------------------
-- Verification (run after applying; expected output noted in comments):
-- ---------------------------------------------------------------------
-- SELECT policyname, cmd, permissive, roles::text, qual
--   FROM pg_policies
--  WHERE schemaname='public' AND tablename='metric_audit_log';
--
-- Expected rows:
--   audit_select_admin   | SELECT          | PERMISSIVE  | {authenticated}        | (private.is_org_admin(org_id))
--   <existing RESTRICTIVE INSERT deny>  | INSERT        | RESTRICTIVE | {authenticated,anon}  | (false)
--   <existing RESTRICTIVE UPDATE deny>  | UPDATE        | RESTRICTIVE | {authenticated,anon}  | (false)
--   <existing RESTRICTIVE DELETE deny>  | DELETE        | RESTRICTIVE | {authenticated,anon}  | (false)

-- ---------------------------------------------------------------------
-- ROLLBACK (paste in SQL editor to revert):
-- ---------------------------------------------------------------------
-- DROP POLICY IF EXISTS "audit_select_admin"          ON public.metric_audit_log;
-- DROP POLICY IF EXISTS "audit_select_admin_or_self"  ON public.metric_audit_log;
-- CREATE POLICY "audit_select_member"
--   ON public.metric_audit_log
--   AS PERMISSIVE
--   FOR SELECT
--   TO authenticated
--   USING (private.is_org_member(org_id));

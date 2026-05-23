-- =====================================================================
-- Phase B / Migration 006 — performance indexes for audit viewer
-- Apply after the audit viewer UI ships (or before, doesn't matter).
-- These indexes make the /settings/audit filtered list and pagination
-- fast as metric_audit_log grows.
--
-- Without these indexes, the audit viewer's query plan is:
--   Seq Scan on metric_audit_log
--     Filter: (org_id = $1 AND created_at >= $2 AND created_at < $3
--              AND action = ANY($4) AND (user_id = $5 OR $5 IS NULL))
-- which is fine at small sizes (the table has ~tens of rows today) but
-- degrades to O(n) as the log accumulates one row per metric write.
--
-- Depends on: Phase A metric_audit_log
-- Rollback: see bottom of file
-- =====================================================================

-- Primary access pattern: filter by org, sort by created_at DESC, paginate.
-- This covers the default "last 30 days, all actions, all users" view.
CREATE INDEX IF NOT EXISTS metric_audit_log_org_created_idx
  ON public.metric_audit_log (org_id, created_at DESC);

-- Secondary access pattern: user activity filter. Covers "show me only
-- entries by user X in org Y" — used by the audit viewer's user dropdown
-- and by potential compliance queries like "all activity by this user
-- across the audit history".
CREATE INDEX IF NOT EXISTS metric_audit_log_org_user_created_idx
  ON public.metric_audit_log (org_id, user_id, created_at DESC);

-- Tertiary access pattern: metric-date lookup. Useful if compliance
-- officers want "all activity that touched 2026-05-15" — answers via
-- index instead of scanning.
CREATE INDEX IF NOT EXISTS metric_audit_log_org_metric_date_idx
  ON public.metric_audit_log (org_id, metric_date);

-- Notes on what we deliberately did NOT index:
--   - `action` alone: low cardinality (3 values), index would be unused
--     because Postgres prefers seq scan once selectivity drops below ~10%.
--   - `user_id` alone: covered by the (org_id, user_id, created_at) composite.
--   - `before` / `after` (jsonb): expensive to index; queries against
--     specific JSON paths are rare in the audit viewer. If you later add
--     full-text search across audit payloads, consider a GIN index then.

-- ---------------------------------------------------------------------
-- Verification (run after applying):
-- ---------------------------------------------------------------------
-- SELECT indexname, indexdef
--   FROM pg_indexes
--  WHERE schemaname = 'public' AND tablename = 'metric_audit_log';
--
-- EXPLAIN ANALYZE
--   SELECT * FROM public.metric_audit_log
--    WHERE org_id = '<your-org-uuid>'
--      AND created_at >= now() - interval '30 days'
--    ORDER BY created_at DESC LIMIT 50;
-- -- Expected plan: Index Scan using metric_audit_log_org_created_idx

-- ---------------------------------------------------------------------
-- ROLLBACK:
-- ---------------------------------------------------------------------
-- DROP INDEX IF EXISTS metric_audit_log_org_created_idx;
-- DROP INDEX IF EXISTS metric_audit_log_org_user_created_idx;
-- DROP INDEX IF EXISTS metric_audit_log_org_metric_date_idx;

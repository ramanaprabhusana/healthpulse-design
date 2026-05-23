// =====================================================================
// /settings/audit — Admin-only Audit Log Viewer
// Phase B / Migration step 7
//
// Reads metric_audit_log (admin-gated via RLS after migration 003).
// Shows filters + table + diff modal. Export uses the same escapeCsvCell
// sanitizer as the existing /metrics export — import that helper from
// wherever it lives in your codebase (typically src/lib/csv.ts).
// =====================================================================

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Download, ScrollText, X } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { escapeCsvCell } from "@/lib/csv"; // <-- existing helper from Phase A

type Action = "create" | "update" | "delete";

type AuditRow = {
  id: string;
  action: Action;
  created_at: string;
  metric_date: string;
  user_id: string;
  org_id: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  actor_email?: string; // populated client-side from a members lookup
};

const PAGE_SIZE = 50;

export default function AuditPage() {
  const navigate = useNavigate();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [emailByUser, setEmailByUser] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  // Filters
  const today = new Date().toISOString().slice(0, 10);
  const thirtyAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const [from, setFrom] = useState(thirtyAgo);
  const [to, setTo] = useState(today);
  const [actions, setActions] = useState<Set<Action>>(new Set(["create", "update", "delete"]));
  const [userIdFilter, setUserIdFilter] = useState<string>("");

  // Pagination
  const [page, setPage] = useState(0);
  const [totalCount, setTotalCount] = useState(0);

  // Diff modal
  const [diff, setDiff] = useState<AuditRow | null>(null);

  // -------- Auth + admin gate --------
  useEffect(() => {
    (async () => {
      const { data: u } = await supabase.auth.getUser();
      if (!u.user) { navigate("/login"); return; }
      const { data: me } = await supabase.from("org_members")
        .select("org_id, role").eq("user_id", u.user.id).single();
      if (!me || me.role !== "admin") {
        toast.error("Audit log is admin-only");
        navigate("/command");
        return;
      }
      setOrgId(me.org_id);
      const { data: list } = await supabase.rpc("list_org_members", { p_org_id: me.org_id });
      if (list) {
        const map: Record<string, string> = {};
        for (const m of list as { user_id: string; email: string }[]) map[m.user_id] = m.email;
        setEmailByUser(map);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -------- Load page --------
  useEffect(() => {
    if (!orgId) return;
    (async () => {
      setLoading(true);
      const actionList = Array.from(actions);
      let query = supabase
        .from("metric_audit_log")
        .select("*", { count: "exact" })
        .eq("org_id", orgId)
        .gte("created_at", `${from}T00:00:00Z`)
        .lt("created_at", `${to}T23:59:59.999Z`)
        .in("action", actionList);
      if (userIdFilter) query = query.eq("user_id", userIdFilter);
      query = query.order("created_at", { ascending: false })
                   .range(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE - 1);
      const { data, count, error } = await query;
      if (error) {
        toast.error(error.message);
      } else {
        const enriched = (data ?? []).map(r => ({
          ...r,
          actor_email: emailByUser[r.user_id] ?? r.user_id,
        })) as AuditRow[];
        setRows(enriched);
        setTotalCount(count ?? 0);
      }
      setLoading(false);
    })();
  }, [orgId, from, to, actions, userIdFilter, page, emailByUser]);

  function toggleAction(a: Action) {
    const next = new Set(actions);
    if (next.has(a)) next.delete(a);
    else next.add(a);
    if (next.size === 0) return; // require at least one
    setActions(next);
    setPage(0);
  }

  function exportFilteredCsv() {
    if (rows.length === 0) { toast.info("Nothing to export"); return; }
    const headers = ["created_at", "action", "metric_date", "actor_email", "user_id", "before", "after"];
    const lines = [headers.map(escapeCsvCell).join(",")];
    for (const r of rows) {
      lines.push([
        escapeCsvCell(r.created_at),
        escapeCsvCell(r.action),
        escapeCsvCell(r.metric_date),
        escapeCsvCell(r.actor_email ?? ""),
        escapeCsvCell(r.user_id),
        escapeCsvCell(r.before ? JSON.stringify(r.before) : ""),
        escapeCsvCell(r.after ? JSON.stringify(r.after) : ""),
      ].join(","));
    }
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-log-${from}-to-${to}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  return (
    <div className="p-8 space-y-6">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <ScrollText /> Audit Log
          </h1>
          <p className="text-muted-foreground">Every create, update, and delete on health metrics in your organization.</p>
        </div>
        <button onClick={exportFilteredCsv}
          className="inline-flex items-center gap-2 rounded border px-3 py-2 hover:bg-accent">
          <Download size={16} /> Export CSV
        </button>
      </header>

      {/* Filters */}
      <section className="rounded-lg border bg-card p-4 grid grid-cols-1 md:grid-cols-[1fr_1fr_2fr_1fr] gap-4 items-end">
        <div>
          <label className="block text-sm mb-1">From</label>
          <input type="date" value={from} onChange={e => { setFrom(e.target.value); setPage(0); }}
            className="w-full rounded border px-3 py-2 bg-background" />
        </div>
        <div>
          <label className="block text-sm mb-1">To</label>
          <input type="date" value={to} onChange={e => { setTo(e.target.value); setPage(0); }}
            className="w-full rounded border px-3 py-2 bg-background" />
        </div>
        <div>
          <label className="block text-sm mb-1">Action</label>
          <div className="flex gap-2">
            {(["create", "update", "delete"] as Action[]).map(a => (
              <button key={a} type="button" onClick={() => toggleAction(a)}
                className={`px-3 py-2 rounded border text-sm ${actions.has(a) ? "bg-primary text-primary-foreground border-primary" : "bg-background"}`}>
                {a}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-sm mb-1">User</label>
          <select value={userIdFilter} onChange={e => { setUserIdFilter(e.target.value); setPage(0); }}
            className="w-full rounded border px-3 py-2 bg-background">
            <option value="">All members</option>
            {Object.entries(emailByUser).map(([uid, email]) => (
              <option key={uid} value={uid}>{email}</option>
            ))}
          </select>
        </div>
      </section>

      {/* Table */}
      <section className="rounded-lg border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/50">
            <tr className="text-left">
              <th className="px-6 py-3">When</th>
              <th className="px-6 py-3">Actor</th>
              <th className="px-6 py-3">Action</th>
              <th className="px-6 py-3">Metric date</th>
              <th className="px-6 py-3 text-right">Diff</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={5} className="px-6 py-6 text-muted-foreground">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={5} className="px-6 py-6 text-muted-foreground">No audit entries for this filter.</td></tr>
            )}
            {!loading && rows.map(r => (
              <tr key={r.id} className="border-t">
                <td className="px-6 py-3 text-muted-foreground">{new Date(r.created_at).toLocaleString()}</td>
                <td className="px-6 py-3">{r.actor_email}</td>
                <td className="px-6 py-3">
                  <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
                    r.action === "create" ? "bg-green-100 text-green-800" :
                    r.action === "update" ? "bg-blue-100 text-blue-800" :
                    "bg-red-100 text-red-800"
                  }`}>{r.action}</span>
                </td>
                <td className="px-6 py-3">{r.metric_date}</td>
                <td className="px-6 py-3 text-right">
                  <button onClick={() => setDiff(r)} className="text-primary hover:underline">View diff</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div className="px-6 py-3 border-t flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              Page {page + 1} of {totalPages} · {totalCount} total entries
            </span>
            <div className="space-x-2">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                className="rounded border px-3 py-1 disabled:opacity-50">Prev</button>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
                className="rounded border px-3 py-1 disabled:opacity-50">Next</button>
            </div>
          </div>
        )}
      </section>

      {/* Diff modal */}
      {diff && <DiffModal row={diff} onClose={() => setDiff(null)} />}
    </div>
  );
}

function DiffModal({ row, onClose }: { row: AuditRow; onClose: () => void }) {
  const beforeKeys = new Set(Object.keys(row.before ?? {}));
  const afterKeys = new Set(Object.keys(row.after ?? {}));
  const allKeys = Array.from(new Set([...beforeKeys, ...afterKeys])).sort();

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-card rounded-lg shadow-xl max-w-4xl w-full max-h-[80vh] overflow-auto" onClick={e => e.stopPropagation()}>
        <header className="px-6 py-4 border-b flex items-center justify-between sticky top-0 bg-card">
          <h2 className="text-lg font-medium">
            {row.action} on {row.metric_date} by {row.actor_email}
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X /></button>
        </header>
        <table className="w-full text-sm font-mono">
          <thead className="bg-muted/50">
            <tr className="text-left">
              <th className="px-4 py-2">Field</th>
              <th className="px-4 py-2">Before</th>
              <th className="px-4 py-2">After</th>
            </tr>
          </thead>
          <tbody>
            {allKeys.map(k => {
              const bv = row.before?.[k];
              const av = row.after?.[k];
              const changed = JSON.stringify(bv) !== JSON.stringify(av);
              return (
                <tr key={k} className={`border-t ${changed ? "bg-yellow-50" : ""}`}>
                  <td className="px-4 py-2">{k}</td>
                  <td className="px-4 py-2 break-all">{bv === undefined ? "—" : JSON.stringify(bv)}</td>
                  <td className="px-4 py-2 break-all">{av === undefined ? "—" : JSON.stringify(av)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

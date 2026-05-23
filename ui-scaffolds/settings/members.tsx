// =====================================================================
// /settings/members — Admin-only Members page
// Phase B / Migration step 4
//
// Adapt the imports + supabase singleton path to match Lovable's project
// layout. The styling assumes Tailwind + shadcn/ui (Button, Table, etc.)
// which is what the rest of the app uses; if you don't have those, swap
// for plain JSX with the same class names.
// =====================================================================

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { UserPlus, Trash2, Mail, X } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

type Role = "admin" | "moderator" | "user";

type Member = {
  user_id: string;
  email: string;
  role: Role;
  joined_at: string;
};

type Invite = {
  id: string;
  email: string;
  role: Role;
  created_at: string;
  expires_at: string;
};

export default function MembersPage() {
  const navigate = useNavigate();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [myUserId, setMyUserId] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("user");
  const [sending, setSending] = useState(false);

  // -------- Auth + admin gate + initial load --------
  useEffect(() => {
    (async () => {
      const { data: userData } = await supabase.auth.getUser();
      if (!userData.user) {
        navigate("/login");
        return;
      }
      setMyUserId(userData.user.id);

      // Resolve user's org + role
      const { data: meRow } = await supabase
        .from("org_members")
        .select("org_id, role")
        .eq("user_id", userData.user.id)
        .single();

      if (!meRow || meRow.role !== "admin") {
        toast.error("Members management is admin-only");
        navigate("/command");
        return;
      }

      setOrgId(meRow.org_id);
      await refresh(meRow.org_id);
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function refresh(orgIdArg: string) {
    // Members list — joining auth.users.email needs a SECURITY DEFINER RPC
    // or a view. Below assumes you've created public.list_org_members(org_id uuid)
    // returning (user_id, email, role, joined_at). If you don't have it yet,
    // swap for a direct SELECT from org_members (no email column).
    const { data: mbrData, error: mbrErr } = await supabase.rpc("list_org_members", {
      p_org_id: orgIdArg,
    });
    if (!mbrErr && mbrData) setMembers(mbrData as Member[]);

    // Pending invites — RLS allows admin SELECT
    const { data: invData } = await supabase
      .from("org_invites")
      .select("id, email, role, created_at, expires_at")
      .eq("org_id", orgIdArg)
      .is("accepted_at", null)
      .is("revoked_at", null)
      .order("created_at", { ascending: false });

    if (invData) setInvites(invData as Invite[]);
  }

  // Adapter so this UI works both pre- and post-migration-005.
  // Pre-005: create_org_invite returns a uuid string (the invite id).
  // Post-005: it returns { invite_id, token } — we must forward token to
  // the Edge Function because the DB no longer stores plaintext.
  function inviteResultToEdgeBody(data: unknown): { invite_id: string; token?: string } {
    if (typeof data === "string") return { invite_id: data };
    if (data && typeof data === "object" && "invite_id" in data) {
      const o = data as { invite_id: string; token?: string };
      return { invite_id: o.invite_id, token: o.token };
    }
    throw new Error("Unexpected create_org_invite return shape");
  }

  // -------- Invite --------
  async function handleSendInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!orgId || !inviteEmail) return;
    setSending(true);
    try {
      const { data, error } = await supabase.rpc("create_org_invite", {
        p_org_id: orgId,
        p_email: inviteEmail,
        p_role: inviteRole,
      });
      if (error) throw error;

      // Trigger email delivery (forwards token after migration 005)
      const { error: fnErr } = await supabase.functions.invoke("send-invite", {
        body: inviteResultToEdgeBody(data),
      });
      if (fnErr) {
        toast.warning(`Invite created but email failed: ${fnErr.message}. You can copy the link from the pending list.`);
      } else {
        toast.success(`Invite sent to ${inviteEmail}`);
      }

      setInviteEmail("");
      setInviteRole("user");
      await refresh(orgId);
    } catch (err: any) {
      toast.error(err.message ?? "Failed to send invite");
    } finally {
      setSending(false);
    }
  }

  async function handleRevoke(inviteId: string) {
    if (!orgId) return;
    if (!confirm("Revoke this invite? The link will stop working.")) return;
    const { error } = await supabase.rpc("revoke_org_invite", { p_invite_id: inviteId });
    if (error) {
      toast.error(error.message);
    } else {
      toast.success("Invite revoked");
      await refresh(orgId);
    }
  }

  async function handleResend(inviteId: string, email: string) {
    // Resend = create new invite (the create_org_invite RPC itself
    // soft-revokes any prior open invite for (org_id, email)), then
    // trigger the Edge Function to send. No need to explicitly revoke.
    if (!orgId) return;
    const existing = invites.find(i => i.id === inviteId);
    const role: Role = existing?.role ?? "user";

    const { data: newInvite, error: cErr } = await supabase.rpc("create_org_invite", {
      p_org_id: orgId,
      p_email: email,
      p_role: role,
    });
    if (cErr) { toast.error(cErr.message); return; }

    const { error: fnErr } = await supabase.functions.invoke("send-invite", {
      body: inviteResultToEdgeBody(newInvite),
    });
    if (fnErr) toast.warning(`New invite created; email delivery failed: ${fnErr.message}`);
    else toast.success(`Invite resent to ${email}`);
    await refresh(orgId);
  }

  async function handleChangeRole(userId: string, newRole: Role) {
    if (!orgId) return;
    const { error } = await supabase.rpc("change_member_role", {
      p_user_id: userId,
      p_org_id: orgId,
      p_new_role: newRole,
    });
    if (error) toast.error(error.message);
    else { toast.success("Role updated"); await refresh(orgId); }
  }

  async function handleRemoveMember(userId: string, email: string) {
    if (!orgId) return;
    if (userId === myUserId) {
      toast.error("You can't remove yourself; ask another admin");
      return;
    }
    if (!confirm(`Remove ${email} from this organization?`)) return;
    const { error } = await supabase.rpc("remove_org_member", {
      p_user_id: userId,
      p_org_id: orgId,
    });
    if (error) toast.error(error.message);
    else { toast.success("Member removed"); await refresh(orgId); }
  }

  const expiresFromNow = (iso: string) => {
    const days = Math.ceil((new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    return days <= 0 ? "expired" : days === 1 ? "1 day" : `${days} days`;
  };

  if (loading) return <div className="p-8 text-muted-foreground">Loading members…</div>;

  return (
    <div className="p-8 space-y-8">
      <header>
        <h1 className="text-3xl font-bold">Members</h1>
        <p className="text-muted-foreground">Manage who has access to your organization.</p>
      </header>

      {/* Members table */}
      <section className="rounded-lg border bg-card">
        <div className="px-6 py-4 border-b font-medium">Active members ({members.length})</div>
        <table className="w-full text-sm">
          <thead className="bg-muted/50">
            <tr className="text-left">
              <th className="px-6 py-3">Email</th>
              <th className="px-6 py-3">Role</th>
              <th className="px-6 py-3">Joined</th>
              <th className="px-6 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.user_id} className="border-t">
                <td className="px-6 py-3">{m.email}</td>
                <td className="px-6 py-3">
                  <select
                    value={m.role}
                    onChange={(e) => handleChangeRole(m.user_id, e.target.value as Role)}
                    disabled={m.user_id === myUserId}
                    className="rounded border px-2 py-1 bg-background"
                  >
                    <option value="admin">admin</option>
                    <option value="moderator">moderator</option>
                    <option value="user">user</option>
                  </select>
                </td>
                <td className="px-6 py-3 text-muted-foreground">
                  {new Date(m.joined_at).toLocaleDateString()}
                </td>
                <td className="px-6 py-3 text-right">
                  <button
                    onClick={() => handleRemoveMember(m.user_id, m.email)}
                    disabled={m.user_id === myUserId}
                    className="inline-flex items-center gap-1 text-destructive hover:underline disabled:opacity-30 disabled:no-underline"
                  >
                    <Trash2 size={16} /> Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Pending invites */}
      <section className="rounded-lg border bg-card">
        <div className="px-6 py-4 border-b font-medium">Pending invites ({invites.length})</div>
        {invites.length === 0 ? (
          <div className="px-6 py-6 text-muted-foreground">No pending invites.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr className="text-left">
                <th className="px-6 py-3">Email</th>
                <th className="px-6 py-3">Role</th>
                <th className="px-6 py-3">Sent</th>
                <th className="px-6 py-3">Expires in</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {invites.map((i) => (
                <tr key={i.id} className="border-t">
                  <td className="px-6 py-3">{i.email}</td>
                  <td className="px-6 py-3">{i.role}</td>
                  <td className="px-6 py-3 text-muted-foreground">
                    {new Date(i.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-3 text-muted-foreground">{expiresFromNow(i.expires_at)}</td>
                  <td className="px-6 py-3 text-right space-x-3">
                    <button
                      onClick={() => handleResend(i.id, i.email)}
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      <Mail size={16} /> Resend
                    </button>
                    <button
                      onClick={() => handleRevoke(i.id)}
                      className="inline-flex items-center gap-1 text-destructive hover:underline"
                    >
                      <X size={16} /> Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Invite form */}
      <section className="rounded-lg border bg-card p-6 max-w-2xl">
        <h2 className="text-lg font-medium mb-4 flex items-center gap-2">
          <UserPlus size={20} /> Invite a new member
        </h2>
        <form onSubmit={handleSendInvite} className="grid grid-cols-[1fr_180px_auto] gap-3 items-end">
          <div>
            <label className="block text-sm font-medium mb-1">Email *</label>
            <input
              type="email"
              required
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="newmember@hospital.org"
              className="w-full rounded border px-3 py-2 bg-background"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Role *</label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as Role)}
              className="w-full rounded border px-3 py-2 bg-background"
            >
              <option value="user">user (read-only)</option>
              <option value="moderator">moderator</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={sending}
            className="rounded bg-primary text-primary-foreground px-4 py-2 font-medium hover:opacity-90 disabled:opacity-50"
          >
            {sending ? "Sending…" : "Send invite"}
          </button>
        </form>
      </section>
    </div>
  );
}

// =====================================================================
// Companion RPC you'll need (add to migrations/002 or a new migration).
// This returns members with emails — needed because RLS on auth.users
// is locked. Returns nothing if caller isn't an admin of the requested org.
//
// CREATE OR REPLACE FUNCTION public.list_org_members(p_org_id uuid)
//   RETURNS TABLE(user_id uuid, email text, role public.app_role, joined_at timestamptz)
//   LANGUAGE plpgsql
//   STABLE
//   SECURITY DEFINER
//   SET search_path = ''
//   AS $$
//   BEGIN
//     IF NOT private.is_org_admin(p_org_id) THEN
//       RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
//     END IF;
//     RETURN QUERY
//       SELECT om.user_id, u.email::text, om.role, om.created_at
//         FROM public.org_members om
//         JOIN auth.users u ON u.id = om.user_id
//        WHERE om.org_id = p_org_id
//        ORDER BY om.created_at DESC;
//   END;
//   $$;
// REVOKE EXECUTE ON FUNCTION public.list_org_members(uuid) FROM PUBLIC;
// GRANT  EXECUTE ON FUNCTION public.list_org_members(uuid) TO authenticated;
// =====================================================================

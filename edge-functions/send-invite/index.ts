// =====================================================================
// HealthPulse — send-invite Edge Function
// Phase B / Migration step 5
//
// Flow:
//   1. Client (admin) calls /functions/v1/send-invite with { invite_id }
//   2. This function verifies the caller is the admin who created the
//      invite (or another admin of the same org), reads the token, then
//      sends an email.
//   3. Tries Supabase Auth admin.inviteUserByEmail first (built-in
//      transactional email via Supabase SMTP). If unavailable or fails,
//      falls back to Resend.
//
// Env vars required:
//   SUPABASE_URL                  - injected by Supabase runtime
//   SUPABASE_SERVICE_ROLE_KEY     - injected by Supabase runtime
//   APP_URL                       - e.g. https://vital-insights-studio.lovable.app
//   RESEND_API_KEY                - optional; if absent, only Supabase path is tried
//   RESEND_FROM_EMAIL             - optional; e.g. invites@healthpulse.example
//
// Deploy (Lovable Cloud or Supabase CLI):
//   supabase functions deploy send-invite --no-verify-jwt=false
//   (We DO verify JWT — this endpoint is admin-only.)
// =====================================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const APP_URL = Deno.env.get("APP_URL") ?? "";
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") ?? "";
const RESEND_FROM = Deno.env.get("RESEND_FROM_EMAIL") ?? "invites@example.com";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type InviteRow = {
  id: string;
  org_id: string;
  email: string;
  role: "admin" | "moderator" | "user";
  // `token` only exists pre-migration-005 (plaintext v1). Post-005 the
  // column is dropped and the client must pass the token in the request
  // body — it was returned ONCE by create_org_invite.
  token?: string;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  // ---- 1. Auth: verify the caller is signed in ----
  const authHeader = req.headers.get("authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return json({ error: "unauthenticated" }, 401);
  const callerJwt = authHeader.slice("Bearer ".length);

  // Caller-scoped client (RLS enforced) — used to verify identity + admin claim
  const callerClient = createClient(SUPABASE_URL, SERVICE_ROLE, {
    global: { headers: { Authorization: `Bearer ${callerJwt}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: callerUser, error: callerErr } = await callerClient.auth.getUser(callerJwt);
  if (callerErr || !callerUser.user) return json({ error: "unauthenticated" }, 401);

  // ---- 2. Parse request body ----
  // `invite_id` is always required. `token` is required AFTER migration
  // 005 (hashed-token variant), since the DB no longer stores plaintext.
  // Pre-005 the function falls back to reading token from the row.
  let body: { invite_id?: string; token?: string; resend?: boolean };
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  if (!body.invite_id) return json({ error: "missing_invite_id" }, 400);

  // ---- 3. Service-role client (bypasses RLS) — used to read the invite ----
  const admin = createClient(SUPABASE_URL, SERVICE_ROLE, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // First try the v1 schema (with plaintext token). If the `token` column
  // doesn't exist (post-005), PostgREST returns PGRST204 — retry without
  // selecting token, and use the token passed in the body instead.
  let invite: InviteRow | null = null;
  {
    const { data, error } = await admin
      .from("org_invites")
      .select("id, org_id, email, role, token, expires_at, accepted_at, revoked_at")
      .eq("id", body.invite_id)
      .single<InviteRow>();

    if (!error && data) {
      invite = data;
    } else if (error?.code === "PGRST204" || /column.*token.*does not exist/i.test(error?.message ?? "")) {
      // Post-migration-005 — retry without selecting `token`
      const { data: d2, error: e2 } = await admin
        .from("org_invites")
        .select("id, org_id, email, role, expires_at, accepted_at, revoked_at")
        .eq("id", body.invite_id)
        .single<InviteRow>();
      if (!e2 && d2) {
        if (!body.token) {
          return json({ error: "missing_token_post_hash_upgrade", hint: "Pass token in request body — it was returned by create_org_invite." }, 400);
        }
        invite = { ...d2, token: body.token };
      } else {
        return json({ error: "invite_not_found" }, 404);
      }
    } else {
      return json({ error: "invite_not_found", db_error: error?.message }, 404);
    }
  }

  if (!invite) return json({ error: "invite_not_found" }, 404);
  if (invite.revoked_at) return json({ error: "invite_revoked" }, 410);
  if (invite.accepted_at) return json({ error: "invite_already_accepted" }, 409);
  if (new Date(invite.expires_at).getTime() < Date.now()) {
    return json({ error: "invite_expired" }, 410);
  }

  // ---- 4. Verify caller is an admin of THIS invite's org ----
  // We use the caller-scoped client + the RLS-protected is_org_admin predicate
  // (exposed via PostgREST RPC). This double-checks beyond the create_org_invite
  // guard, in case an old/leaked token was used by a now-non-admin.
  const { data: isAdminData, error: isAdminErr } = await callerClient.rpc("is_org_admin", {
    p_org_id: invite.org_id,
  });
  if (isAdminErr || isAdminData !== true) {
    return json({ error: "forbidden_not_admin" }, 403);
  }

  // ---- 5. Build the invite acceptance URL ----
  if (!APP_URL) return json({ error: "server_misconfigured_app_url" }, 500);
  const acceptUrl = `${APP_URL.replace(/\/$/, "")}/invite/${encodeURIComponent(invite.token)}`;

  // ---- 6. Try Supabase Auth invite first ----
  // admin.inviteUserByEmail sends a magic-link signup that redirects to
  // emailRedirectTo on first sign-in. The invitee lands on /invite/[token]
  // already authed, ready to call accept_org_invite.
  let primaryProvider: string | null = null;
  let primaryError: string | null = null;

  try {
    const { error: invErr } = await admin.auth.admin.inviteUserByEmail(invite.email, {
      redirectTo: acceptUrl,
      data: { invited_to_org: invite.org_id, invited_role: invite.role },
    });

    if (!invErr) {
      primaryProvider = "supabase_auth";
    } else {
      // If the email already has an account, inviteUserByEmail returns an error
      // ("User already registered"). In that case we still want to email them
      // a plain link to /invite/[token], so fall through to Resend.
      primaryError = invErr.message ?? "supabase_invite_failed";
    }
  } catch (e) {
    primaryError = (e as Error).message ?? "supabase_invite_threw";
  }

  if (primaryProvider === "supabase_auth") {
    return json({ ok: true, provider: "supabase_auth", invite_id: invite.id });
  }

  // ---- 7. Fallback: Resend ----
  if (!RESEND_API_KEY) {
    return json(
      {
        error: "supabase_failed_and_no_resend",
        supabase_error: primaryError,
        hint:
          "Set RESEND_API_KEY env var to enable the fallback, or share the link manually:",
        accept_url: acceptUrl,
      },
      502,
    );
  }

  const html = `
    <p>You've been invited to join <strong>HealthPulse</strong> as <em>${invite.role}</em>.</p>
    <p><a href="${acceptUrl}" style="display:inline-block;padding:10px 16px;background:#1F3A5F;color:#fff;border-radius:6px;text-decoration:none">Accept invitation</a></p>
    <p>Or copy this link: ${acceptUrl}</p>
    <p>This invite expires on ${new Date(invite.expires_at).toUTCString()}.</p>
  `;

  const resendResp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: invite.email,
      subject: "You're invited to HealthPulse",
      html,
    }),
  });

  if (!resendResp.ok) {
    const txt = await resendResp.text();
    return json(
      {
        error: "resend_failed",
        supabase_error: primaryError,
        resend_status: resendResp.status,
        resend_body: txt.slice(0, 400),
      },
      502,
    );
  }

  return json({ ok: true, provider: "resend", invite_id: invite.id });
});

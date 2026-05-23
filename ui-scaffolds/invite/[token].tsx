// =====================================================================
// /invite/[token] — Public invite acceptance landing page
// Phase B / Migration step 6
//
// This page is PUBLIC (no auth gate on the route). It calls
// private.preview_invite(token) which returns only safe fields, then
// renders one of five states:
//
//   not_found  — generic "Link looks broken" message
//   revoked    — "Ask your admin for a new invite"
//   expired    — "This invite expired N days ago. Ask for a new one."
//   accepted   — "Already accepted. Sign in to continue."
//   valid      — render Sign in / Accept based on current auth
//
// AUTH MODEL (post-2026-05-20 Lovable hardening):
// Lovable Cloud set `disable_signup=true` at the auth level, so client-side
// supabase.auth.signUp is dead everywhere. The invite path now relies
// ENTIRELY on Supabase Auth admin invite (sent by the send-invite Edge
// Function via inviteUserByEmail) — which creates the user account and
// emails a magic link in one step. The invitee arrives here already
// signed in via that link. If they come back later from a stale session,
// they request a fresh magic link via "Email me a sign-in link".
// =====================================================================

import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { CheckCircle2, AlertTriangle, Mail } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

type Preview =
  | { status: "not_found" }
  | { status: "revoked"; org_name?: string }
  | { status: "expired"; org_name?: string; expires_at: string }
  | { status: "accepted"; org_name?: string; email: string }
  | {
      status: "valid";
      org_name: string | null;
      role: "admin" | "moderator" | "user";
      email: string;
      expires_at: string;
    };

export default function InvitePage() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const [preview, setPreview] = useState<Preview | null>(null);
  const [authEmail, setAuthEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [accepting, setAccepting] = useState(false);

  useEffect(() => {
    (async () => {
      if (!token) { setLoading(false); return; }
      const { data: pdata, error: perr } = await supabase.rpc("preview_invite", { p_token: token });
      if (perr) {
        toast.error(perr.message);
        setLoading(false);
        return;
      }
      setPreview(pdata as Preview);

      const { data: u } = await supabase.auth.getUser();
      setAuthEmail(u.user?.email ?? null);
      setLoading(false);
    })();
  }, [token]);

  async function handleAccept() {
    if (!token) return;
    setAccepting(true);
    try {
      const { data, error } = await supabase.rpc("accept_org_invite", { p_token: token });
      if (error) throw error;
      toast.success("Welcome! You're now a member.");
      navigate("/command");
    } catch (err: any) {
      toast.error(err.message ?? "Could not accept invite");
    } finally {
      setAccepting(false);
    }
  }

  async function handleSignIn() {
    // Send a magic link so they don't need to remember a password
    if (preview?.status !== "valid") return;
    const { error } = await supabase.auth.signInWithOtp({
      email: preview.email,
      options: { emailRedirectTo: window.location.href },
    });
    if (error) toast.error(error.message);
    else toast.success("Sign-in link sent. Click it to come back and accept.");
  }

  async function handleSwitchAccount() {
    await supabase.auth.signOut();
    setAuthEmail(null);
    toast.info("Signed out. Sign in with the invited email to accept.");
  }

  if (loading) {
    return (
      <Centered>
        <p className="text-muted-foreground">Loading invitation…</p>
      </Centered>
    );
  }

  if (!preview || preview.status === "not_found") {
    return (
      <Centered>
        <ErrorPanel
          title="Invitation not found"
          message="This link looks broken or has been deleted. Ask your administrator to send a new one."
        />
      </Centered>
    );
  }

  if (preview.status === "revoked") {
    return (
      <Centered>
        <ErrorPanel
          title="Invitation revoked"
          message={`This invitation${preview.org_name ? ` to ${preview.org_name}` : ""} was revoked. Ask your administrator to send a new one.`}
        />
      </Centered>
    );
  }

  if (preview.status === "expired") {
    const days = Math.floor((Date.now() - new Date(preview.expires_at).getTime()) / (1000 * 60 * 60 * 24));
    return (
      <Centered>
        <ErrorPanel
          title="Invitation expired"
          message={`This invitation expired ${days === 0 ? "today" : `${days} day${days === 1 ? "" : "s"} ago`}. Ask your administrator to send a new one.`}
        />
      </Centered>
    );
  }

  if (preview.status === "accepted") {
    return (
      <Centered>
        <div className="text-center space-y-4">
          <CheckCircle2 className="mx-auto text-green-600" size={48} />
          <h1 className="text-2xl font-bold">Already accepted</h1>
          <p className="text-muted-foreground">
            You've already accepted this invitation. Sign in to continue.
          </p>
          <button onClick={() => navigate("/login")}
            className="rounded bg-primary text-primary-foreground px-4 py-2 font-medium">
            Sign in
          </button>
        </div>
      </Centered>
    );
  }

  // valid
  const wrongEmail = authEmail && authEmail.toLowerCase() !== preview.email.toLowerCase();
  const expiresIn = Math.ceil((new Date(preview.expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24));

  return (
    <Centered>
      <div className="space-y-6">
        <header className="text-center space-y-2">
          <Mail className="mx-auto text-primary" size={40} />
          <h1 className="text-2xl font-bold">
            Join {preview.org_name ?? "HealthPulse"}
          </h1>
          <p className="text-muted-foreground">
            You've been invited as <span className="font-medium text-foreground">{preview.role}</span>.
            <br />
            Invitation for <span className="font-medium text-foreground">{preview.email}</span> — expires in {expiresIn} day{expiresIn === 1 ? "" : "s"}.
          </p>
        </header>

        {!authEmail && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground text-center">
              Your invite email contains a sign-in link. If you opened this page directly
              or your session expired, request a fresh link below.
            </p>
            <button onClick={handleSignIn}
              className="w-full rounded bg-primary text-primary-foreground px-4 py-3 font-medium">
              Email me a sign-in link
            </button>
          </div>
        )}

        {authEmail && !wrongEmail && (
          <button onClick={handleAccept} disabled={accepting}
            className="w-full rounded bg-primary text-primary-foreground px-4 py-3 font-medium disabled:opacity-50">
            {accepting ? "Accepting…" : `Accept invitation as ${preview.role}`}
          </button>
        )}

        {authEmail && wrongEmail && (
          <div className="space-y-3 p-4 rounded border border-yellow-300 bg-yellow-50">
            <p className="text-sm">
              You're signed in as <span className="font-medium">{authEmail}</span> but this invitation is
              for <span className="font-medium">{preview.email}</span>.
            </p>
            <button onClick={handleSwitchAccount}
              className="rounded bg-foreground text-background px-3 py-2 text-sm font-medium">
              Sign out and switch account
            </button>
          </div>
        )}
      </div>
    </Centered>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <div className="w-full max-w-md bg-card rounded-lg shadow-lg p-8">{children}</div>
    </div>
  );
}

function ErrorPanel({ title, message }: { title: string; message: string }) {
  return (
    <div className="text-center space-y-4">
      <AlertTriangle className="mx-auto text-yellow-600" size={48} />
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}

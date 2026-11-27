"use client";

import { useEffect, useState } from "react";

/** One target the person holds a Work Context at, and the installation it is sealed to. */
export type Installation = {
  id: string;
  target: string;
  namespace?: string;
  /** The module edge that issues a call through THIS installation's bindings,
   * the person present: what the page reaches a module through. */
  moduleApiBase?: string;
};

/** The edge's /auth/session: who is here, and what they hold where. */
export type Session = {
  moduleApiBase?: string;
  personId: string;
  organizationId: string;
  personDisplayName?: string;
  organizationDisplayName?: string;
  roles: string[];
  installations: Installation[];
  /** Every target the authority refused an issue at, in its own words. */
  refused: Record<string, string>;
};

export type SessionState =
  | { status: "loading" }
  | { status: "signed-in"; session: Session }
  | { status: "error"; reason: string };

/** The sign-in page is the EDGE'S, never a route of this app. */
export function signInLocation(pathname: string, search: string): string {
  return "/auth/sign-in?return=" + encodeURIComponent(pathname + search);
}

/** Whether the person may use this solution: the edge's session names an installation of it. */
export function installed(session: Pick<Session, "installations">): boolean {
  return session.installations.some((installation) => installation.target === "codefly-base");
}

/**
 * The module edge the page calls modules through: this solution's
 * installation's, which issues each call through the solution's bindings with
 * the person's role on it. Never the session's own moduleApiBase: that is the
 * person on their own session, where an owner-aware module refuses an
 * organisation role ("reach it through a role on the installation that owns
 * it"). Undefined when the installation names none, which the page reports.
 */
export function pageModuleApiBase(session: Pick<Session, "installations">): string | undefined {
  return session.installations.find((installation) => installation.target === "codefly-base")?.moduleApiBase;
}

/** Why the edge's session names no installation, in the authority's own words. */
export function refusal(session: Pick<Session, "refused">): string | undefined {
  return session.refused["codefly-base"];
}

export function useSession(): SessionState {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  useEffect(() => {
    let cancelled = false;
    fetch("/auth/session", { credentials: "include" })
      .then((response) => {
        // Not signed in: the edge's own sign-in page, with a return to here.
        if (response.status === 401 || response.status === 403) {
          window.location.assign(signInLocation(window.location.pathname, window.location.search));
          return null;
        }
        if (!response.ok) throw new Error("the edge answered " + response.status);
        return response.json();
      })
      .then((session: Session | null) => {
        if (!cancelled && session) setState({ status: "signed-in", session });
      })
      .catch((cause) => {
        if (!cancelled) setState({ status: "error", reason: String(cause) });
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

export async function signOut(): Promise<void> {
  await fetch("/auth/sign-out", { method: "POST", credentials: "include" });
  window.location.assign("/");
}

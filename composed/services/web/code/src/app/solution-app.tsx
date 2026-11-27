"use client";

import dynamic from "next/dynamic";
import { installed, refusal, signOut, useSession } from "./session";

// The page renders in the browser only, as a host mounts it.
const SolutionPage = dynamic(() => import("codefly-base-fe-remote/Page"), { ssr: false });

// Every call the page makes goes to this one same-origin base. The edge in
// front of this page routes /v1/codefly-base to this solution's backend and sends each
// call on with the signed-in person's Work Context.
const apiBase = "/v1/codefly-base";

// The page holds no token: the browser's cookie and the edge carry the viewer.
const noToken = () => null;

// Wrapped, never passed as `fetch` itself: called as a member of the
// binding, the browser's fetch refuses a `this` that is not the window.
const sameOrigin = (input: RequestInfo | URL, init?: RequestInit) => fetch(input, init);

export default function SolutionApp() {
  const signedIn = useSession();

  if (signedIn.status === "loading") return null;

  if (signedIn.status === "error") {
    return (
      <main style={{ padding: "2rem", maxWidth: "48rem" }}>
        <h1>This page is not behind its sign-in edge</h1>
        <p>
          {signedIn.reason}. Open this page at the address the authority's edge
          serves, never at this shell's own port — the edge is what signs the
          person in and routes <code>{apiBase}</code> to the backend.
        </p>
      </main>
    );
  }

  const { session } = signedIn;
  if (!installed(session)) {
    return (
      <main style={{ padding: "2rem", maxWidth: "48rem" }}>
        <h1>Codefly Base is not available to you here</h1>
        <p>
          {refusal(session) ??
            "The edge's session names neither an installation of this solution nor the authority's reason for refusing one: the edge does not route it."}
        </p>
      </main>
    );
  }

  return (
    <main style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
      <header style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600, margin: 0 }}>Codefly Base</h1>
        <span style={{ fontSize: "0.875rem", opacity: 0.7 }}>
          {session.personDisplayName?.trim() || session.personId} ·{" "}
          {session.organizationDisplayName?.trim() || session.organizationId}
          {session.roles.length ? " · " + session.roles.join(", ") : ""}
        </span>
        <button type="button" onClick={() => void signOut()}>Sign out</button>
      </header>
      <SolutionPage
        solutionId="codefly-base"
        apiBase={apiBase}
        getAccessToken={noToken}
        authedFetch={sameOrigin}
        organizationId={session.organizationId}
      />
    </main>
  );
}

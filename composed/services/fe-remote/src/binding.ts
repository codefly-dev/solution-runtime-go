import type { SolutionBinding } from "@codefly-dev/saas-ui/solution";

/**
 * THE HOST↔REMOTE CONTRACT, in this solution's own words.
 *
 * A host mounts `./Page` with its `SolutionPageProps`, which extends
 * `SolutionBinding` — the ONE definition both sides read, in
 * `@codefly-dev/saas-ui/solution`. Pick from it; never restate a field, and
 * never REQUIRE one a host might not inject: an older host omits it, the
 * remote throws inside the host's error boundary, and the page goes blank with
 * nothing in the console to say why.
 *
 * What a host hands over: `solutionId`, `apiBase` (ONE same-origin base for
 * every backend call — this solution's own routes and the host's platform
 * services alike, because the proxy routes on the path), `getAccessToken`,
 * `refreshAccessToken`, `authedFetch`, and optionally `subscribeToken` and
 * `declaredSources`.
 *
 * What it does NOT hand over: which installation of this solution the viewer
 * is looking at. A page that needs one asks its own backend for it, on a route
 * this solution serves (operations.go); it is never a constant in this source.
 */
export type PageProps = Pick<SolutionBinding, "solutionId" | "apiBase"> &
	Partial<Pick<SolutionBinding, "getAccessToken" | "authedFetch" | "subscribeToken">>;

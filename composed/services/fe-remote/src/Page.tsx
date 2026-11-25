import { useMemo } from "react";
import { requestBinding, useAccessToken, useViewerEpoch, viewerOrganization } from "@codefly-dev/saas-ui/solution";
import type { PageProps } from "./binding";
import "./page.css";

/**
 * Codefly Base — the page a host mounts as `./Page`.
 *
 * The title and the nav order the host's shell shows are NOT here: they are
 * declared once, in the backend's `solution.frontend.codefly.yaml`, which the
 * backend embeds and the CLI delivers in the presence document it signs. What
 * this file is, is the page itself.
 *
 * Every call this page makes goes to `apiBase` — one same-origin base, because
 * the host's proxy routes on the path — and arrives at the backend carrying
 * the viewer's own Work Context, where the authority checks it against the
 * route's published policy.
 */
export default function Page(props: PageProps) {
	// A new viewer gets a new page rather than the previous viewer's state.
	const epoch = useViewerEpoch(props.getAccessToken, props.subscribeToken);
	return <SolutionPage key={`${props.apiBase}:${epoch}`} {...props} />;
}

function SolutionPage({ apiBase, getAccessToken, authedFetch, subscribeToken }: PageProps) {
	const token = useAccessToken(getAccessToken, subscribeToken);
	const organizationId = viewerOrganization(token) ?? "";
	// A signed-out viewer has no credential, and so no binding to reach
	// anything with. Build none rather than letting requests go out
	// anonymously and come back as an ordinary sign-in 401.
	const binding = useMemo(
		() => (getAccessToken || authedFetch ? requestBinding(apiBase, getAccessToken, authedFetch) : null),
		[apiBase, getAccessToken, authedFetch],
	);

	if (!binding || !organizationId) {
		return (
			<div className="sol-page">
				<p className="sol-note">Sign in and select an organization to use Codefly Base.</p>
			</div>
		);
	}

	return (
		<div className="sol-page">
			<header className="sol-header">
				<h1>Codefly Base</h1>
				<p>This page is yours to write. It reaches its backend through <code>{apiBase}</code>.</p>
			</header>
			<main className="sol-main">
				<p className="sol-note">
					Add a view here. Call a route this solution serves (its backend's <code>operations.go</code>), or a
					module operation it consumes, at <code>{`${apiBase}/modules/<as>/<package.Service>/<Method>`}</code>.
				</p>
			</main>
		</div>
	);
}

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import Page from "./Page";

// vitest runs without globals here, so testing-library's automatic cleanup is
// not installed: without this each test renders into the previous test's DOM
// and a query that should find one node finds two.
afterEach(cleanup);

// A host mounts `./Page` with its own props and nothing else. These are the
// cases that blank the page in a browser rather than failing a build.
describe("the page a host mounts", () => {
	const props = { solutionId: "codefly-base", apiBase: "/api/solutions/codefly-base/proxy" };

	it("mounts for a signed-out viewer without throwing", () => {
		render(<Page {...props} />);
		expect(screen.getByText(/Sign in/)).toBeTruthy();
	});

	it("mounts with the organization verified by the cookie-authenticated edge", () => {
		render(<Page {...props} organizationId="org-from-edge" authedFetch={fetch} />);
		expect(screen.getByRole("heading", { name: "Codefly Base" })).toBeTruthy();
	});

	it("carries no installation id in its source", async () => {
		// Which installation a page is mounted for is read at runtime, from a
		// route this solution's backend serves — never pasted in. A UUID
		// anywhere in this remote's source is that rule broken, and this is the
		// only place that notices.
		const sources = import.meta.glob("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
		expect(Object.keys(sources).length).toBeGreaterThan(1);
		const uuid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/;
		for (const [path, source] of Object.entries(sources)) {
			expect(uuid.test(source), `${path} carries a UUID`).toBe(false);
		}
	});
});

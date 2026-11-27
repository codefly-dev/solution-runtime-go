import { NextResponse } from "next/server";

// force-static keeps the probe dependency-free and lets it prerender under
// both `output: standalone` and `output: export` (static export rejects a
// route handler that is neither force-static nor revalidating).
export const dynamic = "force-static";

export function GET() {
  return NextResponse.json({ status: "ok" });
}

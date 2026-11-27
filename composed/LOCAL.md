# Running Codefly Base locally

	export NODE_AUTH_TOKEN=$(gh auth token)   # read:packages, for the page's kits
	make run

Then open the address the EDGE prints:

	edge listening on :<port>, routing 1 module(s)

## What runs, and why each one

| | |
|---|---|
| `authority/edge` | the browser's one origin: signs the person in, serves the page, routes `/v1/codefly-base` to the backend with their Work Context |
| `authority/local` | the authority itself, which issues every Work Context and checks each call against the route's published policy |
| `authority/store` | the authority's own store, where approvals persist |
| `codefly-base/backend` | this solution's entry service |
| `codefly-base/web` | the shell that serves the page, mounting the same `./Page` a host federates |

## The token

The page's kits (@codefly-dev/*) are published to GitHub Packages, and
services/fe-remote/.npmrc reads NODE_AUTH_TOKEN for them. Without it npm
answers "401 Unauthorized - unauthenticated" and names no cause, so
make run refuses to start until it is set.

## The two addresses that are not it

- **the shell's own port.** The page asks the edge for `/auth/session` on
  the origin it is served from; on the shell's port there is no edge, and the
  page says "This page is not behind its sign-in edge".
- **the authority's REST port.** That is the authority's API, not the edge.
  Every browser path 404s there.

## Local only

In a cell the host's gateway is the origin and issues the Work Contexts. The
development authority stands in for it here, and nothing in this directory
describes a deployment.

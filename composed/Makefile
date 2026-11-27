.PHONY: run remote scenarios

# Codefly Base on the development authority, as a solution runs in a cell with no saas
# host: the authority's edge is the one origin the browser opens and signs a
# person in from the authority's fixture, and this solution's backend is
# issued every Work Context it sends.
#
# This directory IS the workspace (workspace.codefly.yaml, path: .), so the
# run happens here. There is no playground subdirectory: a playground is a
# MODULE's, somewhere to exercise a module on its own.
#
# THE EDGE IS LISTED FIRST AND THAT IS LOAD-BEARING. It is not a dependency of
# the backend and nothing elects it as ingress, so neither `codefly run solution`
# nor `codefly run workspace` starts it: name it, or the page is served on
# no origin that can sign anyone in.
SERVICES = authority/edge codefly-base/web codefly-base/backend

# THE REMOTE IS BUILT FIRST, and that is not a convenience. The solution
# runtime serves /assets/ from ASSETS_DIR, which defaults to
# ../fe-remote/dist relative to the backend — so with no build there, the
# backend answers 404 for /assets/mf-manifest.json, the manifest it
# advertises in /.well-known/solution.json, and a host can federate nothing.
# The shell also installs the remote as a copy, so it needs it built.
run: remote
	codefly run service $(SERVICES) --env local

remote:
	@test -n "$$NODE_AUTH_TOKEN" || { \
	  echo "NODE_AUTH_TOKEN is not set. The page's kits are published to GitHub"; \
	  echo "Packages, so the install needs a token with read:packages:"; \
	  echo ""; \
	  echo "    export NODE_AUTH_TOKEN=\$$(gh auth token)"; \
	  echo ""; \
	  echo "Without it npm answers 401 Unauthorized and says nothing about why."; \
	  exit 1; }
	cd services/fe-remote && npm install --no-audit --no-fund && npm run build
	test -f services/fe-remote/dist/mf-manifest.json

# ADDED TO THE SCAFFOLD: the composed scenarios (scenarios/). They start this
# solution, the authority, its edge and hop and the document store once, and
# call the backend as fixture people. Needs Docker and NODE_AUTH_TOKEN (the
# run builds the page's remote).
# The scenarios are behind the build tag `composition`; a run that executed
# none of them fails here (and `go test` without the tag fails in tag_test.go).
scenarios:
	cd scenarios && GOWORK=off GOPRIVATE='github.com/obin-ai/*,github.com/codefly-dev/*' \
	  CODEFLY_BINARY=$(or $(CODEFLY_BINARY),$(shell command -v $(or $(CODEFLY),codefly))) \
	  go test -tags composition -run Composed -count=1 -timeout 40m -v . > scenarios.log 2>&1; \
	  status=$$?; cat scenarios.log; \
	  test $$status -eq 0 || exit $$status; \
	  grep -q '^--- PASS: TestComposed' scenarios.log || { echo "no scenario ran"; exit 1; }

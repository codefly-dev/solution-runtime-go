package solution

import (
	"fmt"

	"github.com/codefly-dev/core/solutionhost"
)

// FrontendFileName is the one file a solution declares its frontend in, beside
// the backend service's service.codefly.yaml. The backend embeds it
// (Manifest.Frontend) and serves its manifest route from it; the CLI reads the
// same file into the presence document's frontend block. There is no other
// source: the manifest this runtime used to report to the host with its mint
// is gone, because a presence document is delivered and a process cannot
// declare what the composition did not.
//
// The file is YAML, decoded strictly — an unknown key is refused by name — and
// its top-level mapping is the block itself, no wrapper, so the CLI can decode
// it straight into core's type. Its keys are core's field names, field for
// field, and every scalar is declared: core refuses an omitted one rather than
// reading it as zero, and a file this runtime accepted that the CLI refuses
// would be the two readers disagreeing.
//
//	title: Widgets           # nav title; one non-empty line
//	order: 10                # nav order; declared, zero included
//	exposed_module: ./Page   # Module Federation exposed module; one non-empty line
//	host_contract: 1         # host page-contract major; at least 1
//	dashboard: {...}         # optional; a mapping, served as JSON, bounded at 64 KiB
//	surfaces:                # optional; what the solution offers inside a client
//	  - id: footnote         # lowercase letters and digits, dashes between
//	    client: word         # word, powerpoint, excel or slack
//	    title: Footnote
//	    description: ...     # optional
//	    module: /surfaces/word/footnote.js
//	    contract: 1          # surface contract major; at least 1
//	    applies: always      # declared: "always", or {tagged: [one or more tags]}
//	    events: [documents.entry]   # optional; journal namespaces, lowercase dotted names, each once
const FrontendFileName = "solution.frontend.codefly.yaml"

const frontendDashboardMaxBytes = solutionhost.FrontendDashboardMaxBytes

type frontendDeclaration = solutionhost.Frontend
type frontendSurface = solutionhost.FrontendSurface

// parseFrontend uses the same reader the CLI uses before signed delivery.
// Core owns field semantics and limits; this runtime adds the author's filename.
func parseFrontend(raw []byte) (frontendDeclaration, error) {
	declared, err := solutionhost.ParseFrontend(raw)
	if err != nil {
		return frontendDeclaration{}, fmt.Errorf("%s: %w", FrontendFileName, err)
	}
	return *declared, nil
}

// manifestMap is the manifest this runtime serves at /.well-known/solution.json:
// the declared frontend, and the constants of this runtime's own layout — the
// federation manifest path, the backend's service alias and the capability
// path. The host builds its registry entry from the delivered presence and the
// same constants; this route is what the solution says about itself to
// whoever asks it directly.
func (s *Server) manifestMap() map[string]any {
	m := map[string]any{
		"id":            s.manifest.ID,
		"schemaVersion": solutionManifestSchemaMajor,
		"nav":           map[string]any{"title": s.frontend.Title, "path": "/s/" + s.manifest.ID, "order": s.frontend.Order},
		"frontend": map[string]any{
			"type":          "module-federation",
			"manifestUrl":   s.frontendManifestURL(),
			"exposedModule": s.frontend.ExposedModule,
			"hostContract":  s.frontend.HostContract,
			"reactRange":    "^19",
		},
		"backend": map[string]any{"serviceAlias": s.manifest.ID, "capabilityPath": "/.well-known/capabilities"},
	}
	// Only emit the slot when declared: a null dashboard would break a host that
	// feeds a present slot straight into its data-graph validator, and it keeps
	// the wire byte-identical for solutions that declare no dashboard.
	if s.frontend.Dashboard != nil {
		m["dashboard"] = s.frontend.Dashboard
	}
	if len(s.frontend.Surfaces) > 0 {
		surfaces := make([]any, 0, len(s.frontend.Surfaces))
		for _, surface := range s.frontend.Surfaces {
			entry := map[string]any{
				"id":       surface.ID,
				"client":   surface.Client,
				"title":    surface.Title,
				"module":   surface.Module,
				"contract": surface.Contract,
				"applies":  surface.Applies,
			}
			// Absent, these two say something a client can act on — no
			// description to show, nothing to reconcile on — where a null would
			// only be a slot the client still has to interpret.
			if surface.Description != "" {
				entry["description"] = surface.Description
			}
			if len(surface.Events) > 0 {
				entry["events"] = surface.Events
			}
			surfaces = append(surfaces, entry)
		}
		m["surfaces"] = surfaces
	}
	return m
}

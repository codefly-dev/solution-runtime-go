// Package seam is how the passthrough test harness reaches the solution
// runtime's passthrough without the runtime exposing a way to build one in
// production.
//
// Server.PassthroughHandler used to be exported, and that was a public
// production bypass: New(...).Consumes(...).Credential(source).
// PassthroughHandler(gatewayURL) returned a usable, credential-bearing handler
// having skipped validate(), the mTLS boot, the caller allow-list, the
// published ceiling and authenticated outbound. A deployment that called it
// completed a viewer mint and a module call over plaintext and answered 200 —
// with the viewer's bearer and this workload's credential on the wire — and
// supplying a real credential source defeated the one mitigation it had.
//
// It had to stay reachable from passthroughtest, which is a consumer-facing
// package in this module and the documented seam for running the real
// passthrough against a fake host. Go's internal-package rule is what makes
// those two facts compatible: the root package registers the constructor here
// at init, passthroughtest reads it, and nothing outside this module can import
// this package at all. The gate is the compiler rather than a flag, a name or a
// runtime check, and the remaining looseness of the seam — a plaintext fake
// host, no contract, no listener — is now a property of this module's own tests
// instead of an API a solution can call.
package seam

import "net/http"

// Passthrough builds the passthrough for an already-configured *solution.Server
// against gatewayURL, with consumesJSON standing in for the api.consumes
// projection a boot resolves. The root package sets it; passthroughtest calls
// it.
//
// The server is untyped because the root package imports this one to register
// the function, so this one cannot name its types. The implementation asserts.
var Passthrough func(server any, gatewayURL, consumesJSON string) (http.Handler, error)

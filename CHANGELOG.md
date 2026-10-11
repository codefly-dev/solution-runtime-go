# Changelog

## Unreleased — partial mint-once migration

Breaking API change: `WorkContextRefusal.Code` and `WorkContextRefusal.Message`
are removed. Use `StatusCode` (or unwrap to `GatewayError`) to classify failures.
Errors and passthrough responses no longer expose broker diagnostics.
No registration-secret API remains in the starting revision of this repository.

The projected token path defaults to `/var/run/secrets/codefly/token`; the CLI
mounts it read-only for audience `accounts` with a lifetime of at most 600 seconds.
The runtime reads the bounded file again before each mint. Missing, empty,
unreadable and oversized projections fail closed.

The requested `saas-sdk-go` revision
`v0.0.3-0.20261011091114-217bf9fe3f10` cannot build alongside the current
`sdk-go/workcontext`: its `moduleauthority` package requires the removed
`WorkContextToken` and `ParseWorkContextToken` API. Its `Seams` also requires an
internal perimeter token that this runtime no longer provisions. Switching the
broker and supplying the solution's declared name as its prefix remain blocked
on a compatible SDK. The offline `go get` succeeded, but the subsequent
`moduleauthority` build failed on those symbols. The unusable dependency change
was reverted and `go mod tidy` left the original pins unchanged. No SDK source
was copied or modified locally.

The retained execution SDK marks every non-401/403 HTTP status unavailable and
exposes no typed status for narrowing retries. Therefore the requested retry
policy (only 503 and transient transport failures) is not complete. Execution
refusals still latch; errors from default and consumer-supplied credential sources are now redacted.

### Removed authentication configuration (archive)

These identifiers are deleted, not compatibility inputs:
`MODULE_IDENTITY_SECRET`, `MODULE_IDENTITY_SECRETS`, `MODULE_IDENTITY_PREFIX`,
`MODULE_REGISTRATION_SECRETS`, `SOLUTION_REGISTRATION_SECRETS`,
`CODEFLY__SOLUTION_REGISTRATION_SECRET`, `MintModuleRegistration`, and
`MintSolutionRegistration`.

The compiler-based facade gate reads the two wire spellings below from this
archive and still checks constants, conversions, aliases and compiled fixtures.
Tests never provision a removed identity secret.

| Kind | Removed wire spelling |
| --- | --- |
| header | `X-Codefly-Module-Secret` |
| carrier | `CODEFLY__MODULE_REGISTRATION_SECRETS` |

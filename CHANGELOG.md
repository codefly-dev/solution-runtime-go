# Changelog

## Unreleased — native module-broker execution mint

Breaking API change: `WorkContextRefusal.Code` and `WorkContextRefusal.Message`
are removed. Use `StatusCode` (or unwrap to `GatewayError`) to classify failures.
Errors and passthrough responses no longer expose broker diagnostics.
No registration-secret API remains in the starting revision of this repository.

The projected token path defaults to `/var/run/secrets/codefly/token`; the CLI
mounts it read-only for audience `accounts` with a lifetime of at most 600 seconds.
The runtime reads the bounded file again before each mint. Missing, empty,
unreadable and oversized projections fail closed.

Execution minting now implements the published `saas-sdk-go/moduleauthority`
contract at `217bf9fe3f10` natively: `POST /modules/_work-context`, the declared
`Manifest.ID` as `prefix`, the fresh projected bearer, and the perimeter token
from the declared workspace secret `module-authority/INTERNAL_TOKEN`. The legacy
internal-token variable remains ignored. This is a runtime protocol fix; no SDK
package is vendored or copied and dependency pins are unchanged.

The broker client accepts the camel-case response and delegates structural
capability inspection to Core. The public `CredentialSource` signature is
unchanged. TLS identity, fresh trust/admission checks, frozen authority,
installation/build holds, single-flight acquisition and expiry-driven renewal
remain enforced.

Only 503 and typed timeout/connection-refused/connection-reset failures retry.
401/403 remain terminal refusals; every other status and permanent transport or
response error is terminal. Errors retain safe classification and discard raw
diagnostics. Conformance tests exercise the actual request and response using
an in-memory fake broker, including boot and renewal retry decisions.

The legacy-secret regression again sets nonempty deleted secret variables.
Compiler gates pin the canonical forbidden spellings independently of this
archive; compiled fixtures prove that reintroduced readers are rejected.

### Removed authentication configuration (archive)

These identifiers are deleted, not compatibility inputs:
`MODULE_IDENTITY_SECRET`, `MODULE_IDENTITY_SECRETS`, `MODULE_IDENTITY_PREFIX`,
`MODULE_REGISTRATION_SECRETS`, `SOLUTION_REGISTRATION_SECRETS`,
`CODEFLY__SOLUTION_REGISTRATION_SECRET`, `MintModuleRegistration`, and
`MintSolutionRegistration`.

These archived spellings are also independently pinned by the compiler-based
facade gate. Adversarial tests deliberately provision removed secrets.

| Kind | Removed wire spelling |
| --- | --- |
| header | `X-Codefly-Module-Secret` |
| carrier | `CODEFLY__MODULE_REGISTRATION_SECRETS` |

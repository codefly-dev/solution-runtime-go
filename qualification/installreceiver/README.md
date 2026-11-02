# Installation receiver process fixture

This test-only consumer lets Accounts' `TestCanonicalCombinedInstallQueueThroughRuntime` exercise the real runtime listener and Authority Check transport. It does not implement an installation verifier. Its `OnInstall` callback appends the verified synthetic installation to the specified JSONL file, then acknowledges, refuses, or fails as directed by the test.

When `INSTALL_RECEIVER_SCHEMA` names a protobuf-JSON RecordType, acknowledgement also requires two `DefineRecordType` calls through a declared setup binding, with the second confirming the same identity and revision without minting another revision. An undeclared `DefineProjection` call must be refused. The composing test must provide the `records/ENDPOINT` and `records/BINDING` workspace configuration slots and deliver matching setup, method and owner-aware policies. This mode is not evidence until run through a real composed Authority, hop and Records service.

The Accounts test owns all process configuration, including the solution ID, log path, outcome, Authority endpoint, workload token file and native listener. Run it only with disposable owner test dependencies.

Build with a Go workspace selecting the desired compatible runtime, Core, Authority client and hop revisions, then pass the resulting executable to the Accounts test:

```sh
cd qualification/installreceiver
go build -o /absolute/path/installreceiver .
shasum -a 256 /absolute/path/installreceiver
# From module-saas-starter/module/services/accounts/code, with the same cohort:
INSTALL_RECEIVER_BINARY=/absolute/path/installreceiver go test -count=1 -v -run '^TestCanonicalCombinedInstallQueueThroughRuntime$' ./pkg/adapters
```

Record the source and dependency revisions, workspace selection, binary hash, Codefly version, and test output alongside the run. A skipped test is not a crossing proof.
The nested module uses the published Records client; qualifying unreleased owner changes requires an explicit local Go workspace selecting the matching client, runtime, Core and Authority libraries. Do not commit local replacement paths.

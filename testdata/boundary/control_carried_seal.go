package solution

import carrier "github.com/codefly-dev/sdk-go/workcontext"

func installation(credential carrier.Credential) string { return credential.Seal().GetInstallationId() }

# Application packages

This directory is the additive npm workspace seam for application-owned
packages. The Next.js service agent owns only the framework substrate; it does
not define a product plugin contract or discover packages automatically.

Applications that expose a plugin SDK must keep its contract, explicit
composition root, validation, and release policy in the owning application.
Install a package by adding it here, declaring its exact dependency in the root
`package.json`, regenerating `package-lock.json`, and importing it explicitly
from application configuration.

Do not add filesystem scanning, side-effect registration, deployment URLs, or
product-specific behavior to this generic agent template.

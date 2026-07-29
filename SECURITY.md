# Security Policy

Constellation is pre-release. Security fixes are applied to the current development line and the latest supported release branch once releases exist.

Report suspected vulnerabilities with [GitHub private vulnerability reporting](https://github.com/ZShamsi987/Constellation/security/advisories/new). Include the affected revision, platform, reproduction steps, impact, and any suggested remediation. Do not include real prompts, credentials, private model URLs, or device keys. Maintainers will acknowledge reports within three business days, provide a severity assessment, coordinate a fix and disclosure window, and credit reporters who request attribution.

Public worker ports, disabled authentication on non-loopback interfaces, raw prompt logging, and bypasses of local node resource policy are release-blocking defects.

## Audited dependency exceptions

`RUSTSEC-2023-0071` is narrowly excepted while the upstream `rsa` crate has no
patched release. Constellation receives it through OpenID Connect and uses it
only to verify provider signatures with public keys; it never performs an RSA
private-key operation. Device and cluster private keys are Ed25519. Maintainers
must remove this exception when upstream publishes a patched path and must
re-review it before any public release.

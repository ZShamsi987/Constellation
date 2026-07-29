# Release Process

Constellation uses SemVer. Pre-1.0 minor releases may change native APIs only with an explicit migration guide; protocol and persisted-data compatibility still follow documented windows.

## Preparation

1. Freeze scope and confirm acceptance evidence and known limitations.
2. Update versions, changelog, compatibility matrix, migration/rollback instructions, attribution and third-party notices.
3. Run full unit, integration, E2E, security, chaos, performance, docs and platform suites.
4. Build from a clean tagged revision using locked dependencies.
5. Generate SBOMs and provenance; scan dependencies, licenses, secrets and artifacts.

## Signing and publication

Sign Git tags and release manifests. Code-sign Windows packages, sign and notarize macOS packages, sign Linux repositories/packages, and sign updater metadata separately. Publish checksums, SBOM, provenance, install/uninstall instructions and known limitations. Stable, beta and nightly channels have distinct keys and URLs.

## Rollout

Release to internal hardware, then nightly, beta and stable cohorts. Monitor opt-in content-free crash/update metrics. Pause automatically on signature, migration, crash-free, enrollment or request-success regression. Preserve the previous compatible artifact and metadata for rollback.

## Incident and rollback

Security incidents follow private coordination and key-rotation procedures. A bad release is withdrawn, updater metadata points to a safe version only when downgrade compatibility is verified, and users receive a precise advisory. Destructive migrations require a pre-update backup and tested restore path.

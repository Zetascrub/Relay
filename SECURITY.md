# Security policy

Reconclave is a development preview for authorised assessment on controlled
networks. The current main branch is the maintenance target; there is no LTS
release or guaranteed response schedule yet.

## Reporting a vulnerability

For the public repository, use **Security → Advisories → Report a vulnerability**:
https://github.com/Zetascrub/Reconclave/security/advisories/new

Private vulnerability reporting must be enabled when the repository becomes
public. While that form is unavailable, request a private contact channel from
`Zetascrub` without posting vulnerability details. Do not put credentials,
assessment data, deployment firmware or exploit details in public issues.
Include the affected commit, component, prerequisites, impact and a minimal
reproduction using synthetic data in the private report.

## Scope and trust boundaries

The desktop coordinator, web application, shared protocol, device firmware,
provisioning tools and release tooling are in scope. LAN requests, discovered
peers, browser requests, imported files and radio/tag data are untrusted inputs.
Fleet keys, signing keys, evidence and operator sessions are sensitive assets.

Security review should check authentication and authorisation before actions,
scope enforcement before network assessment, replay rejection, bounded input
handling, evidence integrity and secret handling. UI acknowledgement is not a
substitute for backend validation. These are required properties, not claims
that every implementation has been independently audited.

Reports about bypasses, unsafe parsing, exposed secrets, evidence tampering or
unauthorised updates are welcome. No finding classes are excluded by this policy.
Assess impact against the actual deployment and reachable interfaces; do not
assume that LAN access is trusted or that a test proves a control is correct.

## Current limitations

The development fleet profile uses provisioned HMAC keys and plain HTTP; it
authenticates protected requests but does not provide transport encryption.
Device builds contain deployment keys and must not be redistributed publicly.
Detached Ed25519 release manifests are verified by the release CLI; the firmware
and current OTA path do not enforce those manifests. Device Secure Boot and
flash encryption are not enabled by these tooling changes. See
[release signing](docs/releasing.md) and [fleet trust](docs/trust-architecture.md).
These limitations are not blanket exclusions for related vulnerabilities.

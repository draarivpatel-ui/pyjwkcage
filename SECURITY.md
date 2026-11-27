# Security Policy

## Supported Versions

The latest release on the `main` branch is supported.

## Reporting a Vulnerability

Privately report vulnerabilities through a GitHub Security Advisory for this repository. Do not open a public issue for a vulnerability that can be exploited before users have a fix.

Include a minimal reproduction, the affected version, the security impact, and whether the issue concerns algorithm confusion, key confusion, key leakage, remote key references, parser differentials, or denial of service.

## Boundary

pyjwkcage validates and selects key material. It does not perform cryptographic signing or verification and does not fetch remote key sets. Applications must use a correctly implemented cryptographic library after this firewall has rejected unsafe key material.

# Shared Workflows Migration Security Note

This repository explicitly opts into the centrally managed
`supply-chain-workflows@v1` compatibility channel. The platform repository
moves `v1` only after its validation suite passes; caller updates are not
required for compatible fixes within the major version.

Go-product releases use the shared tag-triggered release workflow. A maintainer
creates a draft GitHub release and publishes it. The resulting semantic-version
tag automatically starts the workflow, which builds and attests the example
binaries and attaches the signed SBOM and documentation to that existing
release without replacing its release notes. Manual release dispatch remains
reserved for services with deployment and post-deployment gates.

Line-level Zizmor exceptions permit symbolic references only on these managed
workflow calls. Third-party actions remain pinned to immutable commit SHAs.

## Behavior and trust boundaries

- Pull requests run Go CI, lint, CodeQL, govulncheck, workflow policy, and
  ShellCheck without repository write, signing, or publication authority.
- Main and semantic-version tag runs may sign SBOMs and publish evidence to
  Interlynk and ReARM. Manual runs fail closed unless they use `main` or a
  semantic-version tag.
- OSV scans the unsigned CycloneDX document. The signed envelope is reserved
  for evidence publishers.
- A valid zero-dependency SBOM produces explicit empty OSV reports. Interlynk
  publication is skipped because its service rejects documents with no
  dependency components.
- Cross-platform tests, example archives, documentation, GitHub Pages, and the
  existing release artifact layout remain repository-owned orchestration.

## Lightweight STRIDE review

| Threat | Control |
| --- | --- |
| Spoofed workflow dependency | Reusable workflows and third-party actions are pinned to reviewed commit SHAs. |
| Tampered evidence | The shared lifecycle signs and verifies the SBOM before publication; missing or malformed evidence fails the job. |
| Repudiated publication | GitHub run metadata and immutable workflow references identify the caller and implementation used. |
| Secret disclosure | PR jobs receive no publication secrets; checkout credentials are disabled; secrets are mapped only to publishing jobs. |
| Denial of service | Reusable jobs use timeouts, and OSV findings are advisory while scanner failures remain terminal. |
| Privilege escalation | Workflow-level permissions are read-only; write scopes remain confined to existing Pages and release jobs. |

## Required configuration names

Secrets: `SECURE_SBOM_API_KEY`, `INTERLYNK_TOKEN`,
`REARM_COMPONENT_API_ID`, and `REARM_COMPONENT_API_KEY`.

Variables: `SECURE_SBOM_SIGNING_KEY_ID`, `SECURE_SBOM_API_URL`,
`REARM_API_URL`, and `REARM_COMPONENT_ID`.

Dependency review is temporarily disabled because the repository dependency
graph is not enabled. Enable the graph, then remove the
`run-dependency-review: false` caller input to activate this shared check.

The module retains Go 1.25 language compatibility and now selects the Go
1.26.10 toolchain for builds. The shared govulncheck job found reachable
standard-library vulnerabilities in Go 1.25.7; disabling the check or building
release artifacts with that runtime would leave those flaws in place.

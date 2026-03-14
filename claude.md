# Hera

Auth security monitor: OAuth2/OIDC security testing and monitoring (JavaScript/Node.js).

## Commands

```bash
npm test                # Run unit tests
npm run test:integration # Run integration tests
npm run lint            # Lint
```

## Governing contracts

**IMPORTANT:** Read the relevant contract before starting any work.

Compact ruleset (60 rules, always loaded): @third_party/prompts/GOVERNANCE-SUMMARY.md
All governance contracts vendored from `cybermonkey/prompts` at `third_party/prompts/`:

| Contract | File | Governs |
|----------|------|---------|
| Session workflow | @third_party/prompts/SOAPIER.md | 14-step SOAPIER process |
| Documentation | @third_party/prompts/DOCUMENTATION.md | Diataxis, frontmatter, naming |
| Testing | @third_party/prompts/TESTING.md | 70/20/10, coverage, evidence |
| Workflow | @third_party/prompts/WORKFLOW.md | CI, PRs, branch lifecycle |
| Git Rules | @third_party/prompts/GIT-RULES.md | Signing, linear history |
| Security | @third_party/prompts/SECURITY.md | Secrets, OWASP, SLSA |
| Coordination | @third_party/prompts/COORDINATION.md | Multi-agent isolation |

## Approach

**Adversarial** — push back with evidence when claims lack rigor.

Security tools report facts they can verify, not guesses. Key principles:
- P0 (Critical): Fix immediately — broken functionality, security vulnerabilities, data loss
- P1 (High): Fix this week — performance, code quality
- P2 (Medium): Schedule for next sprint — feature integrations
- P3 (Low): Defer to future — advanced features, long-term improvements

## Historical context

Adversarial analysis session logs and design decisions are in `docs/adversarial/`:
- OAuth2 evidence collection review
- CVSS 4.0 implementation analysis
- Session management security review
- CSRF boundary analysis

## Cross-repo work

If a fix or issue belongs in a different cybermonkey repo:
1. Create the issue in the **target repo** first (`tea issues create --title`)
2. Use the **cross-repo ISoBAR template** from `third_party/prompts/COORDINATION.md`
3. Cross-link issues bidirectionally

Repo inventory: moni (backend, vhost11), hecate (gateway, vhost7), contracts (data contracts), aphrodite (UI), prompts (governance)

## Testing

@third_party/prompts/TESTING.md
@third_party/prompts/TESTING-JS.md

# electerm-web migration ledger

**Baseline:** 5.1.20 patches `0001`--`0005`, rooted at
`ab011d652e3750cb21b8f49bc0f3504f283036cd`.

**Imported source:** `f1deaf02fead7faa1bfb4381f69fbb734ea7f95f` (5.3.15).

No old patch is applied by this provenance-only import. Applying a diff written
for 5.1.20 would both invalidate the byte-for-byte lock and risk changing
security-sensitive behavior without reviewing the 5.3.15 control flow.

`Carry forward` means this PR enforces the intent in repository policy.
`Supersede` means a source-specific implementation must replace the old diff in
a later reviewed hardening PR. `Drop` means the old implementation or test is
not applicable to the immutable import; it is not an acceptance of the
underlying risk.

| Patch | Prior security behavior | Decision | Reason / successor |
|---|---|---|---|
| 0001 | Empty default AI endpoint and AI preset only when explicitly configured | Supersede | Runtime behavior is not copied into 5.3.15. Re-audit the current AI settings and implement an explicit egress policy against current code. |
| 0001 | Runtime npm module download allowed only with `ALLOW_RUNTIME_NPM_INSTALL=1` and an explicit option | Supersede | The 5.3.15 source still needs a source-specific runtime-extension review. This PR detects new executable-download shell patterns but does not claim to disable current application behavior. |
| 0001 | Default JWT lifetime reduced from 120 years to 12 hours | Supersede | Authentication and token handling must be re-evaluated against the new source before changing defaults. |
| 0001 | Docker build context excluded secrets and runtime state | Carry forward | Root ignore rules and explicit generated/vendor manifest keep imported source separate from local state; no deployment image is introduced here. |
| 0001 | `npm ci --ignore-scripts` and an `.npmrc` denying lifecycle scripts | Carry forward | CI/import never run npm, and every lifecycle hook now requires a hash-bound exception. A build-capable follow-up must keep `--ignore-scripts` as its default. |
| 0001 | Exact-save, peer-dependency workaround, and disabled npm fund/audit settings | Drop | These were operational settings for the 5.1.20 build, not source provenance. No package installation occurs in this PR. |
| 0001 | Pinned Docker base, source-only native rebuild, pruning, and non-root runtime image | Supersede | A new Dockerfile must be designed and reviewed for 5.3.15 after the dependency graph is audited; importing the old build recipe would execute unreviewed upstream build code. |
| 0002 | Cloudflare Access JWT validation with fixed RS256, issuer, audience, bounded key retrieval, and middleware before all routes | Supersede | Do not transplant security middleware across a major source change. Rebuild the integration from the current routing and authentication boundaries. |
| 0002 | Application token bound to the authenticated employee identity | Supersede | Depends on the replacement Cloudflare Access integration and current token model. |
| 0002 | Constant-time local shared-password comparison | Supersede | Re-evaluate the current local-login path before preserving or replacing shared-password fallback. |
| 0002 | Session ownership registry denies unknown and cross-user WebSocket attachment | Supersede | Requires a current session-lifecycle review; no 5.1.20 in-memory ownership code is copied. |
| 0002 | Claim/release hooks and WebSocket identity propagation | Supersede | Must accompany the replacement session ownership design so all creation and attachment paths are covered together. |
| 0002 | Cloudflare Access identity tests, including HS256 rejection | Drop | Tests target removed 5.1.20 modules. Their cases are retained as requirements for the replacement authentication test plan. |
| 0003 | Session-owner test suite for owner, stranger, unknown, and released sessions | Drop | Tests target the 5.1.20 ownership module; preserve the scenarios when the current design is implemented. |
| 0004 | Replace `registry.npmmirror.com` resolved URLs with `registry.npmjs.org` | Carry forward | The immutable import retains 106 historical mirror URLs only through a SHA-bound exception. New mirrors fail policy; a dependency-refresh PR must remove this exception without executing install scripts. |
| 0004 | Only WebDAV bookmark sync enabled by default; cloud, GitHub, and Gitee blocked | Supersede | Sync behavior must be mapped against 5.3.15 before changing data egress. |
| 0004 | CSP `connect-src 'self'` plus explicit admin extensions to block update/AI egress | Supersede | The current client/server asset model must be reviewed before issuing a CSP that could silently break required behavior. |
| 0004 | `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` | Supersede | Reintroduce as part of the current HTTP security-header review rather than copying an old middleware placement. |
| 0004 | Sync-policy test suite | Drop | Tests target the old sync module; retain the denied-target cases for the replacement suite. |
| 0005 | File-backed machine allowlist with exact host, port, CIDR, and wildcard rules; missing policy denies access | Supersede | The target-authorization boundary must be rebuilt against current session types and configuration ownership. |
| 0005 | Local shell reserved for admins and denied attempts logged | Supersede | Must be part of the replacement identity and authorization design, not an unreviewed port. |
| 0005 | Machine policy applied before both session creation and connection testing | Supersede | Current terminal and test-connection call paths require a complete review to avoid bypasses. |
| 0005 | Machine-policy test suite | Drop | Tests target the 5.1.20 module; preserve its allow/deny matrix when the current authorization layer is implemented. |

The only runtime claim made by this PR is negative: it does not execute
upstream source, lifecycle hooks, dependency installation, builds, or tests.

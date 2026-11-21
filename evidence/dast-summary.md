## ZAP baseline results

Counts represent alert types, not individual affected URLs.

- High: 0
- Medium: 3
- Low: 6
- Informational: 7

| Alert | Risk | Instances | CWE |
|---|---|---:|---|
| Absence of Anti-CSRF Tokens | Medium (Low) | 1 | 352 |
| Content Security Policy (CSP) Header Not Set | Medium (High) | 5 | 693 |
| Cross-Domain Misconfiguration | Medium (Medium) | 5 | 264 |
| Application Error Disclosure | Low (Medium) | 1 | 550 |
| Cookie No HttpOnly Flag | Low (Medium) | 5 | 1004 |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low (Medium) | 5 | 693 |
| Cross-Origin-Resource-Policy Header Missing or Invalid | Low (Medium) | 5 | 693 |
| Permissions Policy Header Not Set | Low (Medium) | 5 | 693 |
| Private IP Disclosure | Low (Medium) | 1 | 497 |
| Authentication Request Identified | Informational (High) | 2 | -1 |
| Modern Web Application | Informational (Medium) | 5 | -1 |
| Non-Storable Content | Informational (Medium) | 5 | 524 |
| Session Management Response Identified | Informational (Medium) | 12 | -1 |
| Storable and Cacheable Content | Informational (Medium) | 2 | 524 |
| Storable but Non-Cacheable Content | Informational (Medium) | 5 | 524 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational (Low) | 8 | 20 |

Scope: unauthenticated spider and passive checks of the main Django application.
Isolated exercise containers and authenticated pages are outside this scan's coverage.

# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/nlevenov/SecPosture/security/advisories/new).
Reports are acknowledged within 72 hours.

## Threat model

SecPosture connects to hosts (locally or over SSH) and reads their
configuration. A target may be misconfigured or already compromised, so every
byte it reads is treated as untrusted, and the tool is designed so that
pointing it at a host can never change or harm that host.

| Threat | Mitigation |
|--------|------------|
| The auditor modifying or damaging the target | Collectors expose only read_file / stat / list_dir / a fixed read-only command allowlist. No mutating command exists in the allowlist; no caller-supplied command can run. |
| Command injection via the SSH target | `user@host` is parsed by a strict validator (LDH host / POSIX user, or an IP); anything with shell metacharacters or option-like values is rejected before a connection is attempted. |
| Command injection via commands over SSH | Commands come from the fixed allowlist and every argument is `shlex.quote`d; `PATH`/`LC_ALL` are pinned. |
| Man-in-the-middle on SSH | Host keys are verified against a `known_hosts` file; an unknown or changed key aborts the audit (no trust-on-first-use). |
| Hostile data hijacking the terminal | All target-derived text is stripped of control characters (including ESC), so ANSI escape injection into the terminal is impossible. |
| Stored XSS in the HTML report | Jinja2 autoescaping is on; evidence is rendered as text; the only `|safe` content is SVG generated from numeric counts. |
| Shell injection via the generated remediation script | The script never runs itself (requires `--i-have-reviewed-this`), and every target-derived value (file names, user names, package names) is `shlex.quote`d. |
| Tampered audit results / baselines | Results carry an HMAC-SHA256 signature when a signing key is set (SHA-256 checksum otherwise); loads verify it and the dashboard flags unsigned/invalid results. |
| Resource exhaustion from a hostile target | Filesystem scans use `-xdev` and a timeout (degrade to an ERROR finding, never hang); file reads are size-capped; per-finding evidence is bounded. |
| Scanning hosts you do not control | Active work only ever targets the single host passed to `audit`/`--ssh`; there is no network discovery or sweeping. |
| Unauthorized dashboard access | scrypt password (bounded cost parameters); fails closed with no password; per-session and global brute-force lockout; session expiry. |
| CSRF / DNS rebinding on the dashboard | Streamlit XSRF protection with a SameSite=Strict cookie, `allowedHosts` allow-list, CORS on, loopback binding by default. |
| Credential exposure | SSH passwords come from `getpass`/agent and are never written to disk or logs; the dashboard password is only ever stored as a scrypt hash; config secrets come from environment variables. |
| Malicious model/pickle loading | SecPosture loads no pickled code; results and advisories are JSON, parsed with `json`/`yaml.safe_load`. |
| Vulnerable dependencies | `pip-audit` and `bandit` run in CI; Dependabot updates pip, Actions and Docker. |

## Limits

- Controls assess configuration and known-vulnerability metadata. They do not
  detect a host that is already compromised, and they do not exploit anything.
- Advisory matching is only as current as the feed you provide. The bundled
  sample is a single example; use a real OSV feed or the live API for coverage.
- The dashboard password is a single shared secret. Put the dashboard behind a
  TLS reverse proxy and add SSO / client certificates there if several people
  need access.

## Deployment notes

- Prefer the SSH collector with key authentication and a maintained
  `known_hosts`; run as root (or a role account that can read the audited
  files) for complete results.
- Set `signing_key` so saved results and baselines are authenticated.
- Serve the dashboard on loopback and publish it only through a TLS proxy;
  set `dashboard.allowed_hosts` to the proxy host name.

# Architecture

## Pipeline

`run_audit(collector, settings)` ([`audit.py`](../src/secposture/audit.py)):

1. **Collect** - `host_info()` and `gather()`
   ([`collectors/gather.py`](../src/secposture/collectors/gather.py)) build a
   `HostFacts` from read-only sources: `sshd_config` (+ `sshd_config.d`),
   `login.defs`, `passwd`/`group`/`shadow`, `sysctl -a`, listening sockets
   (`ss`), installed packages (`dpkg`/`rpm`), running services, SUID/SGID and
   world-writable/unowned files (`find -xdev`), firewall state, mounts and the
   permissions of sensitive files. Collection is defensive: one failing source
   becomes a collection note, not an aborted audit.
2. **Evaluate** - every registered control
   ([`controls/`](../src/secposture/controls)) is a pure function of
   `HostFacts` + `CheckContext` returning a `CheckOutcome`. Controls never
   touch the target, so the whole catalog is unit-tested with fixtures.
3. **Scan packages** - `advisories.scan_packages()` matches installed packages
   against OSV advisories.
4. **Score** - `scoring.score()` computes the severity-weighted posture score
   and A-F grade.

## Collectors

A `Collector` exposes four primitives: `read_file`, `stat_file`, `list_dir`,
and `run(key)` where `key` indexes a **fixed command allowlist**
([`collectors/base.py`](../src/secposture/collectors/base.py)). This is the
safety boundary - no method takes a caller-supplied command and no target value
is ever interpolated into one.

- `LocalCollector` reads the local filesystem and runs commands with an
  explicit argv (no shell).
- `SSHCollector` verifies the host key against `known_hosts`, reads files over
  SFTP, and runs the allowlisted commands with every argument `shlex.quote`d.

Because facts are gathered once and controls are pure, a local audit and an SSH
audit of the same host produce identical findings (verified by an integration
test against a real `sshd`).

## Controls

Registered with a decorator that records metadata (id, title, category,
severity, rationale, remediation, profiles, references). A control returns
`pass` / `fail` / `warn` / `not_applicable` / `error` / `manual`. SSH directives
fall back to the OpenSSH compiled-in default when absent, so the audit reflects
effective behaviour. A control that raises becomes an `error` finding and never
sinks the audit.

## Advisories

[`advisories/`](../src/secposture/advisories) parses OSV records, determines the
host's ecosystem from `/etc/os-release` + package manager (so a Ubuntu host is
not matched by a Debian-only advisory), and evaluates each affected range with
the target's **native version comparison** - faithful implementations of dpkg
`verrevcmp` and rpm `rpmvercmp`. Severity comes from a built-in **CVSS 3.1**
base-score calculator when the advisory carries a vector.

## Scoring

Score = share of severity-weighted controls passed (`critical` 40, `high` 20,
`medium` 8, `low` 3, `info` 1); a `warn` earns half credit; `not_applicable` /
`manual` / `error` are excluded. One critical failure therefore costs far more
than many low ones. Package vulnerabilities score like failed controls of the
same severity.

## Reports & integrity

The HTML report ([`report/`](../src/secposture/report)) is self-contained
(inline SVG charts, no external assets) and autoescaped. Results and baselines
are serialized with a detached HMAC signature (or SHA-256 checksum) and verified
on load. The remediation script is review-gated and shell-quotes every
target-derived value.

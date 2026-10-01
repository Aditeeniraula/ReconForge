# ReconForge

An asynchronous **network reconnaissance & vulnerability-assessment framework** for
authorized security testing. Point it at a host you're allowed to test and it will
port-scan, fingerprint the live services, inspect TLS and HTTP, match findings against
a vulnerability signature database, and produce a ranked report (console, JSON, HTML).

> ⚠️ **Authorized use only.** ReconForge ships with a scope gate (see below) that
> refuses to scan public addresses unless you both list them as in-scope *and* pass an
> explicit authorization acknowledgement. Scanning systems you don't own or have written
> permission to test is illegal in most jurisdictions.

---

## Highlights

- **Async connect scanner** — bounded-concurrency `asyncio` port scanning; distinguishes
  open / closed / filtered.
- **Service fingerprinting** — banner grabbing + regex signatures for SSH, HTTP servers,
  Redis, SMTP, MySQL, and more, extracting product & version.
- **TLS inspection** — negotiated protocol/cipher, certificate expiry, self-signed detection.
- **HTTP hygiene** — server/tech identification, page title, and *missing security headers*.
- **Vulnerability engine** — version-range CVE matching + service-exposure heuristics from a
  JSON signature DB you can extend without touching code.
- **Scope gate** — a hard authorization boundary that makes accidental out-of-scope scans fail closed.
- **Reports** — human console output, machine-readable JSON, and a self-contained HTML report.
- **CI-friendly** — exits non-zero when high/critical findings are present.

## Architecture

```
             ┌── authorization.py  (scope gate — runs first, fails closed)
             │
target ─► engine.assess_host ─► scanner.py      (async TCP scan)
             │                   fingerprint.py (banner → service/product/version)
             │                   tls_probe.py   (cert + protocol)
             │                   http_probe.py  (headers, tech, hygiene)
             │
             └─► vulndb.py (signatures + heuristics) ─► report.py (text / JSON / HTML)
```

## Quick start

No third-party dependencies for the tool itself (pure standard library). Python 3.11+.

```bash
# 1. Start the bundled harmless demo target (binds a few loopback ports)
python demo_target.py

# 2. In another terminal, scan it and generate an HTML report
python -m reconforge 127.0.0.1 --ports 2222,6380,8088 --html report.html --json report.json
```

You'll see the old-OpenSSH, unauthenticated-Redis, and missing-header findings, and
`report.html` will contain the full styled write-up.

## Usage

```
python -m reconforge <target> [options]

  --top                 scan the built-in high-signal port set (default)
  --ports 22,80,8000-8100   custom ports / ranges
  --all                 scan all 65535 TCP ports (slow)
  --scope HOST/CIDR     in-scope target (repeatable); required for public hosts
  --i-am-authorized     acknowledge you have permission to test public targets
  --concurrency N       max simultaneous connects (default 200)
  --timeout SECONDS     per-port connect timeout (default 1.5)
  --json PATH           write a JSON report
  --html PATH           write an HTML report
```

Private, loopback, and RFC-5737 documentation ranges are always allowed (your lab).
A public target requires **both** `--scope` covering it **and** `--i-am-authorized`:

```bash
python -m reconforge assets.example.com \
    --scope assets.example.com --scope 198.51.100.0/24 \
    --i-am-authorized --html engagement.html
```

## Extending the vuln database

Edit `data/vuln_signatures.json` — no code changes needed:

- `version_rules`: `{product, max_version, title, severity, cve, recommendation, references}`
  — fires when a detected product's version is `<= max_version`.
- `service_rules`: `{service, condition, title, severity, recommendation}`
  — `condition: "exposed"` fires on presence; `"unauthenticated"` fires on a no-auth banner tell.

## Tests

```bash
pip install pytest pytest-asyncio
pytest -q
```

The suite covers the scope gate, version comparison, fingerprint signatures, the vuln
engine, and a full end-to-end scan against throwaway loopback servers (18 tests).

## Project layout

```
reconforge/
  authorization.py   scope gate
  scanner.py         async TCP connect scanner
  fingerprint.py     banner grabbing + service ID
  tls_probe.py       TLS cert/protocol inspection
  http_probe.py      HTTP fingerprint + header hygiene
  vulndb.py          signature matching engine
  engine.py          orchestration pipeline
  report.py          text / JSON / HTML rendering
  cli.py             argparse entry point
data/vuln_signatures.json
demo_target.py       harmless local target for a full end-to-end run
tests/               pytest suite
```

## Legal & ethics

ReconForge performs **detection and assessment** only — it does not weaponize or exploit.
Use it only against systems you own or have explicit written authorization to test, and
operate within the rules of engagement for your assessment.

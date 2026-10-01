# Portfolio Summary — ReconForge

## Short version (2–3 lines)

**ReconForge** — an asynchronous network reconnaissance and vulnerability-assessment
framework in pure Python. It port-scans a target, fingerprints live services from their
banners, inspects TLS and HTTP configuration, and matches the results against a
vulnerability signature database to produce ranked console/JSON/HTML reports — all behind
a built-in authorization gate that prevents out-of-scope scanning.

## One-liner

Async Python recon & vulnerability-assessment framework: concurrent port scanning, service
fingerprinting, TLS/HTTP inspection, and CVE signature matching, with a safety-first scope gate.

## Résumé bullet points

- Built an async vulnerability-assessment framework (Python `asyncio`, zero third-party
  dependencies) performing concurrent TCP scanning, banner-based service fingerprinting, and
  TLS/HTTP inspection.
- Designed a JSON-driven detection engine matching detected product versions and exposed
  services against CVE signatures, generating severity-ranked HTML/JSON reports.
- Implemented a fail-closed authorization "scope gate" that blocks scanning of out-of-scope
  or public hosts without explicit consent — security-by-design.
- Delivered an 18-test suite (incl. end-to-end scans against throwaway servers) and a
  self-contained demo target for reproducible runs.

## Key facts for interviews

- **Language/stack:** Python 3.11+, standard library only (`asyncio`, `ssl`, `socket`, `re`).
- **Size:** ~9 focused modules + tests + demo target.
- **Tested:** 18 passing tests covering the scope gate, version comparison, fingerprint
  signatures, the vuln engine, and full end-to-end scans.
- **Design themes:** async concurrency, separation of concerns (scanner / probes / engine /
  report), extensibility (add detections via JSON, no code changes), and ethical safety controls.

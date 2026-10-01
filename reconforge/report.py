"""Report rendering — JSON for machines, HTML for humans, text for the console."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime

from .models import HostReport, Severity

_SEV_COLOR = {
    "critical": "#b3123b", "high": "#d9480f", "medium": "#c9820a",
    "low": "#2b6cb0", "info": "#4a5568",
}


def to_dict(report: HostReport) -> dict:
    d = asdict(report)
    d["scanned_at"] = report.scanned_at.isoformat()
    d["summary"] = {
        "open_ports": len(report.open_ports),
        "findings": len(report.findings),
        "max_severity": report.max_severity.value,
    }
    return d


def to_json(report: HostReport, *, indent: int = 2) -> str:
    return json.dumps(to_dict(report), indent=indent, default=str)


def to_text(report: HostReport) -> str:
    lines = [
        f"Target:      {report.target} ({report.resolved_ip})",
        f"Scanned at:  {report.scanned_at.isoformat()}",
        f"Open ports:  {len(report.open_ports)}   "
        f"Findings: {len(report.findings)}   "
        f"Max severity: {report.max_severity.value.upper()}",
        "",
        "OPEN PORTS",
        "-" * 60,
    ]
    for p in report.open_ports:
        svc = "/".join(x for x in (p.service, p.product, p.version) if x) or "unknown"
        lat = f"{p.latency_ms:.0f}ms" if p.latency_ms is not None else "-"
        lines.append(f"  {p.port:>5}/tcp  {svc:<34} {lat}")
    if report.findings:
        lines += ["", "FINDINGS", "-" * 60]
        for f in report.findings:
            tag = f"[{f.severity.value.upper()}]"
            cve = f" ({f.cve})" if f.cve else ""
            lines.append(f"  {tag:<11} {f.title}{cve}  :{f.port}")
            lines.append(f"              evidence: {f.evidence}")
            lines.append(f"              fix: {f.recommendation}")
    else:
        lines += ["", "No findings."]
    return "\n".join(lines)


def to_html(report: HostReport) -> str:
    def esc(x) -> str:
        return html.escape(str(x)) if x is not None else ""

    rows = []
    for p in report.open_ports:
        svc = " ".join(x for x in (p.product, p.version) if x) or (p.service or "")
        extra = []
        if p.http and p.http.get("title"):
            extra.append(f"title: {esc(p.http['title'])}")
        if p.tls and p.tls.get("protocol"):
            extra.append(f"{esc(p.tls['protocol'])}")
        rows.append(
            f"<tr><td class='mono'>{p.port}/tcp</td><td>{esc(p.service)}</td>"
            f"<td>{esc(svc)}</td><td class='dim'>{'; '.join(extra)}</td></tr>"
        )

    finding_cards = []
    for f in report.findings:
        color = _SEV_COLOR[f.severity.value]
        refs = "".join(
            f"<a href='{esc(r)}'>{esc(r)}</a> " for r in f.references
        )
        cve = f"<span class='cve'>{esc(f.cve)}</span>" if f.cve else ""
        finding_cards.append(f"""
        <div class="card" style="border-left-color:{color}">
          <div class="card-head">
            <span class="sev" style="background:{color}">{f.severity.value.upper()}</span>
            <span class="title">{esc(f.title)}</span>{cve}
            <span class="port">:{f.port} {esc(f.service)}</span>
          </div>
          <div class="evidence"><b>Evidence:</b> {esc(f.evidence)}</div>
          <div class="fix"><b>Recommendation:</b> {esc(f.recommendation)}</div>
          {f"<div class='refs'>{refs}</div>" if refs else ""}
        </div>""")

    if not finding_cards:
        finding_cards.append("<p class='dim'>No findings surfaced for this host.</p>")

    sev = report.max_severity.value
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconForge — {esc(report.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0; background:#f6f7f9; color:#1a202c; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#14161a; color:#e4e6eb; }}
    .panel {{ background:#1d2027 !important; }} th {{ background:#242832 !important; }} }}
  header {{ background:linear-gradient(120deg,#1a2b4a,#2b1a4a); color:#fff; padding:28px 32px; }}
  header h1 {{ margin:0 0 4px; font-size:22px; letter-spacing:.5px; }}
  header .meta {{ opacity:.85; font-size:13px; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 32px; }}
  .stat-row {{ display:flex; gap:14px; margin:-40px 0 24px; }}
  .stat {{ flex:1; background:#fff; border-radius:10px; padding:16px; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
  .panel {{ background:#fff; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
  .stat .n {{ font-size:26px; font-weight:700; }} .stat .l {{ font-size:12px; opacity:.7; text-transform:uppercase; letter-spacing:.5px; }}
  h2 {{ font-size:16px; margin:28px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:10px; }}
  th,td {{ text-align:left; padding:9px 14px; font-size:13px; }}
  th {{ background:#eef0f4; }} tr:nth-child(even) td {{ background:rgba(128,128,128,.05); }}
  .mono {{ font-family:ui-monospace,monospace; }} .dim {{ opacity:.6; }}
  .card {{ background:inherit; border:1px solid rgba(128,128,128,.2); border-left-width:5px;
    border-radius:8px; padding:14px 16px; margin:10px 0; }}
  .card-head {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px; }}
  .title {{ font-weight:600; }} .port {{ opacity:.6; font-size:12px; font-family:ui-monospace,monospace; }}
  .cve {{ font-size:11px; background:#333; color:#fff; padding:2px 6px; border-radius:4px; }}
  .evidence,.fix {{ font-size:13px; margin-top:6px; }} .evidence b,.fix b {{ opacity:.7; }}
  .refs a {{ font-size:11px; color:#3182ce; margin-right:8px; word-break:break-all; }}
  .badge-{sev} {{ text-transform:uppercase; }}
  footer {{ text-align:center; font-size:12px; opacity:.5; padding:24px; }}
</style></head>
<body>
<header>
  <h1>🛡 ReconForge Assessment</h1>
  <div class="meta">{esc(report.target)} → {esc(report.resolved_ip)} · {esc(report.scanned_at.strftime("%Y-%m-%d %H:%M UTC"))}</div>
</header>
<div class="wrap">
  <div class="stat-row">
    <div class="stat"><div class="n">{len(report.open_ports)}</div><div class="l">Open ports</div></div>
    <div class="stat"><div class="n">{len(report.findings)}</div><div class="l">Findings</div></div>
    <div class="stat"><div class="n" style="color:{_SEV_COLOR[sev]}">{sev.upper()}</div><div class="l">Max severity</div></div>
  </div>
  <h2>Open ports &amp; services</h2>
  <div class="panel"><table>
    <tr><th>Port</th><th>Service</th><th>Product</th><th>Detail</th></tr>
    {''.join(rows) or "<tr><td colspan=4 class='dim'>No open ports.</td></tr>"}
  </table></div>
  <h2>Findings</h2>
  {''.join(finding_cards)}
</div>
<footer>Generated by ReconForge {esc(datetime.now().year)} · authorized security testing only</footer>
</body></html>"""

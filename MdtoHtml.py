#!/usr/bin/env python3
"""
nuclei2html - Convert Nuclei markdown reports (.md) to clean HTML dashboards.

Supports:
  - Nuclei `-me` (markdown export) directory or single .md file
  - Nuclei `-o` plain text output converted to .md
  - Generic markdown with severity tags

Usage:
  python3 nuclei2html.py report.md                 # single file
  python3 nuclei2html.py ./nuclei-results/          # directory of .md files
  python3 nuclei2html.py report.md -o report.html   # custom output
  python3 nuclei2html.py report.md --title "Pentest Acme Corp"
"""

import argparse
import html
import json
import os
import re
import sys
import hashlib
from datetime import datetime
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field


# ── Data model ──────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#2ecc71",
    "info":     "#3498db",
    "unknown":  "#95a5a6",
}


@dataclass
class Finding:
    template_id: str = ""
    name: str = ""
    severity: str = "unknown"
    host: str = ""
    matched_at: str = ""
    description: str = ""
    reference: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    raw_block: str = ""
    metadata: dict = field(default_factory=dict)
    extracted_results: str = ""
    matcher_name: str = ""
    curl_command: str = ""
    timestamp: str = ""

    @property
    def uid(self):
        blob = f"{self.template_id}:{self.matched_at}:{self.name}"
        return hashlib.md5(blob.encode()).hexdigest()[:10]


# ── Parsers ─────────────────────────────────────────────────────────────────

def parse_nuclei_md_export(content: str) -> list[Finding]:
    """Parse a single Nuclei -me markdown file (one finding per file typically)."""
    findings = []
    # Split on H1/H2/H3 headers that look like finding titles
    blocks = re.split(r'(?=^#{1,3}\s+)', content, flags=re.MULTILINE)

    for block in blocks:
        block = block.strip()
        if not block:
            continue
        f = _parse_block(block)
        if f and (f.template_id or f.name or f.matched_at):
            findings.append(f)

    # If no structured findings found, try line-based parsing (plain nuclei output)
    if not findings:
        findings = _parse_plain_output(content)

    return findings


def _parse_block(block: str) -> Finding | None:
    """Parse a markdown block into a Finding."""
    f = Finding(raw_block=block)

    # Extract title from header
    title_m = re.match(r'^#{1,3}\s+(.+)', block)
    if title_m:
        raw_title = title_m.group(1).strip()
        f.name = re.sub(r'\s*\[.*?\]\s*$', '', raw_title)  # remove trailing [severity]

        sev_m = re.search(r'\[(critical|high|medium|low|info)\]', raw_title, re.I)
        if sev_m:
            f.severity = sev_m.group(1).lower()

    lines = block.splitlines()

    for line in lines:
        line_stripped = line.strip().lstrip('- ').lstrip('* ')

        # Key-value patterns common in Nuclei md exports
        kv = re.match(r'\*\*(.+?)\*\*\s*[:：]\s*(.*)', line_stripped)
        if not kv:
            kv = re.match(r'(\w[\w\s\-]+?)\s*[:：]\s+(.*)', line_stripped)

        if kv:
            key = kv.group(1).strip().lower().replace(' ', '_').replace('-', '_')
            val = kv.group(2).strip()

            if key in ('template', 'template_id', 'id'):
                f.template_id = val.strip('`[] ')
            elif key in ('severity', 'sev'):
                f.severity = val.strip('`[] ').lower()
            elif key in ('host', 'target'):
                f.host = val.strip('`<> ')
            elif key in ('matched_at', 'matched', 'url', 'matched_url', 'endpoint'):
                f.matched_at = val.strip('`<> ')
            elif key in ('description', 'desc', 'detail', 'details'):
                f.description = val
            elif key in ('tags', 'tag'):
                f.tags = [t.strip() for t in val.split(',')]
            elif key in ('reference', 'references', 'ref'):
                f.reference = [r.strip().strip('-* ') for r in val.split(',')]
            elif key in ('matcher_name', 'matcher'):
                f.matcher_name = val
            elif key in ('curl_command', 'curl'):
                f.curl_command = val
            elif key in ('extracted_results', 'extracted', 'result', 'results'):
                f.extracted_results = val
            elif key == 'timestamp':
                f.timestamp = val
            else:
                f.metadata[key] = val

    # Try to extract description from remaining paragraph text
    if not f.description:
        # Grab non-header, non-kv paragraph lines
        desc_lines = []
        for line in lines[1:]:  # skip header
            s = line.strip()
            if not s or s.startswith('**') or re.match(r'\w+\s*:', s) or s.startswith('#'):
                if desc_lines:
                    break
                continue
            if s.startswith('- ') or s.startswith('* '):
                continue
            desc_lines.append(s)
        if desc_lines:
            f.description = ' '.join(desc_lines)

    # Extract references from markdown links
    if not f.reference:
        refs = re.findall(r'https?://\S+', block)
        if refs and f.host:
            f.reference = [r.rstrip(')>]') for r in refs if f.host not in r][:5]

    # If no host but matched_at present, derive host
    if not f.host and f.matched_at:
        hm = re.match(r'(https?://[^/]+)', f.matched_at)
        if hm:
            f.host = hm.group(1)

    return f


def _parse_plain_output(content: str) -> list[Finding]:
    """Parse plain Nuclei stdout-style output lines pasted into a markdown file.
    Format: [template-id] [protocol] [severity] host/url [extra]
    or:     [2024-01-01T...] [template-id] [protocol] [severity] host [matched]
    """
    findings = []
    pattern = re.compile(
        r'\[(?P<ts>\d{4}-\d{2}-\d{2}T[\d:]+[^\]]*)\]\s*'  # optional timestamp
        r'?\[?(?P<tid>[a-zA-Z0-9_\-/:.]+)\]?\s*'
        r'\[(?P<proto>\w+)\]\s*'
        r'\[(?P<sev>critical|high|medium|low|info)\]\s*'
        r'(?P<url>\S+)',
        re.I
    )
    # Simpler pattern without timestamp
    pattern2 = re.compile(
        r'\[(?P<tid>[a-zA-Z0-9_\-/:.]+)\]\s*'
        r'\[(?P<proto>\w+)\]\s*'
        r'\[(?P<sev>critical|high|medium|low|info)\]\s*'
        r'(?P<url>\S+)',
        re.I
    )

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Strip ANSI color codes
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)

        m = pattern.search(line) or pattern2.search(line)
        if m:
            gd = m.groupdict()
            f = Finding(
                template_id=gd.get('tid', ''),
                severity=gd.get('sev', 'unknown').lower(),
                matched_at=gd.get('url', ''),
                timestamp=gd.get('ts', ''),
            )
            f.name = f.template_id.replace('-', ' ').replace('/', ' › ').title()
            hm = re.match(r'(https?://[^/]+)', f.matched_at)
            if hm:
                f.host = hm.group(1)
            f.metadata['protocol'] = gd.get('proto', '')
            findings.append(f)

    return findings


def load_findings(path: str) -> list[Finding]:
    """Load findings from a file or directory."""
    p = Path(path)
    findings = []

    if p.is_dir():
        for md_file in sorted(p.rglob('*.md')):
            with open(md_file, 'r', encoding='utf-8', errors='replace') as fh:
                findings.extend(parse_nuclei_md_export(fh.read()))
    elif p.is_file():
        with open(p, 'r', encoding='utf-8', errors='replace') as fh:
            findings.extend(parse_nuclei_md_export(fh.read()))
    else:
        print(f"[!] Path not found: {path}", file=sys.stderr)
        sys.exit(1)

    # Deduplicate
    seen = set()
    deduped = []
    for f in findings:
        if f.uid not in seen:
            seen.add(f.uid)
            deduped.append(f)

    # Sort by severity
    deduped.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return deduped


# ── HTML generation ─────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return html.escape(str(s))


def generate_html(findings: list[Finding], title: str = "Nuclei Report") -> str:
    stats = Counter(f.severity for f in findings)
    hosts = sorted(set(f.host for f in findings if f.host))
    tags_all = sorted(set(t for f in findings for t in f.tags))
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stats_json = json.dumps({k: stats.get(k, 0) for k in SEVERITY_ORDER})
    colors_json = json.dumps(SEVERITY_COLORS)

    # Build findings JSON for JS filtering
    findings_data = []
    for f in findings:
        findings_data.append({
            "uid": f.uid,
            "template_id": f.template_id,
            "name": f.name,
            "severity": f.severity,
            "host": f.host,
            "matched_at": f.matched_at,
            "tags": f.tags,
        })
    findings_json = json.dumps(findings_data)

    # Build finding cards HTML
    cards_html = []
    for f in findings:
        sev = f.severity
        color = SEVERITY_COLORS.get(sev, "#95a5a6")

        refs_html = ""
        if f.reference:
            refs_items = "".join(
                f'<a href="{_esc(r)}" target="_blank" rel="noopener">{_esc(r[:80])}</a><br>'
                for r in f.reference if r.startswith("http")
            )
            if refs_items:
                refs_html = f'<div class="finding-refs"><span class="label">References</span>{refs_items}</div>'

        tags_html = ""
        if f.tags:
            tags_html = '<div class="finding-tags">' + "".join(
                f'<span class="tag">{_esc(t)}</span>' for t in f.tags
            ) + '</div>'

        extra_html = ""
        if f.extracted_results:
            extra_html += f'<div class="finding-extra"><span class="label">Extracted</span><pre>{_esc(f.extracted_results)}</pre></div>'
        if f.curl_command:
            extra_html += f'<div class="finding-extra"><span class="label">cURL</span><pre>{_esc(f.curl_command)}</pre></div>'
        if f.matcher_name:
            extra_html += f'<div class="finding-meta-item"><span class="label">Matcher</span> {_esc(f.matcher_name)}</div>'

        meta_html = ""
        if f.metadata:
            items = "".join(
                f'<div class="finding-meta-item"><span class="label">{_esc(k)}</span> {_esc(v)}</div>'
                for k, v in f.metadata.items()
            )
            meta_html = f'<div class="finding-metadata">{items}</div>'

        matched_display = ""
        if f.matched_at:
            matched_display = f'<div class="finding-url"><code>{_esc(f.matched_at)}</code></div>'

        cards_html.append(f'''
        <div class="finding-card" data-uid="{f.uid}" data-severity="{sev}" data-host="{_esc(f.host)}" data-tags="{_esc(",".join(f.tags))}">
            <div class="finding-header">
                <span class="severity-badge sev-{sev}">{sev.upper()}</span>
                <span class="finding-title">{_esc(f.name or f.template_id or "Unnamed")}</span>
            </div>
            {f'<div class="finding-tid"><code>{_esc(f.template_id)}</code></div>' if f.template_id else ""}
            {matched_display}
            {f'<div class="finding-host">{_esc(f.host)}</div>' if f.host and f.host != f.matched_at else ""}
            {f'<div class="finding-desc">{_esc(f.description)}</div>' if f.description else ""}
            {tags_html}
            {extra_html}
            {meta_html}
            {refs_html}
        </div>''')

    all_cards = "\n".join(cards_html)

    # Host filter options
    host_options = "".join(f'<option value="{_esc(h)}">{_esc(h)}</option>' for h in hosts)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;600;700&display=swap');

:root {{
    --bg:        #0a0e17;
    --bg-card:   #111827;
    --bg-hover:  #1a2332;
    --border:    #1e293b;
    --text:      #e2e8f0;
    --text-dim:  #64748b;
    --accent:    #22d3ee;
    --accent2:   #a78bfa;
    --critical:  {SEVERITY_COLORS["critical"]};
    --high:      {SEVERITY_COLORS["high"]};
    --medium:    {SEVERITY_COLORS["medium"]};
    --low:       {SEVERITY_COLORS["low"]};
    --info:      {SEVERITY_COLORS["info"]};
    --unknown:   {SEVERITY_COLORS["unknown"]};
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
    --font-sans: 'Outfit', system-ui, sans-serif;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    line-height: 1.6;
    min-height: 100vh;
}}

/* ── Topbar ─────────── */
.topbar {{
    background: linear-gradient(135deg, #0f172a 0%, #1a1040 100%);
    border-bottom: 1px solid var(--border);
    padding: 1.5rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
}}
.topbar h1 {{
    font-size: 1.4rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}}
.topbar h1 .icon {{
    color: var(--accent);
    font-size: 1.2rem;
}}
.topbar .meta {{
    font-size: 0.78rem;
    color: var(--text-dim);
    font-family: var(--font-mono);
}}

/* ── Stats bar ──────── */
.stats-bar {{
    display: flex;
    gap: 0.5rem;
    padding: 1.2rem 2rem;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    align-items: center;
}}
.stat-chip {{
    display: flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.4rem 0.9rem;
    border-radius: 6px;
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    border: 1px solid var(--border);
    cursor: pointer;
    transition: all 0.15s;
    user-select: none;
}}
.stat-chip:hover {{ opacity: 0.85; transform: translateY(-1px); }}
.stat-chip.active {{ box-shadow: 0 0 0 2px currentColor; }}
.stat-chip .dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.stat-total {{
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 0.82rem;
    color: var(--text-dim);
}}

/* ── Filters ────────── */
.filters {{
    padding: 0.8rem 2rem;
    display: flex;
    gap: 0.8rem;
    flex-wrap: wrap;
    align-items: center;
    border-bottom: 1px solid var(--border);
}}
.search-box {{
    flex: 1;
    min-width: 200px;
    max-width: 400px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.8rem;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 0.82rem;
    outline: none;
    transition: border-color 0.15s;
}}
.search-box:focus {{ border-color: var(--accent); }}
.search-box::placeholder {{ color: var(--text-dim); }}

select.filter-select {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.8rem;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 0.82rem;
    outline: none;
    cursor: pointer;
}}
select.filter-select:focus {{ border-color: var(--accent); }}

.counter {{
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-dim);
}}

/* ── Findings ───────── */
.findings {{
    padding: 1.2rem 2rem 3rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    max-width: 1200px;
}}
.finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    transition: all 0.15s;
    border-left: 3px solid var(--border);
}}
.finding-card:hover {{
    background: var(--bg-hover);
    border-left-color: var(--accent);
}}
.finding-card[data-severity="critical"] {{ border-left-color: var(--critical); }}
.finding-card[data-severity="high"]     {{ border-left-color: var(--high); }}
.finding-card[data-severity="medium"]   {{ border-left-color: var(--medium); }}
.finding-card[data-severity="low"]      {{ border-left-color: var(--low); }}
.finding-card[data-severity="info"]     {{ border-left-color: var(--info); }}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin-bottom: 0.5rem;
}}
.severity-badge {{
    font-family: var(--font-mono);
    font-size: 0.68rem;
    font-weight: 700;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    flex-shrink: 0;
}}
.sev-critical {{ background: var(--critical); color: #fff; }}
.sev-high     {{ background: var(--high); color: #fff; }}
.sev-medium   {{ background: var(--medium); color: #1a1a1a; }}
.sev-low      {{ background: var(--low); color: #1a1a1a; }}
.sev-info     {{ background: var(--info); color: #fff; }}
.sev-unknown  {{ background: var(--unknown); color: #fff; }}

.finding-title {{
    font-weight: 600;
    font-size: 0.95rem;
}}
.finding-tid {{
    font-size: 0.78rem;
    margin-bottom: 0.3rem;
}}
.finding-tid code {{
    color: var(--accent2);
    font-family: var(--font-mono);
    background: rgba(167, 139, 250, 0.1);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
}}
.finding-url {{
    margin-bottom: 0.3rem;
    word-break: break-all;
}}
.finding-url code {{
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--accent);
}}
.finding-host {{
    font-size: 0.78rem;
    color: var(--text-dim);
    margin-bottom: 0.3rem;
}}
.finding-desc {{
    font-size: 0.85rem;
    color: var(--text-dim);
    margin: 0.4rem 0;
    line-height: 1.5;
}}
.finding-tags {{
    display: flex;
    gap: 0.35rem;
    flex-wrap: wrap;
    margin: 0.4rem 0;
}}
.tag {{
    font-family: var(--font-mono);
    font-size: 0.7rem;
    padding: 0.15rem 0.5rem;
    background: rgba(34, 211, 238, 0.08);
    border: 1px solid rgba(34, 211, 238, 0.2);
    border-radius: 3px;
    color: var(--accent);
}}
.finding-refs a {{
    color: var(--accent2);
    font-size: 0.78rem;
    font-family: var(--font-mono);
    text-decoration: none;
    word-break: break-all;
}}
.finding-refs a:hover {{ text-decoration: underline; }}
.finding-extra pre {{
    background: var(--bg);
    padding: 0.5rem;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    overflow-x: auto;
    margin-top: 0.2rem;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-all;
}}
.finding-metadata {{ margin-top: 0.3rem; }}
.finding-meta-item {{
    font-size: 0.78rem;
    color: var(--text-dim);
}}
.label {{
    font-weight: 600;
    color: var(--text);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 0.3rem;
}}

.empty-state {{
    text-align: center;
    padding: 4rem 2rem;
    color: var(--text-dim);
    font-family: var(--font-mono);
}}

.hidden {{ display: none !important; }}

/* ── Responsive ─────── */
@media (max-width: 768px) {{
    .topbar, .stats-bar, .filters, .findings {{ padding-left: 1rem; padding-right: 1rem; }}
    .finding-header {{ flex-wrap: wrap; }}
}}
</style>
</head>
<body>

<div class="topbar">
    <h1><span class="icon">◆</span> {_esc(title)}</h1>
    <div class="meta">{generated} &middot; {len(findings)} findings</div>
</div>

<div class="stats-bar" id="statsBar">
    <div class="stat-chip" data-filter="critical" style="color:var(--critical)">
        <span class="dot" style="background:var(--critical)"></span>{stats.get("critical",0)} Critical
    </div>
    <div class="stat-chip" data-filter
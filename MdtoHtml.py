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
  python3 nuclei2html.py report.md --redact          # purge sensitive data
  python3 nuclei2html.py report.md --dual            # full + redacted reports
  python3 nuclei2html.py report.md --dual --pdf       # HTML + PDF for both
  python3 nuclei2html.py report.md --redact --redact-pattern "acme\\.internal"
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


from typing import Union

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


# ── Redaction engine ────────────────────────────────────────────────────────

# Each rule: (name, compiled_regex, replacement_function_or_string)
# Replacements preserve enough context for triage without leaking secrets.

_REDACT_RULES = []


def _build_redact_rules(extra_patterns=None):
    """Build the list of redaction rules. Called once at startup."""
    rules = []

    def _mask(label: str, keep_prefix: int = 0):
        """Return a replacer that keeps `keep_prefix` chars then masks the rest."""
        def _replacer(m):
            val = m.group(0)
            if keep_prefix and len(val) > keep_prefix + 3:
                return val[:keep_prefix] + "[REDACTED]"
            return f"[REDACTED-{label}]"
        return _replacer

    # ── Credentials & secrets ───────────────────────────────────────────

    # AWS keys (AKIA..., ASIA...)
    rules.append(("aws_access_key",
        re.compile(r'(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}', re.I),
        _mask("AWS-KEY", 4)))

    # AWS secret keys (40 char base64-ish after a separator)
    rules.append(("aws_secret",
        re.compile(r'(?<=[\s=:"\'])[A-Za-z0-9/+=]{40}(?=[\s"\',;]|$)'),
        lambda m: "[REDACTED-AWS-SECRET]"))

    # Generic API keys / tokens / secrets in key=value or key: value
    rules.append(("kv_secret",
        re.compile(
            r'(?P<key>(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key'
            r'|auth[_-]?token|bearer|token|password|passwd|pwd|secret'
            r'|private[_-]?key|client[_-]?secret|app[_-]?secret'
            r'|db[_-]?pass(?:word)?|database[_-]?password'
            r'|db[_-]?user(?:name)?|db[_-]?host|db[_-]?name'
            r'|database[_-]?user|database[_-]?host|database[_-]?name'
            r'|redis[_-]?(?:host|url|pass(?:word)?)'
            r'|smtp[_-]?(?:user|pass(?:word)?|host)'
            r'|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key'
            r'|ssh[_-]?key|gpg[_-]?key|connection[_-]?string'
            r'|mysql[_-]?(?:user|pass(?:word)?|host)'
            r'|postgres[_-]?(?:user|pass(?:word)?|host)))'
            r'\s*[=:]\s*["\']?(?P<val>[^\s"\'`,;}{\\]{4,})',
            re.I),
        lambda m: f'{m.group("key")}=[REDACTED]'))

    # Bearer tokens in headers
    rules.append(("bearer_token",
        re.compile(r'(Bearer\s+)[A-Za-z0-9_\-\.]{8,}', re.I),
        lambda m: m.group(1) + "[REDACTED]"))

    # Basic auth in URLs  user:pass@host
    rules.append(("url_basic_auth",
        re.compile(r'(https?://)([^:]+):([^@]+)@'),
        lambda m: m.group(1) + "[REDACTED]:[REDACTED]@"))

    # Authorization headers
    rules.append(("auth_header",
        re.compile(r'(Authorization:\s*(?:Basic|Bearer|Token|Digest)\s+)\S+', re.I),
        lambda m: m.group(1) + "[REDACTED]"))

    # Cookie values
    rules.append(("cookie_value",
        re.compile(r'((?:Cookie|Set-Cookie):\s*)(.+)', re.I),
        lambda m: m.group(1) + "[REDACTED]"))

    # ── Network / infra identifiers ─────────────────────────────────────

    # Internal/private IPv4 (10.x, 172.16-31.x, 192.168.x)
    rules.append(("internal_ipv4",
        re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3})\b'),
        lambda m: "[REDACTED-INTERNAL-IP]"))

    # Internal hostnames (common patterns: *.internal, *.local, *.corp, *.lan, db-*, rds-*)
    rules.append(("internal_hostname",
        re.compile(
            r'\b[a-zA-Z0-9][\w\-]*(?:\.[\w\-]+)*\.(?:internal|local|corp|lan|intra|priv)\b', re.I),
        lambda m: "[REDACTED-INTERNAL-HOST]"))

    # ── PII ─────────────────────────────────────────────────────────────

    # Email addresses
    rules.append(("email",
        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
        lambda m: "[REDACTED-EMAIL]"))

    # ── Misc secrets ────────────────────────────────────────────────────

    # GitHub / GitLab tokens
    rules.append(("gh_token",
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr|glpat)[_\-][A-Za-z0-9]{16,}'),
        _mask("GH-TOKEN", 4)))

    # Slack tokens
    rules.append(("slack_token",
        re.compile(r'xox[bpas]\-[A-Za-z0-9\-]+'),
        _mask("SLACK-TOKEN", 4)))

    # Private keys (PEM blocks)
    rules.append(("pem_key",
        re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
        lambda m: "[REDACTED-PRIVATE-KEY]"))

    # JWTs (xxx.yyy.zzz pattern with long segments)
    rules.append(("jwt",
        re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+'),
        lambda m: "eyJ[REDACTED-JWT]"))

    # Hash-like strings (hex 32+ chars, likely password hashes / API keys)
    rules.append(("hex_hash",
        re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32,64}(?![a-fA-F0-9])'),
        lambda m: m.group(0)[:6] + "[REDACTED-HASH]"))

    # ── User-supplied extra patterns ────────────────────────────────────
    if extra_patterns:
        for i, pat in enumerate(extra_patterns):
            try:
                rules.append((f"custom_{i}", re.compile(pat, re.I), "[REDACTED-CUSTOM]"))
            except re.error as e:
                print(f"[!] Invalid custom regex pattern '{pat}': {e}", file=sys.stderr)

    return rules


def redact_string(text: str, rules: list) -> str:
    """Apply all redaction rules to a string."""
    for name, pattern, replacement in rules:
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)
    return text


def redact_finding(f: Finding, rules: list) -> Finding:
    """Return a deep-redacted copy of a Finding."""
    import copy
    r = copy.deepcopy(f)

    r.host = redact_string(r.host, rules)
    r.matched_at = redact_string(r.matched_at, rules)
    r.description = redact_string(r.description, rules)
    r.extracted_results = redact_string(r.extracted_results, rules)
    r.curl_command = redact_string(r.curl_command, rules)
    r.raw_block = redact_string(r.raw_block, rules)
    r.matcher_name = redact_string(r.matcher_name, rules)

    r.reference = [redact_string(ref, rules) for ref in r.reference]
    r.metadata = {k: redact_string(str(v), rules) for k, v in r.metadata.items()}

    return r


def redact_findings(findings: list[Finding], extra_patterns: list[str] | None = None) -> tuple[list[Finding], dict]:
    """Redact all findings. Returns (redacted_findings, stats)."""
    rules = _build_redact_rules(extra_patterns)

    redacted = []
    redaction_stats = Counter()

    for f in findings:
        original_blob = f"{f.host}|{f.matched_at}|{f.description}|{f.extracted_results}|{f.curl_command}"
        rf = redact_finding(f, rules)
        redacted_blob = f"{rf.host}|{rf.matched_at}|{rf.description}|{rf.extracted_results}|{rf.curl_command}"

        if original_blob != redacted_blob:
            # Count which rules fired
            for name, pattern, _ in rules:
                if pattern.search(original_blob):
                    redaction_stats[name] += 1

        redacted.append(rf)

    return redacted, dict(redaction_stats)


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
        # Strip list markers (- or *) but preserve bold markers (**)
        line_stripped = line.strip()
        line_stripped = re.sub(r'^[-]\s+', '', line_stripped)
        if line_stripped.startswith('* ') and not line_stripped.startswith('**'):
            line_stripped = line_stripped[2:]

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


def generate_html(findings: list[Finding], title: str = "Nuclei Report", redacted: bool = False) -> str:
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

/* ── Redacted banner ── */
.redact-banner {{
    background: repeating-linear-gradient(
        -45deg,
        #1a1a2e, #1a1a2e 10px,
        #16213e 10px, #16213e 20px
    );
    border-bottom: 2px solid #e74c3c;
    padding: 0.7rem 2rem;
    text-align: center;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    font-weight: 700;
    color: #e74c3c;
    letter-spacing: 0.15em;
    text-transform: uppercase;
}}

/* ── Responsive ─────── */
@media (max-width: 768px) {{
    .topbar, .stats-bar, .filters, .findings {{ padding-left: 1rem; padding-right: 1rem; }}
    .finding-header {{ flex-wrap: wrap; }}
}}
</style>
</head>
<body>

{'<div class="redact-banner">⛔ REDACTED — Sensitive data has been purged from this report</div>' if redacted else ''}
<div class="topbar">
    <h1><span class="icon">◆</span> {_esc(title)}{'  <span style="color:#e74c3c;font-size:0.7em;">[REDACTED]</span>' if redacted else ''}</h1>
    <div class="meta">{generated} &middot; {len(findings)} findings</div>
</div>

<div class="stats-bar" id="statsBar">
    <div class="stat-chip" data-filter="critical" style="color:var(--critical)">
        <span class="dot" style="background:var(--critical)"></span>{stats.get("critical",0)} Critical
    </div>
    <div class="stat-chip" data-filter="high" style="color:var(--high)">
        <span class="dot" style="background:var(--high)"></span>{stats.get("high",0)} High
    </div>
    <div class="stat-chip" data-filter="medium" style="color:var(--medium)">
        <span class="dot" style="background:var(--medium)"></span>{stats.get("medium",0)} Medium
    </div>
    <div class="stat-chip" data-filter="low" style="color:var(--low)">
        <span class="dot" style="background:var(--low)"></span>{stats.get("low",0)} Low
    </div>
    <div class="stat-chip" data-filter="info" style="color:var(--info)">
        <span class="dot" style="background:var(--info)"></span>{stats.get("info",0)} Info
    </div>
    <span class="stat-total">{len(findings)} total &middot; {len(hosts)} hosts</span>
</div>

<div class="filters">
    <input type="text" class="search-box" id="searchBox" placeholder="Filter: template, host, url…">
    <select class="filter-select" id="hostFilter">
        <option value="">All hosts</option>
        {host_options}
    </select>
    <span class="counter" id="visibleCount">{len(findings)} / {len(findings)}</span>
</div>

<div class="findings" id="findingsContainer">
    {all_cards}
</div>

<script>
(function() {{
    const cards = Array.from(document.querySelectorAll('.finding-card'));
    const searchBox = document.getElementById('searchBox');
    const hostFilter = document.getElementById('hostFilter');
    const counter = document.getElementById('visibleCount');
    const statsChips = document.querySelectorAll('.stat-chip[data-filter]');
    const total = cards.length;

    let activeSeverities = new Set();

    function applyFilters() {{
        const q = searchBox.value.toLowerCase();
        const host = hostFilter.value;
        let visible = 0;

        cards.forEach(card => {{
            const sev = card.dataset.severity;
            const cardHost = card.dataset.host;
            const text = card.textContent.toLowerCase();

            let show = true;
            if (activeSeverities.size > 0 && !activeSeverities.has(sev)) show = false;
            if (host && cardHost !== host) show = false;
            if (q && !text.includes(q)) show = false;

            card.classList.toggle('hidden', !show);
            if (show) visible++;
        }});

        counter.textContent = visible + ' / ' + total;
    }}

    statsChips.forEach(chip => {{
        chip.addEventListener('click', () => {{
            const sev = chip.dataset.filter;
            if (activeSeverities.has(sev)) {{
                activeSeverities.delete(sev);
                chip.classList.remove('active');
            }} else {{
                activeSeverities.add(sev);
                chip.classList.add('active');
            }}
            applyFilters();
        }});
    }});

    searchBox.addEventListener('input', applyFilters);
    hostFilter.addEventListener('change', applyFilters);
}})();
</script>

</body>
</html>'''


# ── PDF generation ──────────────────────────────────────────────────────────

def generate_pdf(findings: list[Finding], output_path: str, title: str = "Nuclei Report", redacted: bool = False):
    """Generate a professional PDF report from findings using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm, cm
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, HRFlowable
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate, Frame
    from reportlab.lib import colors
    import copy as _copy

    # ── Colors ──────────────────────────────────────────────────────────
    BG_DARK      = HexColor("#0a0e17")
    BG_CARD      = HexColor("#111827")
    BG_HEADER    = HexColor("#0f172a")
    BORDER_COLOR = HexColor("#1e293b")
    TEXT_COLOR   = HexColor("#e2e8f0")
    TEXT_DIM     = HexColor("#64748b")
    ACCENT       = HexColor("#22d3ee")
    ACCENT2      = HexColor("#a78bfa")

    SEV_COLORS = {
        "critical": HexColor("#e74c3c"),
        "high":     HexColor("#e67e22"),
        "medium":   HexColor("#f1c40f"),
        "low":      HexColor("#2ecc71"),
        "info":     HexColor("#3498db"),
        "unknown":  HexColor("#95a5a6"),
    }
    # Badge text color (dark text on yellow/green)
    SEV_TEXT = {
        "critical": white, "high": white, "medium": HexColor("#1a1a1a"),
        "low": HexColor("#1a1a1a"), "info": white, "unknown": white,
    }

    # ── Page setup ──────────────────────────────────────────────────────
    page_w, page_h = A4
    margin = 2 * cm

    # ── Styles ──────────────────────────────────────────────────────────
    s_title = ParagraphStyle(
        "CoverTitle", fontName="Helvetica-Bold", fontSize=26,
        textColor=white, alignment=TA_CENTER, spaceAfter=6*mm,
        leading=32,
    )
    s_subtitle = ParagraphStyle(
        "CoverSub", fontName="Helvetica", fontSize=11,
        textColor=TEXT_DIM, alignment=TA_CENTER, spaceAfter=3*mm,
    )
    s_redact_banner = ParagraphStyle(
        "RedactBanner", fontName="Helvetica-Bold", fontSize=12,
        textColor=HexColor("#e74c3c"), alignment=TA_CENTER,
        spaceBefore=4*mm, spaceAfter=4*mm, borderColor=HexColor("#e74c3c"),
        borderWidth=1, borderPadding=6,
    )
    s_section = ParagraphStyle(
        "Section", fontName="Helvetica-Bold", fontSize=14,
        textColor=ACCENT, spaceBefore=8*mm, spaceAfter=4*mm,
    )
    s_finding_title = ParagraphStyle(
        "FindingTitle", fontName="Helvetica-Bold", fontSize=11,
        textColor=TEXT_COLOR, spaceAfter=2*mm, leading=14,
    )
    s_label = ParagraphStyle(
        "Label", fontName="Helvetica-Bold", fontSize=7.5,
        textColor=TEXT_DIM, spaceAfter=1*mm,
    )
    s_body = ParagraphStyle(
        "Body", fontName="Helvetica", fontSize=9,
        textColor=TEXT_COLOR, spaceAfter=2*mm, leading=12,
    )
    s_mono = ParagraphStyle(
        "Mono", fontName="Courier", fontSize=7.5,
        textColor=ACCENT, spaceAfter=2*mm, leading=10,
        leftIndent=4*mm,
    )
    s_mono_block = ParagraphStyle(
        "MonoBlock", fontName="Courier", fontSize=7,
        textColor=TEXT_COLOR, spaceAfter=2*mm, leading=9.5,
        leftIndent=4*mm, backColor=HexColor("#0d1117"),
        borderColor=BORDER_COLOR, borderWidth=0.5, borderPadding=4,
    )
    s_tag = ParagraphStyle(
        "Tag", fontName="Courier", fontSize=7,
        textColor=ACCENT, spaceAfter=1*mm,
    )
    s_ref = ParagraphStyle(
        "Ref", fontName="Courier", fontSize=7,
        textColor=ACCENT2, spaceAfter=1*mm, leading=9,
    )
    s_toc_item = ParagraphStyle(
        "TOCItem", fontName="Helvetica", fontSize=9,
        textColor=TEXT_COLOR, spaceAfter=1.5*mm, leading=12,
        leftIndent=6*mm,
    )
    s_stat_label = ParagraphStyle(
        "StatLabel", fontName="Helvetica-Bold", fontSize=10,
        textColor=TEXT_COLOR, alignment=TA_CENTER,
    )
    s_stat_num = ParagraphStyle(
        "StatNum", fontName="Helvetica-Bold", fontSize=22,
        alignment=TA_CENTER, spaceAfter=1*mm,
    )
    s_footer = ParagraphStyle(
        "Footer", fontName="Helvetica", fontSize=7,
        textColor=TEXT_DIM, alignment=TA_CENTER,
    )

    # ── Custom page template with dark background ───────────────────────
    generated_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    class DarkPageTemplate(PageTemplate):
        def __init__(self, id, frames, report_title, is_redacted=False, **kwargs):
            super().__init__(id, frames, **kwargs)
            self._report_title = report_title
            self._is_redacted = is_redacted

        def beforeDrawPage(self, canvas, doc):
            canvas.saveState()
            # Dark background
            canvas.setFillColor(BG_DARK)
            canvas.rect(0, 0, page_w, page_h, fill=1, stroke=0)
            # Header bar
            canvas.setFillColor(BG_HEADER)
            canvas.rect(0, page_h - 14*mm, page_w, 14*mm, fill=1, stroke=0)
            canvas.setStrokeColor(BORDER_COLOR)
            canvas.line(0, page_h - 14*mm, page_w, page_h - 14*mm)
            # Header text
            canvas.setFillColor(ACCENT)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(margin, page_h - 10*mm, f"◆  {self._report_title}")
            if self._is_redacted:
                canvas.setFillColor(HexColor("#e74c3c"))
                canvas.setFont("Helvetica-Bold", 8)
                canvas.drawString(page_w - margin - 60, page_h - 10*mm, "[REDACTED]")
            # Footer
            canvas.setFillColor(TEXT_DIM)
            canvas.setFont("Helvetica", 6.5)
            canvas.drawString(margin, 8*mm, f"Generated: {generated_ts}")
            canvas.drawRightString(page_w - margin, 8*mm, f"Page {doc.page}")
            # Redacted stripe at bottom
            if self._is_redacted:
                canvas.setStrokeColor(HexColor("#e74c3c"))
                canvas.setLineWidth(2)
                canvas.line(0, 5*mm, page_w, 5*mm)
            canvas.restoreState()

    # ── Build document ──────────────────────────────────────────────────
    frame = Frame(margin, 14*mm, page_w - 2*margin, page_h - 28*mm, id='main')
    template = DarkPageTemplate('dark', [frame], title, is_redacted=redacted)

    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=16*mm, bottomMargin=16*mm,
    )
    doc.addPageTemplates([template])

    story = []
    stats = Counter(f.severity for f in findings)
    hosts = sorted(set(f.host for f in findings if f.host))

    def _p_esc(text):
        """Escape text for reportlab Paragraph XML."""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;'))

    # ── Cover page ──────────────────────────────────────────────────────
    story.append(Spacer(1, 40*mm))
    story.append(Paragraph(_p_esc(title), s_title))
    if redacted:
        story.append(Paragraph("REDACTED — Sensitive data purged", s_redact_banner))
    story.append(Paragraph(f"Generated: {generated_ts}", s_subtitle))
    story.append(Paragraph(
        f"{len(findings)} findings  |  {len(hosts)} hosts", s_subtitle))
    story.append(Spacer(1, 15*mm))

    # Stats boxes
    sev_order = ["critical", "high", "medium", "low", "info"]
    stat_cells_top = []
    stat_cells_bot = []
    for sev in sev_order:
        count = stats.get(sev, 0)
        stat_cells_top.append(Paragraph(
            f'<font color="{SEV_COLORS[sev].hexval()}">{count}</font>', s_stat_num))
        stat_cells_bot.append(Paragraph(
            sev.upper(), ParagraphStyle(
                "sl", parent=s_stat_label,
                textColor=SEV_COLORS[sev], fontSize=8)))

    stat_table = Table(
        [stat_cells_top, stat_cells_bot],
        colWidths=[(page_w - 2*margin) / 5] * 5,
        rowHeights=[12*mm, 7*mm],
    )
    stat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_CARD),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(stat_table)
    story.append(PageBreak())

    # ── Table of contents ───────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", s_section))
    for i, f in enumerate(findings, 1):
        sev = f.severity
        color = SEV_COLORS.get(sev, TEXT_DIM).hexval()
        name = _p_esc(f.name or f.template_id or "Unnamed")
        host_txt = f'  —  {_p_esc(f.host)}' if f.host else ''
        story.append(Paragraph(
            f'<font color="{color}"><b>[{sev.upper()}]</b></font>  '
            f'{name}{host_txt}',
            s_toc_item))
    story.append(PageBreak())

    # ── Finding details ─────────────────────────────────────────────────
    for i, f in enumerate(findings, 1):
        sev = f.severity
        sev_color = SEV_COLORS.get(sev, TEXT_DIM)
        sev_text_c = SEV_TEXT.get(sev, white)

        elements = []

        # Severity badge + title line
        badge_table = Table(
            [[
                Paragraph(
                    f'<font color="{sev_text_c.hexval()}"><b>{sev.upper()}</b></font>',
                    ParagraphStyle("badge", fontName="Courier-Bold", fontSize=8,
                                   alignment=TA_CENTER, textColor=sev_text_c)),
                Paragraph(
                    _p_esc(f.name or f.template_id or "Unnamed"),
                    s_finding_title),
            ]],
            colWidths=[22*mm, page_w - 2*margin - 24*mm],
            rowHeights=[8*mm],
        )
        badge_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), sev_color),
            ('BACKGROUND', (1, 0), (1, 0), BG_CARD),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(badge_table)
        elements.append(Spacer(1, 2*mm))

        # Metadata rows in a bordered card
        card_rows = []

        if f.template_id:
            card_rows.append(("TEMPLATE", f.template_id))
        if f.matched_at:
            card_rows.append(("URL", f.matched_at))
        if f.host and f.host != f.matched_at:
            card_rows.append(("HOST", f.host))
        if f.matcher_name:
            card_rows.append(("MATCHER", f.matcher_name))
        for k, v in f.metadata.items():
            card_rows.append((k.upper(), str(v)))

        if card_rows:
            meta_table_data = []
            for label, val in card_rows:
                meta_table_data.append([
                    Paragraph(f'<b>{_p_esc(label)}</b>', s_label),
                    Paragraph(
                        f'<font face="Courier" size="7.5">{_p_esc(val)}</font>',
                        s_body),
                ])
            meta_table = Table(
                meta_table_data,
                colWidths=[28*mm, page_w - 2*margin - 30*mm],
            )
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), BG_CARD),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('LINEBELOW', (0, 0), (-1, -2), 0.3, BORDER_COLOR),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(meta_table)
            elements.append(Spacer(1, 2*mm))

        if f.description:
            elements.append(Paragraph(
                f'<b><font color="{TEXT_DIM.hexval()}" size="7.5">DESCRIPTION</font></b>',
                s_label))
            elements.append(Paragraph(_p_esc(f.description), s_body))

        if f.tags:
            tag_str = '  '.join(f'[{_p_esc(t)}]' for t in f.tags)
            elements.append(Paragraph(
                f'<b><font color="{TEXT_DIM.hexval()}" size="7.5">TAGS</font></b>',
                s_label))
            elements.append(Paragraph(tag_str, s_tag))

        if f.extracted_results:
            elements.append(Paragraph(
                f'<b><font color="{TEXT_DIM.hexval()}" size="7.5">EXTRACTED RESULTS</font></b>',
                s_label))
            # Replace literal \n with real newlines for display
            clean = f.extracted_results.replace('\\n', '\n')
            elements.append(Paragraph(
                _p_esc(clean).replace('\n', '<br/>'), s_mono_block))

        if f.curl_command:
            elements.append(Paragraph(
                f'<b><font color="{TEXT_DIM.hexval()}" size="7.5">CURL COMMAND</font></b>',
                s_label))
            elements.append(Paragraph(_p_esc(f.curl_command), s_mono_block))

        if f.reference:
            valid_refs = [r for r in f.reference if r.startswith('http')]
            if valid_refs:
                elements.append(Paragraph(
                    f'<b><font color="{TEXT_DIM.hexval()}" size="7.5">REFERENCES</font></b>',
                    s_label))
                for ref in valid_refs:
                    elements.append(Paragraph(_p_esc(ref), s_ref))

        # Separator
        elements.append(Spacer(1, 3*mm))
        elements.append(HRFlowable(
            width="100%", thickness=0.5, color=BORDER_COLOR,
            spaceAfter=4*mm))

        # Try to keep each finding together on one page, but allow break if too long
        story.append(KeepTogether(elements) if len(elements) < 15 else
                     KeepTogether(elements[:6]))
        if len(elements) >= 15:
            for el in elements[6:]:
                story.append(el)

    # Build
    doc.build(story)



# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Convert Nuclei markdown reports to clean HTML dashboards.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan_results.md
  %(prog)s scan_results.md -o rapport.html --title "Audit Acme Corp"
  %(prog)s ./nuclei-export-dir/
  %(prog)s raw_output.txt -o report.html
  %(prog)s scan.md --redact                            # single redacted report
  %(prog)s scan.md --dual                              # full + redacted side by side
  %(prog)s scan.md --dual --pdf                        # HTML + PDF for both
  %(prog)s scan.md --redact --pdf                      # redacted HTML + PDF only
  %(prog)s scan.md --redact --redact-pattern "corp\\.internal"  # custom extra pattern
        """,
    )
    parser.add_argument("input", help="Nuclei .md report file or directory of .md files")
    parser.add_argument("-o", "--output", help="Output HTML file (default: <input>.html)")
    parser.add_argument("--title", default="Nuclei Scan Report", help="Report title")
    parser.add_argument("--redact", action="store_true",
                        help="Redact sensitive data (credentials, internal IPs, emails, tokens…)")
    parser.add_argument("--dual", action="store_true",
                        help="Generate TWO reports: full + redacted (suffixed _redacted.html)")
    parser.add_argument("--redact-pattern", action="append", dest="redact_patterns", default=[],
                        metavar="REGEX",
                        help="Extra regex pattern to redact (can be specified multiple times)")
    parser.add_argument("--pdf", action="store_true",
                        help="Also generate PDF report(s) alongside HTML")
    args = parser.parse_args()

    inp = Path(args.input)
    if args.output:
        out = Path(args.output)
    elif inp.is_dir():
        out = inp.parent / (inp.name + ".html")
    else:
        out = inp.with_suffix(".html")

    print(f"[*] Loading findings from: {inp}")
    findings = load_findings(str(inp))
    print(f"[+] Parsed {len(findings)} findings")

    if not findings:
        print("[!] No findings parsed. Check input format.", file=sys.stderr)
        print("    Supported: Nuclei -me markdown, plain Nuclei output, structured .md")
        sys.exit(1)

    severity_summary = Counter(f.severity for f in findings)
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_summary.get(sev, 0)
        if count:
            print(f"    {sev:>8}: {count}")

    use_redact = args.redact or args.dual
    extra_pats = args.redact_patterns if args.redact_patterns else None

    # ── Generate full report (unless --redact only) ─────────────────────
    if not args.redact:
        html_content = generate_html(findings, title=args.title, redacted=False)
        out.write_text(html_content, encoding="utf-8")
        print(f"[+] Full report    → {out}  ({out.stat().st_size / 1024:.1f} KB)")

    # ── Generate redacted report ────────────────────────────────────────
    if use_redact:
        redacted_findings, redact_stats = redact_findings(findings, extra_pats)

        if args.dual:
            redact_out = out.with_stem(out.stem + "_redacted") if hasattr(out, 'with_stem') else \
                         out.parent / (out.stem + "_redacted" + out.suffix)
        elif args.redact:
            redact_out = out
        else:
            redact_out = out

        html_redacted = generate_html(redacted_findings, title=args.title, redacted=True)
        redact_out.write_text(html_redacted, encoding="utf-8")
        print(f"[+] Redacted report → {redact_out}  ({redact_out.stat().st_size / 1024:.1f} KB)")

        if redact_stats:
            print(f"[*] Redaction summary:")
            for rule_name, count in sorted(redact_stats.items(), key=lambda x: -x[1]):
                print(f"      {rule_name}: {count} finding(s) affected")
        else:
            print(f"[*] No sensitive data patterns detected (nothing redacted)")

    # ── Generate PDF reports ────────────────────────────────────────────
    if args.pdf:
        if not args.redact:
            pdf_out = out.with_suffix(".pdf")
            generate_pdf(findings, str(pdf_out), title=args.title, redacted=False)
            print(f"[+] Full PDF       → {pdf_out}  ({pdf_out.stat().st_size / 1024:.1f} KB)")

        if use_redact:
            if args.dual:
                pdf_redact_out = out.parent / (out.stem + "_redacted.pdf")
            else:
                pdf_redact_out = out.with_suffix(".pdf")
            generate_pdf(redacted_findings, str(pdf_redact_out), title=args.title, redacted=True)
            print(f"[+] Redacted PDF   → {pdf_redact_out}  ({pdf_redact_out.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
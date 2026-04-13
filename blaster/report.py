import json
import os
from datetime import datetime
from colorama import Fore, Style

# ============================================================
#                     REPORTER MODULE
#
#   Generates reports from Blaster scan results in 3 formats:
#     - JSON  (.json) — structured, machine readable
#     - HTML  (.html) — styled, browser viewable, shareable
#     - TXT   (.txt)  — clean plain text, universal
#
#   Format auto-detected from output filename extension
#   Called from blaster.py after all modules have run
# ============================================================

class Reporter:
    def __init__(self, domain, results, args):
        self.domain    = domain
        self.results   = results   # dict of all module results
        self.args      = args      # argparse namespace
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.date_slug = datetime.now().strftime('%Y%m%d_%H%M%S')


    # --------------------------------------------------------
    #   DETECT FORMAT FROM FILENAME
    # --------------------------------------------------------
    def _get_format(self, output_path):
        ext = os.path.splitext(output_path)[1].lower()
        if ext == '.json':
            return 'json'
        elif ext == '.html':
            return 'html'
        elif ext == '.txt':
            return 'txt'
        else:
            # Default to txt for unknown extensions
            return 'txt'


    # --------------------------------------------------------
    #   SAVE REPORT
    #   Main entry point — detects format and writes file
    # --------------------------------------------------------
    def save(self, output_path):
        fmt = self._get_format(output_path)

        if fmt == 'json':
            content = self._build_json()
        elif fmt == 'html':
            content = self._build_html()
        else:
            content = self._build_txt()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return output_path, fmt


    # ========================================================
    #   JSON REPORT
    #   Clean structured dict — all results serialized
    # ========================================================
    def _build_json(self):
        report = {
            'meta': {
                'tool':      'Blaster',
                'version':   '2.0',
                'author':    'Usman Faridi',
                'domain':    self.domain,
                'timestamp': self.timestamp,
            },
            'results': {}
        }

        # Add each module result if it exists
        for key, value in self.results.items():
            if value is not None:
                report['results'][key] = value

        return json.dumps(report, indent=4, default=str)


    # ========================================================
    #   TXT REPORT
    #   Clean formatted plain text — readable anywhere
    # ========================================================
    def _build_txt(self):
        lines = []
        sep   = '=' * 60
        thin  = '-' * 60

        lines.append(sep)
        lines.append('  BLASTER — Domain Recon Report')
        lines.append(f'  Target    : {self.domain}')
        lines.append(f'  Generated : {self.timestamp}')
        lines.append(f'  Author    : Usman Faridi')
        lines.append(sep)

        # --- DNS ---
        if self.results.get('dns'):
            lines.append('\n[ DNS RECORDS ]')
            lines.append(thin)
            dns = self.results['dns']
            for rtype in ['A', 'MX', 'TXT', 'NS', 'AAAA', 'CNAME']:
                records = dns.get(rtype, [])
                if records and records != [f'No {rtype} records found']:
                    lines.append(f'{rtype} Records:')
                    for r in records:
                        lines.append(f'  • {r}')
            if dns.get('SOA'):
                lines.append('SOA Record:')
                for soa in dns['SOA']:
                    lines.append(f"  • Primary NS : {soa.get('mname', 'N/A')}")
                    lines.append(f"  • Admin Email: {soa.get('rname', 'N/A')}")
            if dns.get('CAA'):
                lines.append('CAA Records:')
                for r in dns['CAA']:
                    lines.append(f'  • {r}')
            dnssec = dns.get('DNSSEC', False)
            lines.append(f"DNSSEC: {'Signed' if dnssec else 'Not signed'}")

        # --- WHOIS ---
        if self.results.get('whois'):
            lines.append('\n[ WHOIS ]')
            lines.append(thin)
            whois = self.results['whois']
            if 'error' in whois:
                lines.append(f"Error: {whois['error']}")
            else:
                parsed = whois.get('parsed', {})
                lines.append(f"Registrar    : {parsed.get('registrar', 'N/A')}")
                lines.append(f"Registrant   : {parsed.get('registrant', 'N/A')}")
                lines.append(f"Country      : {parsed.get('registrant_country', 'N/A')}")
                lines.append(f"Created      : {parsed.get('creation_date', 'N/A')}")
                lines.append(f"Expires      : {parsed.get('expiry_date', 'N/A')}")
                lines.append(f"Updated      : {parsed.get('updated_date', 'N/A')}")

        # --- Subdomains ---
        if self.results.get('subdomains'):
            lines.append('\n[ SUBDOMAINS ]')
            lines.append(thin)
            subs = self.results['subdomains']
            if isinstance(subs, list):
                lines.append(f'Total found: {len(subs)}')
                for s in subs:
                    lines.append(f'  • {s}')

        # --- Ports ---
        if self.results.get('ports'):
            lines.append('\n[ OPEN PORTS ]')
            lines.append(thin)
            for p in self.results['ports']:
                risk = ' [HIGH RISK]' if p.get('risk') else ''
                lines.append(f"  • Port {p['port']}  {p.get('service', '')}  {risk}")
                if p.get('banner'):
                    lines.append(f"    Banner: {p['banner']}")

        # --- SSL ---
        if self.results.get('ssl'):
            lines.append('\n[ SSL/TLS ANALYSIS ]')
            lines.append(thin)
            ssl = self.results['ssl']
            if ssl.get('success'):
                d = ssl['data']
                lines.append(f"Subject CN   : {d.get('subject_cn', 'N/A')}")
                lines.append(f"Issuer       : {d.get('issuer_cn', 'N/A')}")
                lines.append(f"Valid From   : {d.get('valid_from', 'N/A')}")
                lines.append(f"Valid To     : {d.get('valid_to', 'N/A')}")
                lines.append(f"Days Left    : {d.get('days_left', 'N/A')}")
                lines.append(f"TLS Version  : {d.get('tls_version', 'N/A')}")
                lines.append(f"Cipher       : {d.get('cipher_name', 'N/A')}")
                lines.append(f"Self-Signed  : {'Yes' if d.get('self_signed') else 'No'}")
                if d.get('sans'):
                    lines.append(f"SANs ({len(d['sans'])}):")
                    for san in d['sans']:
                        lines.append(f'  • {san}')

        # --- Headers ---
        if self.results.get('headers'):
            lines.append('\n[ HTTP HEADERS AUDIT ]')
            lines.append(thin)
            h = self.results['headers']
            if h.get('success'):
                lines.append(f"Grade        : {h.get('grade', 'N/A')}")
                if h.get('present'):
                    lines.append('Present Headers:')
                    for name in h['present']:
                        lines.append(f'  • {name}')
                if h.get('missing'):
                    lines.append('Missing Headers:')
                    for name, (sev, desc) in h['missing'].items():
                        lines.append(f'  • [{sev}] {name} — {desc}')
                if h.get('disclosed'):
                    lines.append('Info Disclosure:')
                    for name, val in h['disclosed'].items():
                        lines.append(f'  • {name}: {val}')

        # --- Tech ---
        if self.results.get('tech'):
            lines.append('\n[ TECHNOLOGY FINGERPRINT ]')
            lines.append(thin)
            t = self.results['tech']
            if t.get('success'):
                lines.append(f"Web Server   : {t.get('server') or 'Not detected'}")
                lines.append(f"Framework    : {t.get('framework') or 'Not detected'}")
                lines.append(f"CMS          : {t.get('cms') or 'Not detected'}")
                if t.get('cdn'):
                    lines.append(f"CDN          : {', '.join(t['cdn'])}")
                if t.get('waf'):
                    lines.append(f"WAF          : {', '.join(t['waf'])}")
                if t.get('js_frameworks'):
                    lines.append(f"JS Frameworks: {', '.join(t['js_frameworks'])}")

        # --- Threat Intel ---
        if self.results.get('threat'):
            lines.append('\n[ THREAT INTELLIGENCE ]')
            lines.append(thin)
            ti = self.results['threat']
            if ti.get('success'):
                lines.append(f"IP           : {ti.get('ip', 'N/A')}")
                dnsbl = ti.get('dnsbl', {})
                listed = dnsbl.get('listed', [])
                if listed:
                    lines.append(f"Blacklisted  : YES — {', '.join(listed)}")
                else:
                    lines.append('Blacklisted  : No')
                tf = ti.get('threatfox', {})
                total_hits = len(tf.get('domain_hits', [])) + len(tf.get('ip_hits', []))
                lines.append(f"ThreatFox    : {total_hits} IOC match(es)")
                shodan = ti.get('shodan', {})
                if shodan.get('ports'):
                    lines.append(f"Shodan Ports : {', '.join(str(p) for p in shodan['ports'])}")
                if shodan.get('cves'):
                    lines.append(f"CVEs         : {', '.join(shodan['cves'])}")
                else:
                    lines.append('CVEs         : None recorded')

        lines.append(f'\n{sep}')
        lines.append('  End of Report — Generated by Blaster')
        lines.append(sep)

        return '\n'.join(lines)


    # ========================================================
    #   HTML REPORT
    #   Styled single page — opens in any browser
    # ========================================================
    def _build_html(self):

        def section(title, content_html):
            return f"""
            <div class="section">
                <div class="section-title">{title}</div>
                {content_html}
            </div>"""

        def row(label, value, color=''):
            color_style = f'color:{color}' if color else ''
            return f'<tr><td class="label">{label}</td><td style="{color_style}">{value}</td></tr>'

        def badge(text, cls):
            return f'<span class="badge {cls}">{text}</span>'

        def table(rows_html):
            return f'<table>{rows_html}</table>'

        def bullet_list(items):
            if not items:
                return '<p class="muted">None found</p>'
            return '<ul>' + ''.join(f'<li>{i}</li>' for i in items) + '</ul>'

        # Build sections
        sections_html = ''

        # --- DNS ---
        if self.results.get('dns'):
            dns  = self.results['dns']
            rows = ''
            for rtype in ['A', 'MX', 'TXT', 'NS', 'AAAA', 'CNAME']:
                records = dns.get(rtype, [])
                if records and records != [f'No {rtype} records found']:
                    rows += row(f'{rtype} Records', '<br>'.join(str(r) for r in records))
            if dns.get('SOA'):
                for soa in dns['SOA']:
                    rows += row('SOA Primary NS', soa.get('mname', 'N/A'))
                    rows += row('SOA Admin', soa.get('rname', 'N/A'))
            if dns.get('CAA'):
                rows += row('CAA Records', '<br>'.join(dns['CAA']))
            dnssec = dns.get('DNSSEC', False)
            dnssec_badge = badge('Signed', 'green') if dnssec else badge('Not Signed', 'red')
            rows += row('DNSSEC', dnssec_badge)
            sections_html += section('🔍 DNS Records', table(rows))

        # --- WHOIS ---
        if self.results.get('whois'):
            whois = self.results['whois']
            rows  = ''
            if 'error' in whois:
                rows = row('Error', whois['error'])
            else:
                parsed = whois.get('parsed', {})
                rows += row('Registrar',   parsed.get('registrar', 'N/A'))
                rows += row('Registrant',  parsed.get('registrant', 'N/A'))
                rows += row('Country',     parsed.get('registrant_country', 'N/A'))
                rows += row('Created',     parsed.get('creation_date', 'N/A'))
                rows += row('Expires',     parsed.get('expiry_date', 'N/A'))
                rows += row('Updated',     parsed.get('updated_date', 'N/A'))
                rows += row('WHOIS Server',whois.get('server', 'N/A'))
            sections_html += section('📋 WHOIS', table(rows))

        # --- Subdomains ---
        if self.results.get('subdomains'):
            subs = self.results['subdomains']
            if isinstance(subs, list):
                content = f'<p><strong>{len(subs)}</strong> subdomains found</p>'
                content += bullet_list(subs)
            else:
                content = f'<p class="muted">{subs}</p>'
            sections_html += section('🌐 Subdomains', content)

        # --- Live Subdomains ---
        if self.results.get('live'):
            live = self.results['live']
            if isinstance(live, list) and live:
                live_html = f'<p style="padding:12px 20px"><strong>{len(live)}</strong> live subdomains confirmed</p>'
                live_html += '''<table>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>IP</th>
                        <th>Title</th>
                        <th>Redirect</th>
                    </tr>'''
                for item in live:
                    status   = item.get('status') or '—'
                    ip       = item.get('ip') or '—'
                    title    = item.get('title') or '—'
                    redirect = item.get('redirect') or ''

                    # Color status code
                    s = str(status)
                    if s.startswith('2'):
                        status_html = badge(status, 'green')
                    elif s.startswith('3'):
                        status_html = badge(status, 'blue')
                    elif s.startswith('4'):
                        status_html = badge(status, 'orange')
                    elif s.startswith('5'):
                        status_html = badge(status, 'red')
                    else:
                        status_html = badge(status, 'grey')

                    # Truncate redirect for display
                    redirect_display = (redirect[:60] + '...') if len(redirect) > 60 else redirect
                    redirect_html    = f'<span style="color:#58a6ff;font-size:0.85em">{redirect_display}</span>' if redirect else '—'

                    live_html += f"""<tr>
                        <td style="color:#c9d1d9">{item['subdomain']}</td>
                        <td>{status_html}</td>
                        <td style="color:#a855f7">{ip}</td>
                        <td style="color:#8b949e;font-size:0.88em">{title}</td>
                        <td>{redirect_html}</td>
                    </tr>"""
                live_html += '</table>'
                sections_html += section('✅ Live Subdomains', live_html)

        # --- Ports ---
        if self.results.get('ports'):
            ports_html = '''<table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version/Info</th>
                    <th>Banner (Raw)</th>
                    <th>Risk</th>
                </tr>'''
            for p in self.results['ports']:
                risk_badge   = badge('⚠ HIGH RISK', 'red') if p.get('risk') else badge('OK', 'green')
                port_display = f"{p['port']}/tcp"
                version      = p.get('version', '') or '—'
                banner       = p.get('banner', '') or '—'
                # Escape HTML special chars in raw banner and clean line endings
                banner_safe  = (banner
                    .replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('\r\n', '\n')
                    .replace('\r', '\n')
                    .strip()
                )
                ports_html  += f"""<tr>
                    <td><strong style="color:#58a6ff">{port_display}</strong></td>
                    <td><span class="badge green">open</span></td>
                    <td>{p.get('service', 'Unknown')}</td>
                    <td style="color:#3fb950">{version}</td>
                    <td class="muted" style="font-size:0.8em;white-space:pre-wrap;max-width:300px">{banner_safe}</td>
                    <td>{risk_badge}</td>
                </tr>"""
            ports_html += '</table>'
            sections_html += section('🔌 Open Ports', ports_html)

        # --- SSL ---
        if self.results.get('ssl'):
            ssl = self.results['ssl']
            rows = ''
            if ssl.get('success'):
                d = ssl['data']
                rows += row('Subject CN',  d.get('subject_cn', 'N/A'))
                rows += row('Issuer',      d.get('issuer_cn', 'N/A'))
                rows += row('Valid From',  d.get('valid_from', 'N/A'))
                rows += row('Valid To',    d.get('valid_to', 'N/A'))
                days  = d.get('days_left')

                # SSL expiry badge — color coded by urgency
                if d.get('is_expired'):
                    days_html = badge(f'EXPIRED', 'red')
                elif days is not None and days <= 60:
                    days_html = badge(f'⚠ {days} days — Expiring Soon', 'orange')
                elif days is not None:
                    days_html = badge(f'✔ {days} days remaining', 'green')
                else:
                    days_html = 'N/A'

                rows += row('Days Left',   days_html)
                rows += row('TLS Version', d.get('tls_version', 'N/A'))
                rows += row('Cipher',      f"{d.get('cipher_name', 'N/A')} ({d.get('cipher_bits', '?')} bits)")
                ss_badge = badge('YES — Untrusted', 'red') if d.get('self_signed') else badge('No', 'green')
                rows += row('Self-Signed', ss_badge)
                if d.get('sans'):
                    rows += row(f"SANs ({len(d['sans'])})", '<br>'.join(d['sans'][:20]))
            sections_html += section('🔒 SSL/TLS Analysis', table(rows))

        # --- Headers ---
        if self.results.get('headers'):
            h = self.results['headers']
            rows = ''
            if h.get('success'):
                grade = h.get('grade', 'N/A')
                grade_colors = {'A': 'green', 'B': 'blue', 'C': 'orange', 'D': 'orange', 'F': 'red'}
                grade_badge  = badge(f'Grade {grade}', grade_colors.get(grade, 'grey'))
                rows += row('Security Grade', grade_badge)
                rows += row('URL',    h.get('url', 'N/A'))
                rows += row('Status', h.get('status', 'N/A'))

                if h.get('present'):
                    present_html = ''.join(
                        f'<div class="check-ok">✔ {name}</div>'
                        for name in h['present']
                    )
                    rows += row('Present Headers', present_html)

                if h.get('missing'):
                    missing_html = ''.join(
                        f'<div class="check-fail">✘ [{sev}] {name} — {desc}</div>'
                        for name, (sev, desc) in h['missing'].items()
                    )
                    rows += row('Missing Headers', missing_html)

                if h.get('disclosed'):
                    disc_html = ''.join(
                        f'<div class="check-warn">⚠ {name}: {val}</div>'
                        for name, val in h['disclosed'].items()
                    )
                    rows += row('Info Disclosure', disc_html)

            sections_html += section('🛡️ HTTP Headers Audit', table(rows))

        # --- Tech ---
        if self.results.get('tech'):
            t    = self.results['tech']
            rows = ''
            if t.get('success'):
                rows += row('Web Server',    t.get('server') or '<span class="muted">Not detected</span>')
                rows += row('Framework',     t.get('framework') or '<span class="muted">Not detected</span>')
                rows += row('CMS',           t.get('cms') or '<span class="muted">Not detected</span>')
                rows += row('CDN',           ', '.join(t.get('cdn', [])) or '<span class="muted">Not detected</span>')
                rows += row('WAF',           ', '.join(t.get('waf', [])) or '<span class="muted">Not detected</span>')
                rows += row('JS Frameworks', ', '.join(t.get('js_frameworks', [])) or '<span class="muted">Not detected</span>')
            sections_html += section('⚙️ Technology Fingerprint', table(rows))

        # --- Threat Intel ---
        if self.results.get('threat'):
            ti   = self.results['threat']
            rows = ''
            if ti.get('success'):
                rows += row('Domain', ti.get('domain', 'N/A'))
                rows += row('IP',     ti.get('ip', 'N/A'))

                dnsbl  = ti.get('dnsbl', {})
                listed = dnsbl.get('listed', [])
                if listed:
                    rows += row('Blacklists', badge(f'Listed on {len(listed)}: ' + ", ".join(listed), 'red'))
                else:
                    clean = dnsbl.get('clean', [])
                    rows += row('Blacklists', badge(f'Clean on {len(clean)} lists', 'green'))

                tf         = ti.get('threatfox', {})
                total_hits = len(tf.get('domain_hits', [])) + len(tf.get('ip_hits', []))
                tf_badge   = badge(f'{total_hits} IOC matches', 'red') if total_hits else badge('No IOC matches', 'green')
                rows      += row('ThreatFox', tf_badge)

                shodan = ti.get('shodan', {})
                if not shodan.get('no_data') and not shodan.get('error'):
                    rows += row('Shodan Ports', ', '.join(str(p) for p in shodan.get('ports', [])) or 'None')
                    cves  = shodan.get('cves', [])
                    cve_html = ''.join(f'<div class="check-fail">• {c}</div>' for c in cves) if cves else badge('None', 'green')
                    rows += row(f'CVEs ({len(cves)})', cve_html)
                    if shodan.get('tags'):
                        rows += row('Tags', ', '.join(shodan['tags']))
                    if shodan.get('hostnames'):
                        rows += row('Hostnames', '<br>'.join(shodan['hostnames'][:5]))

            sections_html += section('⚠️ Threat Intelligence', table(rows))

        # --- Full HTML page ---
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blaster Report — {self.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 30px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f2e, #252d3d);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px 40px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.2em;
            background: linear-gradient(90deg, #a855f7, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        .header .meta {{
            color: #8b949e;
            font-size: 0.95em;
            line-height: 1.8;
        }}
        .header .domain {{
            font-size: 1.3em;
            color: #58a6ff;
            font-weight: 600;
        }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-title {{
            background: #1c2128;
            padding: 14px 20px;
            font-size: 1.05em;
            font-weight: 600;
            color: #e6edf3;
            border-bottom: 1px solid #30363d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        td, th {{
            padding: 10px 20px;
            border-bottom: 1px solid #21262d;
            font-size: 0.92em;
            vertical-align: top;
        }}
        th {{
            background: #1c2128;
            color: #8b949e;
            font-weight: 600;
            text-align: left;
        }}
        td:last-child {{ border-bottom: none; }}
        tr:last-child td {{ border-bottom: none; }}
        .label {{
            color: #8b949e;
            font-weight: 500;
            width: 180px;
            white-space: nowrap;
        }}
        ul {{
            padding: 12px 20px;
            list-style: none;
        }}
        ul li {{
            padding: 4px 0;
            font-size: 0.9em;
            color: #c9d1d9;
        }}
        ul li::before {{
            content: '• ';
            color: #58a6ff;
        }}
        p {{ padding: 12px 20px; }}
        .muted {{ color: #484f58; font-style: italic; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.82em;
            font-weight: 600;
        }}
        .badge.green  {{ background: #1a3a2a; color: #3fb950; border: 1px solid #3fb950; }}
        .badge.red    {{ background: #3a1a1a; color: #f85149; border: 1px solid #f85149; }}
        .badge.orange {{ background: #3a2a1a; color: #d29922; border: 1px solid #d29922; }}
        .badge.blue   {{ background: #1a2a3a; color: #58a6ff; border: 1px solid #58a6ff; }}
        .badge.grey   {{ background: #21262d; color: #8b949e; border: 1px solid #30363d; }}
        .check-ok   {{ color: #3fb950; padding: 2px 0; font-size: 0.9em; }}
        .check-fail {{ color: #f85149; padding: 2px 0; font-size: 0.9em; }}
        .check-warn {{ color: #d29922; padding: 2px 0; font-size: 0.9em; }}
        .footer {{
            text-align: center;
            color: #484f58;
            font-size: 0.85em;
            margin-top: 30px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ Blaster Recon Report</h1>
        <div class="meta">
            <div class="domain">{self.domain}</div>
            <div>Generated : {self.timestamp}</div>
            <div>Tool      : Blaster v2.0 — Domain Recon Made Brutal</div>
            <div>Author    : Usman Faridi</div>
        </div>
    </div>

    {sections_html}

    <div class="footer">
        Generated by Blaster — Domain Recon Made Brutal &nbsp;|&nbsp; Usman Faridi
    </div>
</body>
</html>"""

        return html
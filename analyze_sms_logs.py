#!/usr/bin/env python3
"""
analyze_sms_logs.py

Reads a Twilio SMS export CSV and produces a CSV report that flags messages likely to be
filtered/marked-as-spam by US carriers, with primary reasons and remediation suggestions.

Usage (PowerShell):
  python ./analyze_sms_logs.py -i ./sms_logs.csv -o ./sms_report.csv

The script uses simple heuristics (links, short domains, spammy words, opt-out, segments,
sender format) — it does not query external APIs.
"""

import csv
import re
import argparse
import os
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime
from collections import Counter
import json

# Common shortener domains and spam indicators
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "adf.ly", "rb.gy"
}
SPAM_WORDS = {
    "free", "winner", "loan", "credit", "urgent", "risk", "coupon",
    "buy now", "call now", "claim", "act now", "limited time", "verify",
    "click here"
}
OPT_OUT_WORDS = {"stop", "unsubscribe", "opt out", "reply stop"}

URL_RE = re.compile(r'https?://\S+', flags=re.IGNORECASE)
US_PHONE_RE = re.compile(r'(?:\+?1[\s\-\(\)]*\d{3}[\s\-\)]*\d{3}[\s\-\)]*\d{4}|\(?\d{3}\)?[\s\-\)]*\d{3}[\s\-\)]*\d{4})')


def extract_domains(text):
    urls = URL_RE.findall(text or "")
    domains = []
    for u in urls:
        try:
            p = urlparse(u)
            host = p.netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            domains.append(host)
        except Exception:
            continue
    return urls, domains


def is_short_domain(dom):
    if not dom:
        return False
    host = dom.split(':')[0].split('@')[-1]
    # Known shorteners are risky
    if host in SHORTENER_DOMAINS:
        return True
    # treat short base label (e.g. spa.guru -> base 'spa' length 3) as suspicious
    base = host.split('.')[0]
    return len(base) <= 4


def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def analyze_row(row):
    body = (row.get("Body") or "").strip()
    from_num = (row.get("From") or "").strip()
    to_num = (row.get("To") or "").strip()
    status = (row.get("Status") or "").strip().lower()

    shortened_flag = str(row.get("ShortenedLinkEnabled") or "").strip().upper() == "TRUE"
    num_segments = safe_int(row.get("NumSegments") or row.get("NumSegments", 0))

    urls, domains = extract_domains(body)
    has_url = len(urls) > 0
    short_domain_used = any(is_short_domain(d) for d in domains)
    contains_phone_in_body = bool(US_PHONE_RE.search(body))
    lower = body.lower()
    spammy_found = [w for w in SPAM_WORDS if w in lower]
    has_opt_out = any(word in lower for word in OPT_OUT_WORDS)

    # Detect if sender looks like a US long code (very simple heuristic)
    sender_is_us_longcode = False
    raw_from = from_num
    if raw_from:
        norm = raw_from.lstrip('+').replace('-', '').replace(' ', '')
        if norm.startswith('1') and len(norm) >= 11:
            sender_is_us_longcode = True
        if len(norm) == 10:  # maybe without country code
            sender_is_us_longcode = True

    score = 0
    reasons = []

    # Heuristics & scoring
    if has_url:
        score += 2
        reasons.append("contains_link")
        if short_domain_used or shortened_flag:
            score += 2
            reasons.append("short_or_untrusted_link")
    if contains_phone_in_body:
        score += 1
        reasons.append("contains_phone_in_body")
    if spammy_found:
        score += 2
        reasons.append("spammy_words:" + ",".join(spammy_found[:3]))
    # Promotional-like long messages should include opt-out
    if not has_opt_out and ("promo" in lower or spammy_found or len(body) > 200):
        score += 1
        reasons.append("missing_opt_out")
    if num_segments and num_segments > 3:
        score += 1
        reasons.append("many_segments")
    if not sender_is_us_longcode:
        score += 1
        reasons.append("sender_not_identified_as_us_longcode")

    # Determine primary reason
    primary = "none"
    if score >= 4:
        if "short_or_untrusted_link" in reasons:
            primary = "suspicious_link_or_shortener"
        elif any(r.startswith('spammy_words') for r in reasons):
            primary = "spammy_content"
        else:
            primary = reasons[0] if reasons else "high_risk"
    elif score >= 2:
        primary = "potential_risk"
    else:
        primary = "low_risk"

    remediations = []
    if "short_or_untrusted_link" in reasons or has_url:
        remediations.append("Use a consistent branded (HTTPS) landing domain; avoid URL shorteners and multi-hop redirects.")
    if "missing_opt_out" in reasons:
        remediations.append("Include clear opt-out instructions (e.g., 'Reply STOP to unsubscribe').")
    if any(r.startswith('spammy_words') for r in reasons):
        remediations.append("Remove promotional phrasing from transactional messages; keep wording plain and specific.")
    if "sender_not_identified_as_us_longcode" in reasons:
        remediations.append("Send via an approved US A2P channel (registered 10DLC, short code, or provisioned toll-free) and map campaigns correctly.")
    if "many_segments" in reasons:
        remediations.append("Shorten messages to avoid multi-segment fragmentation and unexpected encoding.")

    return {
        "Sid": row.get("Sid", ""),
        "From": from_num,
        "To": to_num,
        "Status": status,
        "Body": body,
        "HasURL": has_url,
        "Domains": ";".join(domains),
        "ShortDomain": short_domain_used,
        "ContainsPhoneInBody": contains_phone_in_body,
        "SpammyWords": ",".join(spammy_found),
        "HasOptOut": has_opt_out,
        "NumSegments": num_segments,
        "Score": score,
        "PrimaryReason": primary,
        "Remediation": " | ".join(remediations) or "No action suggested"
    }


def read_csv_rows(path):
    rows = []
    with open(path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def write_report(path, results):
    fieldnames = ["Sid", "From", "To", "Status", "Body", "HasURL", "Domains", "ShortDomain",
                  "ContainsPhoneInBody", "SpammyWords", "HasOptOut", "NumSegments",
                  "Score", "PrimaryReason", "Remediation"]
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)


# New helpers: date parsing, validation and aggregated stats
def parse_date(s):
    if not s:
        return None
    s = s.strip()
    # try ISO format first
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    # common fallback formats
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]
    for f in fmts:
        try:
            return datetime.strptime(s, f)
        except Exception:
            continue
    return None


def validate_columns(rows, required):
    missing = []
    if not rows:
        return required
    first = rows[0]
    for r in required:
        if r not in first:
            missing.append(r)
    return missing


def write_csv_counter(path, counter, key_name='key', value_name='count'):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([key_name, value_name])
        for k, v in counter.most_common():
            writer.writerow([k, v])


def compute_and_write_summary(rows, results, out_base_folder='.'):
    # rows: original CSV rows (list of dict)
    # results: analyzed rows returned by analyze_row
    total = len(results)
    delivered = sum(1 for r in results if r.get('Status') == 'delivered')
    potential = sum(1 for r in results if int(r.get('Score', 0)) >= 2)
    high = sum(1 for r in results if int(r.get('Score', 0)) >= 4)

    # Error summary
    error_counter = Counter()
    for row in rows:
        # Normalize and ignore common 'no-error' markers like '0' or 'none'
        code = (row.get('ErrorCode') or row.get('Error', '') or '').strip()
        if not code:
            continue
        code_norm = code.lower()
        if code_norm in ('0', 'none', 'n/a', 'na', '-'):
            continue
        error_counter[code] += 1

    # Domain and sender counters
    domain_counter = Counter()
    sender_counter = Counter()
    optout_count = 0
    shortlink_count = 0
    segment_counter = Counter()
    hourly = Counter()

    for r, orig in zip(results, rows):
        # domains field from results may be semicolon separated
        domains = (r.get('Domains') or '')
        if domains:
            for d in domains.split(';'):
                if d:
                    domain_counter[d] += 1
        sender = (r.get('From') or orig.get('From') or '').strip()
        if sender:
            sender_counter[sender] += 1

        if str(r.get('HasOptOut', False)).lower() in ('true', '1', 'yes') or r.get('HasOptOut'):
            optout_count += 1

        if str(r.get('ShortDomain', False)).lower() in ('true', '1', 'yes') or str(orig.get('ShortenedLinkEnabled') or '').upper() == 'TRUE':
            shortlink_count += 1

        try:
            segs = int(r.get('NumSegments') or 0)
        except Exception:
            segs = 0
        segment_counter[segs] += 1

        # hourly distribution using SentDate column if present
        sent = orig.get('SentDate') or orig.get('Sent') or orig.get('Date') or orig.get('SentDate (ISO)')
        dt = parse_date(sent)
        if dt:
            hourly_key = dt.strftime('%Y-%m-%d %H:00')
            hourly[hourly_key] += 1

    # write summary text
    summary_path = os.path.join(out_base_folder, 'sms_summary.txt')
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(f'Total messages: {total}\n')
        f.write(f'Delivered: {delivered} ({delivered/total*100:.1f}% if total>0 else 0)\n')
        f.write(f'Potential risk (score>=2): {potential}\n')
        f.write(f'High risk (score>=4): {high}\n')
        f.write('\nTop error codes:\n')
        for code, cnt in error_counter.most_common(20):
            f.write(f' {code}: {cnt}\n')
        f.write('\nTop domains:\n')
        for d, cnt in domain_counter.most_common(20):
            f.write(f' {d}: {cnt}\n')
        f.write('\nTop senders:\n')
        for s, cnt in sender_counter.most_common(20):
            f.write(f' {s}: {cnt}\n')
        f.write(f'Opt-out containing messages: {optout_count}\n')
        f.write(f'Messages with short/untrusted link flag: {shortlink_count}\n')

    # write domain and sender CSVs
    write_csv_counter(os.path.join(out_base_folder, 'domain_stats.csv'), domain_counter, 'domain', 'count')
    write_csv_counter(os.path.join(out_base_folder, 'sender_stats.csv'), sender_counter, 'sender', 'count')
    # write hourly distribution
    with open(os.path.join(out_base_folder, 'hourly_volume.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['hour','count'])
        for k, v in sorted(hourly.items()):
            writer.writerow([k, v])

    return summary_path, os.path.join(out_base_folder, 'domain_stats.csv'), os.path.join(out_base_folder, 'sender_stats.csv')


def generate_html_report(results, rows, out_path):
    """Generate an HTML report with charts and tables (uses Chart.js from CDN)."""
    # Compute aggregates
    risk_counts = Counter()
    error_counter = Counter()
    domain_counter = Counter()
    for r, orig in zip(results, rows):
        # normalize error code (if any). Messages with ErrorCode '0' are accepted by Twilio
        # and should be excluded from the risk pie chart, but we still collect domain
        # and error statistics for other visualizations.
        code = (orig.get('ErrorCode') or orig.get('Error', '') or '').strip()
        cn = code.lower() if code else ''

        # Count risk distribution only for messages that do NOT have ErrorCode '0'
        if cn != '0':
            primary = r.get('PrimaryReason') or 'none'
            if primary == 'low_risk':
                risk_counts['low'] += 1
            elif primary == 'potential_risk':
                risk_counts['potential'] += 1
            elif primary in ('suspicious_link_or_shortener', 'spammy_content', 'high_risk'):
                risk_counts['high'] += 1
            else:
                risk_counts['other'] += 1

        # still accumulate error counts (ignore harmless markers like '0'/'none')
        if code:
            if cn not in ('0', 'none', 'n/a', 'na', '-'):
                error_counter[code] += 1

        # always collect domain counts for domain chart
        domains = (r.get('Domains') or '')
        if domains:
            for d in domains.split(';'):
                if d:
                    domain_counter[d] += 1

    top_domains = domain_counter.most_common(10)

    high_risk_rows = [r for r in results if int(r.get('Score', 0)) >= 4]
    failed_rows = []
    for r, orig in zip(results, rows):
        status = (r.get('Status') or '').lower()
        if status and status not in ('delivered', 'sent', 'queued'):
            failed_rows.append({
                'Sid': r.get('Sid'), 'To': r.get('To'), 'From': r.get('From'),
                'Status': r.get('Status'), 'Error': orig.get('ErrorCode') or orig.get('ErrorMessage') or orig.get('Error') or ''
            })

    # build errors grouped by recipient (To)
    from collections import defaultdict as _defaultdict
    errors_by_to = _defaultdict(Counter)
    example_msg = {}
    for r, orig in zip(results, rows):
        code = (orig.get('ErrorCode') or orig.get('Error') or orig.get('ErrorMessage') or '').strip()
        if not code:
            continue
        cn = code.lower()
        if cn in ('0', 'none', 'n/a', 'na', '-'):
            continue
        to = (r.get('To') or orig.get('To') or '').strip()
        errors_by_to[to][code] += 1
        key = (to, code)
        if key not in example_msg:
            example_msg[key] = (r.get('Body') or orig.get('Body') or '')

    # Prepare JSON blobs for JS
    html_data = {
        'risk': {
            'low': risk_counts.get('low', 0),
            'potential': risk_counts.get('potential', 0),
            'high': risk_counts.get('high', 0),
            'other': risk_counts.get('other', 0)
        },
        'top_domains': top_domains,
         # detailed error descriptions (include common Twilio error codes and descriptions)
         'error_details': [
             # code, count, description
             {
                 'code': str(code),
                 'count': cnt,
                 'desc': (
                     'No Twilio error. These messages were accepted by Twilio.' if str(code) == '0' else
                     'Destination is a landline or otherwise unreachable for SMS.' if str(code) == '30006' else
                     'Message filtered as carrier violation / spam-like content (A2P filtering, content/traffic trust issues).' if str(code) == '30007' else
                     'Invalid To phone number format/value.' if str(code) == '21211' else
                     'Unknown destination handset (number not valid/active for SMS on carrier side).' if str(code) == '30005' else
                     'Usually destination/channel-level delivery restriction (carrier/network policy issue).' if str(code) == '30019' else
                     ''
                 )
             } for code, cnt in error_counter.most_common(20)
         ],
         'errors_by_to': [
             { 'to': to, 'error': code, 'count': cnt, 'example': example_msg.get((to, code), '') }
             for to, ctr in errors_by_to.items() for code, cnt in ctr.items()
         ],
         # omit 'From' (same sender) to reduce visual noise
         'high_risk_rows': [{ 'Sid': r.get('Sid'), 'To': r.get('To'), 'PrimaryReason': r.get('PrimaryReason'), 'Score': r.get('Score'), 'Domains': r.get('Domains'), 'Body': r.get('Body') } for r in high_risk_rows],
         'failed_rows': failed_rows
     }

    # Use a placeholder in the template to avoid Python interpreting JS braces
    html_template = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SMS Analysis Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    html,body { height:100%; margin:0; }
    body { font-family: Arial, sans-serif; background: #fafafa; padding: 24px; }
    #report { background: #fff; border: 1px solid #e0e0e0; padding: 20px; border-radius: 8px; max-width: 1400px; margin: 0 auto; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
    h1 { margin-top: 0; }
    .charts { display:flex; gap:20px; align-items:flex-start; }
    .chart { background: #fff; }
    .chart.bar { flex: 1 1 60%; min-width: 320px; }
    .chart.pie { width: 360px; flex: 0 0 360px; }
    .chart canvas { display:block; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    td.body-cell { max-width: 700px; white-space: normal; word-break: break-word; }
    th { background: #f2f2f2; }
    .section { margin-bottom: 30px; }
  </style>
</head>
<body>
  <div id="report">
  <h1>SMS Analysis Report</h1>
  <div class="section">
    <h2>Risk distribution</h2>
    <div class="charts">
      <div class="chart bar"><canvas id="domainBar" style="height:360px;"></canvas></div>
      <div class="chart pie"><canvas id="riskPie" style="max-width:360px; max-height:360px;"></canvas></div>
    </div>
  </div>
  <div class="section">
    <h2>Error details</h2>
    <table id="errorDetails"><thead><tr><th>Code</th><th>Count</th><th>Description</th></tr></thead><tbody></tbody></table>
  </div>
  <div class="section">
    <h2>Errors by recipient</h2>
    <table id="errorByTo"><thead><tr><th>To</th><th>ErrorCode</th><th>Count</th><th>Example SMS</th></tr></thead><tbody></tbody></table>
  </div>
  <div class="section">
    <h2>High-risk messages (Score >= 4)</h2>
    <table id="highRisk"><thead><tr><th>Sid</th><th>To</th><th>Score</th><th>PrimaryReason</th><th>Domains</th><th>Message</th></tr></thead><tbody></tbody></table>
  </div>
  <div class="section">
    <h2>Failed / non-delivered messages</h2>
    <table id="failed"><thead><tr><th>Sid</th><th>To</th><th>Status</th><th>Error</th></tr></thead><tbody></tbody></table>
  </div>
  </div> <!-- /report -->

<script>
const data = <<DATA>>;
// Domain bar (rendered first)
const ctx2 = document.getElementById('domainBar').getContext('2d');
const domainLabels = (data.top_domains||[]).map(d=>d[0]);
const domainValues = (data.top_domains||[]).map(d=>d[1]);
new Chart(ctx2, {
  type: 'bar',
  data: {
    labels: domainLabels,
    datasets: [{ label: 'Top domains', data: domainValues, backgroundColor: '#2196F3' }]
  },
  options: { indexAxis: 'y', maintainAspectRatio: false }
});
// Risk pie (smaller)
const ctx = document.getElementById('riskPie').getContext('2d');
new Chart(ctx, {
  type: 'pie',
  data: {
    labels: ['Low','Potential','High','Other'],
    datasets: [{
      data: [data.risk.low, data.risk.potential, data.risk.high, data.risk.other],
      backgroundColor: ['#4CAF50','#FF9800','#F44336','#9E9E9E']
    }]
  },
  options: { responsive: true, maintainAspectRatio: true }
});

// Populate error details table with descriptions
const errDetT = document.querySelector('#errorDetails tbody');
(data.error_details||[]).forEach(function(e){ var tr=document.createElement('tr'); tr.innerHTML = '<td>'+ (e.code||'') +'</td><td>'+ (e.count||'') +'</td><td>'+ (e.desc||'') +'</td>'; errDetT.appendChild(tr); });
// Populate errors-by-recipient table
const errByToT = document.querySelector('#errorByTo tbody');
(data.errors_by_to||[]).forEach(function(e){ var tr=document.createElement('tr'); tr.innerHTML = '<td>'+ (e.to||'') +'</td><td>'+ (e.error||'') +'</td><td>'+ (e.count||'') +'</td><td class="body-cell">'+ (e.example||'') +'</td>'; errByToT.appendChild(tr); });
// High risk table
const highT = document.querySelector('#highRisk tbody');
(data.high_risk_rows||[]).forEach(function(r){ var tr=document.createElement('tr'); tr.innerHTML = '<td>'+ (r.Sid||'') +'</td><td>'+ (r.To||'') +'</td><td>'+ (r.Score||'') +'</td><td>'+ (r.PrimaryReason||'') +'</td><td>'+ (r.Domains||'') +'</td><td class="body-cell">'+ (r.Body||'') +'</td>'; highT.appendChild(tr); });
// Failed table
const failT = document.querySelector('#failed tbody');
(data.failed_rows||[]).forEach(function(r){ var tr=document.createElement('tr'); tr.innerHTML = '<td>'+ (r.Sid||'') +'</td><td>'+ (r.To||'') +'</td><td>'+ (r.Status||'') +'</td><td>'+ (r.Error||'') +'</td>'; failT.appendChild(tr); });
</script>
</body>
</html>
"""

    html = html_template.replace('<<DATA>>', json.dumps(html_data))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)


def main():
    p = argparse.ArgumentParser(description='Analyze Twilio SMS CSV and flag likely spammy messages')
    p.add_argument('-i', '--input', required=False, default='sms log.csv', help='input CSV file exported from Twilio (default: "sms log.csv")')
    p.add_argument('-o', '--output', default='sms_report.csv', help='output CSV report file')
    args = p.parse_args()

    # accept a CSV placed in the same folder as the script named 'sms log.csv' by default
    input_path = args.input
    if not os.path.exists(input_path):
        print(f"Input file not found: {input_path}\nMake sure the CSV is uploaded to the workspace and the filename is correct.")
        return

    rows = read_csv_rows(input_path)
    if not rows:
        print('No rows found in input file.')
        return

    # validate required columns
    required = ['Sid','From','To','Body','Status']
    missing = validate_columns(rows, required)
    if missing:
        print('Warning: input CSV missing expected columns:', ', '.join(missing))

    results = [analyze_row(r) for r in rows]
    write_report(args.output, results)

    # additional aggregated reports
    out_folder = os.path.dirname(os.path.abspath(args.output)) or '.'
    summary_path, domain_csv, sender_csv = compute_and_write_summary(rows, results, out_base_folder=out_folder)

    # generate HTML report
    html_path = os.path.join(out_folder, 'sms_report.html')
    generate_html_report(results, rows, html_path)

    total = len(results)
    flagged = [r for r in results if r['Score'] >= 2]
    high_risk = [r for r in results if r['Score'] >= 4]

    print(f"Processed {total} messages. Potential risk: {len(flagged)}. High risk: {len(high_risk)}")
    if high_risk:
        print('\nHigh risk message SIDs and primary reasons:')
        for r in high_risk:
            print(f" {r['Sid'] or '<no-sid>'} -> {r['PrimaryReason']} domains={r['Domains']} score={r['Score']}")

    print(f"Summary written to: {summary_path}")
    print(f"Domain stats: {domain_csv}")
    print(f"Sender stats: {sender_csv}")
    print(f"HTML report: {html_path}")


if __name__ == '__main__':
    main()

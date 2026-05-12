import csv

IN_ORIG = 'sms log.csv'
IN_ANALYZED = 'sms_report.csv'
OUT = 'pie_messages.csv'


def read_rows(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

orig = read_rows(IN_ORIG)
res = read_rows(IN_ANALYZED)

out_rows = []
for r, orig_row in zip(res, orig):
    code = (orig_row.get('ErrorCode') or orig_row.get('Error') or orig_row.get('ErrorMessage') or '').strip()
    cn = code.lower() if code else ''
    # include rows counted in the pie chart (exclude ErrorCode '0')
    if cn == '0':
        continue
    primary = (r.get('PrimaryReason') or '').strip()
    if primary == 'low_risk':
        cat = 'Low'
    elif primary == 'potential_risk':
        cat = 'Potential'
    elif primary in ('suspicious_link_or_shortener', 'spammy_content', 'high_risk'):
        cat = 'High'
    else:
        cat = 'Other'

    out_rows.append({
        'Sid': r.get('Sid',''),
        'To': r.get('To','') or orig_row.get('To',''),
        'From': r.get('From','') or orig_row.get('From',''),
        'Status': r.get('Status',''),
        'ErrorCode': code,
        'Category': cat,
        'PrimaryReason': primary,
        'Score': r.get('Score',''),
        'Domains': r.get('Domains',''),
        'Body': (r.get('Body') or orig_row.get('Body') or '').replace('\r',' ').replace('\n','\n')
    })

with open(OUT, 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['Sid','To','From','Status','ErrorCode','Category','PrimaryReason','Score','Domains','Body']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in out_rows:
        writer.writerow(row)

print(f'Wrote {len(out_rows)} rows to {OUT}')

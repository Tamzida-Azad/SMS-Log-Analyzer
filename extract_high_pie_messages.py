import csv
import os

IN_ORIG = 'sms log.csv'
IN_ANALYZED = 'sms_report.csv'
OUT = 'high_pie_messages.csv'

def read_rows(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

orig = read_rows(IN_ORIG)
res = read_rows(IN_ANALYZED)

high_set = ('suspicious_link_or_shortener','spammy_content','high_risk')

out_rows = []
for r, orig_row in zip(res, orig):
    code = (orig_row.get('ErrorCode') or orig_row.get('Error') or orig_row.get('ErrorMessage') or '').strip()
    cn = code.lower() if code else ''
    primary = (r.get('PrimaryReason') or '').strip()
    # replicate chart inclusion: include when error code is not '0' (empty also included)
    if cn != '0' and primary in high_set:
        out_rows.append({
            'Sid': r.get('Sid',''),
            'To': r.get('To','') or orig_row.get('To',''),
            'From': r.get('From','') or orig_row.get('From',''),
            'Status': r.get('Status',''),
            'ErrorCode': code,
            'PrimaryReason': primary,
            'Score': r.get('Score',''),
            'Domains': r.get('Domains',''),
            'Body': (r.get('Body') or orig_row.get('Body') or '').replace('\r',' ').replace('\n','\n')
        })

# write out
with open(OUT, 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['Sid','To','From','Status','ErrorCode','PrimaryReason','Score','Domains','Body']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in out_rows:
        writer.writerow(row)

print(f'Wrote {len(out_rows)} rows to {OUT}')

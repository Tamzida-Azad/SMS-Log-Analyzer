# SMS Log Analyzer

Lightweight Python scripts to analyze Twilio SMS export CSVs, flag messages likely to be filtered or marked as spam by carriers, and generate CSV and HTML reports.

## Features

- Heuristic detection for suspicious links, short domains, spammy words, opt-out wording, and multi-segment messages.
- Generates a CSV summary, domain/sender stats, hourly volume, and an HTML report with charts.
- Helper extractors to export messages included in report pie-charts (High / All slices).
- Excludes Twilio ErrorCode `0` from risk pie counts while still collecting other stats (configurable).

## Getting started

Requirements: Python 3.8+

Run analyzer:

```
python analyze_sms_logs.py -i "sms log.csv" -o "sms_report.csv"
```

Extract pie-chart messages:

```
python extract_pie_messages.py
python extract_high_pie_messages.py
```

## Output

- `sms_report.csv` — analyzed rows with scores and primary reasons
- `sms_report.html` — interactive HTML report with charts
- `sms_summary.txt`, `domain_stats.csv`, `sender_stats.csv`, `hourly_volume.csv`
- `pie_messages.csv` / `high_pie_messages.csv` — messages included in the pie chart slices

## Notes

- The tool uses heuristics only and does not call external APIs.
- Check file permissions before running; the script will fail if it cannot write the output files.

## License

MIT

# PostgreSQL Slow Query Fingerprint Analyzer CLI (Lite)

A zero-dependency, 100% Python 3.9+ stdlib CLI tool to parse PostgreSQL `log_min_duration_statement` logs and `pg_stat_statements` CSV exports, normalize SQL queries into canonical fingerprints, compute latency percentiles, and flag common SQL anti-patterns.

## Features

- **Zero external dependencies** — pure Python 3.9+ standard library (`argparse`, `csv`, `json`, `re`, `hashlib`, `pathlib`).
- **Dual input support** — parses both PostgreSQL slow-query text logs (including multi-line SQL) and `pg_stat_statements` CSV exports.
- **SQL Fingerprinting** — normalizes literals, `$1` bind parameters, `IN (...)` lists, `VALUES (...)` lists, and comments into canonical fingerprints.
- **Latency Aggregation** — computes `calls`, `total_ms`, `mean_ms`, `p50_ms`, `p95_ms`, and `max_ms`.
- **Built-in Heuristics** — flags `SELECT *`, leading wildcard `LIKE`/`ILIKE` (`'%foo'`), `missing LIMIT` on non-aggregate `SELECT`s, potential `N+1` query patterns, and `large IN (...)` lists.
- **Multiple Output Formats** — `text`, `json`, and `markdown` tables.

## Quick Start

```bash
# Analyze a PostgreSQL slow-query log (text output)
python pg_slow_analyzer.py sample_logs/postgresql_slow.log

# Analyze pg_stat_statements CSV and output JSON sorted by p95 latency
python pg_slow_analyzer.py sample_logs/pg_stat_statements.csv --format json --sort-by p95_ms

# Generate a Markdown report for top 10 slowest fingerprints
python pg_slow_analyzer.py sample_logs/postgresql_slow.log --format markdown --top 10
```

## Metrics Reference

| Metric | Description |
|---|---|
| `calls` | Total number of executions for this query fingerprint |
| `total_ms` | Cumulative execution time in milliseconds |
| `mean_ms` | Average execution time per call (`total_ms / calls`) |
| `p50_ms` | Median (50th percentile) execution time in milliseconds |
| `p95_ms` | 95th percentile execution time in milliseconds |
| `max_ms` | Maximum observed execution time in milliseconds |

## Running Tests

```bash
python -m unittest discover -s tests -v
```

---

## Pro Studio Version (Web UI + MySQL + HTML Reports + Alerting)

Need an interactive **Web UI**, **MySQL slow-query log** support, executive **HTML/PDF Reports**, historical trend diffing, and **Slack/Telegram/Webhook Alerting**?

Check out the **Pro Studio Version** on our storefront:
👉 **[https://funpay.com/users/20096179/](https://funpay.com/users/20096179/)**

## License

MIT License — see [LICENSE](LICENSE).

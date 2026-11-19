#!/usr/bin/env python3
"""
postgres-slow-query-fingerprint-analyzer-cli-lite
100% Python 3.9+ stdlib CLI for PostgreSQL slow-query log & pg_stat_statements CSV analysis.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


# Regexes for PostgreSQL log_min_duration_statement lines
# Example:
# 2026-11-19 10:15:32.123 UTC [12345] app@prod LOG:  duration: 245.678 ms  statement: SELECT * FROM users WHERE id = 42;
# 2026-11-19 10:15:32.123 UTC [12345] LOG:  duration: 120.500 ms  execute <unnamed>: SELECT id FROM orders WHERE status = 'pending'
PG_LOG_DURATION_RE = re.compile(
    r"duration:\s+(?P<duration>\d+(?:\.\d+)?)\s+ms\s+"
    r"(?:statement|execute\s+[^:]+|parse\s+[^:]+|bind\s+[^:]+):\s*(?P<sql>.+)$",
    re.IGNORECASE,
)

# Timestamp prefix to detect new log entries when handling multi-line SQL
PG_LOG_LINE_START_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
)

# SQL normalization patterns
_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_LINE_COMMENT = re.compile(r"--[^\r\n]*")
_RE_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'")
_RE_DOUBLE_QUOTED_STR = re.compile(r'"(?:""|[^"])*"')
_RE_DOLLAR_PARAM = re.compile(r"\$\d+")
_RE_HEX_LITERAL = re.compile(r"\b0x[0-9a-fA-F]+\b")
_RE_FLOAT_LITERAL = re.compile(r"\b\d+\.\d+\b")
_RE_INT_LITERAL = re.compile(r"\b\d+\b")
_RE_BOOL_NULL = re.compile(r"\b(?:TRUE|FALSE|NULL)\b", re.IGNORECASE)
_RE_IN_LIST = re.compile(
    r"\bIN\s*\(\s*(?:\?(?:\s*,\s*\?)*)\s*\)", re.IGNORECASE
)
_RE_VALUES_LIST = re.compile(
    r"\bVALUES\s*(?:\(\s*(?:\?(?:\s*,\s*\?)*)\s*\)\s*,?\s*)+", re.IGNORECASE
)
_RE_WHITESPACE = re.compile(r"\s+")

# Heuristic patterns (applied to raw SQL before full literal stripping where needed)
_RE_SELECT_STAR = re.compile(r"\bSELECT\s+\*", re.IGNORECASE)
_RE_LEADING_WILDCARD_LIKE = re.compile(
    r"\b(?:I?LIKE)\s+'[%_][^']*'", re.IGNORECASE
)
_RE_SELECT_STMT = re.compile(r"^\s*SELECT\b", re.IGNORECASE)
_RE_HAS_LIMIT = re.compile(r"\bLIMIT\b", re.IGNORECASE)
_RE_HAS_AGGREGATE = re.compile(
    r"\b(?:COUNT|SUM|AVG|MIN|MAX)\s*\(", re.IGNORECASE
)
_RE_LARGE_IN = re.compile(
    r"\bIN\s*\(([^)]{1,4000})\)", re.IGNORECASE
)


@dataclass
class QueryEvent:
    sql: str
    duration_ms: float
    calls: int = 1
    source: str = "log"


@dataclass
class FingerprintStats:
    fingerprint_id: str
    fingerprint: str
    sample_sql: str
    calls: int = 0
    total_ms: float = 0.0
    durations: List[float] = field(default_factory=list)
    min_ms: Optional[float] = None
    max_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)

    def add_event(self, event: QueryEvent) -> None:
        self.calls += event.calls
        self.total_ms += event.duration_ms
        # For log events (calls=1), store individual duration; for CSV aggregate rows, store mean per call
        per_call = event.duration_ms / max(event.calls, 1)
        self.durations.append(per_call)
        if self.min_ms is None or per_call < self.min_ms:
            self.min_ms = per_call
        if per_call > self.max_ms:
            self.max_ms = per_call

    @property
    def mean_ms(self) -> float:
        return self.total_ms / self.calls if self.calls > 0 else 0.0

    @property
    def p50_ms(self) -> float:
        return percentile(self.durations, 50.0)

    @property
    def p95_ms(self) -> float:
        return percentile(self.durations, 95.0)


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_vals[int(rank)]
    frac = rank - low
    return sorted_vals[low] + frac * (sorted_vals[high] - sorted_vals[low])


def normalize_sql(sql: str) -> str:
    """Normalize a PostgreSQL query into a canonical fingerprint."""
    cleaned = _RE_BLOCK_COMMENT.sub(" ", sql)
    cleaned = _RE_LINE_COMMENT.sub(" ", cleaned)
    cleaned = _RE_SINGLE_QUOTED.sub("?", cleaned)
    cleaned = _RE_DOLLAR_PARAM.sub("?", cleaned)
    cleaned = _RE_HEX_LITERAL.sub("?", cleaned)
    cleaned = _RE_FLOAT_LITERAL.sub("?", cleaned)
    cleaned = _RE_INT_LITERAL.sub("?", cleaned)
    cleaned = _RE_BOOL_NULL.sub("?", cleaned)
    cleaned = _RE_IN_LIST.sub("IN (?+)", cleaned)
    cleaned = _RE_VALUES_LIST.sub("VALUES (?+)", cleaned)
    cleaned = _RE_WHITESPACE.sub(" ", cleaned).strip()
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    return cleaned


def fingerprint_hash(fingerprint: str) -> str:
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:10]


def detect_heuristics(
    raw_sql: str, calls: int, n_plus_one_threshold: int = 20, large_in_threshold: int = 10
) -> List[str]:
    """Detect common SQL anti-patterns."""
    warnings: List[str] = []
    if _RE_SELECT_STAR.search(raw_sql):
        warnings.append("SELECT *")
    if _RE_LEADING_WILDCARD_LIKE.search(raw_sql):
        warnings.append("leading wildcard LIKE")
    if (
        _RE_SELECT_STMT.search(raw_sql)
        and not _RE_HAS_LIMIT.search(raw_sql)
        and not _RE_HAS_AGGREGATE.search(raw_sql)
    ):
        warnings.append("missing LIMIT")
    if calls >= n_plus_one_threshold:
        warnings.append(f"potential N+1 ({calls} calls)")
    for match in _RE_LARGE_IN.finditer(raw_sql):
        items = [x.strip() for x in match.group(1).split(",") if x.strip()]
        if len(items) >= large_in_threshold:
            warnings.append(f"large IN ({len(items)} items)")
            break
    return warnings


def parse_pg_log(lines: Sequence[str]) -> List[QueryEvent]:
    """Parse PostgreSQL log_min_duration_statement lines (supports multi-line SQL)."""
    events: List[QueryEvent] = []
    current_duration: Optional[float] = None
    current_sql_parts: List[str] = []

    def flush() -> None:
        nonlocal current_duration, current_sql_parts
        if current_duration is not None and current_sql_parts:
            sql = " ".join(part.strip() for part in current_sql_parts if part.strip())
            if sql:
                events.append(QueryEvent(sql=sql, duration_ms=current_duration, calls=1, source="log"))
        current_duration = None
        current_sql_parts = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        match = PG_LOG_DURATION_RE.search(line)
        if match:
            flush()
            current_duration = float(match.group("duration"))
            current_sql_parts = [match.group("sql")]
        elif current_duration is not None:
            if PG_LOG_LINE_START_RE.match(line):
                flush()
            else:
                current_sql_parts.append(line)

    flush()
    return events


def parse_pg_stat_csv(text: str) -> List[QueryEvent]:
    """Parse pg_stat_statements CSV export."""
    events: List[QueryEvent] = []
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return events

    norm_fields = {f.strip().lower(): f for f in reader.fieldnames if f}
    query_col = norm_fields.get("query")
    calls_col = norm_fields.get("calls")
    total_col = (
        norm_fields.get("total_exec_time")
        or norm_fields.get("total_time")
        or norm_fields.get("total_ms")
    )

    if not query_col or not total_col:
        raise ValueError(
            "CSV must contain 'query' and 'total_exec_time' (or 'total_time') columns."
        )

    for row in reader:
        sql = (row.get(query_col) or "").strip()
        if not sql:
            continue
        calls = int(float(row[calls_col])) if calls_col and row.get(calls_col) else 1
        total_ms = float(row.get(total_col) or 0.0)
        events.append(QueryEvent(sql=sql, duration_ms=total_ms, calls=max(calls, 1), source="csv"))

    return events


def analyze_events(
    events: Sequence[QueryEvent],
    n_plus_one_threshold: int = 20,
    large_in_threshold: int = 10,
) -> List[FingerprintStats]:
    """Group events by SQL fingerprint and compute latency & heuristic stats."""
    grouped: Dict[str, FingerprintStats] = {}
    for ev in events:
        fp = normalize_sql(ev.sql)
        if not fp:
            continue
        fp_id = fingerprint_hash(fp)
        if fp_id not in grouped:
            grouped[fp_id] = FingerprintStats(
                fingerprint_id=fp_id,
                fingerprint=fp,
                sample_sql=ev.sql.strip(),
            )
        grouped[fp_id].add_event(ev)

    for stats in grouped.values():
        stats.warnings = detect_heuristics(
            stats.sample_sql,
            stats.calls,
            n_plus_one_threshold=n_plus_one_threshold,
            large_in_threshold=large_in_threshold,
        )

    return list(grouped.values())


def sort_stats(
    stats_list: List[FingerprintStats], sort_by: str = "total_ms", top: int = 20
) -> List[FingerprintStats]:
    key_map = {
        "total_ms": lambda s: s.total_ms,
        "mean_ms": lambda s: s.mean_ms,
        "p95_ms": lambda s: s.p95_ms,
        "max_ms": lambda s: s.max_ms,
        "calls": lambda s: float(s.calls),
    }
    key_fn = key_map.get(sort_by, key_map["total_ms"])
    return sorted(stats_list, key=key_fn, reverse=True)[:top]


def format_text(stats_list: Sequence[FingerprintStats], total_events: int) -> str:
    if not stats_list:
        return "No slow queries found."
    lines = [
        f"PostgreSQL Slow Query Fingerprint Report ({len(stats_list)} fingerprints, {total_events} events)",
        "=" * 96,
    ]
    for idx, s in enumerate(stats_list, start=1):
        warn_str = f" | WARNINGS: {', '.join(s.warnings)}" if s.warnings else ""
        lines.append(
            f"#{idx} [{s.fingerprint_id}] calls={s.calls} total={s.total_ms:.2f}ms "
            f"mean={s.mean_ms:.2f}ms p50={s.p50_ms:.2f}ms p95={s.p95_ms:.2f}ms "
            f"max={s.max_ms:.2f}ms{warn_str}"
        )
        lines.append(f"    SQL: {s.fingerprint}")
    return "\n".join(lines)


def format_json(stats_list: Sequence[FingerprintStats], total_events: int) -> str:
    payload: Dict[str, Any] = {
        "total_events": total_events,
        "fingerprint_count": len(stats_list),
        "fingerprints": [
            {
                "id": s.fingerprint_id,
                "fingerprint": s.fingerprint,
                "calls": s.calls,
                "total_ms": round(s.total_ms, 3),
                "mean_ms": round(s.mean_ms, 3),
                "p50_ms": round(s.p50_ms, 3),
                "p95_ms": round(s.p95_ms, 3),
                "max_ms": round(s.max_ms, 3),
                "warnings": s.warnings,
            }
            for s in stats_list
        ],
    }
    return json.dumps(payload, indent=2)


def format_markdown(stats_list: Sequence[FingerprintStats], total_events: int) -> str:
    if not stats_list:
        return "# PostgreSQL Slow Query Report\n\nNo slow queries found.\n"
    lines = [
        "# PostgreSQL Slow Query Fingerprint Report",
        "",
        f"- **Total events parsed:** {total_events}",
        f"- **Unique fingerprints shown:** {len(stats_list)}",
        "",
        "| # | ID | Calls | Total (ms) | Mean (ms) | p50 (ms) | p95 (ms) | Max (ms) | Warnings | Fingerprint |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for idx, s in enumerate(stats_list, start=1):
        warns = ", ".join(s.warnings) if s.warnings else "-"
        fp_escaped = s.fingerprint.replace("|", "\\|")
        lines.append(
            f"| {idx} | `{s.fingerprint_id}` | {s.calls} | {s.total_ms:.2f} | "
            f"{s.mean_ms:.2f} | {s.p50_ms:.2f} | {s.p95_ms:.2f} | {s.max_ms:.2f} | "
            f"{warns} | `{fp_escaped}` |"
        )
    return "\n".join(lines) + "\n"


def detect_input_format(path: Path, explicit_format: str) -> str:
    if explicit_format != "auto":
        return explicit_format
    if path.suffix.lower() == ".csv":
        return "csv"
    return "log"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pg-slow-analyzer",
        description="Analyze PostgreSQL slow-query logs and pg_stat_statements CSV exports.",
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to PostgreSQL log file or pg_stat_statements CSV file.",
    )
    parser.add_argument(
        "--input-format",
        choices=("auto", "log", "csv"),
        default="auto",
        help="Input file format (default: auto-detect by extension).",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output report format (default: text).",
    )
    parser.add_argument(
        "--sort-by",
        choices=("total_ms", "mean_ms", "p95_ms", "max_ms", "calls"),
        default="total_ms",
        help="Sort fingerprints by metric (default: total_ms).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of fingerprints to display (default: 20).",
    )
    parser.add_argument(
        "--n-plus-one-threshold",
        type=int,
        default=20,
        help="Call count threshold to flag potential N+1 queries (default: 20).",
    )
    parser.add_argument(
        "--large-in-threshold",
        type=int,
        default=10,
        help="Item count threshold to flag large IN (...) lists (default: 10).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.input_file.exists():
        print(f"Error: file not found: {args.input_file}", file=sys.stderr)
        return 1

    content = args.input_file.read_text(encoding="utf-8", errors="replace")
    fmt = detect_input_format(args.input_file, args.input_format)

    try:
        if fmt == "csv":
            events = parse_pg_stat_csv(content)
        else:
            events = parse_pg_log(content.splitlines())
    except ValueError as exc:
        print(f"Error parsing input: {exc}", file=sys.stderr)
        return 1

    stats = analyze_events(
        events,
        n_plus_one_threshold=args.n_plus_one_threshold,
        large_in_threshold=args.large_in_threshold,
    )
    sorted_stats = sort_stats(stats, sort_by=args.sort_by, top=args.top)

    if args.output_format == "json":
        print(format_json(sorted_stats, len(events)))
    elif args.output_format == "markdown":
        print(format_markdown(sorted_stats, len(events)))
    else:
        print(format_text(sorted_stats, len(events)))

    return 0


if __name__ == "__main__":
    sys.exit(main())

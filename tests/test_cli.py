import json
import tempfile
import unittest
from pathlib import Path

import pg_slow_analyzer as cli


class TestNormalizeSql(unittest.TestCase):
    def test_replaces_single_quoted_strings(self):
        self.assertEqual(
            cli.normalize_sql("SELECT id FROM users WHERE email = 'a@b.com';"),
            "SELECT id FROM users WHERE email = ?",
        )

    def test_replaces_escaped_single_quotes(self):
        self.assertEqual(
            cli.normalize_sql("SELECT * FROM users WHERE name = 'O''Reilly'"),
            "SELECT * FROM users WHERE name = ?",
        )

    def test_replaces_integers_and_floats(self):
        self.assertEqual(
            cli.normalize_sql("SELECT * FROM orders WHERE id = 42 AND total > 99.95"),
            "SELECT * FROM orders WHERE id = ? AND total > ?",
        )

    def test_replaces_dollar_params(self):
        self.assertEqual(
            cli.normalize_sql("SELECT id FROM users WHERE id = $1 AND org_id = $2"),
            "SELECT id FROM users WHERE id = ? AND org_id = ?",
        )

    def test_replaces_booleans_and_null(self):
        self.assertEqual(
            cli.normalize_sql("SELECT id FROM users WHERE active = TRUE AND deleted_at IS NULL"),
            "SELECT id FROM users WHERE active = ? AND deleted_at IS ?",
        )

    def test_collapses_in_list(self):
        self.assertEqual(
            cli.normalize_sql("SELECT id FROM items WHERE id IN (1, 2, 3, 4)"),
            "SELECT id FROM items WHERE id IN (?+)",
        )

    def test_collapses_values_list(self):
        self.assertEqual(
            cli.normalize_sql("INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y')"),
            "INSERT INTO t (a, b) VALUES (?+)",
        )

    def test_strips_line_and_block_comments(self):
        sql = "/* trace: 123 */ SELECT id FROM users -- fetch user\nWHERE id = 5"
        self.assertEqual(cli.normalize_sql(sql), "SELECT id FROM users WHERE id = ?")

    def test_replaces_hex_literals(self):
        self.assertEqual(
            cli.normalize_sql("SELECT * FROM blobs WHERE sig = 0xdeadbeef"),
            "SELECT * FROM blobs WHERE sig = ?",
        )


class TestHeuristics(unittest.TestCase):
    def test_detects_select_star(self):
        warns = cli.detect_heuristics("SELECT * FROM users LIMIT 10", calls=1)
        self.assertIn("SELECT *", warns)

    def test_detects_leading_wildcard_like(self):
        warns = cli.detect_heuristics("SELECT id FROM users WHERE name LIKE '%john' LIMIT 10", calls=1)
        self.assertIn("leading wildcard LIKE", warns)

    def test_detects_leading_wildcard_ilike(self):
        warns = cli.detect_heuristics("SELECT id FROM users WHERE name ILIKE '_john' LIMIT 10", calls=1)
        self.assertIn("leading wildcard LIKE", warns)

    def test_detects_missing_limit_on_select(self):
        warns = cli.detect_heuristics("SELECT id FROM users WHERE active = true", calls=1)
        self.assertIn("missing LIMIT", warns)

    def test_no_missing_limit_for_aggregate(self):
        warns = cli.detect_heuristics("SELECT COUNT(*) FROM users", calls=1)
        self.assertNotIn("missing LIMIT", warns)

    def test_detects_n_plus_one(self):
        warns = cli.detect_heuristics("SELECT id FROM users WHERE id = 1 LIMIT 1", calls=25, n_plus_one_threshold=20)
        self.assertTrue(any("N+1" in w for w in warns))

    def test_detects_large_in_list(self):
        items = ", ".join(str(i) for i in range(15))
        warns = cli.detect_heuristics(f"SELECT id FROM users WHERE id IN ({items}) LIMIT 10", calls=1, large_in_threshold=10)
        self.assertTrue(any("large IN" in w for w in warns))


class TestParsersAndStats(unittest.TestCase):
    def test_parse_pg_log_single_line(self):
        lines = [
            "2026-11-19 10:00:00.000 UTC [1] LOG:  duration: 150.5 ms  statement: SELECT 1;",
            "2026-11-19 10:00:01.000 UTC [1] LOG:  duration: 200.0 ms  execute <unnamed>: SELECT 2;",
        ]
        events = cli.parse_pg_log(lines)
        self.assertEqual(len(events), 2)
        self.assertAlmostEqual(events[0].duration_ms, 150.5)
        self.assertAlmostEqual(events[1].duration_ms, 200.0)

    def test_parse_pg_log_multiline_sql(self):
        lines = [
            "2026-11-19 10:00:00.000 UTC [1] LOG:  duration: 300.0 ms  statement: SELECT id",
            "  FROM orders",
            "  WHERE status = 'open';",
            "2026-11-19 10:00:01.000 UTC [1] LOG:  duration: 10.0 ms  statement: SELECT 1;",
        ]
        events = cli.parse_pg_log(lines)
        self.assertEqual(len(events), 2)
        self.assertIn("FROM orders", events[0].sql)
        self.assertIn("WHERE status = 'open';", events[0].sql)

    def test_parse_pg_stat_csv(self):
        csv_text = 'query,calls,total_exec_time\n"SELECT * FROM users WHERE id = $1",10,500.0\n'
        events = cli.parse_pg_stat_csv(csv_text)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].calls, 10)
        self.assertAlmostEqual(events[0].duration_ms, 500.0)

    def test_parse_pg_stat_csv_missing_columns_raises(self):
        with self.assertRaises(ValueError):
            cli.parse_pg_stat_csv("foo,bar\n1,2\n")

    def test_percentile_computation(self):
        vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertAlmostEqual(cli.percentile(vals, 50.0), 30.0)
        self.assertAlmostEqual(cli.percentile(vals, 95.0), 48.0)

    def test_analyze_events_aggregates_same_fingerprint(self):
        events = [
            cli.QueryEvent(sql="SELECT id FROM u WHERE id = 1 LIMIT 1", duration_ms=10.0),
            cli.QueryEvent(sql="SELECT id FROM u WHERE id = 2 LIMIT 1", duration_ms=30.0),
        ]
        stats = cli.analyze_events(events)
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0].calls, 2)
        self.assertAlmostEqual(stats[0].total_ms, 40.0)
        self.assertAlmostEqual(stats[0].mean_ms, 20.0)
        self.assertAlmostEqual(stats[0].max_ms, 30.0)

    def test_sort_stats_by_calls(self):
        s1 = cli.FingerprintStats("a", "SELECT 1", "SELECT 1", calls=5, total_ms=100.0)
        s2 = cli.FingerprintStats("b", "SELECT 2", "SELECT 2", calls=50, total_ms=10.0)
        res = cli.sort_stats([s1, s2], sort_by="calls", top=10)
        self.assertEqual(res[0].fingerprint_id, "b")


class TestFormattersAndCLI(unittest.TestCase):
    def test_format_json_valid(self):
        s = cli.FingerprintStats("abc123", "SELECT ?", "SELECT 1", calls=2, total_ms=25.0, durations=[10.0, 15.0], max_ms=15.0)
        out = cli.format_json([s], total_events=2)
        data = json.loads(out)
        self.assertEqual(data["total_events"], 2)
        self.assertEqual(data["fingerprints"][0]["id"], "abc123")

    def test_format_markdown_table(self):
        s = cli.FingerprintStats("abc123", "SELECT ?", "SELECT 1", calls=1, total_ms=12.0, durations=[12.0], max_ms=12.0)
        out = cli.format_markdown([s], total_events=1)
        self.assertIn("| # | ID | Calls |", out)
        self.assertIn("`abc123`", out)

    def test_cli_end_to_end_sample_log(self):
        sample = Path(__file__).resolve().parent.parent / "sample_logs" / "postgresql_slow.log"
        rc = cli.main([str(sample), "--format", "json"])
        self.assertEqual(rc, 0)

    def test_cli_end_to_end_sample_csv(self):
        sample = Path(__file__).resolve().parent.parent / "sample_logs" / "pg_stat_statements.csv"
        rc = cli.main([str(sample), "--format", "markdown"])
        self.assertEqual(rc, 0)

    def test_cli_missing_file_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does_not_exist.log"
            rc = cli.main([str(missing)])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

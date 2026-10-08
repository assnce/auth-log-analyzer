import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from authlog import Config, Event, analyze, load_events, main, markdown


def event(n, second, user="alice", ip="192.0.2.10", outcome="failure", host="vpn-01"):
    return Event(str(n), datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second), ip, user, host, outcome)


class DetectionTests(unittest.TestCase):
    def rules(self, events, config=Config()):
        return [x["rule"] for x in analyze(events, config)["alerts"]]

    def test_burst_inclusive_boundary(self):
        self.assertIn("failure_burst", self.rules([event(i, t) for i, t in enumerate([0, 75, 150, 225, 300])]))

    def test_burst_outside_boundary(self):
        self.assertEqual([], self.rules([event(i, t) for i, t in enumerate([0, 75, 150, 225, 301])]))

    def test_sustained_burst_is_not_repeated(self):
        self.assertEqual(["failure_burst"], self.rules([event(i, i) for i in range(30)]))

    def test_rearm_after_quiet_period(self):
        events = [event(i, i) for i in range(5)] + [event(i+5, 1000+i) for i in range(5)]
        self.assertEqual(["failure_burst", "failure_burst"], self.rules(events))

    def test_spray_counts_distinct_users(self):
        events = [event(i, i, user=f"u{i}") for i in range(5)]
        self.assertEqual(["possible_password_spray"], self.rules(events))

    def test_spray_does_not_combine_hosts_or_ips(self):
        self.assertEqual([], self.rules([event(i, i, user=f"u{i}", host=f"h{i}") for i in range(5)]))
        self.assertEqual([], self.rules([event(i, i, user=f"u{i}", ip=f"192.0.2.{i+1}") for i in range(5)]))

    def test_success_requires_matching_identity(self):
        fails = [event(i, i) for i in range(5)]
        self.assertNotIn("success_after_failures", self.rules(fails+[event(8, 10, user="other", outcome="success")]))
        self.assertIn("success_after_failures", self.rules(fails+[event(8, 10, outcome="success")]))

    def test_success_window_boundary(self):
        fails = [event(i, i) for i in range(5)]
        self.assertIn("success_after_failures", self.rules(fails+[event(9, 600, outcome="success")]))
        self.assertNotIn("success_after_failures", self.rules(fails+[event(9, 601, outcome="success")]))

    def test_success_resets_sequence(self):
        events = [event(i, i) for i in range(5)]+[event(6, 6, outcome="success"),event(7, 7, outcome="success")]
        self.assertEqual(1, self.rules(events).count("success_after_failures"))

    def test_out_of_order_and_empty(self):
        events = [event(i, i) for i in range(5)]
        self.assertEqual(analyze(events), analyze(list(reversed(events))))
        self.assertEqual(0, analyze([])["alert_count"])

    def test_report_does_not_allow_fence_injection(self):
        text = markdown(analyze([event(i, i, user="```\nspoof") for i in range(5)]))
        self.assertNotIn("```\\nspoof", text)
        self.assertIn("\\u0060", text)


class InputTests(unittest.TestCase):
    def row(self, **changes):
        row = dict(event_id="1", timestamp="2026-01-01T03:00:00+03:00", source_ip="2001:db8::1", username="alice", host="vpn", outcome="failure")
        return row | changes

    def test_timezones_and_ipv6(self):
        self.assertEqual(0, Event.parse(self.row()).time.hour)

    def test_invalid_fields(self):
        for changes in [dict(timestamp="2026-01-01T00:00:00"),dict(source_ip="bad"),dict(outcome="unknown"),dict(username="")]:
            with self.assertRaises(ValueError): Event.parse(self.row(**changes))

    def test_duplicate_ids_and_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"x.jsonl"
            p.write_text((json.dumps(self.row())+"\n")*2)
            with self.assertRaisesRegex(ValueError, "x.jsonl:2: duplicate"):
                load_events(p)

    def test_csv_and_jsonl_equivalence(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,b=Path(tmp)/"a.csv",Path(tmp)/"b.jsonl"
            row=self.row()
            with a.open("w",newline="") as f:
                writer=csv.DictWriter(f,fieldnames=list(row));writer.writeheader();writer.writerow(row)
            b.write_text(json.dumps(row)+"\n")
            self.assertEqual(load_events(a),load_events(b))

    def test_config_and_cli_errors(self):
        with self.assertRaises(ValueError): Config(failure_window=0)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"x.jsonl"; path.write_text(json.dumps(self.row())+"\n")
            self.assertEqual(2,main([str(path),"--output",str(path)]))


if __name__ == "__main__": unittest.main()

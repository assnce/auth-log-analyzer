#!/usr/bin/env python3
"""Offline authentication-event triage. Python 3.11+, standard library only."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("event_id", "timestamp", "source_ip", "username", "host", "outcome")


@dataclass(frozen=True)
class Event:
    event_id: str
    time: datetime
    source_ip: str
    username: str
    host: str
    outcome: str

    @classmethod
    def parse(cls, row: dict) -> "Event":
        if not isinstance(row, dict):
            raise ValueError("event must be an object")
        for key in FIELDS:
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f"{key}: non-empty string required")
        stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        ip = str(ipaddress.ip_address(row["source_ip"]))
        if row["outcome"] not in {"success", "failure"}:
            raise ValueError("outcome must be success or failure")
        return cls(row["event_id"], stamp.astimezone(timezone.utc), ip,
                   row["username"], row["host"], row["outcome"])


@dataclass(frozen=True)
class Config:
    failure_threshold: int = 5
    failure_window: int = 300
    spray_users: int = 5
    spray_window: int = 300
    success_window: int = 600

    def __post_init__(self):
        for key, value in vars(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{key} must be a positive integer")


def load_events(path: Path) -> list[Event]:
    """Strict input: stop at first invalid event; never silently drop evidence."""
    events, seen = [], set()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        if path.suffix.lower() == ".csv":
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or not set(FIELDS) <= set(reader.fieldnames):
                raise ValueError("CSV header must contain: " + ", ".join(FIELDS))
            rows = enumerate(reader, start=2)
        elif path.suffix.lower() == ".jsonl":
            rows = ((n, line) for n, line in enumerate(handle, 1) if line.strip())
        else:
            raise ValueError("input must end in .csv or .jsonl")
        for number, row in rows:
            try:
                event = Event.parse(json.loads(row) if isinstance(row, str) else row)
                if event.event_id in seen:
                    raise ValueError(f"duplicate event_id: {event.event_id}")
                seen.add(event.event_id)
                events.append(event)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path.name}:{number}: {exc}") from exc
    # Stable order: equal timestamps retain their input order.
    return sorted(events, key=lambda event: event.time)


def trim(queue: deque, now: datetime, seconds: int):
    while queue and (now - queue[0].time).total_seconds() > seconds:
        queue.popleft()


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def analyze(events: list[Event], config: Config = Config()) -> dict:
    ordered = sorted(events, key=lambda event: event.time)
    bursts, sprays, previous = defaultdict(deque), defaultdict(deque), defaultdict(deque)
    alerts = []

    def alert(rule, event, evidence, level, reason, window):
        alerts.append({"rule": rule, "severity": level,
                       "timestamp": timestamp(event.time), "source_ip": event.source_ip,
                       "host": event.host, "users": sorted({x.username for x in evidence}),
                       "event_ids": [x.event_id for x in evidence],
                       "start": timestamp(evidence[0].time), "window_seconds": window,
                       "reason": reason})

    for event in ordered:
        key = (event.source_ip, event.username, event.host)
        prior = previous[key]
        trim(prior, event.time, config.success_window)
        if event.outcome == "success":
            if len(prior) >= config.failure_threshold:
                alert("success_after_failures", event, [*prior, event], "high",
                      f"Success after {len(prior)} failures for the same IP, user and host; verify legitimacy.",
                      config.success_window)
            # Success starts a new sequence for this user/IP/host.
            prior.clear()
            bursts[key].clear()
            continue

        prior.append(event)
        burst = bursts[key]
        trim(burst, event.time, config.failure_window)
        before = len(burst)
        burst.append(event)
        if before < config.failure_threshold <= len(burst):
            alert("failure_burst", event, list(burst), "medium",
                  f"At least {config.failure_threshold} failures for one IP, user and host.",
                  config.failure_window)

        spray = sprays[(event.source_ip, event.host)]
        trim(spray, event.time, config.spray_window)
        before_users = len({x.username for x in spray})
        spray.append(event)
        after_users = len({x.username for x in spray})
        if before_users < config.spray_users <= after_users:
            alert("possible_password_spray", event, list(spray), "medium",
                  f"Failures for {after_users} distinct users from one IP on one host; a shared gateway may explain this.",
                  config.spray_window)

    return {"schema_version": 1, "config": vars(config), "event_count": len(ordered),
            "outcomes": dict(sorted(Counter(x.outcome for x in ordered).items())),
            "alert_count": len(alerts), "alerts": alerts}


def markdown(report: dict) -> str:
    lines = ["# Authentication triage report", "",
             f"Events: **{report['event_count']}** · Alerts: **{report['alert_count']}**", "",
             "Heuristic alerts require investigation; they do not prove compromise.", ""]
    for alert in report["alerts"]:
        # Use JSON in fenced blocks, so untrusted usernames cannot inject Markdown tables.
        lines += [f"## {alert['rule']}", "", "```json",
                  json.dumps(alert, ensure_ascii=False, indent=2).replace("`", "\\u0060"), "```", ""]
    if not report["alerts"]:
        lines += ["No configured thresholds were reached. This does not establish that the activity is safe.", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="normalized .csv or .jsonl events")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on-alert", action="store_true", help="exit 1 if alerts exist")
    for name, default in vars(Config()).items():
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=default)
    args = parser.parse_args(argv)
    try:
        config = Config(**{name: getattr(args, name) for name in vars(Config())})
        report = analyze(load_events(args.input), config)
        output = markdown(report) if args.format == "markdown" else json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            if args.output.resolve() == args.input.resolve():
                raise ValueError("output must not overwrite input")
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return int(args.fail_on_alert and report["alert_count"] > 0)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

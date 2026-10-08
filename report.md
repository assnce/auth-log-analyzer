# Authentication triage report

Events: **13** · Alerts: **3**

Heuristic alerts require investigation; they do not prove compromise.

## failure_burst

```json
{
  "rule": "failure_burst",
  "severity": "medium",
  "timestamp": "2026-10-01T10:02:00Z",
  "source_ip": "192.0.2.10",
  "host": "vpn-01",
  "users": [
    "alice"
  ],
  "event_ids": [
    "auth-001",
    "auth-002",
    "auth-003",
    "auth-004",
    "auth-005"
  ],
  "start": "2026-10-01T10:00:00Z",
  "window_seconds": 300,
  "reason": "At least 5 failures for one IP, user and host."
}
```

## success_after_failures

```json
{
  "rule": "success_after_failures",
  "severity": "high",
  "timestamp": "2026-10-01T10:02:30Z",
  "source_ip": "192.0.2.10",
  "host": "vpn-01",
  "users": [
    "alice"
  ],
  "event_ids": [
    "auth-001",
    "auth-002",
    "auth-003",
    "auth-004",
    "auth-005",
    "auth-006"
  ],
  "start": "2026-10-01T10:00:00Z",
  "window_seconds": 600,
  "reason": "Success after 5 failures for the same IP, user and host; verify legitimacy."
}
```

## possible_password_spray

```json
{
  "rule": "possible_password_spray",
  "severity": "medium",
  "timestamp": "2026-10-01T10:11:20Z",
  "source_ip": "198.51.100.20",
  "host": "vpn-01",
  "users": [
    "user1",
    "user2",
    "user3",
    "user4",
    "user5"
  ],
  "event_ids": [
    "auth-007",
    "auth-008",
    "auth-009",
    "auth-010",
    "auth-011"
  ],
  "start": "2026-10-01T10:10:00Z",
  "window_seconds": 300,
  "reason": "Failures for 5 distinct users from one IP on one host; a shared gateway may explain this."
}
```


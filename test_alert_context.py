from datetime import datetime, timedelta
from logalyzer.sources import LogEntry
from logalyzer.alerts import AlertEngine, AlertRule
from logalyzer.config import AlertRule as ConfigAlertRule

entries = []
base_time = datetime(2026, 6, 17, 10, 0, 25)
for i in range(5):
    ts = base_time + timedelta(seconds=i)
    entries.append(LogEntry(
        timestamp=ts,
        source="local-app",
        raw_message=f"{ts} [ERROR] [api] Database connection failed: attempt {i+1}",
        level="ERROR",
    ))

config_rule = ConfigAlertRule(
    name="high-error-rate",
    pattern="ERROR",
    is_regex=False,
    severity="error",
    threshold=5,
    window_seconds=60,
    action="console",
)

alert_engine = AlertEngine()
alert_engine.add_rule(AlertRule(config_rule))

print("Processing 5 ERROR log entries (should trigger high-error-rate at 5th)...")
print()

for idx, entry in enumerate(entries):
    triggered = alert_engine.process_entry(entry)
    print(f"  Entry {idx+1}: {entry.timestamp.strftime('%H:%M:%S')} - {entry.raw_message[:60]}...")
    if triggered:
        for a in triggered:
            print(f"  -> ALERT TRIGGERED: {a.rule_name}")
            print(f"     count: {a.count}")
            print(f"     matched_entries count: {len(a.matched_entries)}")
            print(f"     matched_entries content:")
            for j, e in enumerate(a.matched_entries):
                print(f"       [{j+1}] {e.timestamp.strftime('%H:%M:%S')} | {e.raw_message[:70]}")

print()
print("=" * 70)
alerts = alert_engine.check_alerts()
for a in alerts:
    print(f"Alert: {a.rule_name}, count={a.count}, matched_entries={len(a.matched_entries)}")
    print(f"  All {len(a.matched_entries)} entries in context:")
    for j, e in enumerate(a.matched_entries):
        print(f"    [{j+1}] {e.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {e.level} | {e.raw_message[:80]}")

print()
if len(alerts) > 0 and len(alerts[0].matched_entries) == alerts[0].count:
    print("SUCCESS: Alert.matched_entries correctly contains ALL triggering logs!")
else:
    print("FAILED: Alert.matched_entries count does not match Alert.count!")

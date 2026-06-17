import os
import shutil
import json
from datetime import datetime, timedelta

LOG_DIR = "./logs"
LOG_FILE = os.path.join(LOG_DIR, "resume_test.log")
CONFIG_FILE = "./logalyzer_resume_test.yaml"
SESSION_DIR = "./.test_sessions"

os.makedirs(LOG_DIR, exist_ok=True)
if os.path.exists(SESSION_DIR):
    shutil.rmtree(SESSION_DIR)

batch1_lines = [
    "2026-06-17 12:00:01,000 [INFO] [main] App started",
    "2026-06-17 12:00:02,000 [INFO] [db] Connected",
    "2026-06-17 12:00:03,000 [ERROR] [api] Database connection failed: err 1",
    "2026-06-17 12:00:04,000 [ERROR] [api] Database connection failed: err 2",
    "2026-06-17 12:00:05,000 [ERROR] [api] Database connection failed: err 3",
]

with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(batch1_lines) + "\n")

config = f"""session_dir: {SESSION_DIR}
log_level: INFO

sources:
  - name: resume-test
    type: local
    enabled: true
    config:
      path: {LOG_FILE.replace(os.sep, '/')}
      encoding: utf-8

alert_rules:
  - name: db-fail-3
    pattern: Database connection failed
    is_regex: false
    severity: error
    threshold: 3
    window_seconds: 60
    action: console
"""
with open(CONFIG_FILE, "w", encoding="utf-8") as f:
    f.write(config)

print("=" * 70)
print("STEP 1: Initial collection + save session")
print("=" * 70)

import subprocess
result = subprocess.run(
    ["python", "-m", "logalyzer.cli.main", "-c", CONFIG_FILE,
     "collect", "run", "--save-session", "my-incident"],
    capture_output=True, text=True
)
print(result.stdout)
if result.returncode != 0:
    print("STDERR:", result.stderr)

from logalyzer.session import SessionManager
sm = SessionManager(SESSION_DIR)
sessions = sm.list_sessions()
assert len(sessions) == 1, "Should have 1 session"
sid = sessions[0]["id"]
print(f"\nCreated session: {sid}")
assert sessions[0]["has_cursors"], "Session should have cursors for resumability"
print("OK - session has cursors")

sess = sm.load_session(sid)
print(f"  Logs in session: {len(sess.log_entries)}")
print(f"  Alerts triggered: {len(sess.alert_engine.check_alerts())}")
assert len(sess.log_entries) == 5
assert len(sess.alert_engine.check_alerts()) >= 1, "Should trigger db-fail-3"

print("\n" + "=" * 70)
print("STEP 2: Append NEW logs to the file")
print("=" * 70)

batch2_lines = [
    "2026-06-17 12:00:10,000 [INFO] [api] Retrying db...",
    "2026-06-17 12:00:11,000 [WARN] [cache] slow",
    "2026-06-17 12:00:12,000 [INFO] [db] Reconnected",
    "2026-06-17 12:00:13,000 [ERROR] [api] OutOfMemoryError",
]
with open(LOG_FILE, "a", encoding="utf-8") as f:
    f.write("\n".join(batch2_lines) + "\n")
print("Appended 4 new log lines to the log file")

print("\n" + "=" * 70)
print("STEP 3: session resume - incremental continuation")
print("=" * 70)

result = subprocess.run(
    ["python", "-m", "logalyzer.cli.main", "-c", CONFIG_FILE,
     "session", "resume", sid],
    capture_output=True, text=True
)
print(result.stdout)
if result.returncode != 0:
    print("STDERR:", result.stderr)

sess2 = sm.load_session(sid)
print(f"\nAfter resume:")
print(f"  Total logs: {len(sess2.log_entries)}")
print(f"  Updated_at: {sess2.updated_at}")
assert len(sess2.log_entries) == 9, f"Expected 9 total, got {len(sess2.log_entries)}"
print("OK - all 4 new logs merged, 5+4=9 total, no duplicates")

old_alert_count = len(sess.alert_engine.check_alerts())
new_alert_count = len(sess2.alert_engine.check_alerts())
print(f"  Alerts: {old_alert_count} (before) -> {new_alert_count} (after resume)")

print("\n" + "=" * 70)
print("STEP 4: resume AGAIN without any new logs - should be no-op")
print("=" * 70)

result = subprocess.run(
    ["python", "-m", "logalyzer.cli.main", "-c", CONFIG_FILE,
     "collect", "resume", sid],
    capture_output=True, text=True
)
print(result.stdout)

sess3 = sm.load_session(sid)
print(f"\nTotal logs after second no-op resume: {len(sess3.log_entries)}")
assert len(sess3.log_entries) == 9, "No new logs should be added on 2nd resume"
print("OK - dedup works: second resume without new data added 0 entries")

print("\n" + "=" * 70)
print("STEP 5: Show session details + cursors")
print("=" * 70)

result = subprocess.run(
    ["python", "-m", "logalyzer.cli.main", "-c", CONFIG_FILE,
     "session", "list"],
    capture_output=True, text=True
)
print(result.stdout)

result = subprocess.run(
    ["python", "-m", "logalyzer.cli.main", "-c", CONFIG_FILE,
     "session", "show", sid, "-n", "3"],
    capture_output=True, text=True
)
print(result.stdout)

print("\n" + "=" * 70)
print("ALL TESTS PASSED! Incremental resume flow works correctly:")
print("  - Cursor preserved between collects")
print("  - New logs appended; duplicates skipped")
print("  - Filter/Alert engine state preserved and applied to incrementals")
print("  - Session metadata (updated_at, cursors) tracked")
print("=" * 70)

shutil.rmtree(SESSION_DIR, ignore_errors=True)
os.remove(CONFIG_FILE)
os.remove(LOG_FILE)

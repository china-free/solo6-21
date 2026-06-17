from typing import Iterator, List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import re
import json
from ..sources import LogEntry
from ..config import AlertRule as ConfigAlertRule


@dataclass
class Alert:
    rule_name: str
    severity: str
    message: str
    timestamp: datetime
    matched_entries: List[LogEntry] = field(default_factory=list)
    count: int = 1

    def __str__(self) -> str:
        level_color = {
            "critical": "\033[91m",
            "error": "\033[91m",
            "warning": "\033[93m",
            "info": "\033[94m",
        }
        color = level_color.get(self.severity.lower(), "\033[0m")
        reset = "\033[0m"
        return (
            f"{color}[{self.severity.upper()}] ALERT: {self.rule_name}{reset}\n"
            f"  Time: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Count: {self.count}\n"
            f"  Message: {self.message}\n"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "count": self.count,
            "matched_entries": [e.to_dict() for e in self.matched_entries],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        return cls(
            rule_name=data["rule_name"],
            severity=data["severity"],
            message=data["message"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            count=data.get("count", 1),
            matched_entries=[LogEntry.from_dict(e) for e in data.get("matched_entries", [])],
        )


@dataclass
class AlertState:
    rule_name: str
    match_times: deque = field(default_factory=deque)
    last_alert_time: Optional[datetime] = None
    cooldown_seconds: int = 60

    def add_match(self, timestamp: datetime) -> int:
        self.match_times.append(timestamp)
        return len(self.match_times)

    def cleanup_old(self, window_end: datetime, window_seconds: int) -> None:
        cutoff = window_end - timedelta(seconds=window_seconds)
        while self.match_times and self.match_times[0] < cutoff:
            self.match_times.popleft()

    def should_alert(self, current_time: datetime) -> bool:
        if self.last_alert_time is None:
            return True
        return (current_time - self.last_alert_time).total_seconds() >= self.cooldown_seconds

    def record_alert(self, alert_time: datetime) -> None:
        self.last_alert_time = alert_time


class AlertRule:
    def __init__(self, config: ConfigAlertRule):
        self.name = config.name
        self.pattern = config.pattern
        self.is_regex = config.is_regex
        self.severity = config.severity
        self.threshold = config.threshold
        self.window_seconds = config.window_seconds
        self.action = config.action
        self._compiled_pattern = self._compile_pattern()

    def _compile_pattern(self):
        if self.is_regex:
            return re.compile(self.pattern, re.IGNORECASE)
        return self.pattern.lower()

    def matches(self, entry: LogEntry) -> bool:
        message = entry.raw_message.lower()
        if self.is_regex:
            return bool(self._compiled_pattern.search(entry.raw_message))
        return self._compiled_pattern in message

    def to_config(self) -> ConfigAlertRule:
        return ConfigAlertRule(
            name=self.name,
            pattern=self.pattern,
            is_regex=self.is_regex,
            severity=self.severity,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
            action=self.action,
        )


class AlertEngine:
    def __init__(self, rules: Optional[List[AlertRule]] = None):
        self.rules = rules or []
        self.states: Dict[str, AlertState] = {}
        self.alerts: List[Alert] = []
        self.alert_callbacks: List[Callable[[Alert], None]] = []

    def add_rule(self, rule: AlertRule) -> None:
        self.rules.append(rule)
        if rule.name not in self.states:
            self.states[rule.name] = AlertState(rule_name=rule.name)

    def add_rules_from_config(self, config_rules: List[ConfigAlertRule]) -> None:
        for config_rule in config_rules:
            self.add_rule(AlertRule(config_rule))

    def add_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        self.alert_callbacks.append(callback)

    def process_entry(self, entry: LogEntry) -> List[Alert]:
        triggered_alerts = []
        
        for rule in self.rules:
            if rule.matches(entry):
                state = self.states.setdefault(rule.name, AlertState(rule_name=rule.name))
                count = state.add_match(entry.timestamp)
                state.cleanup_old(entry.timestamp, rule.window_seconds)
                
                if len(state.match_times) >= rule.threshold:
                    if state.should_alert(entry.timestamp):
                        alert = Alert(
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=f"Pattern '{rule.pattern}' matched {len(state.match_times)} times in {rule.window_seconds}s",
                            timestamp=entry.timestamp,
                            matched_entries=list(state.match_times) if isinstance(state.match_times, list) else [],
                            count=len(state.match_times),
                        )
                        alert.matched_entries = [entry]
                        self.alerts.append(alert)
                        state.record_alert(entry.timestamp)
                        triggered_alerts.append(alert)
                        
                        for callback in self.alert_callbacks:
                            try:
                                callback(alert)
                            except Exception as e:
                                print(f"Error in alert callback: {e}")
        
        return triggered_alerts

    def process_entries(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        for entry in entries:
            self.process_entry(entry)
            yield entry

    def check_alerts(self) -> List[Alert]:
        return list(self.alerts)

    def clear_alerts(self) -> None:
        self.alerts.clear()

    def print_alerts(self) -> None:
        for alert in self.alerts:
            print(alert)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rules": [
                {
                    "name": rule.name,
                    "pattern": rule.pattern,
                    "is_regex": rule.is_regex,
                    "severity": rule.severity,
                    "threshold": rule.threshold,
                    "window_seconds": rule.window_seconds,
                    "action": rule.action,
                }
                for rule in self.rules
            ],
            "alerts": [alert.to_dict() for alert in self.alerts],
            "states": {
                name: {
                    "match_times": [t.isoformat() for t in state.match_times],
                    "last_alert_time": state.last_alert_time.isoformat() if state.last_alert_time else None,
                    "cooldown_seconds": state.cooldown_seconds,
                }
                for name, state in self.states.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertEngine":
        rules = []
        for rule_data in data.get("rules", []):
            config_rule = ConfigAlertRule(
                name=rule_data["name"],
                pattern=rule_data["pattern"],
                is_regex=rule_data.get("is_regex", False),
                severity=rule_data.get("severity", "warning"),
                threshold=rule_data.get("threshold", 1),
                window_seconds=rule_data.get("window_seconds", 60),
                action=rule_data.get("action", "console"),
            )
            rules.append(AlertRule(config_rule))
        
        engine = cls(rules)
        
        for alert_data in data.get("alerts", []):
            engine.alerts.append(Alert.from_dict(alert_data))
        
        for name, state_data in data.get("states", {}).items():
            state = AlertState(
                rule_name=name,
                cooldown_seconds=state_data.get("cooldown_seconds", 60),
            )
            for ts_str in state_data.get("match_times", []):
                state.match_times.append(datetime.fromisoformat(ts_str))
            if state_data.get("last_alert_time"):
                state.last_alert_time = datetime.fromisoformat(state_data["last_alert_time"])
            engine.states[name] = state
        
        return engine

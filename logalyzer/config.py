from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import yaml
import os


@dataclass
class LogSourceConfig:
    name: str
    type: str
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class AlertRule:
    name: str
    pattern: str
    is_regex: bool = False
    severity: str = "warning"
    threshold: int = 1
    window_seconds: int = 60
    action: str = "console"


@dataclass
class AppConfig:
    sources: List[LogSourceConfig] = field(default_factory=list)
    alert_rules: List[AlertRule] = field(default_factory=list)
    session_dir: str = ".logalyzer_sessions"
    log_level: str = "INFO"

    @classmethod
    def load_from_file(cls, config_path: str) -> "AppConfig":
        if not os.path.exists(config_path):
            return cls()
        
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        sources = []
        for src in data.get("sources", []):
            sources.append(LogSourceConfig(
                name=src["name"],
                type=src["type"],
                config=src.get("config", {}),
                enabled=src.get("enabled", True)
            ))
        
        alert_rules = []
        for rule in data.get("alert_rules", []):
            alert_rules.append(AlertRule(
                name=rule["name"],
                pattern=rule["pattern"],
                is_regex=rule.get("is_regex", False),
                severity=rule.get("severity", "warning"),
                threshold=rule.get("threshold", 1),
                window_seconds=rule.get("window_seconds", 60),
                action=rule.get("action", "console")
            ))
        
        return cls(
            sources=sources,
            alert_rules=alert_rules,
            session_dir=data.get("session_dir", ".logalyzer_sessions"),
            log_level=data.get("log_level", "INFO")
        )

    def save_to_file(self, config_path: str) -> None:
        data = {
            "sources": [
                {
                    "name": s.name,
                    "type": s.type,
                    "config": s.config,
                    "enabled": s.enabled
                }
                for s in self.sources
            ],
            "alert_rules": [
                {
                    "name": r.name,
                    "pattern": r.pattern,
                    "is_regex": r.is_regex,
                    "severity": r.severity,
                    "threshold": r.threshold,
                    "window_seconds": r.window_seconds,
                    "action": r.action
                }
                for r in self.alert_rules
            ],
            "session_dir": self.session_dir,
            "log_level": self.log_level
        }
        
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

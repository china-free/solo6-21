from typing import Iterator, List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import re
from ..sources import LogEntry


@dataclass
class FilterCondition:
    field: str
    operator: str
    value: Any
    case_sensitive: bool = False

    def matches(self, entry: LogEntry) -> bool:
        field_value = self._get_field_value(entry)
        if field_value is None:
            return False
        
        return self._compare(field_value)

    def _get_field_value(self, entry: LogEntry) -> Any:
        if self.field == "message":
            return entry.raw_message
        elif self.field == "source":
            return entry.source
        elif self.field == "level":
            return entry.level
        elif self.field == "timestamp":
            return entry.timestamp
        elif self.field in entry.metadata:
            return entry.metadata[self.field]
        return None

    def _compare(self, field_value: Any) -> bool:
        op = self.operator.lower()
        value = self.value
        
        if isinstance(field_value, str) and not self.case_sensitive:
            field_value = field_value.lower()
            if isinstance(value, str):
                value = value.lower()
            elif isinstance(value, list):
                value = [v.lower() if isinstance(v, str) else v for v in value]
        
        if op == "contains":
            return value in str(field_value)
        elif op == "not_contains":
            return value not in str(field_value)
        elif op == "equals":
            return field_value == value
        elif op == "not_equals":
            return field_value != value
        elif op == "startswith":
            return str(field_value).startswith(str(value))
        elif op == "endswith":
            return str(field_value).endswith(str(value))
        elif op == "regex":
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return bool(re.search(value, str(field_value), flags))
        elif op == "greater_than":
            return field_value > value
        elif op == "less_than":
            return field_value < value
        elif op == "greater_equal":
            return field_value >= value
        elif op == "less_equal":
            return field_value <= value
        elif op == "in":
            return field_value in value
        elif op == "not_in":
            return field_value not in value
        
        return False


@dataclass
class FilterRule:
    name: str
    conditions: List[FilterCondition] = field(default_factory=list)
    operator: str = "AND"
    enabled: bool = True

    def matches(self, entry: LogEntry) -> bool:
        if not self.enabled or not self.conditions:
            return True
        
        if self.operator.upper() == "AND":
            return all(cond.matches(entry) for cond in self.conditions)
        elif self.operator.upper() == "OR":
            return any(cond.matches(entry) for cond in self.conditions)
        
        return False


class FilterEngine:
    def __init__(self, rules: Optional[List[FilterRule]] = None):
        self.rules = rules or []

    def add_rule(self, rule: FilterRule) -> None:
        self.rules.append(rule)

    def add_keyword_filter(self, keyword: str, case_sensitive: bool = False) -> None:
        self.rules.append(FilterRule(
            name=f"keyword_{keyword}",
            conditions=[
                FilterCondition(
                    field="message",
                    operator="contains",
                    value=keyword,
                    case_sensitive=case_sensitive
                )
            ]
        ))

    def add_regex_filter(self, pattern: str, case_sensitive: bool = False) -> None:
        self.rules.append(FilterRule(
            name=f"regex_{pattern[:20]}",
            conditions=[
                FilterCondition(
                    field="message",
                    operator="regex",
                    value=pattern,
                    case_sensitive=case_sensitive
                )
            ]
        ))

    def add_level_filter(self, levels: List[str]) -> None:
        self.rules.append(FilterRule(
            name=f"level_{','.join(levels)}",
            conditions=[
                FilterCondition(
                    field="level",
                    operator="in",
                    value=[l.upper() for l in levels]
                )
            ]
        ))

    def add_source_filter(self, sources: List[str]) -> None:
        self.rules.append(FilterRule(
            name=f"source_{','.join(sources)}",
            conditions=[
                FilterCondition(
                    field="source",
                    operator="in",
                    value=sources
                )
            ]
        ))

    def add_time_range_filter(self, start_time: Optional[datetime], end_time: Optional[datetime]) -> None:
        conditions = []
        if start_time:
            conditions.append(FilterCondition(
                field="timestamp",
                operator="greater_equal",
                value=start_time
            ))
        if end_time:
            conditions.append(FilterCondition(
                field="timestamp",
                operator="less_equal",
                value=end_time
            ))
        
        if conditions:
            self.rules.append(FilterRule(
                name="time_range",
                conditions=conditions,
                operator="AND"
            ))

    def filter(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        for entry in entries:
            if self.matches_all(entry):
                yield entry

    def matches_all(self, entry: LogEntry) -> bool:
        if not self.rules:
            return True
        
        enabled_rules = [r for r in self.rules if r.enabled]
        if not enabled_rules:
            return True
        
        return all(rule.matches(entry) for rule in enabled_rules)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": rule.name,
                "conditions": [
                    {
                        "field": c.field,
                        "operator": c.operator,
                        "value": c.value.isoformat() if isinstance(c.value, datetime) else c.value,
                        "case_sensitive": c.case_sensitive
                    }
                    for c in rule.conditions
                ],
                "operator": rule.operator,
                "enabled": rule.enabled
            }
            for rule in self.rules
        ]

    @classmethod
    def from_dict(cls, data: List[Dict[str, Any]]) -> "FilterEngine":
        rules = []
        for rule_data in data:
            conditions = []
            for cond_data in rule_data["conditions"]:
                value = cond_data["value"]
                if cond_data["field"] == "timestamp" and isinstance(value, str):
                    try:
                        value = datetime.fromisoformat(value)
                    except ValueError:
                        pass
                
                conditions.append(FilterCondition(
                    field=cond_data["field"],
                    operator=cond_data["operator"],
                    value=value,
                    case_sensitive=cond_data.get("case_sensitive", False)
                ))
            
            rules.append(FilterRule(
                name=rule_data["name"],
                conditions=conditions,
                operator=rule_data.get("operator", "AND"),
                enabled=rule_data.get("enabled", True)
            ))
        
        return cls(rules)

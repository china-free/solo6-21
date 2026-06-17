from typing import Optional, Dict, Any
from datetime import datetime
import re


DEFAULT_TIMESTAMP_PATTERNS = [
    (r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2})?)", "%Y-%m-%d %H:%M:%S"),
    (r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", "%Y/%m/%d %H:%M:%S"),
    (r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})", "%d/%b/%Y:%H:%M:%S %z"),
    (r"(\w{3} +\d{1,2} \d{2}:\d{2}:\d{2})", "%b %d %H:%M:%S"),
    (r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})", "%Y-%m-%d %H:%M:%S,%f"),
]

DEFAULT_LEVEL_PATTERNS = [
    (r"\b(DEBUG|debug)\b", "DEBUG"),
    (r"\b(INFO|info)\b", "INFO"),
    (r"\b(WARN|warning|WARNING)\b", "WARN"),
    (r"\b(ERROR|error)\b", "ERROR"),
    (r"\b(FATAL|fatal|CRITICAL|critical)\b", "FATAL"),
]


class LogParser:
    def __init__(self, format_config: Optional[Dict[str, Any]] = None):
        self.format_config = format_config or {}
        self.timestamp_patterns = self._compile_timestamp_patterns()
        self.level_patterns = self._compile_level_patterns()
        self.custom_fields = self._compile_custom_fields()

    def _compile_timestamp_patterns(self) -> list:
        patterns = []
        
        if "timestamp" in self.format_config:
            ts_config = self.format_config["timestamp"]
            regex = ts_config.get("regex")
            fmt = ts_config.get("format")
            if regex and fmt:
                patterns.append((re.compile(regex), fmt))
            elif regex:
                patterns.append((re.compile(regex), None))
        else:
            for regex, fmt in DEFAULT_TIMESTAMP_PATTERNS:
                patterns.append((re.compile(regex), fmt))
        
        return patterns

    def _compile_level_patterns(self) -> list:
        patterns = []
        
        if "level" in self.format_config:
            level_config = self.format_config["level"]
            regex = level_config.get("regex")
            if regex:
                patterns.append((re.compile(regex, re.IGNORECASE), level_config.get("mapping", {})))
        else:
            for regex, level in DEFAULT_LEVEL_PATTERNS:
                patterns.append((re.compile(regex, re.IGNORECASE), level))
        
        return patterns

    def _compile_custom_fields(self) -> list:
        fields = []
        
        if "fields" in self.format_config:
            for field_name, field_config in self.format_config["fields"].items():
                regex = field_config.get("regex")
                if regex:
                    fields.append((field_name, re.compile(regex)))
        
        return fields

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        if not line.strip():
            return None
        
        result = {}
        
        timestamp = self._extract_timestamp(line)
        if timestamp:
            result["timestamp"] = timestamp
        
        level = self._extract_level(line)
        if level:
            result["level"] = level
        
        for field_name, pattern in self.custom_fields:
            match = pattern.search(line)
            if match:
                if match.groups():
                    result[field_name] = match.group(1)
                else:
                    result[field_name] = match.group(0)
        
        if not result:
            result["timestamp"] = datetime.now()
        
        return result

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for pattern, fmt in self.timestamp_patterns:
            match = pattern.search(line)
            if match:
                ts_str = match.group(1).replace("T", " ")
                
                if fmt:
                    try:
                        if "%f" in fmt and "," in ts_str:
                            ts_str = ts_str.replace(",", ".")
                        return datetime.strptime(ts_str, fmt)
                    except ValueError:
                        pass
                
                try:
                    return datetime.fromisoformat(ts_str)
                except ValueError:
                    pass
        
        return None

    def _extract_level(self, line: str) -> Optional[str]:
        for pattern, level in self.level_patterns:
            match = pattern.search(line)
            if match:
                if isinstance(level, dict):
                    matched_level = match.group(1).upper()
                    return level.get(matched_level, matched_level)
                return level
        
        return None

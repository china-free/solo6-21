from .base import LogSource, LogEntry
from typing import Iterator, Optional, Dict, Any
from datetime import datetime
import os
import time
import re
from ..parsers import LogParser


class LocalFileSource(LogSource):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.file_path = config.get("path", "")
        self.encoding = config.get("encoding", "utf-8")
        self.parser = LogParser(config.get("log_format", {}))

    def connect(self) -> None:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Log file not found: {self.file_path}")
        self.is_connected = True

    def disconnect(self) -> None:
        self.is_connected = False

    def fetch_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[LogEntry]:
        if not self.is_connected:
            self.connect()

        with open(self.file_path, "r", encoding=self.encoding, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                
                entry = self._parse_line(line)
                if entry is None:
                    continue
                
                if start_time and entry.timestamp < start_time:
                    continue
                if end_time and entry.timestamp > end_time:
                    continue
                
                yield entry

            if follow:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    
                    entry = self._parse_line(line)
                    if entry is None:
                        continue
                    
                    if end_time and entry.timestamp > end_time:
                        break
                    
                    yield entry

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        parsed = self.parser.parse(line)
        if parsed is None:
            return None
        
        return LogEntry(
            timestamp=parsed.get("timestamp", datetime.now()),
            source=self.name,
            raw_message=line,
            level=parsed.get("level", "INFO"),
            metadata={k: v for k, v in parsed.items() if k not in ["timestamp", "level"]},
        )

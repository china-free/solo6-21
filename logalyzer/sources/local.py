from .base import LogSource, LogEntry
from typing import Iterator, Optional, Dict, Any, Tuple
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
        for entry, _ in self.fetch_logs_incremental(
            cursor={"last_timestamp": start_time.isoformat()} if start_time else None,
            end_time=end_time,
            follow=follow,
        ):
            yield entry

    def fetch_logs_incremental(
        self,
        cursor: Optional[Dict[str, Any]] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[Tuple[LogEntry, Dict[str, Any]]]:
        if not self.is_connected:
            self.connect()

        cursor = cursor or {}
        start_offset = int(cursor.get("last_offset", 0) or 0)
        start_time = None
        if cursor.get("last_timestamp"):
            start_time = datetime.fromisoformat(cursor["last_timestamp"])
        last_line_seen = cursor.get("last_line", "")

        current_cursor = dict(cursor)
        file_size = os.path.getsize(self.file_path)

        with open(self.file_path, "rb") as bf:
            if 0 < start_offset <= file_size:
                bf.seek(max(0, start_offset - 4096))
                bf.readline()
            elif start_offset > file_size:
                bf.seek(0)
                bf.readline()

            with open(self.file_path, "r", encoding=self.encoding, errors="replace") as f:
                f.seek(bf.tell())

                passed_seen_line = (last_line_seen == "")

                while True:
                    pos_bytes = bf.tell()
                    line_bytes = bf.readline()
                    pos_after_bytes = bf.tell()
                    if not line_bytes:
                        if follow:
                            time.sleep(0.1)
                            continue
                        break
                    line = line_bytes.decode(self.encoding, errors="replace").rstrip("\r\n")
                    f.seek(pos_after_bytes)
                    if not line:
                        current_cursor["last_offset"] = pos_after_bytes
                        current_cursor["last_line"] = ""
                        continue

                    if not passed_seen_line and last_line_seen:
                        if line == last_line_seen:
                            passed_seen_line = True
                        current_cursor["last_offset"] = pos_after_bytes
                        current_cursor["last_line"] = line
                        continue
                    passed_seen_line = True

                    entry = self._parse_line(line)
                    if entry is None:
                        current_cursor["last_offset"] = pos_after_bytes
                        current_cursor["last_line"] = line
                        continue

                    if start_time and entry.timestamp < start_time:
                        current_cursor["last_offset"] = pos_after_bytes
                        current_cursor["last_line"] = line
                        current_cursor["last_timestamp"] = entry.timestamp.isoformat()
                        continue
                    if end_time and entry.timestamp > end_time:
                        break

                    current_cursor["last_offset"] = pos_after_bytes
                    current_cursor["last_line"] = line
                    current_cursor["last_timestamp"] = entry.timestamp.isoformat()
                    current_cursor["last_message_hash"] = entry.dedup_key()
                    yield entry, dict(current_cursor)

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

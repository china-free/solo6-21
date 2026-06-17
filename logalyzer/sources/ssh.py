from .base import LogSource, LogEntry
from typing import Iterator, Optional, Dict, Any, Tuple
from datetime import datetime
import time
import paramiko
from ..parsers import LogParser


class SSHSource(LogSource):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.host = config.get("host", "")
        self.port = config.get("port", 22)
        self.username = config.get("username", "")
        self.password = config.get("password", None)
        self.key_file = config.get("key_file", None)
        self.log_path = config.get("log_path", "")
        self.parser = LogParser(config.get("log_format", {}))
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.sftp_client: Optional[paramiko.SFTPClient] = None

    def connect(self) -> None:
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 10,
        }
        
        if self.key_file:
            connect_kwargs["key_filename"] = self.key_file
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise ValueError("Either password or key_file must be provided for SSH source")
        
        self.ssh_client.connect(**connect_kwargs)
        self.sftp_client = self.ssh_client.open_sftp()
        self.is_connected = True

    def disconnect(self) -> None:
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
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

        try:
            remote_file = self.sftp_client.open(self.log_path, "r")
            if start_offset > 0:
                try:
                    stat = self.sftp_client.stat(self.log_path)
                    if start_offset <= stat.st_size:
                        remote_file.seek(start_offset)
                except Exception:
                    pass

            passed_seen_line = (last_line_seen == "")
            line_count = 0

            while True:
                pos = remote_file.tell()
                line = remote_file.readline()
                if not line:
                    if follow:
                        time.sleep(0.5)
                        continue
                    break
                line = line.rstrip("\n\r")
                if not line:
                    continue

                if not passed_seen_line and last_line_seen:
                    if line == last_line_seen:
                        passed_seen_line = True
                    line_count += len(line.encode("utf-8", errors="replace")) + 1
                    current_cursor["last_offset"] = start_offset + line_count
                    current_cursor["last_line"] = line
                    continue
                passed_seen_line = True

                entry = self._parse_line(line)
                if entry is None:
                    line_count += len(line.encode("utf-8", errors="replace")) + 1
                    current_cursor["last_offset"] = start_offset + line_count
                    current_cursor["last_line"] = line
                    continue

                if start_time and entry.timestamp < start_time:
                    line_count += len(line.encode("utf-8", errors="replace")) + 1
                    current_cursor["last_offset"] = start_offset + line_count
                    current_cursor["last_line"] = line
                    current_cursor["last_timestamp"] = entry.timestamp.isoformat()
                    continue
                if end_time and entry.timestamp > end_time:
                    break

                line_count += len(line.encode("utf-8", errors="replace")) + 1
                current_cursor["last_offset"] = start_offset + line_count
                current_cursor["last_line"] = line
                current_cursor["last_timestamp"] = entry.timestamp.isoformat()
                current_cursor["last_message_hash"] = entry.dedup_key()
                yield entry, dict(current_cursor)

            remote_file.close()
        except Exception as e:
            raise RuntimeError(f"Error fetching logs from {self.host}: {e}")

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

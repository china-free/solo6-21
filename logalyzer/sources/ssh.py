from .base import LogSource, LogEntry
from typing import Iterator, Optional, Dict, Any
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
        if not self.is_connected:
            self.connect()

        try:
            remote_file = self.sftp_client.open(self.log_path, "r")
            
            for line in remote_file:
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
                    line = remote_file.readline()
                    if not line:
                        time.sleep(0.5)
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

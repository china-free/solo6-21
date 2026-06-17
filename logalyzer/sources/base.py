from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, Optional, Dict, Any
from datetime import datetime
import json


@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    raw_message: str
    level: str = "INFO"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "raw_message": self.raw_message,
            "level": self.level,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEntry":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source=data["source"],
            raw_message=data["raw_message"],
            level=data.get("level", "INFO"),
            metadata=data.get("metadata", {}),
        )

    def __str__(self) -> str:
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{self.level}] [{self.source}] {self.raw_message}"


class LogSource(ABC):
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.is_connected = False

    @abstractmethod
    def connect(self) -> None:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def fetch_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[LogEntry]:
        pass

    def __enter__(self) -> "LogSource":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

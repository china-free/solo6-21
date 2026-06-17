from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import os
import json
import uuid
from ..sources import LogEntry
from ..filters import FilterEngine
from ..alerts import AlertEngine
from ..config import AppConfig


@dataclass
class SourceCursor:
    last_timestamp: Optional[datetime] = None
    last_offset: int = 0
    last_message_hash: str = ""
    last_line: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "last_timestamp": self.last_timestamp.isoformat() if self.last_timestamp else None,
            "last_offset": self.last_offset,
            "last_message_hash": self.last_message_hash,
            "last_line": self.last_line,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceCursor":
        return cls(
            last_timestamp=datetime.fromisoformat(data["last_timestamp"]) if data.get("last_timestamp") else None,
            last_offset=data.get("last_offset", 0),
            last_message_hash=data.get("last_message_hash", ""),
            last_line=data.get("last_line", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AnalysisSession:
    id: str
    name: str
    created_at: datetime
    description: str = ""
    log_entries: List[LogEntry] = field(default_factory=list)
    filter_engine: Optional[FilterEngine] = None
    alert_engine: Optional[AlertEngine] = None
    source_names: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: Optional[datetime] = None
    last_collected_at: Optional[datetime] = None
    source_cursors: Dict[str, SourceCursor] = field(default_factory=dict)
    _dedup_keys: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self._dedup_keys:
            self._dedup_keys = {e.dedup_key() for e in self.log_entries}

    def get_latest_timestamp(self) -> Optional[datetime]:
        if not self.log_entries:
            return None
        return max(e.timestamp for e in self.log_entries)

    def get_source_latest_timestamp(self, source_name: str) -> Optional[datetime]:
        entries = [e for e in self.log_entries if e.source == source_name]
        if not entries:
            return None
        return max(e.timestamp for e in entries)

    def rebuild_dedup_index(self) -> None:
        self._dedup_keys = {e.dedup_key() for e in self.log_entries}

    def has_entry(self, entry: LogEntry) -> bool:
        return entry.dedup_key() in self._dedup_keys

    def merge_entries(self, new_entries: List[LogEntry], dedup: bool = True) -> List[LogEntry]:
        added: List[LogEntry] = []
        for e in new_entries:
            if dedup and self.has_entry(e):
                continue
            self.log_entries.append(e)
            self._dedup_keys.add(e.dedup_key())
            added.append(e)
        self.log_entries.sort(key=lambda x: x.timestamp)
        for e in added:
            cursor = self.source_cursors.setdefault(e.source, SourceCursor())
            if cursor.last_timestamp is None or e.timestamp > cursor.last_timestamp:
                cursor.last_timestamp = e.timestamp
                cursor.last_line = e.raw_message
                cursor.last_message_hash = e.dedup_key()
        if added:
            self.last_collected_at = datetime.now()
            latest = self.get_latest_timestamp()
            if latest:
                self.end_time = latest
        return added

    def update_source_cursor(self, source_name: str, cursor: SourceCursor) -> None:
        self.source_cursors[source_name] = cursor

    def get_source_cursor(self, source_name: str) -> SourceCursor:
        return self.source_cursors.get(source_name, SourceCursor())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_collected_at": self.last_collected_at.isoformat() if self.last_collected_at else None,
            "description": self.description,
            "log_entries": [entry.to_dict() for entry in self.log_entries],
            "filter_engine": self.filter_engine.to_dict() if self.filter_engine else [],
            "alert_engine": self.alert_engine.to_dict() if self.alert_engine else {},
            "source_names": self.source_names,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metadata": self.metadata,
            "source_cursors": {k: v.to_dict() for k, v in self.source_cursors.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisSession":
        filter_engine = None
        if "filter_engine" in data and data["filter_engine"]:
            filter_engine = FilterEngine.from_dict(data["filter_engine"])
        
        alert_engine = None
        if "alert_engine" in data and data["alert_engine"]:
            alert_engine = AlertEngine.from_dict(data["alert_engine"])
        
        source_cursors = {}
        for k, v in data.get("source_cursors", {}).items():
            source_cursors[k] = SourceCursor.from_dict(v)
        
        entries = [LogEntry.from_dict(e) for e in data.get("log_entries", [])]
        session = cls(
            id=data["id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            description=data.get("description", ""),
            log_entries=entries,
            filter_engine=filter_engine,
            alert_engine=alert_engine,
            source_names=data.get("source_names", []),
            start_time=datetime.fromisoformat(data["start_time"]) if data.get("start_time") else None,
            end_time=datetime.fromisoformat(data["end_time"]) if data.get("end_time") else None,
            metadata=data.get("metadata", {}),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_collected_at=datetime.fromisoformat(data["last_collected_at"]) if data.get("last_collected_at") else None,
            source_cursors=source_cursors,
        )
        session.rebuild_dedup_index()
        return session


class SessionManager:
    def __init__(self, session_dir: str = ".logalyzer_sessions"):
        self.session_dir = session_dir
        self._ensure_session_dir()

    def _ensure_session_dir(self) -> None:
        if not os.path.exists(self.session_dir):
            os.makedirs(self.session_dir, exist_ok=True)

    def create_session(
        self,
        name: str,
        description: str = "",
        log_entries: Optional[List[LogEntry]] = None,
        filter_engine: Optional[FilterEngine] = None,
        alert_engine: Optional[AlertEngine] = None,
        source_names: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> AnalysisSession:
        session_id = str(uuid.uuid4())[:8]
        session = AnalysisSession(
            id=session_id,
            name=name,
            created_at=datetime.now(),
            description=description,
            log_entries=log_entries or [],
            filter_engine=filter_engine,
            alert_engine=alert_engine,
            source_names=source_names or [],
            start_time=start_time,
            end_time=end_time,
        )
        return session

    def save_session(self, session: AnalysisSession) -> str:
        session.updated_at = datetime.now()
        session_path = self._get_session_path(session.id)
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
        return session_path

    def build_source_cursors(self, session: AnalysisSession) -> Dict[str, Dict[str, Any]]:
        cursors: Dict[str, Dict[str, Any]] = {}
        for source_name in session.source_names:
            cursor = session.get_source_cursor(source_name)
            cursor_dict = cursor.to_dict()
            if not cursor_dict.get("last_timestamp"):
                latest_ts = session.get_source_latest_timestamp(source_name)
                if latest_ts:
                    cursor_dict["last_timestamp"] = latest_ts.isoformat()
            cursors[source_name] = cursor_dict
        return cursors

    def apply_incremental_result(
        self,
        session: AnalysisSession,
        new_entries: List[LogEntry],
        cursor_updates: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[LogEntry]:
        added = session.merge_entries(new_entries, dedup=True)
        if cursor_updates:
            for source_name, cursor_dict in cursor_updates.items():
                cursor = SourceCursor.from_dict(cursor_dict)
                existing = session.source_cursors.get(source_name)
                if existing:
                    if cursor.last_timestamp and (
                        existing.last_timestamp is None
                        or cursor.last_timestamp > existing.last_timestamp
                    ):
                        session.source_cursors[source_name] = cursor
                    else:
                        existing.last_offset = max(existing.last_offset, cursor.last_offset)
                        if cursor.last_line:
                            existing.last_line = cursor.last_line
                else:
                    session.source_cursors[source_name] = cursor
        return added

    def load_session(self, session_id: str) -> Optional[AnalysisSession]:
        session_path = self._get_session_path(session_id)
        if not os.path.exists(session_path):
            return None
        
        with open(session_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return AnalysisSession.from_dict(data)

    def list_sessions(self) -> List[Dict[str, Any]]:
        sessions = []
        for filename in os.listdir(self.session_dir):
            if filename.endswith(".json"):
                session_id = filename[:-5]
                try:
                    session_path = os.path.join(self.session_dir, filename)
                    with open(session_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    latest_ts = None
                    for e in data.get("log_entries", []):
                        ts = e.get("timestamp")
                        if ts and (latest_ts is None or ts > latest_ts):
                            latest_ts = ts
                    sessions.append({
                        "id": data["id"],
                        "name": data["name"],
                        "created_at": data["created_at"],
                        "updated_at": data.get("updated_at"),
                        "last_collected_at": data.get("last_collected_at"),
                        "description": data.get("description", ""),
                        "log_count": len(data.get("log_entries", [])),
                        "source_names": data.get("source_names", []),
                        "latest_log_timestamp": latest_ts,
                        "has_cursors": bool(data.get("source_cursors")),
                    })
                except Exception:
                    continue
        
        sessions.sort(key=lambda x: x["created_at"], reverse=True)
        return sessions

    def delete_session(self, session_id: str) -> bool:
        session_path = self._get_session_path(session_id)
        if os.path.exists(session_path):
            os.remove(session_path)
            return True
        return False

    def update_session(
        self,
        session_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        append_logs: Optional[List[LogEntry]] = None,
        filter_engine: Optional[FilterEngine] = None,
        alert_engine: Optional[AlertEngine] = None,
    ) -> Optional[AnalysisSession]:
        session = self.load_session(session_id)
        if not session:
            return None
        
        if name is not None:
            session.name = name
        if description is not None:
            session.description = description
        if append_logs is not None:
            session.log_entries.extend(append_logs)
            session.log_entries.sort(key=lambda x: x.timestamp)
        if filter_engine is not None:
            session.filter_engine = filter_engine
        if alert_engine is not None:
            session.alert_engine = alert_engine
        
        self.save_session(session)
        return session

    def _get_session_path(self, session_id: str) -> str:
        return os.path.join(self.session_dir, f"{session_id}.json")

    def get_session_path(self, session_id: str) -> str:
        return self._get_session_path(session_id)

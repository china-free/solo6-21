from typing import List, Optional, Dict, Any
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "description": self.description,
            "log_entries": [entry.to_dict() for entry in self.log_entries],
            "filter_engine": self.filter_engine.to_dict() if self.filter_engine else [],
            "alert_engine": self.alert_engine.to_dict() if self.alert_engine else {},
            "source_names": self.source_names,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisSession":
        filter_engine = None
        if "filter_engine" in data and data["filter_engine"]:
            filter_engine = FilterEngine.from_dict(data["filter_engine"])
        
        alert_engine = None
        if "alert_engine" in data and data["alert_engine"]:
            alert_engine = AlertEngine.from_dict(data["alert_engine"])
        
        return cls(
            id=data["id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            description=data.get("description", ""),
            log_entries=[LogEntry.from_dict(e) for e in data.get("log_entries", [])],
            filter_engine=filter_engine,
            alert_engine=alert_engine,
            source_names=data.get("source_names", []),
            start_time=datetime.fromisoformat(data["start_time"]) if data.get("start_time") else None,
            end_time=datetime.fromisoformat(data["end_time"]) if data.get("end_time") else None,
            metadata=data.get("metadata", {}),
        )


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
        session_path = self._get_session_path(session.id)
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
        return session_path

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
                    sessions.append({
                        "id": data["id"],
                        "name": data["name"],
                        "created_at": data["created_at"],
                        "description": data.get("description", ""),
                        "log_count": len(data.get("log_entries", [])),
                        "source_names": data.get("source_names", []),
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

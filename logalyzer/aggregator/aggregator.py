from typing import Iterator, List, Optional, Tuple, Dict, Any
from datetime import datetime
import heapq
from ..sources import LogSource, LogEntry


class LogAggregator:
    def __init__(self, sources: List[LogSource]):
        self.sources = sources
        self._source_iterators = []
        self._heap: List = []
        self._current_cursors: Dict[str, Dict[str, Any]] = {}

    def aggregate(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[LogEntry]:
        cursors: Dict[str, Dict[str, Any]] = {}
        if start_time:
            cursors = {s.name: {"last_timestamp": start_time.isoformat()} for s in self.sources}
        for entry, _ in self.aggregate_incremental(cursors, end_time, follow):
            yield entry

    def aggregate_incremental(
        self,
        source_cursors: Optional[Dict[str, Dict[str, Any]]] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[Tuple[LogEntry, Dict[str, Dict[str, Any]]]]:
        source_cursors = source_cursors or {}
        self._current_cursors = {
            s.name: dict(source_cursors.get(s.name, {})) for s in self.sources
        }
        self._source_iterators = []
        self._heap = []

        try:
            for source in self.sources:
                try:
                    source.connect()
                    cursor = self._current_cursors.get(source.name, {})
                    it = source.fetch_logs_incremental(cursor, end_time, follow)
                    self._source_iterators.append((source, it))
                except Exception as e:
                    print(f"Warning: Failed to connect to source '{source.name}': {e}")

            for idx in range(len(self._source_iterators)):
                self._advance_inc(idx)

            while self._heap:
                _, source_idx, (entry, cursor) = heapq.heappop(self._heap)
                source = self._source_iterators[source_idx][0]
                self._current_cursors[source.name] = cursor
                self._advance_inc(source_idx)
                yield entry, {source.name: dict(cursor)}
        finally:
            for source, _ in self._source_iterators:
                try:
                    source.disconnect()
                except Exception:
                    pass

    def _advance_inc(self, source_idx: int) -> None:
        source, it = self._source_iterators[source_idx]
        try:
            item = next(it)
            if item:
                entry, cursor = item
                heapq.heappush(self._heap, (entry.timestamp, source_idx, (entry, cursor)))
        except StopIteration:
            pass
        except Exception as e:
            print(f"Warning: Error reading from source '{source.name}': {e}")

    def collect_all(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[LogEntry]:
        return list(self.aggregate(start_time, end_time))

    def get_last_cursors(self) -> Dict[str, Dict[str, Any]]:
        return {k: dict(v) for k, v in self._current_cursors.items()}

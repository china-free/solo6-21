from typing import Iterator, List, Optional, Tuple
from datetime import datetime
import heapq
from ..sources import LogSource, LogEntry


class LogAggregator:
    def __init__(self, sources: List[LogSource]):
        self.sources = sources
        self._source_iterators = []
        self._heap = []
        self._next_entries = {}

    def aggregate(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[LogEntry]:
        self._init_iterators(start_time, end_time, follow)
        
        try:
            self._fill_heap()
            
            while self._heap:
                entry = self._pop_next()
                if entry:
                    yield entry
        finally:
            self._cleanup()

    def _init_iterators(
        self,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        follow: bool,
    ) -> None:
        self._source_iterators = []
        
        for source in self.sources:
            try:
                source.connect()
                it = source.fetch_logs(start_time, end_time, follow)
                self._source_iterators.append((source, it))
            except Exception as e:
                print(f"Warning: Failed to connect to source '{source.name}': {e}")

    def _fill_heap(self) -> None:
        for idx, (source, it) in enumerate(self._source_iterators):
            self._advance_source(idx)

    def _advance_source(self, source_idx: int) -> None:
        source, it = self._source_iterators[source_idx]
        try:
            entry = next(it)
            if entry:
                heapq.heappush(self._heap, (entry.timestamp, source_idx, entry))
        except StopIteration:
            pass
        except Exception as e:
            print(f"Warning: Error reading from source '{source.name}': {e}")

    def _pop_next(self) -> Optional[LogEntry]:
        if not self._heap:
            return None
        
        timestamp, source_idx, entry = heapq.heappop(self._heap)
        self._advance_source(source_idx)
        return entry

    def _cleanup(self) -> None:
        for source, _ in self._source_iterators:
            try:
                source.disconnect()
            except Exception:
                pass

    def collect_all(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[LogEntry]:
        return list(self.aggregate(start_time, end_time))

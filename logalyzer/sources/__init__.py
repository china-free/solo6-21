from .base import LogSource, LogEntry
from .local import LocalFileSource
from .ssh import SSHSource
from .cloud import CloudStorageSource
from typing import Dict, Type


SOURCE_REGISTRY: Dict[str, Type[LogSource]] = {
    "local": LocalFileSource,
    "ssh": SSHSource,
    "cloud": CloudStorageSource,
}


def create_source(source_type: str, name: str, config: dict) -> LogSource:
    if source_type not in SOURCE_REGISTRY:
        raise ValueError(f"Unknown source type: {source_type}")
    return SOURCE_REGISTRY[source_type](name, config)

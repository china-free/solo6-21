from .base import LogSource, LogEntry
from typing import Iterator, Optional, Dict, Any
from datetime import datetime, timedelta
import boto3
from ..parsers import LogParser


class CloudStorageSource(LogSource):
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.provider = config.get("provider", "s3")
        self.bucket = config.get("bucket", "")
        self.prefix = config.get("prefix", "")
        self.region = config.get("region", "us-east-1")
        self.access_key = config.get("access_key", None)
        self.secret_key = config.get("secret_key", None)
        self.endpoint_url = config.get("endpoint_url", None)
        self.parser = LogParser(config.get("log_format", {}))
        self.s3_client = None

    def connect(self) -> None:
        client_kwargs = {
            "service_name": "s3",
            "region_name": self.region,
        }
        
        if self.access_key and self.secret_key:
            client_kwargs["aws_access_key_id"] = self.access_key
            client_kwargs["aws_secret_access_key"] = self.secret_key
        
        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url
        
        self.s3_client = boto3.client(**client_kwargs)
        self.is_connected = True

    def disconnect(self) -> None:
        self.s3_client = None
        self.is_connected = False

    def fetch_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        follow: bool = False,
    ) -> Iterator[LogEntry]:
        if not self.is_connected:
            self.connect()

        objects = self._list_objects(start_time, end_time)
        
        for obj in objects:
            content = self._read_object(obj["Key"])
            for line in content.split("\n"):
                line = line.rstrip()
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
            raise NotImplementedError("Follow mode is not supported for cloud storage sources")

    def _list_objects(self, start_time: Optional[datetime], end_time: Optional[datetime]) -> list:
        paginator = self.s3_client.get_paginator("list_objects_v2")
        objects = []
        
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            if "Contents" not in page:
                continue
            
            for obj in page["Contents"]:
                last_modified = obj["LastModified"].replace(tzinfo=None)
                
                if start_time and last_modified < start_time:
                    continue
                if end_time and last_modified > end_time:
                    continue
                
                objects.append(obj)
        
        objects.sort(key=lambda x: x["LastModified"])
        return objects

    def _read_object(self, key: str) -> str:
        response = self.s3_client.get_object(Bucket=self.bucket, Key=key)
        return response["Body"].read().decode("utf-8", errors="replace")

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

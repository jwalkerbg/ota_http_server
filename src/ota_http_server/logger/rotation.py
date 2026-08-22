import logging
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path


@dataclass(frozen=True)
class RotationPolicy:
    strategy: str
    max_bytes: int
    backup_count: int
    when: str
    interval: int
    utc: bool


class SizeAndTimeRotatingFileHandler(TimedRotatingFileHandler):
    """Rotate when either time or size limits are reached."""

    def __init__(
        self,
        filename: str,
        when: str = "midnight",
        interval: int = 1,
        backupCount: int = 0,
        encoding: str | None = None,
        delay: bool = False,
        utc: bool = False,
        atTime=None,
        errors: str | None = None,
        *,
        maxBytes: int = 0,
    ):
        super().__init__(
            filename=filename,
            when=when,
            interval=interval,
            backupCount=backupCount,
            encoding=encoding,
            delay=delay,
            utc=utc,
            atTime=atTime,
            errors=errors,
        )
        self.maxBytes = max(0, int(maxBytes))

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        if super().shouldRollover(record):
            return True

        if self.maxBytes <= 0:
            return False

        if self.stream is None:
            self.stream = self._open()

        message = f"{self.format(record)}\n"
        message_size = len(message.encode(self.encoding or "utf-8", errors="replace"))
        return self.stream.tell() + message_size >= self.maxBytes


def create_rotating_file_handler(log_file_path: Path, policy: RotationPolicy) -> logging.Handler:
    """Create a rotation-enabled file handler with a reusable policy."""
    strategy = policy.strategy.lower()
    log_file = str(log_file_path)
    encoding = "utf-8"

    if strategy == "size":
        return RotatingFileHandler(
            filename=log_file,
            maxBytes=max(0, int(policy.max_bytes)),
            backupCount=max(1, int(policy.backup_count)),
            encoding=encoding,
        )

    if strategy == "time":
        return TimedRotatingFileHandler(
            filename=log_file,
            when=policy.when,
            interval=max(1, int(policy.interval)),
            backupCount=max(1, int(policy.backup_count)),
            encoding=encoding,
            utc=policy.utc,
        )

    if strategy == "hybrid":
        return SizeAndTimeRotatingFileHandler(
            filename=log_file,
            when=policy.when,
            interval=max(1, int(policy.interval)),
            backupCount=max(1, int(policy.backup_count)),
            encoding=encoding,
            utc=policy.utc,
            maxBytes=max(0, int(policy.max_bytes)),
        )

    raise ValueError(f"Unsupported log rotation strategy: {policy.strategy}")

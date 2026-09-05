import logging
import os
import re
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


class SafeRotateMixin:
    """Tolerate rotation failures caused by another process holding the log file open.

    On Windows, ``os.rename`` fails with ``PermissionError`` (WinError 32) if another
    process (e.g. a concurrently running ``runserver`` instance) has the log file open.
    Without this guard, that exception propagates out of ``doRollover``, gets reported by
    ``logging.Handler.handleError`` as a noisy "Logging error" traceback, and the log
    record that triggered it is dropped. Skipping the rotation for this attempt lets
    logging continue uninterrupted; the file will be rotated on a later attempt once the
    lock is released.
    """

    def rotate(self, source: str, dest: str) -> None:
        try:
            super().rotate(source, dest)  # type: ignore[misc]
        except OSError as exc:
            logging.getLogger(__name__).debug(
                "Skipping log rotation for %s -> %s: %s", source, dest, exc
            )


class SafeRotatingFileHandler(SafeRotateMixin, RotatingFileHandler):
    """Size-based rotation that tolerates concurrent-process file locks."""


class DateAwareTimedRotatingFileHandler(SafeRotateMixin, TimedRotatingFileHandler):
    """Rotate logs to names like "app-2026-08-22.log" instead of "app.log.2026-08-22"."""

    _DATE_SUFFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

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
        self.namer = self._date_namer

    def _date_namer(self, default_name: str) -> str:
        directory, file_name = os.path.split(default_name)
        if "." not in file_name:
            return default_name

        rotated_name, date_suffix = file_name.rsplit(".", 1)
        if not self._DATE_SUFFIX_RE.fullmatch(date_suffix):
            return default_name

        stem, extension = os.path.splitext(rotated_name)
        if not extension:
            return default_name

        new_file_name = f"{stem}-{date_suffix}{extension}"
        return os.path.join(directory, new_file_name) if directory else new_file_name


class SizeAndTimeRotatingFileHandler(DateAwareTimedRotatingFileHandler):
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
        return SafeRotatingFileHandler(
            filename=log_file,
            maxBytes=max(0, int(policy.max_bytes)),
            backupCount=max(1, int(policy.backup_count)),
            encoding=encoding,
        )

    if strategy == "time":
        return DateAwareTimedRotatingFileHandler(
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

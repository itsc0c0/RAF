"""Structured logging for R$F itself.

* Console: concise human output on stderr (WARNING+ unless ``--debug``).
* File: JSON lines in ``RAF_HOME/logs/raf.log`` (rotating), INFO+.
* Every record passes a redaction filter so secrets never reach logs.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from raf.core.security.redaction import redact_text

_RESERVED = set(vars(logging.LogRecord("x", 0, "x", 0, "x", None, None))) | {"message", "asctime"}


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging crash the caller
            return True
        redacted = redact_text(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        return True


class ConsoleFilter(logging.Filter):
    """Keep records marked ``file_only`` (e.g. internal tracebacks) off the console."""

    def __init__(self, debug: bool) -> None:
        super().__init__()
        self.debug = debug

    def filter(self, record: logging.LogRecord) -> bool:
        return self.debug or not getattr(record, "file_only", False)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value if isinstance(value, str | int | float | bool | type(None)) else str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return redact_text(json.dumps(payload, ensure_ascii=False))


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extras = " ".join(
            f"{k}={v}" for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")
        )
        base = f"[{record.levelname.lower()}] {record.name}: {record.getMessage()}"
        if extras:
            base += f" ({extras})"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


_configured = False


def configure_logging(level: str = "WARNING", *, log_dir: Path | None = None, debug: bool = False) -> None:
    """Configure the ``raf`` logger hierarchy (idempotent)."""
    global _configured
    root = logging.getLogger("raf")
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.DEBUG)
    root.propagate = False
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if debug else getattr(logging, level.upper(), logging.WARNING))
    console.setFormatter(ConsoleFormatter())
    console.addFilter(RedactingFilter())
    console.addFilter(ConsoleFilter(debug))
    root.addHandler(console)
    if log_dir is not None:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_dir / "raf.log", maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
            file_handler.setFormatter(JsonFormatter())
            file_handler.addFilter(RedactingFilter())
            root.addHandler(file_handler)
        except OSError:
            root.warning("could not open log file in %s", log_dir)
    _configured = True


@contextmanager
def timed(logger: logging.Logger, operation: str, **fields: Any) -> Iterator[dict[str, Any]]:
    """Log the duration of an operation (``duration_ms``); yields a dict for extra result fields."""
    extra: dict[str, Any] = {}
    start = time.perf_counter()
    status = "ok"
    try:
        yield extra
    except BaseException:
        status = "error"
        raise
    finally:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "%s finished",
            operation,
            extra={"operation": operation, "duration_ms": duration_ms, "status": status, **fields, **extra},
        )

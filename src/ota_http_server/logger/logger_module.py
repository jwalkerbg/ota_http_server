# logger.py

# logger_module.py
import sys
import logging
import colorama
from typing import Optional
from datetime import datetime

TAGNAME = "invoices"

# Custom Formatter
class CustomFormatter(logging.Formatter):
    def __init__(self, show_prefix: bool = True):
        super().__init__()
        self.show_prefix = show_prefix

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()

        if not self.show_prefix:
            return f"{message}"

        # Original prefix formatting
        log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{log_time} - {record.name} - {record.levelname} - {message}"
        return log_message

# Custom Logging Handler
class StringHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.log_messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        log_entry = self.format(record)
        self.log_messages.append(log_entry)

    def get_logs(self) -> str:
        return '\n'.join(self.log_messages)

    def clear_logs(self) -> None:
        self.log_messages = []

# ================================================================
#  Custom log levels: VERBOSE(15) and QUIET(25)
# ================================================================
QUIET_LEVEL = 25
VERBOSE_LEVEL = 15

if not hasattr(logging, "QUIET"):
    logging.addLevelName(QUIET_LEVEL, "QUIET")

    def quiet(self, msg, *args, **kwargs):
        if self.isEnabledFor(QUIET_LEVEL):
            self._log(QUIET_LEVEL, msg, args, **kwargs)
    logging.Logger.quiet = quiet

if not hasattr(logging, "VERBOSE"):
    logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")

    def verbose(self, msg, *args, **kwargs):
        if self.isEnabledFor(VERBOSE_LEVEL):
            self._log(VERBOSE_LEVEL, msg, args, **kwargs)
    logging.Logger.verbose = verbose

# Initialize colorama for Windows ANSI support
colorama.init()

# ================================================================
#  Color map
# ================================================================
RESET = "\033[0m"
COLORS = {
    "DEBUG": "\033[90m",    # Bright black (grey)
    "VERBOSE": "\033[37m",  # White
    "INFO": "\033[36m",     # Cyan
    "QUIET": "\033[32m",    # Green
    "WARNING": "\033[33m",  # Yellow
    "ERROR": "\033[31m",    # Red
    "CRITICAL": "\033[41m", # White on red background
}

# ================================================================
#  Custom formatter with prefix toggle + color
# ================================================================
class ColorFormatter(logging.Formatter):

    def __init__(self, prefix_enabled: bool, use_color: bool = True):
        if prefix_enabled:
            fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        else:
            fmt = "%(message)s"

        super().__init__(fmt)
        self.prefix_enabled = prefix_enabled
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        color = COLORS.get(record.levelname, "") if self.use_color else ""
        return f"{color}{message}{RESET}" if self.use_color else message


# ================================================================
#  String handler (optional)
# ================================================================
class StringHandler(logging.Handler):
    """Stores logs in an internal buffer with enable/disable control."""

    def __init__(self, level=logging.INFO):
        super().__init__(level)
        self.buffer : list[str]= []
        self.enabled = True  # can disable storing without affecting normal logging

    def emit(self, record: logging.LogRecord):
        if self.enabled:
            self.buffer.append(self.format(record))

    def get_logs(self) -> str:
        """Return all stored logs as a single string."""
        return "\n".join(self.buffer)

    def clear_logs(self) -> None:
        """Clear the buffer."""
        self.buffer.clear()

    def disable(self) -> None:
        self.enabled = False

    def enable(self) -> None:
        self.enabled = True

string_handler_instance = None  # global to reuse

# ================================================================
#  Main setup function (no duplicate handlers)
# ================================================================
def setup_logging(verbosity: int = 3,
                  log_prefix: bool = True,
                  use_color: bool = True,
                  use_string_handler: bool = False):
    """
    Configure logging with custom levels, prefix toggle, color output,
    and optional string handler.
    """

    # -----------------------------------------
    # Map verbosity → logging level
    # -----------------------------------------
    LEVELS = {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARNING,
        3: QUIET_LEVEL,
        4: logging.INFO,
        5: VERBOSE_LEVEL,
        6: logging.DEBUG,
    }

    level = LEVELS.get(verbosity, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # -----------------------------------------
    # Create formatter
    # -----------------------------------------
    formatter = ColorFormatter(prefix_enabled=log_prefix, use_color=use_color)

    # -----------------------------------------
    # STREAM HANDLER (stdout) — avoid duplicates
    # -----------------------------------------
    console_handler = None
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stdout:
            console_handler = h
            break

    if console_handler is None:
        console_handler = logging.StreamHandler(sys.stdout)
        root.addHandler(console_handler)

    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    # -----------------------------------------
    # STRING HANDLER — optional, unique
    # -----------------------------------------
    global string_handler_instance

    if use_string_handler:
        if string_handler_instance is None:
            string_handler_instance = StringHandler(level)
            root.addHandler(string_handler_instance)

        string_handler_instance.setLevel(level)
        string_handler_instance.setFormatter(formatter)

    return string_handler_instance

def get_app_logger(area_tag: str) -> logging.Logger:
    """
    Returns a logger for a given module/area tag.
    Inherits configuration from root logger.
    """
    if not area_tag:
        area_tag = ""
    lg = logging.getLogger(area_tag)
    # Do not set level here; inherit from root
    return lg

def disable_string_handler() -> None:
    if string_handler_instance:
        string_handler_instance.disable()

def enable_string_handler() -> None:
    if string_handler_instance:
        string_handler_instance.enable()

def get_string_logs() -> str:
    if string_handler_instance:
        return string_handler_instance.get_logs()
    return ""

def clear_string_logs() -> None:
    if string_handler_instance:
        string_handler_instance.clear_logs()

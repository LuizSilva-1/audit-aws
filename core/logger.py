import logging
import re
import sys


class RedactFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._patterns = [
            re.compile(r"(ASIA|AKIA)[0-9A-Z]{16}"),
            re.compile(r"(?i)(aws_secret_access_key|secret_access_key)\\s*[:=]\\s*[^\\s]+"),
            re.compile(r"(?i)(aws_access_key_id|access_key_id)\\s*[:=]\\s*[^\\s]+"),
            re.compile(r"(?i)(aws_session_token|session_token)\\s*[:=]\\s*[^\\s]+"),
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern in self._patterns:
            msg = pattern.sub("[REDACTADO]", msg)
        record.msg = msg
        record.args = ()
        return True


def setup_logger(name: str = "aws-audit", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    handler.addFilter(RedactFilter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger

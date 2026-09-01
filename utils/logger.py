import sys
import logging
from pathlib import Path
from loguru import logger

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

class InvestigationLogger:
    def __init__(self, case_id: str = "GENERAL"):
        self.case_id = case_id
        self.log_file = LOG_DIR / f"investigation_{case_id}.log"
        self._configure_logger()

    def _configure_logger(self):
        logger.remove()

        log_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{extra[case_id]}</cyan> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )

        # 1. Sortie Console (INFO)
        logger.add(sys.stdout, format=log_format, level="INFO", colorize=True)

        # 2. Sortie Fichier (DEBUG - Chronologique et complet)
        logger.add(
            self.log_file,
            format=log_format,
            level="DEBUG",
            rotation="10 MB",
            retention="30 days",
            enqueue=True,
            encoding="utf-8"
        )

    def get_logger(self):
        return logger.bind(case_id=self.case_id)

def get_investigation_logger(case_id: str = "GENERAL"):
    inv_logger = InvestigationLogger(case_id=case_id)
    return inv_logger.get_logger()

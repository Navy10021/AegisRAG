"""
AegisRAG Logging Configuration
로깅 설정 시스템
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from .config import DEFAULT_LOGGING_CONFIG, LoggingConfig


def setup_logging(config: Optional[LoggingConfig] = None) -> logging.Logger:
    """
    로깅 시스템 설정

    Args:
        config: 로깅 설정 (None일 경우 기본값 사용)

    Returns:
        설정된 루트 로거
    """
    if config is None:
        config = DEFAULT_LOGGING_CONFIG

    # 로그 디렉토리 생성
    log_dir = Path(config.LOG_FILE).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    # 로그 레벨 설정
    log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)

    # 포매터 생성
    formatter = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)

    # 콘솔 핸들러
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    # 파일 핸들러 (로테이션)
    file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.MAX_LOG_SIZE_MB * 1024 * 1024,
        backupCount=config.BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    # 루트 로거 설정
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # 기존 핸들러 제거 (중복 방지)
    root_logger.handlers.clear()

    # 핸들러 추가
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # 초기 로그
    root_logger.info("=" * 80)
    root_logger.info("AegisRAG Logging System Initialized")
    root_logger.info(f"Log Level: {config.LOG_LEVEL}")
    root_logger.info(f"Log File: {config.LOG_FILE}")
    root_logger.info("=" * 80)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    모듈별 로거 생성

    Args:
        name: 로거 이름 (보통 __name__)

    Returns:
        로거 인스턴스
    """
    return logging.getLogger(name)

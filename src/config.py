"""
AegisRAG Configuration Management
Configuration management system
"""

import os
from dataclasses import dataclass
from typing import Dict


@dataclass
class AnalyzerConfig:
    """Analyzer configuration"""

    # Severity settings
    SEVERITY_MULTIPLIERS: Dict[str, float] = None
    SEVERITY_POINTS: Dict[str, int] = None

    # Cache settings
    CACHE_SIZE: int = 256
    MAX_HISTORY_SIZE: int = 1000

    # Pattern detection
    MAX_DETECTED_PATTERNS: int = 3
    MAX_KEY_FACTORS: int = 5

    # Search weights
    SEMANTIC_WEIGHT: float = 0.5
    BM25_WEIGHT: float = 0.2
    KEYWORD_WEIGHT: float = 0.3

    # Thresholds
    RELEVANCE_THRESHOLD_HIGH: float = 0.8
    RELEVANCE_THRESHOLD_MEDIUM: float = 0.6
    RELEVANCE_THRESHOLD_LOW: float = 0.4

    # Risk score thresholds
    RISK_CRITICAL_THRESHOLD: int = 60
    RISK_HIGH_THRESHOLD: int = 40
    RISK_MEDIUM_THRESHOLD: int = 20

    # Timeout settings (seconds)
    LLM_TIMEOUT: int = 30
    REGEX_TIMEOUT: float = 0.1

    # Context memory
    TEMPORAL_WINDOW_HOURS: int = 24
    MIN_CHAIN_LENGTH: int = 3
    MIN_USER_ANALYSES: int = 5

    # Input limits
    MAX_INPUT_LENGTH: int = 10000

    def __post_init__(self):
        if self.SEVERITY_MULTIPLIERS is None:
            self.SEVERITY_MULTIPLIERS = {
                "critical": 1.5,
                "high": 1.2,
                "medium": 1.0,
                "low": 0.8
            }

        if self.SEVERITY_POINTS is None:
            self.SEVERITY_POINTS = {
                'critical': 30,
                'high': 20,
                'medium': 10,
                'low': 5
            }


@dataclass
class SecurityConfig:
    """Security configuration"""

    # API Key management
    OPENAI_API_KEY: str = None

    # Input sanitization
    ENABLE_INPUT_SANITIZATION: bool = True
    MAX_PROMPT_LENGTH: int = 1000

    # Allowed special characters in input
    ALLOWED_SPECIAL_CHARS: str = ".,!?;:()[]{}'-\"/@#$%&*+=_<>~`| \n\t"

    def __post_init__(self):
        if self.OPENAI_API_KEY is None:
            self.OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')


@dataclass
class LoggingConfig:
    """Logging configuration"""

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/aegis.log"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
    MAX_LOG_SIZE_MB: int = 10
    BACKUP_COUNT: int = 5

    def __post_init__(self):
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', self.LOG_LEVEL).upper()


# Default configurations
DEFAULT_ANALYZER_CONFIG = AnalyzerConfig()
DEFAULT_SECURITY_CONFIG = SecurityConfig()
DEFAULT_LOGGING_CONFIG = LoggingConfig()

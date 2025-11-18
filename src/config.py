"""
AegisRAG Configuration Management
Configuration management system
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AnalyzerConfig:
    """Analyzer configuration"""

    # Severity settings
    SEVERITY_MULTIPLIERS: Optional[Dict[str, float]] = None
    SEVERITY_POINTS: Optional[Dict[str, int]] = None

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

    # Relationship analysis weights
    RELATIONSHIP_TEMPORAL_WEIGHT: float = 0.3
    RELATIONSHIP_SEMANTIC_WEIGHT: float = 0.5
    RELATIONSHIP_USER_WEIGHT: float = 0.2
    RELATIONSHIP_THRESHOLD: float = 0.3

    # Similarity calculation weights
    SIMILARITY_VIOLATION_WEIGHT: float = 0.6
    SIMILARITY_SCORE_WEIGHT: float = 0.4

    # Input limits
    MAX_INPUT_LENGTH: int = 10000

    # Direct analysis patterns (threat keywords and scores)
    DIRECT_ANALYSIS_PATTERNS: Optional[Dict[str, int]] = None

    # LLM configuration
    MAX_POLICIES_FOR_LLM: int = 10

    # Memory and context
    MAX_USER_HISTORY: int = 100
    BEHAVIOR_TREND_THRESHOLD_UP: float = 5.0
    BEHAVIOR_TREND_THRESHOLD_DOWN: float = -5.0
    CONTEXT_ADJUSTMENT_BASE: int = 10
    CONTEXT_ADJUSTMENT_VIOLATION_MULTIPLIER: int = 5
    CONTEXT_ADJUSTMENT_MAX: int = 30
    CONTEXT_ADJUSTMENT_VIOLATION_THRESHOLD: int = 3

    # Explanation thresholds
    EXPLANATION_MIN_SCORE: float = 5.0
    EXPLANATION_FACTOR_THRESHOLD_HIGH: float = 30.0
    EXPLANATION_FACTOR_THRESHOLD_MEDIUM: float = 15.0
    EXPLANATION_FACTOR_THRESHOLD_LOW: float = 10.0
    MAX_SIMILAR_CASES: int = 3
    VISUALIZATION_BAR_SCALE: int = 5

    # BM25 parameters
    BM25_K1: float = 1.5
    BM25_B: float = 0.75

    # Numerical epsilon
    EPSILON: float = 1e-10

    def __post_init__(self):
        if self.SEVERITY_MULTIPLIERS is None:
            self.SEVERITY_MULTIPLIERS = {
                "critical": 1.5,
                "high": 1.2,
                "medium": 1.0,
                "low": 0.8,
            }

        if self.SEVERITY_POINTS is None:
            self.SEVERITY_POINTS = {"critical": 30, "high": 20, "medium": 10, "low": 5}

        if self.DIRECT_ANALYSIS_PATTERNS is None:
            self.DIRECT_ANALYSIS_PATTERNS = {
                "hack": 20,
                "crack": 20,
                "exploit": 25,
                "breach": 25,
                "steal": 15,
                "leak": 20,
                "unauthorized": 18,
                "malicious": 22,
            }


@dataclass
class SecurityConfig:
    """Security configuration"""

    # API Key management
    OPENAI_API_KEY: Optional[str] = None

    # Input sanitization
    ENABLE_INPUT_SANITIZATION: bool = True
    MAX_PROMPT_LENGTH: int = 1000

    # Allowed special characters in input
    ALLOWED_SPECIAL_CHARS: str = ".,!?;:()[]{}'-\"/@#$%&*+=_<>~`| \n\t"

    def __post_init__(self):
        if self.OPENAI_API_KEY is None:
            self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


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
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", self.LOG_LEVEL).upper()


# Default configurations
DEFAULT_ANALYZER_CONFIG = AnalyzerConfig()
DEFAULT_SECURITY_CONFIG = SecurityConfig()
DEFAULT_LOGGING_CONFIG = LoggingConfig()

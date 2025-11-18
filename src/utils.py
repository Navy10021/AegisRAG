"""
RAG Security Analyzer - Utilities
Utility functions and classes
"""

import json
import logging
import os
import re
from functools import lru_cache
from enum import Enum
from typing import Optional, Pattern, List

logger = logging.getLogger(__name__)

# langdetect availability check
try:
    from langdetect import detect, LangDetectException

    LANGDETECT_AVAILABLE = True
except (ImportError, ModuleNotFoundError) as e:
    LANGDETECT_AVAILABLE = False
    logger.warning(f"langdetect not available: {e}")


# ============================================================
# Language Detection
# ============================================================


class LanguageDetector:
    """Multi-language support"""

    SUPPORTED = {"ko": "한국어", "en": "English", "ja": "日本語", "zh-cn": "中文"}

    @staticmethod
    def detect_language(text: str) -> str:
        """Detect text language"""
        if not LANGDETECT_AVAILABLE or not text.strip():
            return "unknown"

        try:
            lang = detect(text)
            if lang.startswith("zh"):
                lang = "zh-cn"
            if lang not in LanguageDetector.SUPPORTED:
                return "en"
            return lang
        except LangDetectException as e:
            logger.debug(f"Language detection failed: {e}")
            return "en"
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid input for language detection: {e}")
            return "en"

    @staticmethod
    @lru_cache(maxsize=4)
    def get_patterns(language: str) -> dict:
        """Load security patterns by language"""
        language = language.lower()
        base_path = f"./data/patterns_{language}.json"

        if not os.path.exists(base_path):
            base_path = "./data/patterns_en.json"

        try:
            with open(base_path, "r", encoding="utf-8") as f:
                patterns = json.load(f)
            return patterns
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load patterns for {language}: {e}")
            return {}


# ============================================================
# Security Pattern Strength
# ============================================================


class SecurityPatternStrength(Enum):
    """Security pattern strength"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================
# Input Sanitization
# ============================================================


def sanitize_input(
    text: str, max_length: int = 10000, allowed_chars: Optional[str] = None
) -> str:
    """
    Safely sanitize user input

    Args:
        text: Input text
        max_length: Maximum length
        allowed_chars: Allowed special characters (if None, all unicode allowed)

    Returns:
        Sanitized text

    Raises:
        TypeError: If text is not a string

    Example:
        >>> sanitize_input("Test\\x00malicious")
        'Testmalicious'
    """
    # Handle None gracefully
    if text is None:
        return ""

    # Type validation
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")

    if not text:
        return ""

    # 1. Length limit
    text = text[:max_length]

    # 2. Remove NULL bytes
    text = text.replace("\x00", "")

    # 3. Remove control characters (except newlines, tabs)
    text = "".join(char for char in text if char.isprintable() or char in "\n\t\r")

    # 4. Clean up consecutive whitespace
    text = re.sub(r"\s+", " ", text)

    # 5. Filter special characters (optional)
    if allowed_chars is not None:
        text = "".join(
            char
            for char in text
            if char.isalnum() or char.isspace() or char in allowed_chars
        )

    return text.strip()


# Pre-compiled prompt injection patterns for better performance
_INJECTION_PATTERNS: List[Pattern] = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+all\s+above", re.IGNORECASE),
    re.compile(r"forget\s+everything", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"<\s*script\s*>", re.IGNORECASE),
]


def sanitize_prompt_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize input for LLM prompts (more strict)

    Args:
        text: Input text
        max_length: Maximum length

    Returns:
        Sanitized text
    """
    # Basic sanitization
    text = sanitize_input(text, max_length)

    # Escape quotes
    text = text.replace('"', '\\"').replace("'", "\\'")

    # Remove potential prompt injection patterns using pre-compiled patterns
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("", text)

    return text

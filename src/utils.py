"""
RAG Security Analyzer - Utilities
유틸리티 함수 및 클래스
"""

import json
import logging
import os
import re
from functools import lru_cache
from enum import Enum
from typing import Dict, List

logger = logging.getLogger(__name__)

# langdetect 가용성 체크
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
    """다중 언어 지원"""
    
    SUPPORTED = {
        'ko': '한국어',
        'en': 'English',
        'ja': '日本語',
        'zh-cn': '中文'
    }
    
    @staticmethod
    def detect_language(text: str) -> str:
        """텍스트 언어 감지"""
        if not LANGDETECT_AVAILABLE or not text.strip():
            return "unknown"
        
        try:
            lang = detect(text)
            if lang.startswith("zh"):
                lang = "zh-cn"
            if lang not in LanguageDetector.SUPPORTED:
                return "en"
            return lang
        except (LangDetectException, Exception) as e:
            logger.debug(f"Language detection failed: {e}")
            return "en"
    
    @staticmethod
    @lru_cache(maxsize=4)
    def get_patterns(language: str) -> dict:
        """언어별 보안 패턴 로드"""
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
    """보안 패턴 강도"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================
# Input Sanitization
# ============================================================

def sanitize_input(
    text: str,
    max_length: int = 10000,
    allowed_chars: str = None
) -> str:
    """
    사용자 입력을 안전하게 정제

    Args:
        text: 입력 텍스트
        max_length: 최대 길이
        allowed_chars: 허용된 특수문자 (None일 경우 모든 유니코드 허용)

    Returns:
        정제된 텍스트

    Example:
        >>> sanitize_input("Test\\x00malicious")
        'Testmalicious'
    """
    if not text:
        return ""

    # 1. 길이 제한
    text = text[:max_length]

    # 2. NULL 바이트 제거
    text = text.replace('\x00', '')

    # 3. 제어 문자 제거 (줄바꿈, 탭 제외)
    text = ''.join(char for char in text
                   if char.isprintable() or char in '\n\t\r')

    # 4. 연속된 공백 정리
    text = re.sub(r'\s+', ' ', text)

    # 5. 특수문자 필터링 (옵션)
    if allowed_chars is not None:
        text = ''.join(char for char in text
                      if char.isalnum() or char.isspace() or char in allowed_chars)

    return text.strip()


def sanitize_prompt_input(text: str, max_length: int = 1000) -> str:
    """
    LLM 프롬프트용 입력 정제 (더 엄격)

    Args:
        text: 입력 텍스트
        max_length: 최대 길이

    Returns:
        정제된 텍스트
    """
    # 기본 정제
    text = sanitize_input(text, max_length)

    # 따옴표 이스케이프
    text = text.replace('"', '\\"').replace("'", "\\'")

    # 잠재적 프롬프트 인젝션 패턴 제거
    injection_patterns = [
        r'ignore\s+previous\s+instructions',
        r'disregard\s+all\s+above',
        r'forget\s+everything',
        r'system\s*:',
        r'<\s*script\s*>',
    ]

    for pattern in injection_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)

    return text

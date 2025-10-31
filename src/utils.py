"""
RAG Security Analyzer - Utilities
유틸리티 함수 및 클래스
"""

import json
import logging
import os
from functools import lru_cache
from enum import Enum
from typing import Dict, List

logger = logging.getLogger(__name__)

# langdetect 가용성 체크
try:
    from langdetect import detect, LangDetectException
    LANGDETECT_AVAILABLE = True
except:
    LANGDETECT_AVAILABLE = False


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
        except:
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
        except:
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

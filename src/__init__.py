"""
RAG Security Analyzer v3.0
Self-RAG 기반 보안 분석 시스템
"""

__version__ = "3.0.0"
__author__ = "Aegis Security Team"

# Core models
from .models import (
    SecurityPolicy,
    AnalysisResult,
    SelfRAGResult,
    ScoreBreakdown,
    ExplanationData,
    RetrievalNeed,
    RelevanceScore,
    SupportLevel,
    UtilityScore,
    get_analysis_result,
    is_self_rag_result,
)

# Main analyzer
from .analyzer import AdvancedRAGAnalyzer

# Retrieval system
from .retriever import BM25, hybrid_search, get_embedding_model, encode_texts

# Memory and context
from .memory import ContextMemorySystem, RelationshipAnalyzer

# Explainability
from .explainer import ExplainableAI

# Self-RAG
from .self_rag import (
    SelfRAGEngine,
    EnhancedSecurityPatternDetector,
    SecurityPatternStrength,
)

# Utilities
from .utils import LanguageDetector

__all__ = [
    # Version
    "__version__",
    # Core models
    "SecurityPolicy",
    "AnalysisResult",
    "SelfRAGResult",
    "ScoreBreakdown",
    "ExplanationData",
    "RetrievalNeed",
    "RelevanceScore",
    "SupportLevel",
    "UtilityScore",
    "get_analysis_result",
    "is_self_rag_result",
    # Main analyzer
    "AdvancedRAGAnalyzer",
    # Retrieval
    "BM25",
    "hybrid_search",
    "get_embedding_model",
    "encode_texts",
    # Memory
    "ContextMemorySystem",
    "RelationshipAnalyzer",
    # Explainability
    "ExplainableAI",
    # Self-RAG
    "SelfRAGEngine",
    "EnhancedSecurityPatternDetector",
    "SecurityPatternStrength",
    # Utils
    "LanguageDetector",
]

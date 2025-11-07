"""
RAG Security Analyzer - Data Models
Data model definitions (SecurityPolicy, AnalysisResult, SelfRAGResult, etc.)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Tuple, Any, Union

from pydantic import BaseModel, Field, validator


# ============================================================
# Core Data Models
# ============================================================


@dataclass
class SecurityPolicy:
    """Security policy data model"""

    # Core fields (required)
    id: str
    title: str
    content: str
    severity: str

    # Basic fields (backward compatible)
    keywords: List[str] = field(default_factory=list)
    category: str = "general"
    compliance_standards: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)

    # Extended fields (v2.0) - all optional
    risk_score: int = 50
    priority: int = 3
    affected_departments: List[str] = field(default_factory=list)
    detection_patterns: Dict[str, Any] = field(default_factory=dict)
    related_policies: List[str] = field(default_factory=list)
    examples: List[Dict[str, str]] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)
    auto_response: Dict[str, Any] = field(default_factory=dict)
    notification_channels: List[str] = field(default_factory=list)
    last_updated: str = ""
    version: str = "1.0"

    def __post_init__(self):
        valid = ["critical", "high", "medium", "low"]
        if self.severity not in valid:
            raise ValueError(f"severity must be one of {valid}")

        if not 0 <= self.risk_score <= 100:
            raise ValueError(f"risk_score must be 0-100")

        if not 1 <= self.priority <= 5:
            raise ValueError(f"priority must be 1-5")

        if not self.notification_channels:
            self.notification_channels = ["email"]

        if not self.detection_patterns:
            self.detection_patterns = {
                "file_extensions": [],
                "suspicious_combinations": [],
                "data_volume_threshold_mb": 100,
            }

    def __hash__(self):
        return hash(self.id)

    def get_risk_level_from_score(self) -> str:
        """Convert risk_score to risk level"""
        if self.risk_score >= 90:
            return "CRITICAL"
        elif self.risk_score >= 70:
            return "HIGH"
        elif self.risk_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"

    def is_auto_response_enabled(self) -> bool:
        return self.auto_response.get("enabled", False)

    def get_auto_actions(self) -> List[str]:
        return self.auto_response.get("actions", [])


class ScoreBreakdown(BaseModel):
    """Score breakdown details"""

    keyword_matches: Dict[str, float] = Field(default_factory=dict)
    policy_similarities: Dict[str, float] = Field(default_factory=dict)
    semantic_scores: Dict[str, float] = Field(default_factory=dict)
    bm25_scores: Dict[str, float] = Field(default_factory=dict)
    total_base_score: float = 0.0
    final_score: float = 0.0


class ExplanationData(BaseModel):
    """XAI explanation data"""

    score_breakdown: ScoreBreakdown
    key_factors: List[Tuple[str, float, str, str]] = Field(default_factory=list)
    counterfactuals: List[str] = Field(default_factory=list)
    similar_cases: List[Tuple[float, str, str, float]] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Security analysis result"""

    text: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: str
    violations: List[str] = Field(default_factory=list)
    threats: List[str] = Field(default_factory=list)
    explanation: str
    related_policies: List[str] = Field(default_factory=list)
    policy_similarities: Dict[str, float] = Field(default_factory=dict)
    processing_time: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    confidence_score: float = Field(default=0.0, ge=0, le=1)
    remediation_suggestions: List[str] = Field(default_factory=list)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    detected_language: str = "unknown"
    explanation_data: Optional[ExplanationData] = None
    context_adjusted: bool = False

    @validator("risk_level")
    def validate_risk_level(cls, v):
        if v not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            raise ValueError(f"invalid risk_level: {v}")
        return v


# ============================================================
# Self-RAG Data Models
# ============================================================


class RetrievalNeed(Enum):
    """Retrieval necessity assessment"""

    REQUIRED = "required"
    OPTIONAL = "optional"
    NOT_NEEDED = "not_needed"


class RelevanceScore(Enum):
    """Retrieval result relevance"""

    HIGHLY_RELEVANT = "highly_relevant"
    RELEVANT = "relevant"
    PARTIALLY_RELEVANT = "partially_relevant"
    NOT_RELEVANT = "not_relevant"


class SupportLevel(Enum):
    """Answer evidence support level"""

    FULLY_SUPPORTED = "fully_supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    NO_SUPPORT = "no_support"


class UtilityScore(Enum):
    """Answer utility"""

    HIGHLY_USEFUL = 5
    USEFUL = 4
    MODERATELY_USEFUL = 3
    SLIGHTLY_USEFUL = 2
    NOT_USEFUL = 1


@dataclass
class SelfRAGResult:
    """Self-RAG analysis result"""

    original_result: AnalysisResult
    retrieval_need: RetrievalNeed
    relevance_scores: Dict[str, RelevanceScore]
    support_level: SupportLevel
    utility_score: UtilityScore
    reflection_notes: List[str]
    confidence_boost: float = 0.0


# ============================================================
# Helper Functions
# ============================================================


def get_analysis_result(result: Union[AnalysisResult, SelfRAGResult]) -> AnalysisResult:
    """
    Extract actual analysis result from SelfRAGResult or AnalysisResult
    """
    if isinstance(result, SelfRAGResult) or hasattr(result, "original_result"):
        return result.original_result
    return result


def is_self_rag_result(result) -> bool:
    """Check if result is SelfRAGResult"""
    return isinstance(result, SelfRAGResult) or hasattr(result, "original_result")

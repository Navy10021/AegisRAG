"""
RAG Security Analyzer - Explainable AI
Explainable AI (XAI) System
"""

import logging
from typing import List, Optional, Union

from .models import (
    AnalysisResult,
    ExplanationData,
    ScoreBreakdown,
    SelfRAGResult,
    get_analysis_result,
)
from .config import AnalyzerConfig, DEFAULT_ANALYZER_CONFIG

logger = logging.getLogger(__name__)


# ============================================================
# Explainable AI
# ============================================================


class ExplainableAI:
    """Explainable AI - Provides rationale for analysis results"""

    @staticmethod
    def generate_explanation(
        result: Union[AnalysisResult, SelfRAGResult],
        score_breakdown: ScoreBreakdown,
        similar_cases: Optional[List[Union[AnalysisResult, SelfRAGResult]]] = None,
        config: Optional[AnalyzerConfig] = None,
    ) -> ExplanationData:
        """Generate explanation data"""
        config = config or DEFAULT_ANALYZER_CONFIG
        # Handle SelfRAGResult case
        analysis = get_analysis_result(result)

        # Extract key factors
        key_factors = []
        for keyword, score in score_breakdown.keyword_matches.items():
            if score > config.EXPLANATION_MIN_SCORE:
                importance = (
                    "CRITICAL"
                    if score > config.EXPLANATION_FACTOR_THRESHOLD_HIGH
                    else (
                        "HIGH"
                        if score > config.EXPLANATION_FACTOR_THRESHOLD_MEDIUM
                        else "MEDIUM"
                    )
                )
                key_factors.append(
                    (keyword, score, importance, f"'{keyword}' keyword detected")
                )

        for policy_id, score in score_breakdown.policy_similarities.items():
            if score > config.EXPLANATION_FACTOR_THRESHOLD_LOW:
                key_factors.append(
                    (policy_id, score, "HIGH", f"Policy {policy_id} matched")
                )

        key_factors.sort(key=lambda x: x[1], reverse=True)

        # Counterfactual explanations
        counterfactuals = []
        if score_breakdown.keyword_matches:
            top_kw = max(score_breakdown.keyword_matches.items(), key=lambda x: x[1])
            counterfactuals.append(
                f"If '{top_kw[0]}' keyword was absent: {analysis.risk_score - top_kw[1]:.1f} points"
            )

        # Similar cases
        similar_case_data = []
        if similar_cases:
            for case in similar_cases[: config.MAX_SIMILAR_CASES]:
                case_analysis = get_analysis_result(case)
                sim = ExplainableAI._calc_similarity(analysis, case_analysis)
                similar_case_data.append(
                    (
                        sim,
                        case_analysis.timestamp[:19],
                        case_analysis.risk_level,
                        case_analysis.risk_score,
                    )
                )

        return ExplanationData(
            score_breakdown=score_breakdown,
            key_factors=key_factors,
            counterfactuals=counterfactuals,
            similar_cases=similar_case_data,
        )

    @staticmethod
    def _calc_similarity(
        case1: Union[AnalysisResult, SelfRAGResult],
        case2: Union[AnalysisResult, SelfRAGResult]
    ) -> float:
        """Calculate similarity between two cases"""
        # Convert both to AnalysisResult
        a1 = (
            get_analysis_result(case1)
            if not isinstance(case1, AnalysisResult)
            else case1
        )
        a2 = (
            get_analysis_result(case2)
            if not isinstance(case2, AnalysisResult)
            else case2
        )

        v1, v2 = set(a1.violations), set(a2.violations)
        # Prevent division by zero
        union_len = len(v1 | v2)
        viol_sim = len(v1 & v2) / max(union_len, 1)
        score_sim = 1.0 - abs(a1.risk_score - a2.risk_score) / 100.0

        # Use configurable weights from DEFAULT_ANALYZER_CONFIG
        from .config import DEFAULT_ANALYZER_CONFIG
        return (
            viol_sim * DEFAULT_ANALYZER_CONFIG.SIMILARITY_VIOLATION_WEIGHT
            + score_sim * DEFAULT_ANALYZER_CONFIG.SIMILARITY_SCORE_WEIGHT
        )

    @staticmethod
    def print_explanation(
        result: Union[AnalysisResult, SelfRAGResult],
        config: Optional[AnalyzerConfig] = None
    ) -> None:
        """Print explanation to console"""
        config = config or DEFAULT_ANALYZER_CONFIG
        analysis = get_analysis_result(result)

        if not analysis.explanation_data:
            return

        exp = analysis.explanation_data
        print("\n" + "=" * 80)
        print("🔍 Detailed Explanation")
        print("=" * 80)
        print(f"\n📊 Risk Score: {analysis.risk_score:.1f}/100")

        if exp.key_factors:
            print("\n🎯 Key Factors:")
            for i, (factor, score, imp, desc) in enumerate(exp.key_factors[:5], 1):
                emoji = "🔴" if imp == "CRITICAL" else "🟠" if imp == "HIGH" else "🟡"
                bar = "█" * int(score / config.VISUALIZATION_BAR_SCALE)
                print(f"  {i}. {emoji} {factor}: +{score:.1f} {bar}")
                print(f"     {desc}")

        if exp.counterfactuals:
            print("\n💭 What-If:")
            for cf in exp.counterfactuals:
                print(f"  • {cf}")

        print("=" * 80 + "\n")

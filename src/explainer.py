"""
RAG Security Analyzer - Explainable AI
Explainable AI (XAI) System
"""

import logging
from typing import List, Optional

from .models import (
    AnalysisResult, SelfRAGResult, 
    ExplanationData, ScoreBreakdown,
    get_analysis_result
)

logger = logging.getLogger(__name__)


# ============================================================
# Explainable AI
# ============================================================

class ExplainableAI:
    """Explainable AI - Provides rationale for analysis results"""
    
    @staticmethod
    def generate_explanation(
        result,
        score_breakdown: ScoreBreakdown,
        similar_cases: Optional[List] = None
    ) -> ExplanationData:
        """Generate explanation data"""
        # Handle SelfRAGResult case
        analysis = get_analysis_result(result)

        # Extract key factors
        key_factors = []
        for keyword, score in score_breakdown.keyword_matches.items():
            if score > 5:
                importance = 'CRITICAL' if score > 30 else 'HIGH' if score > 15 else 'MEDIUM'
                key_factors.append((keyword, score, importance, f"'{keyword}' keyword detected"))

        for policy_id, score in score_breakdown.policy_similarities.items():
            if score > 10:
                key_factors.append((policy_id, score, 'HIGH', f"Policy {policy_id} matched"))

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
            for case in similar_cases[:3]:
                case_analysis = get_analysis_result(case)
                sim = ExplainableAI._calc_similarity(analysis, case_analysis)
                similar_case_data.append((
                    sim,
                    case_analysis.timestamp[:19],
                    case_analysis.risk_level,
                    case_analysis.risk_score
                ))

        return ExplanationData(
            score_breakdown=score_breakdown,
            key_factors=key_factors,
            counterfactuals=counterfactuals,
            similar_cases=similar_case_data
        )
    
    @staticmethod
    def _calc_similarity(case1, case2) -> float:
        """Calculate similarity between two cases"""
        # Convert both to AnalysisResult
        a1 = get_analysis_result(case1) if not isinstance(case1, AnalysisResult) else case1
        a2 = get_analysis_result(case2) if not isinstance(case2, AnalysisResult) else case2
        
        v1, v2 = set(a1.violations), set(a2.violations)
        viol_sim = len(v1 & v2) / max(len(v1 | v2), 1)
        score_sim = 1.0 - abs(a1.risk_score - a2.risk_score) / 100
        return viol_sim * 0.6 + score_sim * 0.4
    
    @staticmethod
    def print_explanation(result):
        """Print explanation to console"""
        analysis = get_analysis_result(result)
        
        if not analysis.explanation_data:
            return
        
        exp = analysis.explanation_data
        print("\n" + "="*80)
        print("🔍 Detailed Explanation")
        print("="*80)
        print(f"\n📊 Risk Score: {analysis.risk_score:.1f}/100")
        
        if exp.key_factors:
            print("\n🎯 Key Factors:")
            for i, (factor, score, imp, desc) in enumerate(exp.key_factors[:5], 1):
                emoji = "🔴" if imp == "CRITICAL" else "🟠" if imp == "HIGH" else "🟡"
                bar = "█" * int(score / 5)
                print(f"  {i}. {emoji} {factor}: +{score:.1f} {bar}")
                print(f"     {desc}")
        
        if exp.counterfactuals:
            print(f"\n💭 What-If:")
            for cf in exp.counterfactuals:
                print(f"  • {cf}")
        
        print("="*80 + "\n")

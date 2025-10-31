"""
RAG Security Analyzer - Explainable AI
설명 가능한 AI (XAI) 시스템
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
    """설명 가능한 AI - 분석 결과의 근거 제공"""
    
    @staticmethod
    def generate_explanation(
        result,
        score_breakdown: ScoreBreakdown,
        similar_cases: Optional[List] = None
    ) -> ExplanationData:
        """설명 데이터 생성"""
        # result가 SelfRAGResult인 경우 처리
        analysis = get_analysis_result(result)
        
        # 주요 요인 추출
        key_factors = []
        for keyword, score in score_breakdown.keyword_matches.items():
            if score > 5:
                importance = 'CRITICAL' if score > 30 else 'HIGH' if score > 15 else 'MEDIUM'
                key_factors.append((keyword, score, importance, f"'{keyword}' 키워드 감지"))
        
        for policy_id, score in score_breakdown.policy_similarities.items():
            if score > 10:
                key_factors.append((policy_id, score, 'HIGH', f"정책 {policy_id} 매칭"))
        
        key_factors.sort(key=lambda x: x[1], reverse=True)
        
        # 반사실적 설명 (Counterfactual)
        counterfactuals = []
        if score_breakdown.keyword_matches:
            top_kw = max(score_breakdown.keyword_matches.items(), key=lambda x: x[1])
            counterfactuals.append(
                f"만약 '{top_kw[0]}' 키워드가 없었다면: {analysis.risk_score - top_kw[1]:.1f}점"
            )
        
        # 유사 사례
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
        """두 케이스 간의 유사도 계산"""
        # 둘 다 AnalysisResult로 변환
        a1 = get_analysis_result(case1) if not isinstance(case1, AnalysisResult) else case1
        a2 = get_analysis_result(case2) if not isinstance(case2, AnalysisResult) else case2
        
        v1, v2 = set(a1.violations), set(a2.violations)
        viol_sim = len(v1 & v2) / max(len(v1 | v2), 1)
        score_sim = 1.0 - abs(a1.risk_score - a2.risk_score) / 100
        return viol_sim * 0.6 + score_sim * 0.4
    
    @staticmethod
    def print_explanation(result):
        """설명을 콘솔에 출력"""
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

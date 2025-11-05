"""
Unit tests for Explainable AI (XAI) System
"""

import pytest
from src.explainer import ExplainableAI
from src.models import (
    AnalysisResult,
    ScoreBreakdown,
    ExplanationData
)


class TestExplainableAI:
    """Test suite for ExplainableAI"""

    @pytest.fixture
    def sample_result(self):
        """Create a sample analysis result"""
        return AnalysisResult(
            text="password leak detected",
            risk_score=85.0,
            risk_level="CRITICAL",
            violations=["P001", "P002"],
            threats=["Password exposure", "Credential theft"],
            explanation="Critical security violation detected",
            policy_similarities={"P001": 0.95, "P002": 0.87}
        )

    @pytest.fixture
    def score_breakdown(self):
        """Create a sample score breakdown"""
        breakdown = ScoreBreakdown()
        breakdown.keyword_matches = {
            "password": 30.0,
            "leak": 25.0,
            "detected": 10.0
        }
        breakdown.policy_similarities = {
            "P001": 28.5,
            "P002": 17.4
        }
        breakdown.final_score = 85.0
        return breakdown

    def test_generate_explanation_basic(self, sample_result, score_breakdown):
        """Test basic explanation generation"""
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown,
            similar_cases=None
        )

        assert isinstance(explanation, ExplanationData)
        assert explanation.score_breakdown == score_breakdown
        assert len(explanation.key_factors) > 0
        assert len(explanation.counterfactuals) > 0

    def test_key_factors_extraction(self, sample_result, score_breakdown):
        """Test key factors extraction"""
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown
        )

        # Check key factors
        assert len(explanation.key_factors) > 0
        for factor, score, importance, desc in explanation.key_factors:
            assert isinstance(factor, str)
            assert isinstance(score, float)
            assert importance in ['CRITICAL', 'HIGH', 'MEDIUM']
            assert isinstance(desc, str)

    def test_key_factors_sorting(self, sample_result, score_breakdown):
        """Test that key factors are sorted by score"""
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown
        )

        # Check if sorted in descending order
        scores = [score for _, score, _, _ in explanation.key_factors]
        assert scores == sorted(scores, reverse=True)

    def test_counterfactual_generation(self, sample_result, score_breakdown):
        """Test counterfactual explanation generation"""
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown
        )

        assert len(explanation.counterfactuals) > 0
        # Check counterfactual format
        for cf in explanation.counterfactuals:
            assert isinstance(cf, str)
            assert "만약" in cf or "점" in cf  # Korean format check

    def test_similar_cases_integration(self, sample_result, score_breakdown):
        """Test similar cases integration"""
        # Create sample similar cases
        similar_case1 = AnalysisResult(
            text="credential theft",
            risk_score=80.0,
            risk_level="HIGH",
            violations=["P001"],
            threats=["Credential theft"],
            explanation="Test"
        )
        similar_case2 = AnalysisResult(
            text="password exposure",
            risk_score=90.0,
            risk_level="CRITICAL",
            violations=["P001", "P002"],
            threats=["Password exposure"],
            explanation="Test"
        )

        similar_cases = [similar_case1, similar_case2]
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown,
            similar_cases=similar_cases
        )

        assert len(explanation.similar_cases) > 0
        # Check similar case format
        for sim, timestamp, level, score in explanation.similar_cases:
            assert isinstance(sim, float)
            assert 0.0 <= sim <= 1.0
            assert isinstance(timestamp, str)
            assert level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            assert isinstance(score, float)

    def test_calc_similarity_identical(self):
        """Test similarity calculation for identical cases"""
        result1 = AnalysisResult(
            text="test",
            risk_score=50.0,
            risk_level="MEDIUM",
            violations=["P001", "P002"],
            threats=["Test"],
            explanation="Test"
        )
        result2 = AnalysisResult(
            text="test",
            risk_score=50.0,
            risk_level="MEDIUM",
            violations=["P001", "P002"],
            threats=["Test"],
            explanation="Test"
        )

        similarity = ExplainableAI._calc_similarity(result1, result2)
        assert similarity == 1.0

    def test_calc_similarity_different(self):
        """Test similarity calculation for different cases"""
        result1 = AnalysisResult(
            text="test1",
            risk_score=20.0,
            risk_level="LOW",
            violations=["P001"],
            threats=["Test1"],
            explanation="Test"
        )
        result2 = AnalysisResult(
            text="test2",
            risk_score=80.0,
            risk_level="HIGH",
            violations=["P002", "P003"],
            threats=["Test2"],
            explanation="Test"
        )

        similarity = ExplainableAI._calc_similarity(result1, result2)
        assert 0.0 <= similarity < 1.0

    def test_calc_similarity_no_violations(self):
        """Test similarity calculation with no violations"""
        result1 = AnalysisResult(
            text="test1",
            risk_score=10.0,
            risk_level="LOW",
            violations=[],
            threats=[],
            explanation="Test"
        )
        result2 = AnalysisResult(
            text="test2",
            risk_score=15.0,
            risk_level="LOW",
            violations=[],
            threats=[],
            explanation="Test"
        )

        similarity = ExplainableAI._calc_similarity(result1, result2)
        assert 0.0 <= similarity <= 1.0

    def test_print_explanation_no_data(self, sample_result, capsys):
        """Test print_explanation with no explanation data"""
        sample_result.explanation_data = None
        ExplainableAI.print_explanation(sample_result)
        captured = capsys.readouterr()
        # Should not crash and should not print anything
        assert True

    def test_print_explanation_with_data(self, sample_result, score_breakdown, capsys):
        """Test print_explanation with data"""
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown
        )
        sample_result.explanation_data = explanation

        ExplainableAI.print_explanation(sample_result)
        captured = capsys.readouterr()

        # Check if output contains expected sections
        assert "Detailed Explanation" in captured.out
        assert "Risk Score" in captured.out

    def test_empty_breakdown(self, sample_result):
        """Test with empty score breakdown"""
        empty_breakdown = ScoreBreakdown()
        explanation = ExplainableAI.generate_explanation(
            sample_result,
            empty_breakdown
        )

        assert isinstance(explanation, ExplanationData)
        assert explanation.score_breakdown == empty_breakdown
        assert len(explanation.key_factors) == 0
        assert len(explanation.counterfactuals) == 0

    def test_high_score_keywords_only(self, sample_result):
        """Test explanation with only high-score keywords"""
        breakdown = ScoreBreakdown()
        breakdown.keyword_matches = {
            "critical": 40.0,
            "breach": 35.0
        }
        breakdown.final_score = 75.0

        explanation = ExplainableAI.generate_explanation(
            sample_result,
            breakdown
        )

        # Should only include keywords with score > 5
        assert all(score > 5 for _, score, _, _ in explanation.key_factors)

    def test_policy_similarity_in_factors(self, sample_result):
        """Test policy similarities appear in key factors"""
        breakdown = ScoreBreakdown()
        breakdown.policy_similarities = {
            "P001": 25.0,
            "P002": 15.0,
            "P003": 5.0  # Should be filtered out (≤ 10)
        }
        breakdown.final_score = 45.0

        explanation = ExplainableAI.generate_explanation(
            sample_result,
            breakdown
        )

        # Check that only policies with score > 10 are included
        policy_factors = [f for f, _, _, _ in explanation.key_factors if f.startswith('P')]
        assert "P001" in policy_factors or "P002" in policy_factors
        assert "P003" not in policy_factors

    def test_similar_cases_limit(self, sample_result, score_breakdown):
        """Test that similar cases are limited to 3"""
        # Create many similar cases
        similar_cases = []
        for i in range(10):
            case = AnalysisResult(
                text=f"case {i}",
                risk_score=float(50 + i),
                risk_level="MEDIUM",
                violations=["P001"],
                threats=[f"Threat {i}"],
                explanation="Test"
            )
            similar_cases.append(case)

        explanation = ExplainableAI.generate_explanation(
            sample_result,
            score_breakdown,
            similar_cases=similar_cases
        )

        # Should limit to 3 cases
        assert len(explanation.similar_cases) <= 3

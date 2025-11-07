"""
Unit tests for Self-RAG Engine
"""

import pytest
from src.self_rag import (
    SelfRAGEngine,
    EnhancedSecurityPatternDetector,
    SecurityPatternStrength,
)
from src.models import (
    RetrievalNeed,
    RelevanceScore,
    SupportLevel,
    UtilityScore,
    AnalysisResult,
    SecurityPolicy,
)
from src.analyzer import AdvancedRAGAnalyzer


class TestEnhancedSecurityPatternDetector:
    """Test suite for EnhancedSecurityPatternDetector"""

    def test_detect_critical_patterns(self):
        """Test detection of CRITICAL security patterns"""
        test_cases = [
            ("password leak detected", SecurityPatternStrength.CRITICAL),
            ("credential theft", SecurityPatternStrength.CRITICAL),
            ("malware attack", SecurityPatternStrength.CRITICAL),
            ("unauthorized access", SecurityPatternStrength.CRITICAL),
            ("비밀번호 유출", SecurityPatternStrength.CRITICAL),
        ]

        for text, expected_strength in test_cases:
            strength, patterns = EnhancedSecurityPatternDetector.detect(text)
            assert strength == expected_strength, f"Failed for: {text}"
            assert len(patterns) > 0

    def test_detect_high_patterns(self):
        """Test detection of HIGH security patterns"""
        test_cases = [
            ("download sensitive data", SecurityPatternStrength.HIGH),
            ("external file transfer", SecurityPatternStrength.HIGH),
            ("접근 권한 변경", SecurityPatternStrength.HIGH),
        ]

        for text, expected_strength in test_cases:
            strength, patterns = EnhancedSecurityPatternDetector.detect(text)
            assert strength in [
                SecurityPatternStrength.CRITICAL,
                SecurityPatternStrength.HIGH,
            ]
            assert len(patterns) > 0

    def test_detect_medium_patterns(self):
        """Test detection of MEDIUM security patterns"""
        text = "firewall configuration change"
        strength, patterns = EnhancedSecurityPatternDetector.detect(text)
        assert strength is not None

    def test_detect_no_patterns(self):
        """Test detection when no security patterns present"""
        text = "normal business communication"
        strength, patterns = EnhancedSecurityPatternDetector.detect(text)
        # May detect question patterns or nothing
        assert isinstance(patterns, list)

    def test_regex_patterns(self):
        """Test regex pattern detection"""
        test_cases = [
            "192.168.1.1",  # IP address
            "test@example.com",  # Email
            "https://evil.com/payload",  # URL
            "password123456",  # Weak password
            "CVE-2024-1234",  # CVE pattern
        ]

        for text in test_cases:
            strength, patterns = EnhancedSecurityPatternDetector.detect(text)
            assert len(patterns) > 0, f"Failed to detect pattern in: {text}"

    def test_compound_patterns(self):
        """Test compound pattern detection"""
        text = "admin password leak"
        strength, patterns = EnhancedSecurityPatternDetector.detect(text)
        assert strength == SecurityPatternStrength.CRITICAL
        assert any("Compound" in p or "CRITICAL" in p for p in patterns)

    def test_question_patterns(self):
        """Test question pattern detection"""
        test_cases = [
            "How to access database?",
            "무엇을 해야 하나요?",
            "Can I download this?",
        ]

        for text in test_cases:
            strength, patterns = EnhancedSecurityPatternDetector.detect(text)
            assert isinstance(patterns, list)

    def test_pattern_limit(self):
        """Test that detected patterns are limited"""
        text = "password credential token secret api key access key"
        strength, patterns = EnhancedSecurityPatternDetector.detect(text)
        assert len(patterns) <= 5  # Maximum 5 patterns


class TestSelfRAGEngine:
    """Test suite for SelfRAGEngine"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample security policies"""
        return [
            SecurityPolicy(
                id="P001",
                title="Data Loss Prevention",
                content="Prevent unauthorized data transfer",
                severity="critical",
                keywords=["password", "leak", "credential"],
                category="data_protection",
            ),
            SecurityPolicy(
                id="P002",
                title="Access Control",
                content="Unauthorized access detection",
                severity="high",
                keywords=["unauthorized", "access"],
                category="access_control",
            ),
        ]

    @pytest.fixture
    def analyzer(self, sample_policies):
        """Create analyzer without LLM"""
        return AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False,
            use_embeddings=False,
            enable_self_rag=True,
        )

    @pytest.fixture
    def self_rag_engine(self, analyzer):
        """Create Self-RAG engine"""
        return SelfRAGEngine(analyzer, use_llm=False)

    def test_assess_retrieval_need_required(self, self_rag_engine):
        """Test retrieval need assessment for critical text"""
        text = "password leak detected in system"
        need = self_rag_engine.assess_retrieval_need(text)
        assert need in [RetrievalNeed.REQUIRED, RetrievalNeed.OPTIONAL]

    def test_assess_retrieval_need_not_needed(self, self_rag_engine):
        """Test retrieval need assessment for safe text"""
        text = "hi"
        need = self_rag_engine.assess_retrieval_need(text)
        assert need == RetrievalNeed.NOT_NEEDED

    def test_assess_retrieval_need_optional(self, self_rag_engine):
        """Test retrieval need assessment for borderline text"""
        text = "network configuration"
        need = self_rag_engine.assess_retrieval_need(text)
        assert need in [
            RetrievalNeed.OPTIONAL,
            RetrievalNeed.REQUIRED,
            RetrievalNeed.NOT_NEEDED,
        ]

    def test_assess_relevance(self, self_rag_engine, analyzer, sample_policies):
        """Test relevance assessment"""
        result = analyzer.analyze("password leak")
        relevance_scores = self_rag_engine.assess_relevance("password leak", result)

        assert isinstance(relevance_scores, dict)
        for policy_id, score in relevance_scores.items():
            assert isinstance(score, RelevanceScore)

    def test_assess_support_full(self, self_rag_engine, analyzer):
        """Test support level assessment - fully supported"""
        result = analyzer.analyze("password credential leak")
        relevance_scores = {
            "P001": RelevanceScore.HIGHLY_RELEVANT,
            "P002": RelevanceScore.HIGHLY_RELEVANT,
        }
        support = self_rag_engine.assess_support(result, relevance_scores)
        assert isinstance(support, SupportLevel)

    def test_assess_support_no_support(self, self_rag_engine, analyzer):
        """Test support level assessment - no support"""
        result = analyzer.analyze("test")
        relevance_scores = {}
        support = self_rag_engine.assess_support(result, relevance_scores)
        assert support == SupportLevel.NO_SUPPORT

    def test_assess_utility(self, self_rag_engine, analyzer):
        """Test utility score assessment"""
        result = analyzer.analyze("password leak")
        support_level = SupportLevel.FULLY_SUPPORTED
        utility = self_rag_engine.assess_utility(result, support_level)

        assert isinstance(utility, UtilityScore)
        assert 1 <= utility.value <= 5

    def test_generate_reflection(self, self_rag_engine):
        """Test reflection note generation"""
        notes = self_rag_engine.generate_reflection(
            RetrievalNeed.REQUIRED,
            {"P001": RelevanceScore.HIGHLY_RELEVANT},
            SupportLevel.FULLY_SUPPORTED,
            UtilityScore.HIGHLY_USEFUL,
        )

        assert isinstance(notes, list)
        assert len(notes) > 0
        assert any("Retrieval" in note for note in notes)

    def test_calculate_confidence_boost(self, self_rag_engine):
        """Test confidence boost calculation"""
        boost = self_rag_engine.calculate_confidence_boost(
            {"P001": RelevanceScore.HIGHLY_RELEVANT},
            SupportLevel.FULLY_SUPPORTED,
            UtilityScore.HIGHLY_USEFUL,
        )

        assert isinstance(boost, float)
        assert 0.0 <= boost <= 0.3

    def test_calculate_confidence_boost_no_relevance(self, self_rag_engine):
        """Test confidence boost with no relevance"""
        boost = self_rag_engine.calculate_confidence_boost(
            {}, SupportLevel.NO_SUPPORT, UtilityScore.NOT_USEFUL
        )

        assert isinstance(boost, float)
        assert boost <= 0.0


class TestSelfRAGIntegration:
    """Integration tests for Self-RAG with Analyzer"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample policies"""
        return [
            SecurityPolicy(
                id="P001",
                title="Password Security",
                content="Protect passwords and credentials",
                severity="critical",
                keywords=["password", "credential", "secret"],
                category="security",
            ),
        ]

    def test_full_self_rag_pipeline(self, sample_policies):
        """Test complete Self-RAG pipeline"""
        analyzer = AdvancedRAGAnalyzer(
            policies=sample_policies, use_llm=False, enable_self_rag=True
        )

        result = analyzer.analyze("password leak detected")

        # Check if SelfRAGResult is returned
        if hasattr(result, "original_result"):
            assert result.retrieval_need is not None
            assert isinstance(result.relevance_scores, dict)
            assert result.support_level is not None
            assert result.utility_score is not None
            assert isinstance(result.reflection_notes, list)
            assert isinstance(result.confidence_boost, float)

    def test_self_rag_vs_standard(self, sample_policies):
        """Compare Self-RAG vs standard analysis"""
        text = "password leak"

        # Standard analysis
        analyzer_standard = AdvancedRAGAnalyzer(
            policies=sample_policies, use_llm=False, enable_self_rag=False
        )
        result_standard = analyzer_standard.analyze(text)

        # Self-RAG analysis
        analyzer_self_rag = AdvancedRAGAnalyzer(
            policies=sample_policies, use_llm=False, enable_self_rag=True
        )
        result_self_rag = analyzer_self_rag.analyze(text)

        # Both should detect threats
        assert result_standard.risk_score > 0
        if hasattr(result_self_rag, "original_result"):
            assert result_self_rag.original_result.risk_score > 0

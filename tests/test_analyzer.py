"""
Unit tests for AdvancedRAGAnalyzer
"""

import pytest
from src.analyzer import AdvancedRAGAnalyzer
from src.models import SecurityPolicy, AnalysisResult
from src.config import AnalyzerConfig


class TestAdvancedRAGAnalyzer:
    """Test suite for AdvancedRAGAnalyzer"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample security policies for testing"""
        return [
            SecurityPolicy(
                id="P001",
                title="Data Loss Prevention",
                content="Prevent unauthorized data transfer",
                severity="critical",
                keywords=["password", "leak", "credential", "secret"],
                category="data_protection"
            ),
            SecurityPolicy(
                id="P002",
                title="Access Control",
                content="Unauthorized access detection",
                severity="high",
                keywords=["unauthorized", "access", "login", "breach"],
                category="access_control"
            ),
            SecurityPolicy(
                id="P003",
                title="Malware Detection",
                content="Detect malicious software",
                severity="critical",
                keywords=["virus", "malware", "trojan", "ransomware"],
                category="malware"
            )
        ]

    @pytest.fixture
    def analyzer_no_llm(self, sample_policies):
        """Create analyzer without LLM (rule-based only)"""
        return AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False,
            use_embeddings=False,
            enable_self_rag=False
        )

    def test_analyzer_initialization(self, sample_policies):
        """Test analyzer initialization"""
        analyzer = AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False
        )
        assert analyzer.policies == sample_policies
        assert analyzer.config is not None
        assert analyzer.stats['total'] == 0

    def test_analyze_critical_threat(self, analyzer_no_llm):
        """Test analysis of critical threat"""
        result = analyzer_no_llm.analyze("password leak detected")

        assert isinstance(result, AnalysisResult)
        assert result.risk_score > 0
        assert result.risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        assert len(result.threats) > 0

    def test_analyze_low_risk_text(self, analyzer_no_llm):
        """Test analysis of low-risk text"""
        result = analyzer_no_llm.analyze("hello world")

        assert isinstance(result, AnalysisResult)
        assert result.risk_level == 'LOW'

    def test_analyze_empty_text(self, analyzer_no_llm):
        """Test analysis with empty text"""
        result = analyzer_no_llm.analyze("")

        # Should handle gracefully
        assert isinstance(result, AnalysisResult)

    def test_analyze_with_user_id(self, analyzer_no_llm):
        """Test analysis with user tracking"""
        result = analyzer_no_llm.analyze(
            "unauthorized access attempt",
            user_id="user123"
        )

        assert result.user_id == "user123"

    def test_batch_analysis(self, analyzer_no_llm):
        """Test batch analysis"""
        texts = [
            "password leak",
            "malware detected",
            "normal activity"
        ]

        results = analyzer_no_llm.analyze_batch(texts)

        assert len(results) == 3
        assert all(isinstance(r, AnalysisResult) for r in results)

    def test_config_integration(self, sample_policies):
        """Test custom configuration"""
        custom_config = AnalyzerConfig()
        custom_config.RISK_CRITICAL_THRESHOLD = 70

        analyzer = AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False,
            config=custom_config
        )

        assert analyzer.config.RISK_CRITICAL_THRESHOLD == 70

    def test_stats_tracking(self, analyzer_no_llm):
        """Test statistics tracking"""
        initial_total = analyzer_no_llm.stats['total']

        analyzer_no_llm.analyze("test text")

        assert analyzer_no_llm.stats['total'] == initial_total + 1
        assert analyzer_no_llm.stats['rule'] > 0

    def test_policy_matching(self, analyzer_no_llm):
        """Test policy violation detection"""
        result = analyzer_no_llm.analyze("password credential leak")

        # Should match P001 (Data Loss Prevention)
        assert 'P001' in result.violations or len(result.threats) > 0

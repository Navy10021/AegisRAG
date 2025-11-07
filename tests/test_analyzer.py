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
                category="data_protection",
            ),
            SecurityPolicy(
                id="P002",
                title="Access Control",
                content="Unauthorized access detection",
                severity="high",
                keywords=["unauthorized", "access", "login", "breach"],
                category="access_control",
            ),
            SecurityPolicy(
                id="P003",
                title="Malware Detection",
                content="Detect malicious software",
                severity="critical",
                keywords=["virus", "malware", "trojan", "ransomware"],
                category="malware",
            ),
        ]

    @pytest.fixture
    def analyzer_no_llm(self, sample_policies):
        """Create analyzer without LLM (rule-based only)"""
        return AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False,
            use_embeddings=False,
            enable_self_rag=False,
        )

    def test_analyzer_initialization(self, sample_policies):
        """Test analyzer initialization"""
        analyzer = AdvancedRAGAnalyzer(policies=sample_policies, use_llm=False)
        assert analyzer.policies == sample_policies
        assert analyzer.config is not None
        assert analyzer.stats["total"] == 0

    def test_analyze_critical_threat(self, analyzer_no_llm):
        """Test analysis of critical threat"""
        result = analyzer_no_llm.analyze("password leak detected")

        assert isinstance(result, AnalysisResult)
        assert result.risk_score > 0
        assert result.risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert len(result.threats) > 0

    def test_analyze_low_risk_text(self, analyzer_no_llm):
        """Test analysis of low-risk text"""
        result = analyzer_no_llm.analyze("hello world")

        assert isinstance(result, AnalysisResult)
        assert result.risk_level == "LOW"

    def test_analyze_empty_text(self, analyzer_no_llm):
        """Test analysis with empty text"""
        # Empty text should now raise ValueError after Phase 3 input validation
        with pytest.raises(ValueError, match="empty"):
            analyzer_no_llm.analyze("")

    def test_analyze_with_user_id(self, analyzer_no_llm):
        """Test analysis with user tracking"""
        result = analyzer_no_llm.analyze(
            "unauthorized access attempt", user_id="user123"
        )

        assert result.user_id == "user123"

    def test_batch_analysis(self, analyzer_no_llm):
        """Test batch analysis"""
        texts = ["password leak", "malware detected", "normal activity"]

        results = analyzer_no_llm.analyze_batch(texts)

        assert len(results) == 3
        assert all(isinstance(r, AnalysisResult) for r in results)

    def test_config_integration(self, sample_policies):
        """Test custom configuration"""
        custom_config = AnalyzerConfig()
        custom_config.RISK_CRITICAL_THRESHOLD = 70

        analyzer = AdvancedRAGAnalyzer(
            policies=sample_policies, use_llm=False, config=custom_config
        )

        assert analyzer.config.RISK_CRITICAL_THRESHOLD == 70

    def test_stats_tracking(self, analyzer_no_llm):
        """Test statistics tracking"""
        initial_total = analyzer_no_llm.stats["total"]

        analyzer_no_llm.analyze("test text")

        assert analyzer_no_llm.stats["total"] == initial_total + 1
        assert analyzer_no_llm.stats["rule"] > 0

    def test_policy_matching(self, analyzer_no_llm):
        """Test policy violation detection"""
        result = analyzer_no_llm.analyze("password credential leak")

        # Should match P001 (Data Loss Prevention)
        assert "P001" in result.violations or len(result.threats) > 0


class TestAnalyzerEdgeCases:
    """Edge case tests for AdvancedRAGAnalyzer"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample security policies"""
        return [
            SecurityPolicy(
                id="P001",
                title="Test Policy",
                content="Test policy content",
                severity="medium",
                keywords=["test", "security"],
            )
        ]

    @pytest.fixture
    def analyzer(self, sample_policies):
        """Create analyzer without LLM"""
        return AdvancedRAGAnalyzer(
            policies=sample_policies,
            use_llm=False,
            use_embeddings=False,
            enable_self_rag=False,
        )

    def test_empty_string_input(self, analyzer):
        """Test with empty string"""
        with pytest.raises(ValueError, match="empty"):
            analyzer.analyze("")

    def test_whitespace_only_input(self, analyzer):
        """Test with whitespace only"""
        with pytest.raises(ValueError, match="empty"):
            analyzer.analyze("   \n\t  ")

    def test_very_long_input(self, analyzer):
        """Test with very long input (>10000 chars)"""
        long_text = "test " * 3000  # ~15000 chars
        result = analyzer.analyze(long_text)

        # Should be truncated to MAX_INPUT_LENGTH
        assert isinstance(result, AnalysisResult)

    def test_null_bytes_in_input(self, analyzer):
        """Test input with NULL bytes"""
        text = "test\x00malicious\x00code"
        result = analyzer.analyze(text)

        # NULL bytes should be sanitized
        assert isinstance(result, AnalysisResult)
        assert "\x00" not in result.text

    def test_control_characters_input(self, analyzer):
        """Test input with control characters"""
        text = "test\x01\x02\x03security"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)
        # Control chars should be removed
        assert "\x01" not in result.text

    def test_unicode_input(self, analyzer):
        """Test with Unicode characters"""
        text = "Test 안전 🔒 security 世界"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)

    def test_special_characters_input(self, analyzer):
        """Test with special characters"""
        text = "<script>alert('test')</script> @#$%^&*()"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)

    def test_batch_empty_list(self, analyzer):
        """Test batch analysis with empty list"""
        with pytest.raises(ValueError, match="at least one"):
            analyzer.analyze_batch([])

    def test_batch_with_empty_string(self, analyzer):
        """Test batch with one empty string"""
        texts = ["valid text", "", "another valid"]

        # Should raise on the empty string
        with pytest.raises(ValueError):
            analyzer.analyze_batch(texts)

    def test_batch_all_valid(self, analyzer):
        """Test batch with all valid texts"""
        texts = ["test1", "test2", "test3"]
        results = analyzer.analyze_batch(texts)

        assert len(results) == 3
        assert all(isinstance(r, AnalysisResult) for r in results)

    def test_user_id_tracking(self, analyzer):
        """Test user ID is properly tracked"""
        result = analyzer.analyze("test", user_id="user123")

        assert result.user_id == "user123"

    def test_session_id_tracking(self, analyzer):
        """Test session ID is properly tracked"""
        result = analyzer.analyze("test", session_id="sess456")

        assert result.session_id == "sess456"

    def test_none_text_input(self, analyzer):
        """Test None as input (should be sanitized to empty)"""
        with pytest.raises(ValueError):
            analyzer.analyze(None)

    def test_concurrent_analysis_simulation(self, analyzer):
        """Test multiple rapid successive analyses"""
        results = []
        for i in range(10):
            result = analyzer.analyze(f"test security event {i}")
            results.append(result)

        assert len(results) == 10
        assert all(isinstance(r, AnalysisResult) for r in results)
        # Stats should track all analyses
        assert analyzer.stats["total"] >= 10

    def test_max_length_boundary(self, analyzer):
        """Test input at exact MAX_INPUT_LENGTH"""
        text = "A" * 10000  # Exactly max length
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)

    def test_repeated_analysis_same_text(self, analyzer):
        """Test analyzing same text multiple times"""
        text = "test security"
        results = [analyzer.analyze(text) for _ in range(5)]

        assert len(results) == 5
        # All should have similar risk scores (caching may apply)
        scores = [r.risk_score for r in results]
        assert len(set(scores)) <= 2  # Allow for minor variations

    def test_batch_with_user_ids(self, analyzer):
        """Test batch analysis with user IDs"""
        texts = ["test1", "test2"]
        user_ids = ["user1", "user2"]

        results = analyzer.analyze_batch(texts, user_ids=user_ids)

        assert results[0].user_id == "user1"
        assert results[1].user_id == "user2"

    def test_batch_user_ids_length_mismatch(self, analyzer):
        """Test batch when user_ids list is shorter than texts"""
        texts = ["test1", "test2", "test3"]
        user_ids = ["user1"]  # Only 1 user_id for 3 texts

        results = analyzer.analyze_batch(texts, user_ids=user_ids)

        # Should handle gracefully by zipping (only 1 result)
        assert len(results) == 1

    def test_malformed_input_types(self, analyzer):
        """Test with unexpected input types"""
        # Integer input - should raise TypeError from sanitize_input
        with pytest.raises(TypeError):
            analyzer.analyze(12345)

        # List input - should raise TypeError from sanitize_input
        with pytest.raises(TypeError):
            analyzer.analyze(["test"])

    def test_extremely_long_word(self, analyzer):
        """Test with extremely long single word"""
        long_word = "A" * 5000
        result = analyzer.analyze(long_word)

        assert isinstance(result, AnalysisResult)

    def test_mixed_language_input(self, analyzer):
        """Test with mixed language text"""
        text = "Test security 안전 セキュリティ 安全"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)

    def test_newlines_and_tabs(self, analyzer):
        """Test input with newlines and tabs"""
        text = "line1\nline2\tword3"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)

    def test_xss_pattern_in_input(self, analyzer):
        """Test XSS-like patterns in input"""
        text = "<script>alert(document.cookie)</script>"
        result = analyzer.analyze(text)

        assert isinstance(result, AnalysisResult)
        # Should be sanitized
        assert result.text is not None

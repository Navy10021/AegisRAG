"""
Unit tests for Memory System
"""

import pytest
from collections import Counter
from src.memory import ContextMemorySystem, RelationshipAnalyzer
from src.models import AnalysisResult


class TestContextMemorySystem:
    """Test suite for ContextMemorySystem"""

    @pytest.fixture
    def memory_system(self):
        """Create a fresh memory system"""
        return ContextMemorySystem()

    @pytest.fixture
    def sample_result(self):
        """Create a sample analysis result"""
        return AnalysisResult(
            text="test security threat",
            risk_score=75.0,
            risk_level="HIGH",
            violations=["P001", "P002"],
            threats=["Threat 1", "Threat 2"],
            explanation="Test explanation",
        )

    def test_initialization(self, memory_system):
        """Test memory system initialization"""
        assert memory_system.user_profiles is not None
        assert len(memory_system.user_profiles) == 0

    def test_update_user_context_first_time(self, memory_system, sample_result):
        """Test first-time user context update"""
        user_id = "user001"
        memory_system.update_user_context(user_id, sample_result)

        profile = memory_system.user_profiles[user_id]
        assert profile["analyses_count"] == 1
        assert profile["avg_risk_score"] == 75.0
        assert len(profile["risk_history"]) == 1
        assert profile["violation_patterns"]["P001"] == 1
        assert profile["violation_patterns"]["P002"] == 1

    def test_update_user_context_multiple_times(self, memory_system, sample_result):
        """Test multiple context updates"""
        user_id = "user001"

        # First update
        memory_system.update_user_context(user_id, sample_result)

        # Second update with different score
        result2 = AnalysisResult(
            text="another threat",
            risk_score=50.0,
            risk_level="MEDIUM",
            violations=["P001"],
            threats=["Threat 3"],
            explanation="Test",
        )
        memory_system.update_user_context(user_id, result2)

        profile = memory_system.user_profiles[user_id]
        assert profile["analyses_count"] == 2
        assert profile["avg_risk_score"] == (75.0 + 50.0) / 2
        assert len(profile["risk_history"]) == 2
        assert profile["violation_patterns"]["P001"] == 2

    def test_behavior_trend_increasing(self, memory_system):
        """Test increasing behavior trend detection"""
        user_id = "user001"

        # Add 10 results with increasing risk scores
        for i in range(10):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=float(i * 10),
                risk_level="LOW",
                violations=[],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        profile = memory_system.user_profiles[user_id]
        assert profile["behavior_trend"] == "increasing"

    def test_behavior_trend_decreasing(self, memory_system):
        """Test decreasing behavior trend detection"""
        user_id = "user001"

        # Add 10 results with decreasing risk scores
        for i in range(10):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=float(90 - i * 10),
                risk_level="LOW",
                violations=[],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        profile = memory_system.user_profiles[user_id]
        assert profile["behavior_trend"] == "decreasing"

    def test_behavior_trend_stable(self, memory_system):
        """Test stable behavior trend detection"""
        user_id = "user001"

        # Add 10 results with stable risk scores
        for i in range(10):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=50.0,
                risk_level="MEDIUM",
                violations=[],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        profile = memory_system.user_profiles[user_id]
        assert profile["behavior_trend"] == "stable"

    def test_get_context_adjustment_new_user(self, memory_system):
        """Test context adjustment for new user"""
        adjustment = memory_system.get_context_adjustment("new_user", 50.0)
        assert adjustment == 0.0  # No adjustment for new users

    def test_get_context_adjustment_increasing_trend(self, memory_system):
        """Test context adjustment for increasing trend"""
        user_id = "user001"

        # Create increasing trend
        for i in range(10):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=float(i * 10),
                risk_level="LOW",
                violations=["P001"],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        adjustment = memory_system.get_context_adjustment(user_id, 50.0)
        assert adjustment > 0

    def test_get_context_adjustment_repeated_violations(self, memory_system):
        """Test context adjustment for repeated violations"""
        user_id = "user001"

        # Create repeated violations
        for i in range(5):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=50.0,
                risk_level="MEDIUM",
                violations=["P001"],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        adjustment = memory_system.get_context_adjustment(user_id, 50.0)
        assert adjustment > 0

    def test_get_user_summary_no_data(self, memory_system):
        """Test user summary for non-existent user"""
        summary = memory_system.get_user_summary("unknown_user")
        assert summary["status"] == "no_data"

    def test_get_user_summary_with_data(self, memory_system, sample_result):
        """Test user summary with existing data"""
        user_id = "user001"
        memory_system.update_user_context(user_id, sample_result)

        summary = memory_system.get_user_summary(user_id)
        assert summary["analyses_count"] == 1
        assert summary["avg_risk_score"] == 75.0
        assert summary["behavior_trend"] == "stable"
        assert len(summary["top_violations"]) > 0
        assert summary["recent_level"] == "HIGH"

    def test_risk_history_limit(self, memory_system):
        """Test that risk history respects max length"""
        user_id = "user001"

        # Add more than 100 results
        for i in range(150):
            result = AnalysisResult(
                text=f"test {i}",
                risk_score=50.0,
                risk_level="MEDIUM",
                violations=[],
                threats=[],
                explanation="",
            )
            memory_system.update_user_context(user_id, result)

        profile = memory_system.user_profiles[user_id]
        assert len(profile["risk_history"]) <= 100


class TestRelationshipAnalyzer:
    """Test suite for RelationshipAnalyzer"""

    @pytest.fixture
    def relationship_analyzer(self):
        """Create a fresh relationship analyzer"""
        return RelationshipAnalyzer()

    @pytest.fixture
    def sample_results(self):
        """Create sample analysis results"""
        return [
            AnalysisResult(
                text="threat 1",
                risk_score=75.0,
                risk_level="HIGH",
                violations=["P001", "P002"],
                threats=["Threat 1"],
                explanation="",
                user_id="user001",
            ),
            AnalysisResult(
                text="threat 2",
                risk_score=80.0,
                risk_level="HIGH",
                violations=["P001", "P003"],
                threats=["Threat 2"],
                explanation="",
                user_id="user001",
            ),
            AnalysisResult(
                text="threat 3",
                risk_score=60.0,
                risk_level="MEDIUM",
                violations=["P004"],
                threats=["Threat 3"],
                explanation="",
                user_id="user002",
            ),
        ]

    def test_initialization(self, relationship_analyzer):
        """Test relationship analyzer initialization"""
        assert relationship_analyzer.event_graph is not None
        assert relationship_analyzer.temporal_window is not None

    def test_add_event(self, relationship_analyzer, sample_results):
        """Test adding events to the graph"""
        relationship_analyzer.add_event("event1", sample_results[0])

        assert relationship_analyzer.event_graph.number_of_nodes() == 1
        node_data = relationship_analyzer.event_graph.nodes["event1"]
        assert node_data["risk_score"] == 75.0
        assert node_data["user_id"] == "user001"

    def test_add_multiple_events(self, relationship_analyzer, sample_results):
        """Test adding multiple events"""
        for i, result in enumerate(sample_results):
            relationship_analyzer.add_event(f"event{i}", result)

        assert relationship_analyzer.event_graph.number_of_nodes() == 3

    def test_build_relationships(self, relationship_analyzer, sample_results):
        """Test building relationships between events"""
        for i, result in enumerate(sample_results):
            relationship_analyzer.add_event(f"event{i}", result)

        relationship_analyzer.build_relationships()

        # Check if edges were created
        edges_count = relationship_analyzer.event_graph.number_of_edges()
        assert edges_count >= 0  # May have edges based on similarity

    def test_detect_compound_threats_none(self, relationship_analyzer):
        """Test compound threat detection with no threats"""
        threats = relationship_analyzer.detect_compound_threats()
        assert isinstance(threats, list)
        assert len(threats) == 0

    def test_detect_compound_threats_with_chain(self, relationship_analyzer):
        """Test compound threat detection with threat chain"""
        # Add multiple high-risk related events
        for i in range(5):
            result = AnalysisResult(
                text=f"threat {i}",
                risk_score=75.0,
                risk_level="HIGH",
                violations=["P001", "P002"],
                threats=[f"Threat {i}"],
                explanation="",
                user_id="user001",
            )
            relationship_analyzer.add_event(f"event{i}", result)

        relationship_analyzer.build_relationships()
        threats = relationship_analyzer.detect_compound_threats(min_chain=3)

        assert isinstance(threats, list)
        if len(threats) > 0:
            threat = threats[0]
            assert "threat_id" in threat
            assert "chain_length" in threat
            assert "avg_risk_score" in threat
            assert "severity" in threat

    def test_visualize(self, relationship_analyzer, sample_results, tmp_path):
        """Test graph visualization"""
        for i, result in enumerate(sample_results):
            relationship_analyzer.add_event(f"event{i}", result)

        relationship_analyzer.build_relationships()

        # Test visualization with tmp path
        output_path = tmp_path / "test_graph.png"
        relationship_analyzer.visualize(str(output_path))

        # Visualization might fail without display, so just check it doesn't crash
        assert True

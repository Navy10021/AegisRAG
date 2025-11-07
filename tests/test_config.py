"""
Unit tests for configuration management
"""

import pytest
from src.config import AnalyzerConfig, SecurityConfig, LoggingConfig


class TestAnalyzerConfig:
    """Test AnalyzerConfig"""

    def test_default_initialization(self):
        """Test default configuration values"""
        config = AnalyzerConfig()

        assert config.CACHE_SIZE == 256
        assert config.MAX_HISTORY_SIZE == 1000
        assert config.SEMANTIC_WEIGHT == 0.5
        assert config.RISK_CRITICAL_THRESHOLD == 60

    def test_severity_multipliers(self):
        """Test severity multipliers are set"""
        config = AnalyzerConfig()

        assert "critical" in config.SEVERITY_MULTIPLIERS
        assert "high" in config.SEVERITY_MULTIPLIERS
        assert (
            config.SEVERITY_MULTIPLIERS["critical"] > config.SEVERITY_MULTIPLIERS["low"]
        )

    def test_severity_points(self):
        """Test severity points are set"""
        config = AnalyzerConfig()

        assert "critical" in config.SEVERITY_POINTS
        assert config.SEVERITY_POINTS["critical"] > config.SEVERITY_POINTS["low"]

    def test_custom_values(self):
        """Test custom configuration values"""
        config = AnalyzerConfig()
        config.CACHE_SIZE = 512
        config.MAX_HISTORY_SIZE = 2000

        assert config.CACHE_SIZE == 512
        assert config.MAX_HISTORY_SIZE == 2000


class TestSecurityConfig:
    """Test SecurityConfig"""

    def test_default_initialization(self):
        """Test default security configuration"""
        config = SecurityConfig()

        assert config.ENABLE_INPUT_SANITIZATION == True
        assert config.MAX_PROMPT_LENGTH == 1000

    def test_api_key_from_env(self):
        """Test API key loading from environment"""
        import os

        # Save original
        original = os.environ.get("OPENAI_API_KEY")

        try:
            os.environ["OPENAI_API_KEY"] = "test-key-123"
            config = SecurityConfig()
            assert config.OPENAI_API_KEY == "test-key-123"
        finally:
            # Restore original
            if original:
                os.environ["OPENAI_API_KEY"] = original
            elif "OPENAI_API_KEY" in os.environ:
                del os.environ["OPENAI_API_KEY"]


class TestLoggingConfig:
    """Test LoggingConfig"""

    def test_default_initialization(self):
        """Test default logging configuration"""
        config = LoggingConfig()

        assert config.LOG_LEVEL == "INFO"
        assert config.LOG_FILE == "logs/aegis.log"
        assert config.MAX_LOG_SIZE_MB == 10
        assert config.BACKUP_COUNT == 5

    def test_log_format(self):
        """Test log format is set"""
        config = LoggingConfig()

        assert "asctime" in config.LOG_FORMAT
        assert "levelname" in config.LOG_FORMAT

    def test_custom_log_level(self):
        """Test custom log level"""
        config = LoggingConfig()
        config.LOG_LEVEL = "DEBUG"

        assert config.LOG_LEVEL == "DEBUG"

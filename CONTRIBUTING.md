# Contributing to AegisRAG

Thank you for your interest in contributing to AegisRAG! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Community](#community)

---

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please:

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility and apologize for mistakes

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of RAG systems and security analysis

### First Contribution

1. Star the repository ⭐
2. Fork the repository
3. Clone your fork
4. Create a new branch
5. Make your changes
6. Submit a pull request

---

## 💻 Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/AegisRAG.git
cd AegisRAG
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

### 4. Set Up Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your OpenAI API key
# OPENAI_API_KEY=sk-your-api-key-here
```

### 5. Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

---

## 🛠️ How to Contribute

### Types of Contributions

We welcome various types of contributions:

#### 🐛 Bug Reports
- Use the GitHub Issues tracker
- Include detailed reproduction steps
- Provide system information (OS, Python version)
- Include error messages and stack traces

#### ✨ Feature Requests
- Open an issue to discuss the feature
- Explain the use case and benefits
- Consider implementation complexity

#### 📝 Documentation
- Fix typos and grammar
- Improve code examples
- Add usage tutorials
- Translate documentation

#### 🧪 Tests
- Add missing test coverage
- Improve existing tests
- Add integration tests

#### 🔧 Code Improvements
- Bug fixes
- Performance optimizations
- Refactoring
- New features

---

## 🔄 Pull Request Process

### 1. Create a Branch

```bash
# For features
git checkout -b feature/your-feature-name

# For bug fixes
git checkout -b fix/bug-description

# For documentation
git checkout -b docs/what-you-are-documenting
```

### 2. Make Changes

- Write clean, readable code
- Follow our coding standards
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Changes

Use clear, descriptive commit messages:

```bash
git commit -m "feat: Add new feature description"
git commit -m "fix: Fix bug description"
git commit -m "docs: Update documentation"
git commit -m "test: Add tests for X"
git commit -m "refactor: Improve code quality"
```

**Commit Message Prefixes:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or modifications
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Build process or auxiliary tool changes

### 4. Push and Create PR

```bash
git push origin your-branch-name
```

Then create a Pull Request on GitHub with:
- Clear title and description
- Reference related issues (#123)
- List of changes made
- Screenshots (if UI changes)
- Test results

### 5. PR Review Process

- Maintainers will review your PR
- Address feedback and make requested changes
- CI checks must pass
- At least one approval required
- Maintainer will merge when ready

---

## 📐 Coding Standards

### Python Style

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

```python
# Use black for formatting
black src/ tests/

# Use isort for import sorting
isort src/ tests/

# Use flake8 for linting
flake8 src/ --max-line-length=120
```

### Code Guidelines

#### 1. **Naming Conventions**

```python
# Classes: PascalCase
class SecurityAnalyzer:
    pass

# Functions and variables: snake_case
def analyze_threat(user_input):
    risk_score = 0
    return risk_score

# Constants: UPPER_SNAKE_CASE
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Private methods: prefix with underscore
def _internal_helper(self):
    pass
```

#### 2. **Docstrings**

Use Google-style docstrings:

```python
def analyze(text: str, user_id: Optional[str] = None) -> AnalysisResult:
    """
    Analyze text for security threats.

    Args:
        text: Text to analyze (max 10,000 characters)
        user_id: User identifier for context tracking (optional)

    Returns:
        AnalysisResult containing risk score, violations, and threats

    Raises:
        ValueError: If text is empty

    Example:
        >>> result = analyzer.analyze("password leak")
        >>> print(result.risk_score)
        85.0
    """
```

#### 3. **Type Hints**

Always use type hints:

```python
from typing import List, Dict, Optional, Union

def process_policies(
    policies: List[SecurityPolicy],
    threshold: float = 0.5
) -> Dict[str, float]:
    """Process security policies."""
    return {}
```

#### 4. **Error Handling**

```python
# Specific exceptions
try:
    result = analyze_text(text)
except ValueError as e:
    logger.error(f"Invalid input: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return default_result()

# Avoid bare except
# DON'T: except:
# DO: except Exception as e:
```

#### 5. **Comments**

```python
# Good: Explain WHY, not WHAT
# Calculate confidence boost from Self-RAG evaluation
# Higher scores indicate better policy alignment
confidence_boost = self._calculate_boost(scores)

# Bad: Redundant comments
# Add 1 to counter
counter += 1
```

---

## 🧪 Testing Guidelines

### Test Structure

```python
# tests/test_module.py
import pytest
from src.module import MyClass

class TestMyClass:
    """Test suite for MyClass"""

    @pytest.fixture
    def sample_data(self):
        """Create sample data for tests"""
        return {"key": "value"}

    def test_basic_functionality(self, sample_data):
        """Test basic functionality"""
        obj = MyClass()
        result = obj.process(sample_data)
        assert result is not None

    def test_edge_case(self):
        """Test edge case handling"""
        obj = MyClass()
        with pytest.raises(ValueError):
            obj.process(None)
```

### Test Coverage

- Aim for > 80% code coverage
- Test happy paths and edge cases
- Test error handling
- Use meaningful test names
- Keep tests isolated and independent

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_analyzer.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run fast tests only
pytest tests/ -m "not slow"
```

---

## 📚 Documentation

### Code Documentation

- All public functions must have docstrings
- Include type hints
- Provide usage examples
- Document exceptions

### README Updates

When adding new features:
1. Update installation instructions if needed
2. Add usage examples
3. Update feature list
4. Add to changelog

### API Documentation

- Document all public APIs
- Include request/response examples
- Specify error codes
- Version changes appropriately

---

## 🌐 Community

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Email**: iyunseob4@gmail.com for private inquiries

### Stay Updated

- Watch the repository for updates
- Star the project ⭐
- Follow [@Navy10021](https://github.com/Navy10021)

---

## 🎯 Good First Issues

Looking for a place to start? Check issues labeled:
- `good first issue`: Perfect for newcomers
- `help wanted`: We need your expertise
- `documentation`: Improve our docs
- `bug`: Fix existing issues

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 Thank You!

Every contribution, no matter how small, makes AegisRAG better. Thank you for being part of our community!

**Questions?** Feel free to open an issue or reach out to the maintainers.

---

<div align="center">

**Happy Contributing! 🎉**

[Back to README](README.md) • [Report Bug](https://github.com/Navy10021/aegisrag/issues) • [Request Feature](https://github.com/Navy10021/aegisrag/issues)

</div>

"""
Basic Usage Example for AegisRAG v3.0

This example demonstrates how to use the AdvancedRAGAnalyzer
for simple security analysis.
"""

import json
from src.analyzer import AdvancedRAGAnalyzer
from src.models import SecurityPolicy


def load_policies(filepath='data/policies.json'):
    """Load security policies from JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    policies = []
    for p in data.get('policies', []):
        policies.append(SecurityPolicy(**p))

    return policies


def main():
    # Load policies
    print("Loading security policies...")
    policies = load_policies()
    print(f"✅ Loaded {len(policies)} policies\n")

    # Initialize analyzer (without LLM for quick demo)
    print("Initializing analyzer...")
    analyzer = AdvancedRAGAnalyzer(
        policies=policies,
        use_llm=False,  # Set to True if you have OpenAI API key
        use_embeddings=True,
        enable_self_rag=False  # Disable Self-RAG for simplicity
    )
    print("✅ Analyzer ready\n")

    # Test texts
    test_cases = [
        "Employee leaked password to external party",
        "Malware detected in system files",
        "Regular business email communication",
        "Unauthorized access to database detected",
    ]

    # Analyze each text
    print("="*80)
    print("ANALYSIS RESULTS")
    print("="*80 + "\n")

    for i, text in enumerate(test_cases, 1):
        print(f"Test Case #{i}: {text}")
        result = analyzer.analyze(text)

        print(f"  Risk Score: {result.risk_score:.1f}/100")
        print(f"  Risk Level: {result.risk_level}")
        print(f"  Violations: {len(result.violations)}")
        print(f"  Threats: {len(result.threats)}")
        if result.threats:
            print(f"  Top Threat: {result.threats[0]}")
        print()

    # Show statistics
    analyzer.print_stats()


if __name__ == "__main__":
    main()

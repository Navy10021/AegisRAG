"""
Advanced Usage Example for AegisRAG v3.0

This example demonstrates advanced features:
- Self-RAG meta-evaluation
- Context memory and user profiling
- Batch analysis
- Memory management
"""

import json
import os
from src.analyzer import AdvancedRAGAnalyzer
from src.models import SecurityPolicy
from src.config import AnalyzerConfig


def load_policies(filepath='data/policies.json'):
    """Load security policies from JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    policies = []
    for p in data.get('policies', []):
        policies.append(SecurityPolicy(**p))

    return policies


def main():
    # Custom configuration
    config = AnalyzerConfig()
    config.RISK_CRITICAL_THRESHOLD = 70  # Custom threshold
    config.MAX_HISTORY_SIZE = 500  # Limit history

    # Load policies
    print("Loading security policies...")
    policies = load_policies()
    print(f"✅ Loaded {len(policies)} policies\n")

    # Initialize analyzer with advanced features
    print("Initializing advanced analyzer...")
    analyzer = AdvancedRAGAnalyzer(
        policies=policies,
        api_key=os.getenv('OPENAI_API_KEY'),  # Optional: LLM support
        use_llm=False,  # Set to True if API key is available
        use_embeddings=True,
        enable_self_rag=True,  # Enable Self-RAG
        enable_advanced=True,  # Enable context memory
        config=config
    )
    print("✅ Analyzer ready with Self-RAG v3.0\n")

    # Simulate user behavior analysis
    print("="*80)
    print("USER BEHAVIOR ANALYSIS")
    print("="*80 + "\n")

    user_activities = [
        ("user123", "Downloading customer database"),
        ("user123", "Accessing external file sharing service"),
        ("user123", "Transferring large files to personal email"),
        ("user456", "Normal document editing"),
        ("user456", "Sending routine business email"),
    ]

    results = []
    for user_id, activity in user_activities:
        print(f"[{user_id}] {activity}")
        result = analyzer.analyze(activity, user_id=user_id)
        results.append(result)

        print(f"  Risk: {result.risk_score:.1f}/100 ({result.risk_level})")
        if hasattr(result, 'confidence_boost'):
            print(f"  Confidence Boost: +{result.confidence_boost:.1%}")
        print()

    # User profile summary
    print("\n" + "="*80)
    print("USER PROFILES")
    print("="*80 + "\n")

    for user_id in ["user123", "user456"]:
        profile = analyzer.get_user_profile(user_id)
        if 'error' not in profile:
            print(f"User: {user_id}")
            print(f"  Analyses: {profile['analyses_count']}")
            print(f"  Avg Risk: {profile['avg_risk_score']:.1f}")
            print(f"  Trend: {profile['behavior_trend']}")
            print(f"  Recent Level: {profile['recent_level']}")
            print()

    # Batch analysis
    print("="*80)
    print("BATCH ANALYSIS")
    print("="*80 + "\n")

    batch_texts = [
        "Password shared via chat",
        "Malware detected",
        "Suspicious login from unknown location",
        "Normal file access"
    ]

    batch_results = analyzer.analyze_batch(batch_texts)

    for text, result in zip(batch_texts, batch_results):
        print(f"Text: {text}")
        print(f"  Risk: {result.risk_score:.1f} ({result.risk_level})")
        print()

    # Memory management
    print("="*80)
    print("MEMORY MANAGEMENT")
    print("="*80 + "\n")

    usage = analyzer.get_memory_usage()
    print("Current Memory Usage:")
    for key, value in usage.items():
        print(f"  {key}: {value}")

    # Cleanup old entries
    removed = analyzer.cleanup_old_history(max_age_hours=1)
    print(f"\nCleaned up {removed} old entries")

    # Statistics
    print()
    analyzer.print_stats()


if __name__ == "__main__":
    main()

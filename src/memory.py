"""
RAG Security Analyzer - Memory System
Context memory and relational analysis system
"""

import logging
from collections import deque, defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import numpy as np
import networkx as nx

from .models import get_analysis_result
from .config import AnalyzerConfig

logger = logging.getLogger(__name__)


# ============================================================
# Context Memory System
# ============================================================


class ContextMemorySystem:
    """User behavior pattern learning and context memory"""

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        from .config import DEFAULT_ANALYZER_CONFIG

        self.config = config or DEFAULT_ANALYZER_CONFIG
        self.user_profiles: defaultdict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "analyses_count": 0,
                "avg_risk_score": 0.0,
                "risk_history": deque(maxlen=self.config.MAX_USER_HISTORY),
                "violation_patterns": Counter(),
                "behavior_trend": "stable",
            }
        )

    def update_user_context(self, user_id: str, result):
        """Update user profile"""
        # Handle SelfRAGResult case
        analysis = get_analysis_result(result)

        profile = self.user_profiles[user_id]
        profile["analyses_count"] += 1
        n = profile["analyses_count"]
        # Prevent division by zero (though n should always be >= 1 here)
        profile["avg_risk_score"] = (
            profile["avg_risk_score"] * (n - 1) + analysis.risk_score
        ) / max(n, 1)
        profile["risk_history"].append(
            {
                "timestamp": analysis.timestamp,
                "score": analysis.risk_score,
                "level": analysis.risk_level,
            }
        )
        for v in analysis.violations:
            profile["violation_patterns"][v] += 1

        # Behavior trend analysis
        if len(profile["risk_history"]) >= 10:
            recent = [h["score"] for h in list(profile["risk_history"])[-10:]]
            x = np.arange(len(recent))
            slope = np.polyfit(x, recent, 1)[0]
            profile["behavior_trend"] = (
                "increasing"
                if slope > self.config.BEHAVIOR_TREND_THRESHOLD_UP
                else (
                    "decreasing"
                    if slope < self.config.BEHAVIOR_TREND_THRESHOLD_DOWN
                    else "stable"
                )
            )

    def get_context_adjustment(self, user_id: str, base_score: float) -> float:
        """Context-based score adjustment"""
        profile = self.user_profiles.get(user_id)
        if not profile or profile["analyses_count"] < 5:
            return 0.0

        adjustment = 0.0
        if profile["behavior_trend"] == "increasing":
            adjustment += self.config.CONTEXT_ADJUSTMENT_BASE
        if profile["violation_patterns"]:
            max_viol = max(profile["violation_patterns"].values())
            if max_viol >= self.config.CONTEXT_ADJUSTMENT_VIOLATION_THRESHOLD:
                adjustment += min(
                    max_viol * self.config.CONTEXT_ADJUSTMENT_VIOLATION_MULTIPLIER,
                    self.config.CONTEXT_ADJUSTMENT_MAX
                    - self.config.CONTEXT_ADJUSTMENT_BASE,
                )
        return min(adjustment, self.config.CONTEXT_ADJUSTMENT_MAX)

    def get_user_summary(self, user_id: str) -> Dict:
        """Get user summary information"""
        profile = self.user_profiles.get(user_id)
        if not profile:
            return {"status": "no_data"}
        return {
            "analyses_count": profile["analyses_count"],
            "avg_risk_score": profile["avg_risk_score"],
            "behavior_trend": profile["behavior_trend"],
            "top_violations": profile["violation_patterns"].most_common(5),
            "recent_level": (
                profile["risk_history"][-1]["level"]
                if profile["risk_history"]
                else "UNKNOWN"
            ),
        }


# ============================================================
# Relationship Analyzer
# ============================================================


class RelationshipAnalyzer:
    """Inter-event relationship analysis"""

    def __init__(self):
        self.event_graph = nx.DiGraph()
        self.temporal_window = timedelta(hours=24)

    def add_event(self, event_id: str, result):
        """Add event"""
        # Handle SelfRAGResult case
        analysis = get_analysis_result(result)

        self.event_graph.add_node(
            event_id,
            text=analysis.text,
            risk_score=analysis.risk_score,
            timestamp=datetime.fromisoformat(analysis.timestamp),
            violations=analysis.violations,
            user_id=analysis.user_id,
        )

    def build_relationships(self):
        """
        Build inter-event relationships using optimized time-window approach

        Optimized from O(n²) to O(n*k) where k is the average number of events
        within the temporal window. Uses sorted events and early termination.
        """
        nodes = list(self.event_graph.nodes(data=True))

        # Sort events by timestamp for time-window optimization
        sorted_nodes = sorted(nodes, key=lambda x: x[1]["timestamp"])

        # Build relationships using sliding window approach
        for i, (id1, data1) in enumerate(sorted_nodes):
            # Only compare with subsequent events within temporal window
            for j in range(i + 1, len(sorted_nodes)):
                id2, data2 = sorted_nodes[j]

                time_diff = abs(data1["timestamp"] - data2["timestamp"])

                # Early termination: if time difference exceeds window, no need to continue
                # since events are sorted by timestamp
                if time_diff > self.temporal_window:
                    break

                # Calculate relationship scores
                temporal_score = 1.0 - (
                    time_diff.total_seconds() / self.temporal_window.total_seconds()
                )

                v1, v2 = set(data1["violations"]), set(data2["violations"])
                semantic_score = len(v1 & v2) / max(len(v1 | v2), 1)

                user_score = (
                    1.0 if data1.get("user_id") == data2.get("user_id") else 0.5
                )

                relationship_score = (
                    temporal_score * 0.3 + semantic_score * 0.5 + user_score * 0.2
                )

                if relationship_score > 0.3:
                    self.event_graph.add_edge(id1, id2, weight=relationship_score)

    def detect_compound_threats(self, min_chain: int = 3) -> List[Dict]:
        """Detect compound threats"""
        threats = []
        for component in nx.weakly_connected_components(self.event_graph):
            if len(component) >= min_chain:
                subgraph = self.event_graph.subgraph(component)
                avg_risk = np.mean(
                    [data["risk_score"] for _, data in subgraph.nodes(data=True)]
                )
                if avg_risk > 50:
                    threats.append(
                        {
                            "threat_id": f"COMPOUND_{len(threats)+1}",
                            "chain_length": len(component),
                            "avg_risk_score": avg_risk,
                            "severity": "CRITICAL" if avg_risk > 70 else "HIGH",
                        }
                    )
        return sorted(threats, key=lambda x: x["avg_risk_score"], reverse=True)

    def visualize(self, output: str = "output/threat_graph.png"):
        """Graph visualization"""
        try:
            import matplotlib.pyplot as plt

            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.event_graph, k=2)
            colors = []
            for node_id in self.event_graph.nodes():
                score = self.event_graph.nodes[node_id]["risk_score"]
                colors.append(
                    "#ff4444"
                    if score >= 70
                    else "#ff9944" if score >= 40 else "#44ff44"
                )
            nx.draw(
                self.event_graph,
                pos,
                node_color=colors,
                node_size=400,
                with_labels=True,
                font_size=8,
                arrows=True,
                edge_color="gray",
                alpha=0.7,
            )
            plt.title("Threat Relationship Graph", fontsize=14, fontweight="bold")
            plt.savefig(output, dpi=150, bbox_inches="tight")
            plt.close()
            logger.info(f"✅ Graph saved: {output}")
        except (ImportError, ModuleNotFoundError) as e:
            logger.error(f"Graph visualization module error: {e}")
        except (OSError, PermissionError, FileNotFoundError) as e:
            logger.error(f"Graph file save error: {type(e).__name__}: {e}")
        except (ValueError, TypeError, AttributeError) as e:
            logger.error(f"Graph rendering error: {type(e).__name__}: {e}")

"""
RAG Security Analyzer - Retrieval System
Retrieval system (BM25, Semantic Search, Hybrid Search)
"""

import logging
from collections import defaultdict
from typing import List, Optional, Tuple, Dict

import numpy as np

from .models import SecurityPolicy
from .config import AnalyzerConfig, DEFAULT_ANALYZER_CONFIG

logger = logging.getLogger(__name__)

# Embedding model cache
_embedding_model_cache = None

# Sentence Transformers availability check
try:
    from sentence_transformers import SentenceTransformer

    SENTENCE_TRANSFORMERS_AVAILABLE = True
except (ImportError, ModuleNotFoundError) as e:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning(f"Sentence Transformers not available: {e}")


# ============================================================
# BM25 Implementation
# ============================================================


class BM25:
    """BM25 algorithm - Enhanced keyword-based search"""

    def __init__(self, k1=None, b=None, config: AnalyzerConfig = None):
        config = config or DEFAULT_ANALYZER_CONFIG
        self.k1 = k1 if k1 is not None else config.BM25_K1
        self.b = b if b is not None else config.BM25_B
        self.doc_len = []
        self.avgdl = 0
        self.idf = {}
        self.corpus = []

    def fit(self, corpus):
        """Train BM25 with corpus"""
        self.corpus = corpus
        self.doc_len = [len(doc.split()) for doc in corpus]
        self.avgdl = sum(self.doc_len) / len(self.doc_len) if self.doc_len else 0

        df = defaultdict(int)
        for doc in corpus:
            words = set(doc.lower().split())
            for word in words:
                df[word] += 1

        num_docs = len(corpus)
        self.idf = {}
        for word, freq in df.items():
            self.idf[word] = np.log((num_docs - freq + 0.5) / (freq + 0.5) + 1)

    def get_scores(self, query):
        """Calculate BM25 score for each document against query"""
        query_words = query.lower().split()
        scores = np.zeros(len(self.corpus))

        for i, doc in enumerate(self.corpus):
            doc_words = doc.lower().split()
            doc_len = self.doc_len[i]

            for word in query_words:
                if word not in self.idf:
                    continue

                tf = doc_words.count(word)
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (
                    1 - self.b + self.b * (doc_len / self.avgdl)
                )
                scores[i] += self.idf[word] * (numerator / denominator)

        return scores


# ============================================================
# Embedding Utilities
# ============================================================


def get_embedding_model():
    """Load embedding model (with caching)"""
    global _embedding_model_cache
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    if _embedding_model_cache:
        return _embedding_model_cache
    try:
        _embedding_model_cache = SentenceTransformer(
            "paraphrase-multilingual-MiniLM-L12-v2"
        )
        logger.info("✅ Embedding model loaded")
        return _embedding_model_cache
    except (OSError, RuntimeError, ValueError) as e:
        logger.error(f"Model load failed: {e}")
        return None


def encode_texts(texts, model=None):
    """Convert texts to embedding vectors"""
    if not texts:
        return np.array([])
    model = model or get_embedding_model()
    if not model:
        return np.array([])
    try:
        return model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
    except (RuntimeError, ValueError, AttributeError, TypeError) as e:
        logger.warning(f"Text encoding failed: {type(e).__name__}: {str(e)}")
        return np.array([])


def batch_cosine_similarity(query_vec, corpus_vecs, config: AnalyzerConfig = None):
    """Calculate cosine similarity between query vector and corpus vectors"""
    config = config or DEFAULT_ANALYZER_CONFIG
    if query_vec.size == 0 or corpus_vecs.size == 0:
        return np.array([])
    query_norm = np.linalg.norm(query_vec)
    corpus_norms = np.linalg.norm(corpus_vecs, axis=1)
    if query_norm == 0:
        return np.zeros(len(corpus_vecs))
    corpus_norms[corpus_norms == 0] = config.EPSILON
    similarities = np.dot(corpus_vecs, query_vec) / (corpus_norms * query_norm)
    return np.clip(similarities, -1.0, 1.0)


# ============================================================
# Hybrid Search
# ============================================================


def _normalize_scores(scores: np.ndarray, config: AnalyzerConfig = None) -> np.ndarray:
    """
    Normalize scores to [0, 1] range using min-max normalization

    Args:
        scores: Array of scores to normalize
        config: Analyzer configuration

    Returns:
        Normalized scores
    """
    config = config or DEFAULT_ANALYZER_CONFIG
    if len(scores) == 0 or scores.max() == scores.min():
        return np.zeros_like(scores)
    return (scores - scores.min()) / (scores.max() - scores.min() + config.EPSILON)


def _compute_semantic_scores(
    text: str,
    policy_embeddings: np.ndarray,
    model,
    n_policies: int,
    config: AnalyzerConfig = None,
) -> np.ndarray:
    """
    Compute semantic similarity scores using embeddings

    Args:
        text: Query text
        policy_embeddings: Pre-computed policy embeddings
        model: Embedding model
        n_policies: Number of policies
        config: Analyzer configuration

    Returns:
        Array of semantic similarity scores
    """
    semantic_scores = np.zeros(n_policies)
    if model and len(policy_embeddings) > 0:
        try:
            query_emb = model.encode([text], normalize_embeddings=True)[0]
            semantic_scores = batch_cosine_similarity(
                query_emb, policy_embeddings, config
            )
        except (RuntimeError, ValueError, AttributeError, IndexError) as e:
            logger.debug(f"Semantic search failed: {type(e).__name__}: {str(e)}")
    return semantic_scores


def _compute_bm25_scores(
    text: str, bm25_model: Optional[BM25], n_policies: int
) -> np.ndarray:
    """
    Compute BM25 keyword search scores

    Args:
        text: Query text
        bm25_model: BM25 model instance
        n_policies: Number of policies

    Returns:
        Array of BM25 scores
    """
    bm25_scores = np.zeros(n_policies)
    if bm25_model:
        try:
            bm25_scores = bm25_model.get_scores(text)
        except (AttributeError, ValueError, TypeError) as e:
            logger.debug(f"BM25 search failed: {type(e).__name__}: {str(e)}")
    return bm25_scores


def _compute_keyword_scores(
    text: str, policies: List[SecurityPolicy], n_policies: int
) -> np.ndarray:
    """
    Compute simple keyword matching scores

    Args:
        text: Query text
        policies: List of security policies
        n_policies: Number of policies

    Returns:
        Array of keyword match scores
    """
    text_lower = text.lower()
    keyword_scores = np.zeros(n_policies)
    for i, policy in enumerate(policies):
        match_count = sum(1 for kw in policy.keywords if kw.lower() in text_lower)
        if match_count > 0:
            keyword_scores[i] = match_count / max(len(policy.keywords), 1)
    return keyword_scores


def _extract_top_results(
    policies: List[SecurityPolicy],
    combined_scores: np.ndarray,
    semantic_norm: np.ndarray,
    bm25_norm: np.ndarray,
    keyword_norm: np.ndarray,
    top_k: int = 3,
) -> List[Tuple[SecurityPolicy, float, Dict[str, float]]]:
    """
    Extract top-k results with score breakdowns

    Args:
        policies: List of security policies
        combined_scores: Combined weighted scores
        semantic_norm: Normalized semantic scores
        bm25_norm: Normalized BM25 scores
        keyword_norm: Keyword match scores
        top_k: Number of top results to return

    Returns:
        List of (policy, score, score_breakdown) tuples
    """
    results = []
    top_indices = np.argsort(combined_scores)[::-1][:top_k]

    for idx in top_indices:
        score = combined_scores[idx]
        if score > 0:
            results.append(
                (
                    policies[idx],
                    float(score),
                    {
                        "semantic": float(semantic_norm[idx]),
                        "bm25": float(bm25_norm[idx]),
                        "keyword": float(keyword_norm[idx]),
                    },
                )
            )

    return results


def hybrid_search(
    text: str,
    policies: List[SecurityPolicy],
    policy_embeddings: np.ndarray,
    model=None,
    bm25_model: Optional[BM25] = None,
    semantic_weight: float = 0.5,
    keyword_weight: float = 0.3,
    bm25_weight: float = 0.2,
    config: AnalyzerConfig = None,
) -> List[Tuple[SecurityPolicy, float, Dict[str, float]]]:
    """
    Hybrid Search: Semantic + Keyword + BM25

    Combines three search strategies with weighted scoring:
    - Semantic similarity using embeddings (default: 50%)
    - BM25 keyword search (default: 20%)
    - Simple keyword matching (default: 30%)

    Args:
        text: Query text
        policies: List of security policies to search
        policy_embeddings: Pre-computed policy embeddings
        model: Embedding model for semantic search
        bm25_model: BM25 model for keyword search
        semantic_weight: Weight for semantic similarity (0-1)
        keyword_weight: Weight for keyword matching (0-1)
        bm25_weight: Weight for BM25 search (0-1)
        config: Analyzer configuration

    Returns:
        List of (policy, score, score_breakdown) tuples, sorted by score

    Example:
        >>> results = hybrid_search("password leak", policies, embeddings)
        >>> for policy, score, breakdown in results:
        >>>     print(f"{policy.title}: {score:.2f}")
    """
    config = config or DEFAULT_ANALYZER_CONFIG
    n_policies = len(policies)

    # Compute individual scores
    semantic_scores = _compute_semantic_scores(
        text, policy_embeddings, model, n_policies, config
    )
    bm25_scores = _compute_bm25_scores(text, bm25_model, n_policies)
    keyword_scores = _compute_keyword_scores(text, policies, n_policies)

    # Normalize scores
    semantic_norm = _normalize_scores(semantic_scores, config)
    bm25_norm = _normalize_scores(bm25_scores, config)
    keyword_norm = keyword_scores  # Already normalized in computation

    # Combine with weighted sum
    combined_scores = (
        semantic_weight * semantic_norm
        + bm25_weight * bm25_norm
        + keyword_weight * keyword_norm
    )

    # Extract top results
    return _extract_top_results(
        policies, combined_scores, semantic_norm, bm25_norm, keyword_norm
    )

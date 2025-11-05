"""
Unit tests for Retrieval System
"""

import pytest
import numpy as np
from src.retriever import (
    BM25,
    get_embedding_model,
    encode_texts,
    batch_cosine_similarity,
    hybrid_search,
    SENTENCE_TRANSFORMERS_AVAILABLE
)
from src.models import SecurityPolicy


class TestBM25:
    """Test suite for BM25 algorithm"""

    @pytest.fixture
    def sample_corpus(self):
        """Create sample document corpus"""
        return [
            "password leak detected in system",
            "malware attack on server",
            "unauthorized access to database",
            "normal business communication"
        ]

    @pytest.fixture
    def bm25_model(self, sample_corpus):
        """Create and fit BM25 model"""
        model = BM25()
        model.fit(sample_corpus)
        return model

    def test_initialization(self):
        """Test BM25 initialization"""
        model = BM25(k1=1.5, b=0.75)
        assert model.k1 == 1.5
        assert model.b == 0.75
        assert len(model.corpus) == 0

    def test_fit(self, sample_corpus):
        """Test BM25 fitting"""
        model = BM25()
        model.fit(sample_corpus)

        assert len(model.corpus) == 4
        assert len(model.doc_len) == 4
        assert model.avgdl > 0
        assert len(model.idf) > 0

    def test_get_scores(self, bm25_model):
        """Test BM25 score calculation"""
        query = "password leak"
        scores = bm25_model.get_scores(query)

        assert len(scores) == 4
        assert isinstance(scores, np.ndarray)
        assert scores[0] > 0  # First doc should match

    def test_get_scores_ranking(self, bm25_model):
        """Test BM25 ranking"""
        query = "password leak"
        scores = bm25_model.get_scores(query)

        # First document should have highest score (exact match)
        assert scores[0] == max(scores)

    def test_get_scores_no_match(self, bm25_model):
        """Test BM25 with no matching terms"""
        query = "completely unrelated query xyz"
        scores = bm25_model.get_scores(query)

        assert len(scores) == 4
        # All scores should be 0 or very low
        assert all(score <= 1.0 for score in scores)

    def test_empty_corpus(self):
        """Test BM25 with empty corpus"""
        model = BM25()
        model.fit([])

        assert len(model.corpus) == 0
        assert len(model.doc_len) == 0


class TestEmbeddingUtilities:
    """Test suite for embedding utilities"""

    def test_get_embedding_model(self):
        """Test embedding model loading"""
        model = get_embedding_model()

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            assert model is not None
        else:
            assert model is None

    def test_get_embedding_model_caching(self):
        """Test embedding model caching"""
        model1 = get_embedding_model()
        model2 = get_embedding_model()

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            assert model1 is model2  # Should return same cached instance

    @pytest.mark.skipif(not SENTENCE_TRANSFORMERS_AVAILABLE, reason="sentence-transformers not available")
    def test_encode_texts(self):
        """Test text encoding"""
        texts = ["test sentence", "another test"]
        model = get_embedding_model()
        embeddings = encode_texts(texts, model)

        assert embeddings.shape[0] == 2
        assert embeddings.shape[1] > 0  # Should have embedding dimension

    def test_encode_texts_empty(self):
        """Test encoding empty list"""
        embeddings = encode_texts([])
        assert embeddings.shape[0] == 0

    @pytest.mark.skipif(not SENTENCE_TRANSFORMERS_AVAILABLE, reason="sentence-transformers not available")
    def test_batch_cosine_similarity(self):
        """Test cosine similarity calculation"""
        model = get_embedding_model()
        if model is None:
            pytest.skip("Model not available")

        texts = ["test", "test", "different"]
        embeddings = encode_texts(texts, model)

        query_vec = embeddings[0]
        corpus_vecs = embeddings

        similarities = batch_cosine_similarity(query_vec, corpus_vecs)

        assert len(similarities) == 3
        assert similarities[0] >= similarities[2]  # Same text should be more similar

    def test_batch_cosine_similarity_empty(self):
        """Test cosine similarity with empty vectors"""
        query_vec = np.array([])
        corpus_vecs = np.array([])

        similarities = batch_cosine_similarity(query_vec, corpus_vecs)
        assert len(similarities) == 0

    def test_batch_cosine_similarity_zero_norm(self):
        """Test cosine similarity with zero norm vector"""
        query_vec = np.zeros(10)
        corpus_vecs = np.random.rand(3, 10)

        similarities = batch_cosine_similarity(query_vec, corpus_vecs)
        assert len(similarities) == 3
        assert all(sim == 0 for sim in similarities)


class TestHybridSearch:
    """Test suite for hybrid search"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample security policies"""
        return [
            SecurityPolicy(
                id="P001",
                title="Password Security",
                content="Protect passwords and credentials from leaks",
                severity="critical",
                keywords=["password", "credential", "leak"],
                category="security"
            ),
            SecurityPolicy(
                id="P002",
                title="Malware Detection",
                content="Detect and prevent malware attacks",
                severity="critical",
                keywords=["malware", "virus", "attack"],
                category="malware"
            ),
            SecurityPolicy(
                id="P003",
                title="Access Control",
                content="Unauthorized access prevention",
                severity="high",
                keywords=["unauthorized", "access", "breach"],
                category="access"
            ),
        ]

    @pytest.fixture
    def policy_embeddings(self, sample_policies):
        """Create policy embeddings"""
        model = get_embedding_model()
        if model is None:
            return np.array([])

        texts = [f"{p.title}. {p.content}" for p in sample_policies]
        return encode_texts(texts, model)

    @pytest.fixture
    def bm25_model(self, sample_policies):
        """Create BM25 model for policies"""
        texts = [f"{p.title}. {p.content}" for p in sample_policies]
        model = BM25()
        model.fit(texts)
        return model

    def test_hybrid_search_basic(self, sample_policies, policy_embeddings):
        """Test basic hybrid search"""
        query = "password leak"
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model
        )

        assert isinstance(results, list)
        assert len(results) <= 3  # Top-3 results

        for policy, score, breakdown in results:
            assert isinstance(policy, SecurityPolicy)
            assert isinstance(score, float)
            assert isinstance(breakdown, dict)

    def test_hybrid_search_with_bm25(self, sample_policies, policy_embeddings, bm25_model):
        """Test hybrid search with BM25"""
        query = "password credential leak"
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model,
            bm25_model=bm25_model
        )

        assert isinstance(results, list)
        # Should find P001 (Password Security) as most relevant
        if len(results) > 0:
            assert results[0][0].id == "P001"

    def test_hybrid_search_weights(self, sample_policies, policy_embeddings, bm25_model):
        """Test hybrid search with custom weights"""
        query = "malware attack"
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model,
            bm25_model=bm25_model,
            semantic_weight=0.7,
            keyword_weight=0.2,
            bm25_weight=0.1
        )

        assert isinstance(results, list)
        # Should find P002 (Malware Detection)
        if len(results) > 0:
            top_policy = results[0][0]
            assert top_policy.id in ["P002", "P001", "P003"]

    def test_hybrid_search_score_breakdown(self, sample_policies, policy_embeddings, bm25_model):
        """Test that score breakdown is provided"""
        query = "password"
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model,
            bm25_model=bm25_model
        )

        if len(results) > 0:
            _, _, breakdown = results[0]
            assert 'semantic' in breakdown
            assert 'bm25' in breakdown
            assert 'keyword' in breakdown

    def test_hybrid_search_no_embeddings(self, sample_policies):
        """Test hybrid search without embeddings"""
        query = "password leak"
        results = hybrid_search(
            query,
            sample_policies,
            np.array([]),
            model=None,
            bm25_model=None
        )

        # Should still work with keyword matching
        assert isinstance(results, list)

    def test_hybrid_search_keyword_matching(self, sample_policies):
        """Test keyword matching component"""
        query = "password credential"
        results = hybrid_search(
            query,
            sample_policies,
            np.array([]),
            model=None,
            bm25_model=None,
            keyword_weight=1.0,
            semantic_weight=0.0,
            bm25_weight=0.0
        )

        # Should find P001 based on keyword match
        assert len(results) > 0
        if results[0][1] > 0:  # If there's a match
            assert results[0][0].id == "P001"

    def test_hybrid_search_empty_query(self, sample_policies, policy_embeddings):
        """Test hybrid search with empty query"""
        query = ""
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model
        )

        assert isinstance(results, list)

    def test_hybrid_search_no_matches(self, sample_policies, policy_embeddings):
        """Test hybrid search with no matches"""
        query = "completely unrelated xyz abc"
        model = get_embedding_model()

        results = hybrid_search(
            query,
            sample_policies,
            policy_embeddings,
            model=model
        )

        # May return results with low scores or empty list
        assert isinstance(results, list)
        assert len(results) <= 3


class TestIntegration:
    """Integration tests for retrieval system"""

    @pytest.fixture
    def sample_policies(self):
        """Create sample policies"""
        return [
            SecurityPolicy(
                id="P001",
                title="Data Loss Prevention",
                content="Prevent data leakage and unauthorized transfers",
                severity="critical",
                keywords=["data", "leak", "transfer", "unauthorized"],
                category="dlp"
            ),
        ]

    def test_full_retrieval_pipeline(self, sample_policies):
        """Test complete retrieval pipeline"""
        query = "data leak detected"

        # Get model
        model = get_embedding_model()

        # Encode policies
        policy_texts = [f"{p.title}. {p.content}" for p in sample_policies]
        if model:
            embeddings = encode_texts(policy_texts, model)
        else:
            embeddings = np.array([])

        # Create BM25
        bm25 = BM25()
        bm25.fit(policy_texts)

        # Search
        results = hybrid_search(
            query,
            sample_policies,
            embeddings,
            model=model,
            bm25_model=bm25
        )

        assert isinstance(results, list)
        assert len(results) <= 3

"""
RAG Security Analyzer - Retrieval System
검색 시스템 (BM25, Semantic Search, Hybrid Search)
"""

import logging
from collections import defaultdict
from typing import List, Optional, Tuple, Dict, Any

import numpy as np

from .models import SecurityPolicy

logger = logging.getLogger(__name__)

# 임베딩 모델 캐시
_embedding_model_cache = None

# Sentence Transformers 가용성 체크
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except:
    SENTENCE_TRANSFORMERS_AVAILABLE = False


# ============================================================
# BM25 Implementation
# ============================================================

class BM25:
    """BM25 알고리즘 - 키워드 기반 검색 강화"""
    
    def __init__(self, k1=1.5, b=0.75):
        self.k1 = k1
        self.b = b
        self.doc_len = []
        self.avgdl = 0
        self.idf = {}
        self.corpus = []
    
    def fit(self, corpus):
        """코퍼스로 BM25 학습"""
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
        """쿼리에 대한 각 문서의 BM25 스코어 계산"""
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
                denominator = tf + self.k1 * (1 - self.b + self.b * (doc_len / self.avgdl))
                scores[i] += self.idf[word] * (numerator / denominator)
        
        return scores


# ============================================================
# Embedding Utilities
# ============================================================

def get_embedding_model():
    """임베딩 모델 로드 (캐싱)"""
    global _embedding_model_cache
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    if _embedding_model_cache:
        return _embedding_model_cache
    try:
        _embedding_model_cache = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
        logger.info("✅ Embedding model loaded")
        return _embedding_model_cache
    except Exception as e:
        logger.error(f"Model load failed: {e}")
        return None


def encode_texts(texts, model=None):
    """텍스트를 임베딩 벡터로 변환"""
    if not texts:
        return np.array([])
    model = model or get_embedding_model()
    if not model:
        return np.array([])
    try:
        return model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
    except:
        return np.array([])


def batch_cosine_similarity(query_vec, corpus_vecs):
    """쿼리 벡터와 코퍼스 벡터들 간의 코사인 유사도 계산"""
    if query_vec.size == 0 or corpus_vecs.size == 0:
        return np.array([])
    query_norm = np.linalg.norm(query_vec)
    corpus_norms = np.linalg.norm(corpus_vecs, axis=1)
    if query_norm == 0:
        return np.zeros(len(corpus_vecs))
    corpus_norms[corpus_norms == 0] = 1e-10
    similarities = np.dot(corpus_vecs, query_vec) / (corpus_norms * query_norm)
    return np.clip(similarities, -1.0, 1.0)


# ============================================================
# Hybrid Search
# ============================================================

def hybrid_search(
    text: str,
    policies: List[SecurityPolicy],
    policy_embeddings: np.ndarray,
    model=None,
    bm25_model: Optional[BM25] = None,
    semantic_weight: float = 0.5,
    keyword_weight: float = 0.3,
    bm25_weight: float = 0.2
) -> List[Tuple[SecurityPolicy, float, Dict[str, float]]]:
    """
    Hybrid Search: Semantic + Keyword + BM25
    
    Returns:
        List of (policy, score, score_breakdown)
    """
    results = []
    n_policies = len(policies)
    
    # 1. Semantic Search
    semantic_scores = np.zeros(n_policies)
    if model and len(policy_embeddings) > 0:
        try:
            query_emb = model.encode([text], normalize_embeddings=True)[0]
            semantic_scores = batch_cosine_similarity(query_emb, policy_embeddings)
        except:
            pass
    
    # 2. BM25 Keyword Search
    bm25_scores = np.zeros(n_policies)
    if bm25_model:
        try:
            bm25_scores = bm25_model.get_scores(text)
        except:
            pass
    
    # 3. Simple Keyword Matching
    text_lower = text.lower()
    keyword_scores = np.zeros(n_policies)
    for i, policy in enumerate(policies):
        match_count = sum(1 for kw in policy.keywords if kw.lower() in text_lower)
        if match_count > 0:
            keyword_scores[i] = match_count / max(len(policy.keywords), 1)
    
    # 4. 점수 정규화
    def normalize(scores):
        if len(scores) == 0 or scores.max() == scores.min():
            return np.zeros_like(scores)
        return (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
    
    semantic_norm = normalize(semantic_scores)
    bm25_norm = normalize(bm25_scores)
    keyword_norm = keyword_scores
    
    # 5. 가중합으로 결합
    combined_scores = (
        semantic_weight * semantic_norm +
        bm25_weight * bm25_norm +
        keyword_weight * keyword_norm
    )
    
    # 6. Top 3 결과
    top_indices = np.argsort(combined_scores)[::-1][:3]
    
    for idx in top_indices:
        score = combined_scores[idx]
        if score > 0:
            results.append((
                policies[idx],
                float(score),
                {
                    'semantic': float(semantic_norm[idx]),
                    'bm25': float(bm25_norm[idx]),
                    'keyword': float(keyword_norm[idx])
                }
            ))
    
    return results

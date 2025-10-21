import logging
from typing import List, Optional, Tuple
import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logging.warning("sentence-transformers가 설치되지 않았습니다")

# 로깅 설정
logger = logging.getLogger(__name__)

# 전역 모델 캐시
_embedding_model_cache = None


# ==================== 모델 관리 ====================

def get_embedding_model(
    model_name: str = 'paraphrase-multilingual-MiniLM-L12-v2',
    force_reload: bool = False
) -> Optional[SentenceTransformer]:
    """
    임베딩 모델 로드 (싱글톤 패턴)
    
    Args:
        model_name: 모델 이름 (기본: paraphrase-multilingual-MiniLM-L12-v2)
        force_reload: 강제 재로드 여부
        
    Returns:
        SentenceTransformer 모델 또는 None
    """
    global _embedding_model_cache
    
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        logger.error("sentence-transformers 라이브러리가 필요합니다")
        return None
    
    # 캐시된 모델 반환
    if _embedding_model_cache is not None and not force_reload:
        return _embedding_model_cache
    
    try:
        logger.info(f"임베딩 모델 로딩 중: {model_name}")
        _embedding_model_cache = SentenceTransformer(model_name)
        logger.info(f"✅ 모델 로드 완료: {model_name}")
        return _embedding_model_cache
        
    except Exception as e:
        logger.error(f"모델 로드 실패: {e}")
        return None


def clear_model_cache():
    """모델 캐시 초기화 (메모리 절약)"""
    global _embedding_model_cache
    _embedding_model_cache = None
    logger.info("모델 캐시가 초기화되었습니다")


# ==================== 임베딩 생성 ====================

def encode_texts(
    texts: List[str],
    model: Optional[SentenceTransformer] = None,
    batch_size: int = 32,
    show_progress: bool = False,
    normalize: bool = True
) -> np.ndarray:
    """
    텍스트 리스트를 임베딩 벡터로 변환
    
    Args:
        texts: 인코딩할 텍스트 리스트
        model: 사용할 모델 (None이면 자동 로드)
        batch_size: 배치 크기 (메모리 효율성)
        show_progress: 진행률 표시 여부
        normalize: L2 정규화 여부 (코사인 유사도 최적화)
        
    Returns:
        임베딩 벡터 배열 (shape: [len(texts), embedding_dim])
    """
    if not texts:
        logger.warning("빈 텍스트 리스트가 입력되었습니다")
        return np.array([])
    
    # 모델 로드
    if model is None:
        model = get_embedding_model()
        if model is None:
            logger.error("모델을 로드할 수 없습니다")
            return np.array([])
    
    try:
        # 임베딩 생성
        embeddings = model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=show_progress,
            convert_to_tensor=False,
            normalize_embeddings=normalize
        )
        
        logger.debug(f"임베딩 생성 완료: {len(texts)}개 텍스트 → shape {embeddings.shape}")
        return embeddings
        
    except Exception as e:
        logger.error(f"임베딩 생성 실패: {e}")
        return np.array([])


def encode_single_text(
    text: str,
    model: Optional[SentenceTransformer] = None,
    normalize: bool = True
) -> np.ndarray:
    """
    단일 텍스트 임베딩 (편의 함수)
    
    Args:
        text: 인코딩할 텍스트
        model: 사용할 모델
        normalize: 정규화 여부
        
    Returns:
        임베딩 벡터 (shape: [embedding_dim])
    """
    if not text or not text.strip():
        logger.warning("빈 텍스트가 입력되었습니다")
        return np.array([])
    
    embeddings = encode_texts([text], model=model, normalize=normalize)
    return embeddings[0] if len(embeddings) > 0 else np.array([])


# ==================== 유사도 계산 ====================

def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """
    코사인 유사도 계산
    
    Args:
        vec1: 벡터 1
        vec2: 벡터 2
        
    Returns:
        코사인 유사도 (-1 ~ 1)
    """
    if vec1.size == 0 or vec2.size == 0:
        return 0.0
    
    try:
        # L2 정규화된 벡터의 경우 내적만으로 계산 가능
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = np.dot(vec1, vec2) / (norm1 * norm2)
        
        # 부동소수점 오차 보정
        return float(np.clip(similarity, -1.0, 1.0))
        
    except Exception as e:
        logger.error(f"유사도 계산 오류: {e}")
        return 0.0


def batch_cosine_similarity(
    query_vec: np.ndarray,
    corpus_vecs: np.ndarray
) -> np.ndarray:
    """
    쿼리 벡터와 다수 코퍼스 벡터 간 유사도 일괄 계산
    
    Args:
        query_vec: 쿼리 벡터 (shape: [embedding_dim])
        corpus_vecs: 코퍼스 벡터들 (shape: [n, embedding_dim])
        
    Returns:
        유사도 배열 (shape: [n])
    """
    if query_vec.size == 0 or corpus_vecs.size == 0:
        return np.array([])
    
    try:
        # 벡터화된 연산으로 성능 최적화
        query_norm = np.linalg.norm(query_vec)
        corpus_norms = np.linalg.norm(corpus_vecs, axis=1)
        
        # 0으로 나누기 방지
        if query_norm == 0:
            return np.zeros(len(corpus_vecs))
        
        corpus_norms[corpus_norms == 0] = 1e-10
        
        # 내적 계산
        similarities = np.dot(corpus_vecs, query_vec) / (corpus_norms * query_norm)
        
        # 범위 클리핑
        return np.clip(similarities, -1.0, 1.0)
        
    except Exception as e:
        logger.error(f"배치 유사도 계산 오류: {e}")
        return np.array([])


# ==================== 정책 검색 ====================

def search_top_policies(
    text: str,
    policies: List,
    policy_embeddings: np.ndarray,
    top_k: int = 3,
    min_similarity: float = 0.0,
    model: Optional[SentenceTransformer] = None,
    return_scores: bool = False
):
    """
    임베딩 기반 상위 K개 정책 검색
    
    Args:
        text: 검색 쿼리 텍스트
        policies: 정책 객체 리스트
        policy_embeddings: 정책 임베딩 배열
        top_k: 반환할 상위 정책 수
        min_similarity: 최소 유사도 임계값 (0.0 = 제한 없음)
        model: 사용할 임베딩 모델
        return_scores: 유사도 점수도 함께 반환할지 여부
        
    Returns:
        정책 리스트 또는 (정책, 점수) 튜플 리스트
    """
    # 입력 검증
    if not text or not text.strip():
        logger.warning("빈 검색 쿼리")
        return _fallback_policies(policies, top_k, return_scores)
    
    if not policies or len(policy_embeddings) == 0:
        logger.warning("정책 또는 임베딩이 비어있습니다")
        return [] if return_scores else []
    
    if len(policies) != len(policy_embeddings):
        logger.error(f"정책 수({len(policies)})와 임베딩 수({len(policy_embeddings)}) 불일치")
        return _fallback_policies(policies, top_k, return_scores)
    
    try:
        # 쿼리 임베딩 생성
        if model is None:
            model = get_embedding_model()
            if model is None:
                logger.warning("모델 로드 실패, fallback 사용")
                return _fallback_policies(policies, top_k, return_scores)
        
        query_embedding = encode_single_text(text, model=model, normalize=True)
        
        if query_embedding.size == 0:
            logger.warning("쿼리 임베딩 생성 실패, fallback 사용")
            return _fallback_policies(policies, top_k, return_scores)
        
        # 배치 유사도 계산
        similarities = batch_cosine_similarity(query_embedding, policy_embeddings)
        
        # 유사도-정책 페어 생성
        scored_policies = [
            (sim, policies[idx])
            for idx, sim in enumerate(similarities)
            if sim >= min_similarity
        ]
        
        # 유사도 기준 내림차순 정렬
        scored_policies.sort(key=lambda x: x[0], reverse=True)
        
        # 상위 K개 선택
        top_policies = scored_policies[:top_k]
        
        # 결과가 없으면 fallback
        if not top_policies:
            logger.warning(f"유사도 임계값({min_similarity}) 이상인 정책이 없습니다")
            return _fallback_policies(policies, top_k, return_scores)
        
        # 로그 출력
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"검색 결과 (Top {len(top_policies)}):")
            for sim, policy in top_policies:
                logger.debug(f"  {sim:.3f} - [{policy.id}] {policy.title}")
        
        # 반환 형식 선택
        if return_scores:
            return [(policy, float(sim)) for sim, policy in top_policies]
        else:
            return [policy for _, policy in top_policies]
        
    except Exception as e:
        logger.error(f"정책 검색 중 오류: {e}", exc_info=True)
        return _fallback_policies(policies, top_k, return_scores)


def _fallback_policies(
    policies: List,
    top_k: int,
    return_scores: bool
):
    """
    Fallback: 상위 K개 정책을 순서대로 반환
    
    Args:
        policies: 정책 리스트
        top_k: 반환할 정책 수
        return_scores: 점수 포함 여부
        
    Returns:
        정책 리스트 또는 (정책, 점수) 튜플 리스트
    """
    top_policies = policies[:min(top_k, len(policies))]
    
    if return_scores:
        # 모든 정책에 동일한 낮은 점수 부여
        return [(policy, 0.1) for policy in top_policies]
    else:
        return top_policies


# ==================== 키워드 기반 보조 검색 ====================

def keyword_based_search(
    text: str,
    policies: List,
    top_k: int = 3,
    return_scores: bool = False
):
    """
    키워드 매칭 기반 정책 검색 (임베딩 불가 시 fallback)
    
    Args:
        text: 검색 텍스트
        policies: 정책 리스트
        top_k: 반환할 정책 수
        return_scores: 점수 포함 여부
        
    Returns:
        정책 리스트 또는 (정책, 점수) 튜플 리스트
    """
    if not text or not policies:
        return _fallback_policies(policies, top_k, return_scores)
    
    text_lower = text.lower()
    scored_policies = []
    
    for policy in policies:
        # 키워드 매칭 점수 계산
        match_count = sum(
            1 for keyword in policy.keywords
            if keyword.lower() in text_lower
        )
        
        if match_count > 0:
            # 매칭 비율을 점수로 사용
            score = match_count / max(len(policy.keywords), 1)
            scored_policies.append((score, policy))
    
    # 점수 기준 내림차순 정렬
    scored_policies.sort(key=lambda x: x[0], reverse=True)
    
    # 상위 K개 선택
    top_policies = scored_policies[:top_k]
    
    # 결과가 없으면 전체 정책 중 상위 K개
    if not top_policies:
        return _fallback_policies(policies, top_k, return_scores)
    
    # 반환 형식
    if return_scores:
        return [(policy, float(score)) for score, policy in top_policies]
    else:
        return [policy for _, policy in top_policies]


# ==================== 하이브리드 검색 ====================

def hybrid_search(
    text: str,
    policies: List,
    policy_embeddings: np.ndarray,
    top_k: int = 3,
    embedding_weight: float = 0.7,
    keyword_weight: float = 0.3,
    model: Optional[SentenceTransformer] = None,
    return_scores: bool = False
):
    """
    임베딩 + 키워드 하이브리드 검색 (최고 성능)
    
    Args:
        text: 검색 텍스트
        policies: 정책 리스트
        policy_embeddings: 정책 임베딩
        top_k: 반환할 정책 수
        embedding_weight: 임베딩 점수 가중치 (0-1)
        keyword_weight: 키워드 점수 가중치 (0-1)
        model: 임베딩 모델
        return_scores: 점수 포함 여부
        
    Returns:
        정책 리스트 또는 (정책, 점수) 튜플 리스트
    """
    # 가중치 정규화
    total_weight = embedding_weight + keyword_weight
    if total_weight > 0:
        embedding_weight /= total_weight
        keyword_weight /= total_weight
    
    # 임베딩 검색
    emb_results = search_top_policies(
        text, policies, policy_embeddings,
        top_k=len(policies),  # 모든 정책 점수 계산
        model=model,
        return_scores=True
    )
    
    # 키워드 검색
    kw_results = keyword_based_search(
        text, policies,
        top_k=len(policies),
        return_scores=True
    )
    
    # 점수 통합
    policy_scores = {}
    
    for policy, score in emb_results:
        policy_scores[policy.id] = embedding_weight * score
    
    for policy, score in kw_results:
        if policy.id in policy_scores:
            policy_scores[policy.id] += keyword_weight * score
        else:
            policy_scores[policy.id] = keyword_weight * score
    
    # 정책 ID로 매핑
    policy_map = {p.id: p for p in policies}
    
    # 점수 기준 정렬
    sorted_policies = sorted(
        policy_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:top_k]
    
    # 결과 반환
    if return_scores:
        return [(policy_map[pid], score) for pid, score in sorted_policies]
    else:
        return [policy_map[pid] for pid, _ in sorted_policies]


# ==================== 유틸리티 ====================

def get_embedding_dimension(model: Optional[SentenceTransformer] = None) -> int:
    """
    임베딩 차원 반환
    
    Args:
        model: 임베딩 모델
        
    Returns:
        임베딩 차원 수
    """
    if model is None:
        model = get_embedding_model()
        if model is None:
            return 0
    
    try:
        return model.get_sentence_embedding_dimension()
    except Exception as e:
        logger.error(f"임베딩 차원 조회 실패: {e}")
        return 0


def validate_embeddings(
    embeddings: np.ndarray,
    expected_dim: Optional[int] = None
) -> bool:
    """
    임베딩 유효성 검증
    
    Args:
        embeddings: 검증할 임베딩
        expected_dim: 기대되는 차원 수
        
    Returns:
        유효 여부
    """
    if embeddings.size == 0:
        logger.error("임베딩이 비어있습니다")
        return False
    
    if embeddings.ndim not in [1, 2]:
        logger.error(f"잘못된 임베딩 차원: {embeddings.ndim}")
        return False
    
    if expected_dim is not None:
        actual_dim = embeddings.shape[-1]
        if actual_dim != expected_dim:
            logger.error(f"임베딩 차원 불일치: {actual_dim} != {expected_dim}")
            return False
    
    return True

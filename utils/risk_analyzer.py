import os
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from datetime import datetime
from functools import lru_cache
import asyncio

from pydantic import BaseModel, Field, validator
import openai

# embedding_utils의 새로운 기능들 임포트
from .embedding_utils import (
    get_embedding_model,
    encode_texts,
    search_top_policies,
    hybrid_search,
    cosine_similarity,
    clear_model_cache,
    get_embedding_dimension,
    validate_embeddings,
    SENTENCE_TRANSFORMERS_AVAILABLE
)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== 데이터 모델 ====================

@dataclass
class SecurityPolicy:
    """보안 정책 (불변성 추가)"""
    id: str
    title: str
    content: str
    severity: str  # critical, high, medium, low
    keywords: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """유효성 검증"""
        valid_severities = ['critical', 'high', 'medium', 'low']
        if self.severity not in valid_severities:
            raise ValueError(f"severity는 {valid_severities} 중 하나여야 합니다")
        if not self.keywords:
            logger.warning(f"정책 {self.id}에 키워드가 없습니다")
    
    def __hash__(self):
        """해싱 가능하도록 (캐싱용)"""
        return hash(self.id)


class AnalysisResult(BaseModel):
    """분석 결과 (검증 강화)"""
    text: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: str
    violations: List[str] = Field(default_factory=list)
    threats: List[str] = Field(default_factory=list)
    explanation: str
    related_policies: List[str] = Field(default_factory=list)
    policy_similarities: Dict[str, float] = Field(default_factory=dict)  # 신규 추가
    processing_time: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    
    @validator('risk_level')
    def validate_risk_level(cls, v):
        """위험도 레벨 검증"""
        valid_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        if v not in valid_levels:
            raise ValueError(f"risk_level은 {valid_levels} 중 하나여야 합니다")
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# ==================== 유틸리티 함수 ====================

def load_policies(json_path: str) -> List[SecurityPolicy]:
    """정책 로드 (에러 처리 강화)"""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"보안 정책 JSON 파일을 찾을 수 없습니다: {json_path}")
    
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            raise ValueError("정책 JSON은 리스트 형태여야 합니다")
        
        policies = [SecurityPolicy(**p) for p in data]
        logger.info(f"✅ {len(policies)}개 정책 로드 완료: {json_path}")
        return policies
        
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON 파싱 오류: {e}")
    except Exception as e:
        raise Exception(f"정책 로드 실패: {e}")


# ==================== 메인 분석기 ====================

class RAGSecurityAnalyzer:
    """RAG 기반 보안 분석기 (최종 최적화 버전)"""
    
    # 클래스 레벨 상수
    THREAT_PATTERNS = {
        '퇴사': ('내부자 위협 - 퇴사', 30),
        '이직': ('내부자 위협 - 이직', 25),
        '경쟁사': ('정보 유출 위험', 35),
        '다운로드': ('데이터 반출', 20),
        'USB': ('외부 반출', 20),
        '클라우드': ('외부 클라우드 공유', 30),
        '개인정보': ('개인정보 침해', 25),
        '주민등록번호': ('개인정보 침해', 25),
        '핵심기술': ('기술 유출', 40),
        '설계도': ('기밀 설계도 유출', 35),
        'R&D': ('연구개발 자료 유출', 30),
        '고객리스트': ('영업비밀 침해', 25),
        '가격정책': ('영업비밀 침해', 20),
        '마케팅전략': ('영업 전략 유출', 20),
        '판매전략': ('영업 전략 유출', 20),
        '비인가': ('비인가 접근', 15),
        '권한': ('권한 남용', 15),
        '로그인': ('시스템 접근 위험', 10),
        '이메일': ('외부 전송 위험', 15),
        '메신저': ('외부 전송 위험', 15),
    }
    
    SEVERITY_MULTIPLIER = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.8
    }
    
    SEVERITY_POINTS = {
        'critical': 30,
        'high': 20,
        'medium': 10,
        'low': 5
    }
    
    def __init__(
        self,
        policies: List[SecurityPolicy],
        api_key: Optional[str] = None,
        use_llm: bool = True,
        use_embeddings: bool = True,
        search_mode: str = "hybrid",  # "embedding", "keyword", "hybrid"
        verbose: bool = True,
        cache_size: int = 128
    ):
        """
        초기화
        
        Args:
            policies: 보안 정책 리스트
            api_key: OpenAI API 키
            use_llm: LLM 사용 여부
            use_embeddings: 임베딩 사용 여부
            search_mode: 검색 모드 ("embedding"|"keyword"|"hybrid")
            verbose: 상세 로그 출력
            cache_size: LRU 캐시 크기
        """
        if not policies:
            raise ValueError("최소 1개 이상의 정책이 필요합니다")
        
        self.policies = policies
        self.use_llm = use_llm
        self.use_embeddings = use_embeddings and SENTENCE_TRANSFORMERS_AVAILABLE
        self.search_mode = search_mode
        self.verbose = verbose
        self.cache_size = cache_size
        
        # 통계 추적
        self.stats = {
            'total_analyzed': 0,
            'llm_calls': 0,
            'rule_based_calls': 0,
            'cache_hits': 0,
            'errors': 0,
            'avg_policy_similarity': 0.0  # 신규 추가
        }
        
        # API 키 설정
        if api_key:
            os.environ['OPENAI_API_KEY'] = api_key
        self.api_key = os.getenv('OPENAI_API_KEY')
        
        # 임베딩 모델 준비
        if self.use_embeddings:
            try:
                logger.info("🔧 임베딩 모델 초기화 중...")
                self.embedding_model = get_embedding_model()
                
                if self.embedding_model is None:
                    raise Exception("임베딩 모델 로드 실패")
                
                # 정책 임베딩 생성
                policy_texts = [f"{p.title}. {p.content}" for p in self.policies]
                self.policy_embeddings = encode_texts(
                    policy_texts,
                    model=self.embedding_model,
                    batch_size=32,
                    show_progress=False,
                    normalize=True
                )
                
                # 임베딩 검증
                expected_dim = get_embedding_dimension(self.embedding_model)
                if not validate_embeddings(self.policy_embeddings, expected_dim):
                    raise Exception("임베딩 검증 실패")
                
                logger.info(f"✅ 임베딩 초기화 완료 (차원: {expected_dim})")
                
            except Exception as e:
                logger.warning(f"⚠️ 임베딩 초기화 실패: {e}, 키워드 검색 사용")
                self.use_embeddings = False
                self.search_mode = "keyword"
        
        # LLM 초기화
        if self.use_llm:
            if self.api_key:
                openai.api_key = self.api_key
                logger.info("✅ OpenAI LLM 모드 활성화")
            else:
                logger.warning("⚠️ API 키 없음, 규칙 기반 모드 사용")
                self.use_llm = False
        
        # 검색 모드 검증
        if self.search_mode not in ["embedding", "keyword", "hybrid"]:
            logger.warning(f"잘못된 검색 모드: {self.search_mode}, 'hybrid'로 변경")
            self.search_mode = "hybrid"
        
        if self.search_mode in ["embedding", "hybrid"] and not self.use_embeddings:
            logger.warning("임베딩 비활성화, 검색 모드를 'keyword'로 변경")
            self.search_mode = "keyword"
        
        # 캐시 초기화
        self._search_policies_cached = lru_cache(maxsize=cache_size)(
            self._search_policies_impl
        )
        
        logger.info(f"✅ 분석기 준비 완료! (검색 모드: {self.search_mode})\n")
    
    def _search_policies_impl(self, text: str) -> Tuple:
        """정책 검색 (캐싱용 내부 메서드)"""
        if self.search_mode == "hybrid":
            # 하이브리드 검색 (최고 성능)
            results = hybrid_search(
                text,
                self.policies,
                self.policy_embeddings,
                top_k=3,
                embedding_weight=0.7,
                keyword_weight=0.3,
                model=self.embedding_model,
                return_scores=True
            )
            return tuple(results)
            
        elif self.search_mode == "embedding":
            # 순수 임베딩 검색
            results = search_top_policies(
                text,
                self.policies,
                self.policy_embeddings,
                top_k=3,
                min_similarity=0.0,
                model=self.embedding_model,
                return_scores=True
            )
            return tuple(results)
            
        else:  # keyword
            # 키워드 검색
            from .embedding_utils import keyword_based_search
            results = keyword_based_search(
                text,
                self.policies,
                top_k=3,
                return_scores=True
            )
            return tuple(results)
    
    def _search_policies(self, text: str) -> List[Tuple[SecurityPolicy, float]]:
        """정책 검색 (캐시 활용, 점수 포함)"""
        cache_info_before = self._search_policies_cached.cache_info()
        result = self._search_policies_cached(text)
        cache_info_after = self._search_policies_cached.cache_info()
        
        # 캐시 히트 확인
        if cache_info_after.hits > cache_info_before.hits:
            self.stats['cache_hits'] += 1
            if self.verbose:
                logger.debug("💾 캐시 히트")
        
        return list(result)
    
    def analyze(self, text: str) -> AnalysisResult:
        """
        텍스트 분석 (성능 모니터링 추가)
        
        Args:
            text: 분석할 텍스트
            
        Returns:
            AnalysisResult: 분석 결과
        """
        start_time = datetime.now()
        
        try:
            # 입력 검증
            if not text or not text.strip():
                raise ValueError("분석할 텍스트가 비어있습니다")
            
            # 정책 검색 (점수 포함)
            policy_results = self._search_policies(text)
            policies = [policy for policy, _ in policy_results]
            similarities = {policy.id: score for policy, score in policy_results}
            
            # 평균 유사도 추적
            if similarities:
                avg_sim = sum(similarities.values()) / len(similarities)
                self.stats['avg_policy_similarity'] = (
                    self.stats['avg_policy_similarity'] * self.stats['total_analyzed'] + avg_sim
                ) / (self.stats['total_analyzed'] + 1)
            
            if self.verbose:
                logger.info(f"📚 관련 정책 {len(policies)}개:")
                for policy, score in policy_results:
                    logger.info(f"   {score:.3f} - [{policy.id}] {policy.title}")
            
            # 분석 수행
            if self.use_llm:
                result = self._analyze_with_llm(text, policies)
                self.stats['llm_calls'] += 1
            else:
                result = self._analyze_with_rules(text, policies, similarities)
                self.stats['rule_based_calls'] += 1
            
            # 메타데이터 추가
            result.related_policies = [p.id for p in policies]
            result.policy_similarities = similarities
            result.processing_time = (datetime.now() - start_time).total_seconds()
            
            self.stats['total_analyzed'] += 1
            
            return result
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ 분석 오류: {e}", exc_info=True)
            
            # 안전한 기본 결과 반환
            return AnalysisResult(
                text=text,
                risk_score=0.0,
                risk_level='LOW',
                explanation=f"분석 중 오류 발생: {str(e)}",
                processing_time=(datetime.now() - start_time).total_seconds()
            )
    
    def _analyze_with_llm(
        self,
        text: str,
        policies: List[SecurityPolicy]
    ) -> AnalysisResult:
        """LLM 기반 분석 (재시도 로직 추가)"""
        policy_context = "\n".join([
            f"[{p.id}] {p.title} ({p.severity}): {p.content}"
            for p in policies
        ])
        
        prompt = f"""당신은 보안 전문가입니다. 다음 텍스트를 분석하세요.

관련 보안 정책:
{policy_context}

분석할 텍스트:
"{text}"

JSON 형식으로 응답하세요:
{{
    "risk_score": <0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "violations": ["위반된 정책 ID들"],
    "threats": ["탐지된 위협들"],
    "explanation": "분석 설명"
}}"""

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.verbose:
                    logger.info(f"📞 LLM 호출 (시도 {attempt + 1}/{max_retries})")
                
                response = openai.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "system",
                            "content": "보안 분석 전문가. 요청된 JSON 스키마만 응답."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    response_format={"type": "json_object"},
                    timeout=30
                )
                
                result_dict = json.loads(response.choices[0].message.content)
                
                # 결과 검증
                if not all(k in result_dict for k in ['risk_score', 'risk_level']):
                    raise ValueError("응답에 필수 필드가 없습니다")
                
                return AnalysisResult(text=text, **result_dict)
                
            except openai.APIError as e:
                logger.warning(f"⚠️ OpenAI API 오류 (시도 {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    logger.error("❌ LLM 호출 실패, 규칙 기반으로 전환")
                    return self._analyze_with_rules(text, policies, {})
                continue
                
            except Exception as e:
                logger.error(f"❌ 예상치 못한 오류: {e}")
                return self._analyze_with_rules(text, policies, {})
    
    def _analyze_with_rules(
        self,
        text: str,
        policies: List[SecurityPolicy],
        similarities: Dict[str, float]
    ) -> AnalysisResult:
        """규칙 기반 분석 (유사도 점수 반영)"""
        violations = []
        threats = []
        score = 0.0
        
        # 위협 탐지
        detected_keywords = []
        for keyword, (threat, points) in self.THREAT_PATTERNS.items():
            if keyword in text:
                threats.append(threat)
                score += points
                detected_keywords.append(keyword)
        
        # 정책 위반 확인 (유사도 가중치 적용)
        for policy in policies:
            matched_keywords = [kw for kw in policy.keywords if kw in text]
            
            if matched_keywords:
                violations.append(policy.id)
                
                # 기본 점수
                base_points = self.SEVERITY_POINTS.get(policy.severity, 10)
                multiplier = self.SEVERITY_MULTIPLIER.get(policy.severity, 1.0)
                
                # 키워드 매칭 비율
                match_ratio = len(matched_keywords) / max(len(policy.keywords), 1)
                
                # 유사도 가중치 (있으면 적용)
                similarity_weight = similarities.get(policy.id, 0.5)
                
                # 최종 점수 = 기본점수 × 심각도 × 매칭비율 × 유사도
                policy_score =  base_points * multiplier * (0.8 + similarity_weight * 0.7) * (0.6 + match_ratio * 0.4)
                score += policy_score
                
                if self.verbose:
                    logger.debug(
                        f"정책 {policy.id}: "
                        f"base={base_points}, mult={multiplier:.1f}, "
                        f"match={match_ratio:.2f}, sim={similarity_weight:.2f} "
                        f"→ {policy_score:.1f}점"
                    )
        
        # 점수 정규화 및 레벨 결정
        score = min(score, 100.0)
        
        if score >= 60:
            level = "CRITICAL"
        elif score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        # 설명 생성
        explanation_parts = []
        if threats:
            explanation_parts.append(f"{len(threats)}개 위협 탐지")
        if violations:
            explanation_parts.append(f"{len(violations)}개 정책 위반")
        if detected_keywords:
            explanation_parts.append(f"주요 키워드: {', '.join(detected_keywords[:5])}")
        if similarities:
            avg_sim = sum(similarities.values()) / len(similarities)
            explanation_parts.append(f"평균 정책 유사도: {avg_sim:.2f}")
        
        explanation = " | ".join(explanation_parts) if explanation_parts else "위협 없음"
        
        return AnalysisResult(
            text=text,
            risk_score=round(score, 1),
            risk_level=level,
            violations=violations,
            threats=threats,
            explanation=explanation
        )
    
    async def analyze_async(self, text: str) -> AnalysisResult:
        """비동기 분석"""
        return await asyncio.to_thread(self.analyze, text)
    
    async def analyze_batch_async(
        self,
        texts: List[str],
        max_concurrent: int = 5
    ) -> List[AnalysisResult]:
        """비동기 배치 분석 (동시 실행 수 제어)"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_with_limit(text: str) -> AnalysisResult:
            async with semaphore:
                return await self.analyze_async(text)
        
        tasks = [analyze_with_limit(text) for text in texts]
        return await asyncio.gather(*tasks, return_exceptions=False)
    
    def analyze_batch(self, texts: List[str]) -> List[AnalysisResult]:
        """동기 배치 분석"""
        return [self.analyze(t) for t in texts]
    
    def print_result(self, result: AnalysisResult):
        """결과 출력 (유사도 점수 추가)"""
        emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }[result.risk_level]
        
        print("=" * 80)
        print(f"🛡️  보안 분석 결과")
        print("=" * 80)
        print(f"\n📝 텍스트: {result.text}")
        print(f"🕒 분석 시간: {result.processing_time:.3f}초")
        print(f"📅 타임스탬프: {result.timestamp}\n")
        print(f"{emoji} 위험도: {result.risk_score:.1f}/100 ({result.risk_level})")
        print(f"\n📊 분석 결과:")
        print(f"   • 정책 위반: {len(result.violations)}건")
        if result.violations:
            print(f"     → {', '.join(result.violations)}")
        print(f"   • 위협 징후: {len(result.threats)}건")
        if result.threats:
            for i, threat in enumerate(result.threats[:5], 1):
                print(f"     {i}. {threat}")
        print(f"   • 참조 정책: {', '.join(result.related_policies)}")
        
        # 유사도 점수 출력
        if result.policy_similarities:
            print(f"\n🔍 정책 유사도:")
            for policy_id, sim in sorted(
                result.policy_similarities.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                print(f"     {policy_id}: {sim:.3f}")
        
        print(f"\n💡 설명: {result.explanation}")
        print("\n" + "=" * 80 + "\n")
    
    def get_statistics(self) -> Dict:
        """분석 통계 반환"""
        cache_info = self._search_policies_cached.cache_info()
        
        return {
            **self.stats,
            'search_mode': self.search_mode,
            'cache_info': {
                'hits': cache_info.hits,
                'misses': cache_info.misses,
                'size': cache_info.currsize,
                'max_size': cache_info.maxsize,
                'hit_rate': (cache_info.hits / max(cache_info.hits + cache_info.misses, 1)) * 100
            }
        }
    
    def print_statistics(self):
        """통계 출력"""
        stats = self.get_statistics()
        
        print("\n" + "=" * 80)
        print("📊 분석 통계")
        print("=" * 80)
        print(f"검색 모드: {stats['search_mode']}")
        print(f"총 분석: {stats['total_analyzed']}건")
        print(f"LLM 사용: {stats['llm_calls']}건")
        print(f"규칙 기반: {stats['rule_based_calls']}건")
        print(f"오류: {stats['errors']}건")
        print(f"평균 정책 유사도: {stats['avg_policy_similarity']:.3f}")
        print(f"\n캐시 성능:")
        print(f"  히트: {stats['cache_info']['hits']}회")
        print(f"  미스: {stats['cache_info']['misses']}회")
        print(f"  히트율: {stats['cache_info']['hit_rate']:.1f}%")
        print(f"  현재 크기: {stats['cache_info']['size']}/{stats['cache_info']['max_size']}")
        print("=" * 80 + "\n")
    
    def export_results(
        self,
        results: List[AnalysisResult],
        filepath: str,
        format: str = 'json'
    ):
        """결과 내보내기"""
        try:
            if format == 'json':
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(
                        [r.dict() for r in results],
                        f,
                        ensure_ascii=False,
                        indent=2
                    )
            elif format == 'csv':
                import csv
                with open(filepath, 'w', encoding='utf-8', newline='') as f:
                    if results:
                        writer = csv.DictWriter(f, fieldnames=results[0].dict().keys())
                        writer.writeheader()
                        for r in results:
                            writer.writerow(r.dict())
            
            logger.info(f"💾 결과 저장 완료: {filepath}")
            
        except Exception as e:
            logger.error(f"결과 저장 실패: {e}")
    
    def cleanup(self):
        """리소스 정리"""
        clear_model_cache()
        self._search_policies_cached.cache_clear()
        logger.info("🧹 리소스 정리 완료")

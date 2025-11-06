"""
RAG Security Analyzer - Main Analyzer
Main security analyzer with Self-RAG integration
"""

import json
import logging
import os
import re
import time
from collections import deque
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Optional, Union

from .models import (
    AnalysisResult, SelfRAGResult, ScoreBreakdown,
    SecurityPolicy, RelevanceScore,
    get_analysis_result, is_self_rag_result
)
from .retriever import (
    BM25, get_embedding_model, encode_texts,
    hybrid_search, SENTENCE_TRANSFORMERS_AVAILABLE
)
from .memory import ContextMemorySystem, RelationshipAnalyzer
from .explainer import ExplainableAI
from .utils import LanguageDetector, sanitize_prompt_input, sanitize_input
from .self_rag import SelfRAGEngine
from .models import RetrievalNeed, SupportLevel, UtilityScore
from .config import AnalyzerConfig, DEFAULT_ANALYZER_CONFIG

logger = logging.getLogger(__name__)

# Check OpenAI availability
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except (ImportError, ModuleNotFoundError) as e:
    OPENAI_AVAILABLE = False
    logger.warning(f"OpenAI module not available: {e}")


# ============================================================
# Advanced RAG Analyzer
# ============================================================

class AdvancedRAGAnalyzer:
    """
    Advanced RAG Security Analyzer with Self-RAG Integration (v3.0)

    A comprehensive security analysis framework combining Self-RAG meta-evaluation,
    hybrid semantic retrieval, and explainable AI for insider threat detection.

    Features:
        - Self-RAG: 5-stage meta-evaluation pipeline
        - Hybrid Search: Semantic (85%) + BM25 (10%) + Keyword (5%)
        - Pattern Detection: 900+ security keywords (multi-language)
        - Explainable AI: LIME-inspired factor attribution
        - Context Memory: User behavior profiling
        - Relationship Analysis: Multi-event correlation

    Example:
        >>> policies = [SecurityPolicy(id="P1", title="Data Loss", ...)]
        >>> analyzer = AdvancedRAGAnalyzer(policies, api_key="sk-...")
        >>> result = analyzer.analyze("password leak", user_id="user123")
        >>> print(f"Risk: {result.risk_score}/100")
    """

    def __init__(
        self,
        policies: List[SecurityPolicy],
        api_key: Optional[str] = None,
        use_llm: bool = True,
        use_embeddings: bool = True,
        enable_advanced: bool = True,
        enable_bm25: bool = True,
        enable_self_rag: bool = True,
        config: AnalyzerConfig = None
    ):
        """
        Initialize the Advanced RAG Analyzer.

        Args:
            policies: List of security policies for analysis
            api_key: OpenAI API key (optional, uses env var if not provided)
            use_llm: Enable LLM-based analysis
            use_embeddings: Enable semantic search
            enable_advanced: Enable context memory and relationship analysis
            enable_bm25: Enable BM25 keyword search
            enable_self_rag: Enable Self-RAG meta-evaluation
            config: Custom configuration (uses defaults if None)
        """
        # Basic initialization
        self._initialize_basic_components(
            policies, config, use_llm, use_embeddings,
            enable_bm25, enable_self_rag, enable_advanced
        )

        # API key setup
        self._setup_api_key(api_key)

        # Initialize Self-RAG engine
        if self.enable_self_rag:
            self.self_rag_engine = SelfRAGEngine(self, use_llm=self.use_llm)

        # Initialize search components (embeddings + BM25)
        self._initialize_search_components(policies)

        # Initialize LLM
        self._initialize_llm()

        # Setup cache and finalize
        self._search_cached = lru_cache(maxsize=self.config.CACHE_SIZE)(self._search_impl)

        version = "v3.0 (Self-RAG)" if self.enable_self_rag else "v2.5"
        logger.info(f"✅ Analyzer {version} ready")

    def _initialize_basic_components(
        self,
        policies: List[SecurityPolicy],
        config: Optional[AnalyzerConfig],
        use_llm: bool,
        use_embeddings: bool,
        enable_bm25: bool,
        enable_self_rag: bool,
        enable_advanced: bool
    ):
        """Initialize basic components and settings"""
        self.policies = policies
        self.config = config or DEFAULT_ANALYZER_CONFIG
        self.use_llm = use_llm and OPENAI_AVAILABLE
        self.use_embeddings = use_embeddings and SENTENCE_TRANSFORMERS_AVAILABLE
        self.enable_bm25 = enable_bm25
        self.enable_self_rag = enable_self_rag
        self.stats = {
            'total': 0, 'llm': 0, 'rule': 0, 'errors': 0,
            'self_rag': 0, 'self_rag_skipped': 0
        }

        # Initialize advanced components if enabled
        self.context_memory = ContextMemorySystem() if enable_advanced else None
        self.relationship_analyzer = RelationshipAnalyzer() if enable_advanced else None
        self.language_detector = LanguageDetector() if enable_advanced else None
        self.analysis_history = deque(maxlen=self.config.MAX_HISTORY_SIZE)

    def _setup_api_key(self, api_key: Optional[str]):
        """Setup API key from parameter or environment"""
        if api_key:
            self._api_key = api_key
            logger.info("API key provided via parameter")
        else:
            self._api_key = os.getenv('OPENAI_API_KEY', '')
            if self._api_key:
                logger.info("API key loaded from environment")
            else:
                logger.warning("No API key found - LLM features will be disabled")

    def _initialize_search_components(self, policies: List[SecurityPolicy]):
        """Initialize embedding model and BM25 for hybrid search"""
        if not self.use_embeddings:
            return

        try:
            self.embedding_model = get_embedding_model()
            if self.embedding_model:
                policy_texts = [
                    f"{p.title}. {p.content}. {' '.join(p.keywords)}"
                    for p in policies
                ]
                self.policy_embeddings = encode_texts(policy_texts, self.embedding_model)

                if self.enable_bm25:
                    self.bm25_model = BM25()
                    self.bm25_model.fit(policy_texts)
                    logger.info("✅ Hybrid Search (Semantic + BM25 + Keyword) ready")
                else:
                    self.bm25_model = None
            else:
                self.use_embeddings = False
                self.bm25_model = None
        except (RuntimeError, ValueError, OSError) as e:
            logger.warning(f"Embedding initialization failed: {e}")
            self.use_embeddings = False
            self.bm25_model = None

    def _initialize_llm(self):
        """Initialize OpenAI LLM client"""
        if self.use_llm and self._api_key:
            # Initialize OpenAI client (avoids global state modification)
            self.openai_client = OpenAI(api_key=self._api_key)
            logger.info("✅ LLM ready")
        else:
            self.use_llm = False
            self.openai_client = None
    
    def _search_impl(self, text: str):
        """Hybrid Search"""
        if self.use_embeddings:
            results = hybrid_search(text, self.policies, self.policy_embeddings,
                                  self.embedding_model, self.bm25_model)
            return tuple([(r[0], r[1]) for r in results])
        
        # Fallback
        text_lower = text.lower()
        scored = []
        for p in self.policies:
            match = sum(1 for kw in p.keywords if kw.lower() in text_lower)
            if match > 0:
                scored.append((p, match / max(len(p.keywords), 1)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return tuple(scored[:3])
    
    def analyze(
        self,
        text: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        use_self_rag: Optional[bool] = None
    ) -> Union[AnalysisResult, SelfRAGResult]:
        """
        Analyze text for security threats and policy violations.

        Performs comprehensive security analysis using Self-RAG, hybrid retrieval,
        pattern detection, and LLM/rule-based evaluation. Supports context-aware
        analysis with user behavior profiling.

        Args:
            text: Text to analyze (max 10,000 characters)
            user_id: User identifier for context tracking (optional)
            session_id: Session identifier for grouping analyses (optional)
            use_self_rag: Override Self-RAG setting (None=use global config)

        Returns:
            SelfRAGResult if Self-RAG enabled, otherwise AnalysisResult
            Contains: risk_score (0-100), risk_level, violations, threats,
                     explanation, confidence_score, and XAI data

        Raises:
            ValueError: If text is empty

        Example:
            >>> result = analyzer.analyze("password leaked to external")
            >>> print(f"{result.risk_level}: {result.risk_score}/100")
            CRITICAL: 85.0/100
            >>> print(f"Confidence: {result.confidence_score:.0%}")
            Confidence: 92%
        """
        # Sanitize input to prevent injection attacks
        text = sanitize_input(text, max_length=self.config.MAX_INPUT_LENGTH)

        # Validate sanitized input
        if not text or not text.strip():
            raise ValueError("Text is empty or invalid after sanitization")

        should_use_self_rag = use_self_rag if use_self_rag is not None else self.enable_self_rag
        
        if should_use_self_rag and self.enable_self_rag:
            return self._analyze_with_self_rag(text, user_id, session_id)
        else:
            return self._analyze_standard(text, user_id, session_id)
    
    def _analyze_with_self_rag(
        self,
        text: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """v3.0: Self-RAG 파이프라인"""
        start = datetime.now()
        
        try:
            # Step 1: 검색 필요성 판단
            retrieval_need = self.self_rag_engine.assess_retrieval_need(text)
            
            if retrieval_need == RetrievalNeed.NOT_NEEDED:
                result = self._direct_analysis(text, user_id, session_id)
                self.stats['self_rag_skipped'] += 1
                
                return SelfRAGResult(
                    original_result=result,
                    retrieval_need=retrieval_need,
                    relevance_scores={},
                    support_level=SupportLevel.NO_SUPPORT,
                    utility_score=UtilityScore.MODERATELY_USEFUL,
                    reflection_notes=["No retrieval needed"],
                    confidence_boost=0.0
                )
            
            # Step 2: 표준 분석 (검색 포함)
            result = self._analyze_standard(text, user_id, session_id)
            
            # Step 3: 관련성 평가
            relevance_scores = self.self_rag_engine.assess_relevance(text, result)
            
            # Step 4: 지원도 평가
            support_level = self.self_rag_engine.assess_support(result, relevance_scores)
            
            # Step 5: 유용성 평가
            utility_score = self.self_rag_engine.assess_utility(result, support_level)
            
            # 반성 노트 생성
            reflection_notes = self.self_rag_engine.generate_reflection(
                retrieval_need, relevance_scores, support_level, utility_score
            )
            
            # 신뢰도 증가
            confidence_boost = self.self_rag_engine.calculate_confidence_boost(
                relevance_scores, support_level, utility_score
            )
            
            result.confidence_score = min(result.confidence_score + confidence_boost, 1.0)
            result.processing_time = (datetime.now() - start).total_seconds()
            
            self.stats['self_rag'] += 1
            self.stats['total'] += 1
            
            return SelfRAGResult(
                original_result=result,
                retrieval_need=retrieval_need,
                relevance_scores=relevance_scores,
                support_level=support_level,
                utility_score=utility_score,
                reflection_notes=reflection_notes,
                confidence_boost=confidence_boost
            )
        
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Self-RAG error: {e}")
            return self._analyze_standard(text, user_id, session_id)
    
    def _analyze_standard(
        self,
        text: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """표준 분석 (v2.5 방식)"""
        start = datetime.now()
        event_id = f"EVT_{int(time.time()*1000)}"
        
        try:
            if not text.strip():
                raise ValueError("Empty text")
            
            detected_lang = 'unknown'
            if self.language_detector:
                detected_lang = self.language_detector.detect_language(text)
            
            policy_results = list(self._search_cached(text))
            policies = [p for p, _ in policy_results]
            similarities = {p.id: s for p, s in policy_results}
            
            if self.use_llm:
                result = self._analyze_llm(text, policies)
                self.stats['llm'] += 1
            else:
                result = self._analyze_rules(text, policies, similarities, detected_lang)
                self.stats['rule'] += 1
            
            result.user_id = user_id
            result.session_id = session_id
            result.detected_language = detected_lang
            result.related_policies = [p.id for p in policies]
            result.policy_similarities = similarities
            result.processing_time = (datetime.now() - start).total_seconds()
            
            if self.context_memory and user_id:
                adj = self.context_memory.get_context_adjustment(user_id, result.risk_score)
                if adj != 0:
                    result.risk_score = min(result.risk_score + adj, 100)
                    result.context_adjusted = True
                self.context_memory.update_user_context(user_id, result)
            
            breakdown = self._create_breakdown(result, similarities)
            similar = self._find_similar(result, 3)
            result.explanation_data = ExplainableAI.generate_explanation(result, breakdown, similar)
            
            result.confidence_score = self._calc_confidence(result, similarities)
            result.remediation_suggestions = self._get_remediation(result, policies)
            
            if self.relationship_analyzer:
                self.relationship_analyzer.add_event(event_id, result)
                self.relationship_analyzer.build_relationships()
            
            self.stats['total'] += 1
            self.analysis_history.append(result)
            
            return result
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Analysis error: {type(e).__name__}: {str(e)}", exc_info=True)
            return AnalysisResult(
                text=text, risk_score=0, risk_level='LOW',
                explanation="Analysis failed due to internal error. Please contact support.",
                processing_time=(datetime.now() - start).total_seconds(),
                user_id=user_id
            )
    
    def _direct_analysis(
        self,
        text: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """검색 없는 직접 분석"""
        risk_score = 10.0
        threats = []
        
        dangerous = {'hack': 20, 'crack': 20, 'steal': 15, 'breach': 25}
        text_lower = text.lower()
        for pattern, points in dangerous.items():
            if pattern in text_lower:
                risk_score += points
                threats.append(f"Detected: {pattern}")
        
        risk_level = "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 30 else "LOW"
        
        return AnalysisResult(
            text=text,
            risk_score=min(risk_score, 100),
            risk_level=risk_level,
            threats=threats,
            explanation="Direct analysis",
            user_id=user_id,
            session_id=session_id
        )
    
    def _create_breakdown(self, result, similarities):
        """점수 세부 분석 생성"""
        breakdown = ScoreBreakdown()
        patterns = self.language_detector.get_patterns(result.detected_language) if self.language_detector else {}
        for threat in result.threats:
            for kw, (desc, pts) in patterns.items():
                if desc in threat:
                    breakdown.keyword_matches[kw] = float(pts)
        for pid, sim in similarities.items():
            if pid in result.violations:
                p = next(p for p in self.policies if p.id == pid)
                score = (
                    self.config.SEVERITY_POINTS.get(p.severity, 10) *
                    self.config.SEVERITY_MULTIPLIERS.get(p.severity, 1.0) *
                    sim
                )
                breakdown.policy_similarities[pid] = score
        breakdown.final_score = result.risk_score
        return breakdown
    
    def _find_similar(self, current, top_k: int = 3):
        """유사 케이스 찾기"""
        if not self.analysis_history:
            return []
        scored = []
        for past in self.analysis_history:
            past_analysis = get_analysis_result(past)
            current_analysis = get_analysis_result(current)
            if past_analysis.text == current_analysis.text:
                continue
            sim = ExplainableAI._calc_similarity(current_analysis, past_analysis)
            if sim > 0.3:
                scored.append((sim, past))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [case for _, case in scored[:top_k]]
    
    def _calc_confidence(self, result, similarities):
        """신뢰도 계산"""
        conf = 0.5
        if similarities:
            conf += sum(similarities.values()) / len(similarities) * 0.3
        if result.violations:
            conf += min(len(result.violations) * 0.1, 0.2)
        return min(conf, 1.0)
    
    def _get_remediation(self, result, policies):
        """교정 제안 생성"""
        suggestions = []
        for p in policies:
            if p.id in result.violations and p.remediation_steps:
                suggestions.extend(p.remediation_steps[:2])
        if not suggestions and result.risk_level in ['CRITICAL', 'HIGH']:
            suggestions.append("즉시 보안팀에 보고하세요")
        return suggestions[:5]
    
    def _analyze_llm(self, text: str, policies: List[SecurityPolicy]):
        """LLM 기반 분석"""
        # 입력 sanitization (프롬프트 인젝션 방지)
        sanitized_text = sanitize_prompt_input(
            text,
            max_length=self.config.MAX_INPUT_LENGTH
        )

        context = "\n".join([f"[{p.id}] {p.title}: {p.content}" for p in policies[:10]])  # 최대 10개 정책
        prompt = f"""Security expert. Analyze:

Policies:
{context}

Text: "{sanitized_text}"

JSON:
{{
    "risk_score": <0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "violations": ["ids"],
    "threats": ["descriptions"],
    "explanation": "why"
}}"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Security expert. JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
                timeout=30
            )
            result_dict = json.loads(response.choices[0].message.content)
            return AnalysisResult(text=text, **result_dict)
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return self._analyze_rules(text, policies, {}, 'unknown')
    
    def _analyze_rules(
        self,
        text: str,
        policies: List[SecurityPolicy],
        similarities: Dict[str, float],
        language: str
    ) -> AnalysisResult:
        """규칙 기반 분석"""
        violations, threats, score = [], [], 0.0
        text_lower = text.lower()
        keywords = []
        
        patterns = self.language_detector.get_patterns(language) if self.language_detector else {}
        
        for kw, (threat, pts) in patterns.items():
            if re.search(r'\b' + re.escape(kw.lower()) + r'\b', text_lower):
                threats.append(threat)
                score += pts
                keywords.append(kw)
        
        for policy in policies:
            matched = [k for k in policy.keywords if re.search(r'\b' + re.escape(k.lower()) + r'\b', text_lower)]
            if matched:
                violations.append(policy.id)
                base = self.config.SEVERITY_POINTS.get(policy.severity, 10)
                mult = self.config.SEVERITY_MULTIPLIERS.get(policy.severity, 1.0)
                match_ratio = len(matched) / max(len(policy.keywords), 1)
                sim = similarities.get(policy.id, 0.5)
                score += base * mult * (0.8 + sim * 0.7) * (0.6 + match_ratio * 0.4)
        
        score = min(score, 100.0)
        level = (
            "CRITICAL" if score >= self.config.RISK_CRITICAL_THRESHOLD
            else "HIGH" if score >= self.config.RISK_HIGH_THRESHOLD
            else "MEDIUM" if score >= self.config.RISK_MEDIUM_THRESHOLD
            else "LOW"
        )
        
        exp_parts = []
        if threats:
            exp_parts.append(f"{len(threats)} threat(s)")
        if violations:
            exp_parts.append(f"{len(violations)} violation(s)")
        if keywords:
            exp_parts.append(f"Keywords: {', '.join(keywords[:5])}")
        
        return AnalysisResult(
            text=text, risk_score=round(score, 1), risk_level=level,
            violations=violations, threats=threats,
            explanation=" | ".join(exp_parts) if exp_parts else "No threats"
        )
    
    def analyze_batch(self, texts: List[str], user_ids: Optional[List[str]] = None, use_self_rag: Optional[bool] = None):
        """
        Batch analysis of multiple texts

        Args:
            texts: List of texts to analyze
            user_ids: Optional list of user IDs corresponding to each text
            use_self_rag: Override Self-RAG setting

        Returns:
            List of analysis results (AnalysisResult or SelfRAGResult)

        Raises:
            ValueError: If texts is empty or None
        """
        # Validate input
        if not texts:
            raise ValueError("Batch analysis requires at least one text")

        if user_ids is None:
            user_ids = [None] * len(texts)

        # Each text will be sanitized in analyze() method
        return [self.analyze(t, user_id=uid, use_self_rag=use_self_rag)
                for t, uid in zip(texts, user_ids)]
    
    def print_result(self, result, show_explanation: bool = True):
        """결과 출력"""
        # SelfRAGResult 처리
        if is_self_rag_result(result):
            self._print_self_rag_result(result, show_explanation)
            return
        
        # 표준 AnalysisResult
        analysis = get_analysis_result(result)
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[analysis.risk_level]
        version = "v3.0 (Self-RAG)" if self.enable_self_rag else "v2.5"
        
        print("="*80)
        print(f"🛡️  Analysis Result {version}")
        print("="*80)
        print(f"\n📝 Text: {analysis.text}")
        if analysis.user_id:
            print(f"👤 User: {analysis.user_id}")
        if analysis.detected_language != 'unknown':
            print(f"🌐 Language: {analysis.detected_language}")
        print(f"🕒 Time: {analysis.processing_time:.3f}s | 🎯 Confidence: {analysis.confidence_score:.0%}")
        if analysis.context_adjusted:
            print(f"📊 Context-adjusted")
        print(f"{emoji} Risk: {analysis.risk_score:.1f}/100 ({analysis.risk_level})")
        print(f"\n📊 Analysis:")
        print(f"   • Violations: {len(analysis.violations)}")
        if analysis.violations:
            print(f"     → {', '.join(analysis.violations)}")
        print(f"   • Threats: {len(analysis.threats)}")
        for i, t in enumerate(analysis.threats[:3], 1):
            print(f"     {i}. {t}")
        if analysis.remediation_suggestions:
            print(f"\n💡 Remediation:")
            for i, s in enumerate(analysis.remediation_suggestions[:3], 1):
                print(f"     {i}. {s}")
        print(f"\n💭 {analysis.explanation}")
        print("="*80 + "\n")
        
        if show_explanation and analysis.explanation_data:
            ExplainableAI.print_explanation(result)
    
    def _print_self_rag_result(self, self_rag_result: SelfRAGResult, show_explanation: bool = True):
        """Self-RAG 결과 출력"""
        result = self_rag_result.original_result
        
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[result.risk_level]
        
        print("\n" + "="*80)
        print("🧠 Self-RAG Analysis Result v3.0")
        print("="*80)
        
        print(f"\n📝 Text: {result.text}")
        if result.user_id:
            print(f"👤 User: {result.user_id}")
        if result.detected_language != 'unknown':
            print(f"🌐 Language: {result.detected_language}")
        print(f"🕒 Time: {result.processing_time:.3f}s")
        
        print(f"\n{emoji} Risk Assessment:")
        print(f"   Score: {result.risk_score:.1f}/100")
        print(f"   Level: {result.risk_level}")
        print(f"   Confidence: {result.confidence_score:.0%} (+{self_rag_result.confidence_boost:.1%} from Self-RAG)")
        
        print(f"\n🔍 Self-RAG Evaluation:")
        print(f"   Retrieval Need: {self_rag_result.retrieval_need.value}")
        print(f"   Support Level: {self_rag_result.support_level.value}")
        print(f"   Utility Score: {self_rag_result.utility_score.value}/5 {'★' * self_rag_result.utility_score.value}")
        
        if self_rag_result.relevance_scores:
            print(f"\n📊 Policy Relevance:")
            for policy_id, score in self_rag_result.relevance_scores.items():
                emoji_rel = {
                    RelevanceScore.HIGHLY_RELEVANT: "🟢",
                    RelevanceScore.RELEVANT: "🟡",
                    RelevanceScore.PARTIALLY_RELEVANT: "🟠",
                    RelevanceScore.NOT_RELEVANT: "🔴"
                }[score]
                print(f"   {emoji_rel} {policy_id}: {score.value}")
        
        if result.violations:
            print(f"\n⚠️  Violations ({len(result.violations)}):")
            for v in result.violations:
                print(f"   • {v}")
        
        if result.threats:
            print(f"\n🚨 Threats ({len(result.threats)}):")
            for i, t in enumerate(result.threats[:3], 1):
                print(f"   {i}. {t}")
        
        if result.remediation_suggestions:
            print(f"\n💡 Remediation:")
            for i, s in enumerate(result.remediation_suggestions[:3], 1):
                print(f"   {i}. {s}")
        
        if self_rag_result.reflection_notes:
            print(f"\n💭 Self-Reflection:")
            for note in self_rag_result.reflection_notes:
                print(f"   {note}")
        
        print("\n" + "="*80 + "\n")
        
        if show_explanation and result.explanation_data:
            ExplainableAI.print_explanation(result)
    
    def get_user_profile(self, user_id: str):
        """사용자 프로필 조회"""
        if not self.context_memory:
            return {'error': 'Context memory disabled'}
        return self.context_memory.get_user_summary(user_id)
    
    def detect_compound_threats(self):
        """복합 위협 탐지"""
        if not self.relationship_analyzer:
            return []
        return self.relationship_analyzer.detect_compound_threats()
    
    def visualize_relationships(self):
        """관계 그래프 시각화"""
        if self.relationship_analyzer:
            self.relationship_analyzer.visualize()
    
    def print_stats(self):
        """통계 출력"""
        version = "v3.0 (Self-RAG)" if self.enable_self_rag else "v2.5"
        print("\n" + "="*80)
        print(f"📊 Statistics {version}")
        print("="*80)
        print(f"Total: {self.stats['total']}")
        print(f"LLM: {self.stats['llm']}")
        print(f"Rule: {self.stats['rule']}")
        print(f"Errors: {self.stats['errors']}")
        
        if self.enable_self_rag:
            print(f"\n🧠 Self-RAG:")
            print(f"   With Self-RAG: {self.stats['self_rag']}")
            print(f"   Direct: {self.stats['self_rag_skipped']}")
        
        if self.context_memory:
            print(f"\n👥 Users: {len(self.context_memory.user_profiles)}")
        
        if self.relationship_analyzer:
            g = self.relationship_analyzer.event_graph
            print(f"🔗 Events: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

        print("="*80 + "\n")

    def cleanup_old_history(self, max_age_hours: int = 24) -> int:
        """
        Clean up old analysis history entries.

        Removes analysis results older than specified hours to free memory.
        Useful for long-running services to prevent memory bloat.

        Args:
            max_age_hours: Maximum age in hours (default: 24)

        Returns:
            Number of entries removed

        Example:
            >>> removed = analyzer.cleanup_old_history(max_age_hours=12)
            >>> print(f"Cleaned up {removed} old entries")
        """
        from datetime import timedelta

        if not self.analysis_history:
            return 0

        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        original_count = len(self.analysis_history)

        # Filter out old entries
        filtered = deque(
            (r for r in self.analysis_history
             if datetime.fromisoformat(get_analysis_result(r).timestamp) > cutoff),
            maxlen=self.config.MAX_HISTORY_SIZE
        )

        self.analysis_history = filtered
        removed = original_count - len(self.analysis_history)

        if removed > 0:
            logger.info(f"Cleaned up {removed} old analysis entries")

        return removed

    def clear_cache(self):
        """
        Clear all caches to free memory.

        Clears LRU cache and resets analysis history.
        Use with caution as this will impact performance temporarily.

        Example:
            >>> analyzer.clear_cache()
            >>> print("All caches cleared")
        """
        # Clear LRU cache
        if hasattr(self, '_search_cached'):
            self._search_cached.cache_clear()
            logger.info("Search cache cleared")

        # Clear analysis history
        original_size = len(self.analysis_history)
        self.analysis_history.clear()
        logger.info(f"Cleared {original_size} analysis history entries")

    def get_memory_usage(self) -> Dict[str, int]:
        """
        Get current memory usage statistics.

        Returns:
            Dictionary with memory usage information

        Example:
            >>> usage = analyzer.get_memory_usage()
            >>> print(f"History: {usage['history_count']} entries")
        """
        usage = {
            'history_count': len(self.analysis_history),
            'cache_size': self.config.CACHE_SIZE,
        }

        if self.context_memory:
            usage['user_profiles'] = len(self.context_memory.user_profiles)

        if self.relationship_analyzer:
            g = self.relationship_analyzer.event_graph
            usage['graph_nodes'] = g.number_of_nodes()
            usage['graph_edges'] = g.number_of_edges()

        return usage

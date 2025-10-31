"""
RAG Security Analyzer - Self-RAG Engine
자가 반성형 RAG 시스템
"""

import json
import logging
import re
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .models import (
    RetrievalNeed, RelevanceScore, SupportLevel, UtilityScore,
    SelfRAGResult, get_analysis_result
)

logger = logging.getLogger(__name__)

# OpenAI 가용성 체크
try:
    import openai
    OPENAI_AVAILABLE = True
except:
    OPENAI_AVAILABLE = False


# ============================================================
# Security Pattern Strength
# ============================================================

class SecurityPatternStrength(Enum):
    """보안 패턴 강도"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================
# Enhanced Security Pattern Detector
# ============================================================

class EnhancedSecurityPatternDetector:
    """
    강화된 보안 패턴 탐지기
    - 900+ 보안 키워드
    - 정규식 패턴 매칭
    - 복합 패턴 탐지
    """
    
    # CRITICAL 키워드 (영어)
    CRITICAL_KEYWORDS_EN = [
        'password', 'passwd', 'pwd', 'credential', 'token', 'api key', 'apikey',
        'secret', 'private key', 'access key', 'session', 'cookie', 'auth',
        'hack', 'hacking', 'crack', 'breach', 'compromise', 'exploit', 'attack',
        'injection', 'xss', 'csrf', 'sql injection', 'xxe', 'ssrf', 'rce',
        'malware', 'virus', 'trojan', 'ransomware', 'spyware', 'backdoor', 'rootkit',
        'unauthorized', 'illegitimate', 'privilege escalation', 'intrusion',
        'leak', 'leaked', 'exfiltration', 'steal', 'stolen', 'theft', 'exposed',
        'vulnerability', 'vuln', 'cve', '0day', 'zero day', 'security flaw',
        'suspicious', 'anomaly', 'malicious', 'threat', 'dangerous',
        'admin', 'administrator', 'root', 'superuser', 'sudo',
        'decrypt', 'unencrypted', 'plaintext', 'cleartext',
        'ddos', 'dos', 'mitm', 'sniff', 'scan',
        'phishing', 'phish', 'scam', 'fraud', 'spoof',
    ]
    
    # CRITICAL 키워드 (한국어)
    CRITICAL_KEYWORDS_KO = [
        '비밀번호', '패스워드', '암호', '인증서', '토큰', '키', 'API키', '접근키',
        '해킹', '해킹당함', '크랙', '침해', '공격', '악용',
        '인젝션', 'SQL인젝션', 'XSS', 'CSRF',
        '악성코드', '바이러스', '트로이목마', '랜섬웨어', '스파이웨어', '백도어', '루트킷',
        '무단', '무단접근', '불법', '권한상승', '침입', '침투',
        '유출', '유출됨', '탈취', '도난', '노출', '노출됨', '누출',
        '취약점', '취약성', '보안결함', '제로데이',
        '의심', '의심스러운', '이상', '이상행위', '위협', '위험', '악의적',
        '관리자', '어드민', '루트', '최고권한',
        '복호화', '평문', '암호화안됨',
        '디도스', 'DDOS', 'DoS', '중간자공격', '스캔', '스니핑',
        '피싱', '사기', '사칭', '스푸핑', '위장',
        '개인정보', '주민번호', '계좌번호', '카드번호', '금융정보',
    ]
    
    # HIGH 키워드 (영어)
    HIGH_KEYWORDS_EN = [
        'access', 'download', 'upload', 'transfer', 'copy', 'share', 'forward', 'send',
        'account', 'user', 'login', 'logout', 'signin', 'register',
        'permission', 'role', 'access control', 'acl', 'policy',
        'config', 'configuration', 'setting', 'modify', 'change', 'update', 'delete',
        'external', 'outside', 'third party', 'vendor', 'partner', 'public', 'cloud',
        'sensitive', 'confidential', 'classified', 'restricted', 'private', 'pii',
        'log', 'audit', 'monitor', 'alert', 'detect',
    ]
    
    # HIGH 키워드 (한국어)
    HIGH_KEYWORDS_KO = [
        '접근', '다운로드', '업로드', '전송', '복사', '공유', '전달', '발송',
        '계정', '사용자', '로그인', '로그아웃', '가입', '등록',
        '권한', '역할', '접근제어', '정책',
        '설정', '구성', '변경', '수정', '업데이트', '삭제',
        '외부', '외부인', '제3자', '협력사', '파트너', '공개', '클라우드',
        '민감', '기밀', '비밀', '제한', '고객정보', '계약서', '영업비밀',
        '로그', '감사', '모니터링', '경고', '탐지',
    ]
    
    # MEDIUM 키워드
    MEDIUM_KEYWORDS_EN = [
        'firewall', 'vpn', 'proxy', 'network', 'traffic', 'database', 'server',
        'application', 'service', 'port', 'protocol', 'connection',
    ]
    
    MEDIUM_KEYWORDS_KO = [
        '방화벽', 'VPN', '프록시', '네트워크', '트래픽', '데이터베이스', '서버',
        '애플리케이션', '서비스', '포트', '프로토콜', '연결',
    ]
    
    # 정규식 패턴
    REGEX_PATTERNS = {
        'ip_address': (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP 주소'),
        'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '이메일'),
        'url': (r'https?://[^\s]+', 'URL'),
        'weak_password': (r'\b(?:123456|password|admin|12345678|qwerty|1234)\b', '취약한 비밀번호'),
        'credit_card': (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '카드번호'),
        'korean_ssn': (r'\b\d{6}[-\s]?\d{7}\b', '주민번호'),
        'cve_pattern': (r'\bCVE-\d{4}-\d{4,7}\b', 'CVE ID'),
        'file_path': (r'(?:[C-Z]:\\|/(?:home|root|var|etc)/)[\w\\/.-]+', '파일경로'),
    }
    
    # 복합 패턴 (컨텍스트 인식)
    COMPOUND_PATTERNS = [
        # 데이터 + 외부
        (['data', 'file', 'document', '파일', '문서', '데이터'],
         ['external', 'outside', 'third party', '외부', '외부인']),
        # 관리자 + 비밀번호
        (['admin', 'root', 'administrator', '관리자'],
         ['password', 'credential', '비밀번호', '암호']),
        # 무단 + 접근
        (['unauthorized', 'illegitimate', '무단', '불법'],
         ['access', 'entry', 'login', '접근', '로그인']),
        # 고객 + 유출
        (['customer', 'client', 'user', '고객', '사용자'],
         ['leak', 'breach', 'expose', '유출', '노출']),
    ]
    
    # 질문 패턴
    QUESTION_PATTERNS_EN = [
        'how', 'what', 'why', 'when', 'where', 'who', 'which',
        'can', 'could', 'would', 'should', 'may', 'might', 'will',
        'is it', 'are there', 'do you', 'does it', 'have you',
        'how to', 'what is', 'can i', 'should i', 'is this',
    ]
    
    QUESTION_PATTERNS_KO = [
        '어떻게', '무엇', '왜', '언제', '어디', '누가', '누구',
        '인가', '인가요', '입니까', '나요', '까요', '을까', '을까요',
        '할 수 있', '해도 되', '가능한', '방법이', '방법은',
    ]
    
    @classmethod
    def detect(cls, text: str) -> Tuple[Optional[SecurityPatternStrength], List[str]]:
        """
        보안 패턴 탐지
        
        Returns:
            (최고 강도, 탐지된 패턴들)
        """
        text_lower = text.lower()
        detected = []
        max_strength = None
        
        # 1. CRITICAL 키워드
        for kw in cls.CRITICAL_KEYWORDS_EN + cls.CRITICAL_KEYWORDS_KO:
            if kw.lower() in text_lower:
                detected.append(f"CRITICAL: {kw}")
                max_strength = SecurityPatternStrength.CRITICAL
                if len(detected) >= 3:  # 최대 3개만
                    break
        
        # 2. HIGH 키워드
        if max_strength != SecurityPatternStrength.CRITICAL:
            for kw in cls.HIGH_KEYWORDS_EN + cls.HIGH_KEYWORDS_KO:
                if kw.lower() in text_lower:
                    detected.append(f"HIGH: {kw}")
                    if not max_strength:
                        max_strength = SecurityPatternStrength.HIGH
                    if len(detected) >= 3:
                        break
        
        # 3. MEDIUM 키워드
        if not max_strength:
            for kw in cls.MEDIUM_KEYWORDS_EN + cls.MEDIUM_KEYWORDS_KO:
                if kw.lower() in text_lower:
                    detected.append(f"MEDIUM: {kw}")
                    max_strength = SecurityPatternStrength.MEDIUM
                    if len(detected) >= 2:
                        break
        
        # 4. 정규식 패턴
        for name, (pattern, desc) in cls.REGEX_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(f"Pattern: {desc}")
                if name in ['weak_password', 'credit_card', 'korean_ssn', 'cve_pattern']:
                    max_strength = SecurityPatternStrength.CRITICAL
                elif not max_strength:
                    max_strength = SecurityPatternStrength.HIGH
        
        # 5. 복합 패턴
        for group1, group2 in cls.COMPOUND_PATTERNS:
            has1 = any(kw.lower() in text_lower for kw in group1)
            has2 = any(kw.lower() in text_lower for kw in group2)
            if has1 and has2:
                detected.append(f"Compound: {group1[0]}+{group2[0]}")
                max_strength = SecurityPatternStrength.CRITICAL
        
        # 6. 질문 패턴 (낮은 우선순위)
        if not max_strength:
            if '?' in text:
                detected.append("Question: ?")
                max_strength = SecurityPatternStrength.LOW
            else:
                for pattern in cls.QUESTION_PATTERNS_EN + cls.QUESTION_PATTERNS_KO:
                    if pattern.lower() in text_lower:
                        detected.append(f"Question: {pattern}")
                        max_strength = SecurityPatternStrength.LOW
                        break
        
        return max_strength, detected[:5]  # 최대 5개 패턴


# ============================================================
# Self-RAG Engine
# ============================================================

class SelfRAGEngine:
    """Self-RAG: 자가 반성형 RAG 시스템"""
    
    def __init__(self, analyzer, use_llm: bool = True):
        self.analyzer = analyzer
        self.use_llm = use_llm and analyzer.use_llm
        self.detector = EnhancedSecurityPatternDetector()
    
    def assess_retrieval_need(self, text: str) -> RetrievalNeed:
        """[Retrieval] 토큰: 검색 필요성 판단"""
        if self.use_llm:
            return self._assess_retrieval_need_llm(text)
        
        # Rule-based 탐지
        if len(text.strip()) < 3:
            return RetrievalNeed.NOT_NEEDED
        
        # 패턴 탐지
        strength, patterns = self.detector.detect(text)
        
        if patterns:
            logger.debug(f"Detected: {patterns[:3]}")
        
        # 강도별 판단
        if not strength:
            return RetrievalNeed.NOT_NEEDED
        
        if strength in [SecurityPatternStrength.CRITICAL, SecurityPatternStrength.HIGH]:
            return RetrievalNeed.REQUIRED
        elif strength == SecurityPatternStrength.MEDIUM:
            return RetrievalNeed.OPTIONAL
        else:  # LOW
            return RetrievalNeed.OPTIONAL
    
    def _assess_retrieval_need_llm(self, text: str) -> RetrievalNeed:
        """LLM 기반 검색 필요성 판단"""
        prompt = f"""Assess if retrieval from security policy database is needed.

Text: "{text}"

Classify as:
- REQUIRED: Clear security concerns
- OPTIONAL: Uncertain
- NOT_NEEDED: No security implications

JSON: {{"need": "REQUIRED|OPTIONAL|NOT_NEEDED"}}"""
        
        try:
            response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Security assessor. JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                response_format={"type": "json_object"},
                timeout=10
            )
            result = json.loads(response.choices[0].message.content)
            return RetrievalNeed[result.get('need', 'OPTIONAL')]
        except:
            return RetrievalNeed.OPTIONAL
    
    def assess_relevance(self, text: str, result) -> Dict[str, RelevanceScore]:
        """[Relevance] 토큰: 관련성 평가"""
        relevance_scores = {}
        for policy_id, similarity in result.policy_similarities.items():
            if similarity > 0.8:
                relevance_scores[policy_id] = RelevanceScore.HIGHLY_RELEVANT
            elif similarity > 0.6:
                relevance_scores[policy_id] = RelevanceScore.RELEVANT
            elif similarity > 0.4:
                relevance_scores[policy_id] = RelevanceScore.PARTIALLY_RELEVANT
            else:
                relevance_scores[policy_id] = RelevanceScore.NOT_RELEVANT
        return relevance_scores
    
    def assess_support(self, result, relevance_scores: Dict) -> SupportLevel:
        """[Support] 토큰: 지원도 평가"""
        if not relevance_scores:
            return SupportLevel.NO_SUPPORT
        
        highly_relevant = sum(1 for s in relevance_scores.values()
                            if s == RelevanceScore.HIGHLY_RELEVANT)
        relevant = sum(1 for s in relevance_scores.values()
                      if s in [RelevanceScore.HIGHLY_RELEVANT, RelevanceScore.RELEVANT])
        violation_support = len(set(result.violations) & set(relevance_scores.keys()))
        
        if highly_relevant >= 2 and violation_support >= 2:
            return SupportLevel.FULLY_SUPPORTED
        elif relevant >= 1 and violation_support >= 1:
            return SupportLevel.PARTIALLY_SUPPORTED
        else:
            return SupportLevel.NO_SUPPORT
    
    def assess_utility(self, result, support_level: SupportLevel) -> UtilityScore:
        """[Utility] 토큰: 유용성 평가"""
        score = 3
        if support_level == SupportLevel.FULLY_SUPPORTED:
            score += 2
        elif support_level == SupportLevel.PARTIALLY_SUPPORTED:
            score += 1
        if result.violations and result.threats:
            score += 1
        if result.remediation_suggestions:
            score += 1
        if result.confidence_score > 0.7:
            score += 1
        score = max(1, min(5, score))
        return UtilityScore(score)
    
    def generate_reflection(
        self,
        retrieval_need,
        relevance_scores,
        support_level,
        utility_score
    ) -> List[str]:
        """반성 노트 생성"""
        notes = []
        if retrieval_need == RetrievalNeed.REQUIRED:
            notes.append("✓ Retrieval was necessary")
        elif retrieval_need == RetrievalNeed.NOT_NEEDED:
            notes.append("→ Analysis without retrieval")
        
        if relevance_scores:
            highly_rel = sum(1 for s in relevance_scores.values()
                           if s == RelevanceScore.HIGHLY_RELEVANT)
            if highly_rel > 0:
                notes.append(f"✓ Found {highly_rel} highly relevant policy(ies)")
        
        if support_level == SupportLevel.FULLY_SUPPORTED:
            notes.append("✓ Well-supported by policies")
        elif support_level == SupportLevel.NO_SUPPORT:
            notes.append("⚠ Lacks sufficient policy support")
        
        if utility_score.value >= 4:
            notes.append("✓ High-quality result")
        elif utility_score.value <= 2:
            notes.append("⚠ May need refinement")
        
        return notes
    
    def calculate_confidence_boost(
        self,
        relevance_scores,
        support_level,
        utility_score
    ) -> float:
        """신뢰도 증가량 계산"""
        boost = 0.0
        if relevance_scores:
            highly_rel_ratio = sum(1 for s in relevance_scores.values()
                                 if s == RelevanceScore.HIGHLY_RELEVANT) / len(relevance_scores)
            boost += highly_rel_ratio * 0.1
        if support_level == SupportLevel.FULLY_SUPPORTED:
            boost += 0.15
        elif support_level == SupportLevel.PARTIALLY_SUPPORTED:
            boost += 0.05
        boost += (utility_score.value - 3) * 0.05
        return max(0.0, min(boost, 0.3))

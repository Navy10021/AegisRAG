"""
RAG 기반 보안 위험도 평가 시스템 - 최종 최적화 버전 (Jupyter/CLI 안전 실행 포함)

주요 기능:
    - 3가지 실행 모드 (배치/대화형/파일)
    - 하이브리드 검색 지원
    - 비동기 배치 처리 (Jupyter/CLI 모두 안전)
    - 실시간 통계 및 모니터링
    - 결과 자동 저장
"""

import os
import sys
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# 프로젝트 모듈 임포트
from utils.risk_analyzer import (
    SecurityPolicy,
    RAGSecurityAnalyzer,
    load_policies,
    AnalysisResult
)

# ==================== 설정 ====================

# 경로 설정
POLICIES_FILE = os.path.join("data", "security_policies.json")
OUTPUT_DIR = "output"
CONFIG_FILE = "config.json"

# 기본 설정
DEFAULT_CONFIG = {
    "search_mode": "hybrid",
    "use_llm": True,
    "use_embeddings": True,
    "async_batch": True,
    "max_concurrent": 5,
    "cache_size": 256,
    "verbose": True,
    "auto_save": True,
    "min_risk_score_alert": 60.0
}

# ==================== 안전한 비동기 실행 유틸 ====================

def run_async_task(coro):
    """
    Jupyter / Colab / 일반 Python 환경에서 안전하게 비동기 코루틴을 실행.
    - Jupyter/Colab: 기존 루프 재사용 (nest_asyncio 적용)
    - 일반 CLI: asyncio.run 사용
    반환값: 코루틴의 결과 (또는 None: 실패 시)
    """
    try:
        # nest_asyncio 적용 시도 (Jupyter/Colab에서 필요)
        try:
            import nest_asyncio
            nest_asyncio.apply()
        except Exception:
            # nest_asyncio가 없어도 일반 환경에서 asyncio.run 으로 동작
            pass

        try:
            # 이미 실행 중인 루프가 있으면 run_until_complete 사용
            loop = asyncio.get_running_loop()
            return loop.run_until_complete(coro)
        except RuntimeError:
            # 실행 중인 루프가 없으면 안전하게 asyncio.run 사용
            return asyncio.run(coro)
    except Exception as e:
        print(f"⚠️ 비동기 실행 중 오류 발생: {e}")
        return None

# ==================== 설정 관리 ====================

def load_config() -> dict:
    """설정 파일 로드"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print(f"⚙️  설정 파일 로드: {CONFIG_FILE}")
            return {**DEFAULT_CONFIG, **config}
        except Exception as e:
            print(f"⚠️  설정 파일 로드 실패: {e}, 기본 설정 사용")
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """설정 파일 저장"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"💾 설정 저장: {CONFIG_FILE}")
    except Exception as e:
        print(f"⚠️  설정 저장 실패: {e}")

# ==================== 유틸리티 ====================

def ensure_output_dir():
    """출력 디렉토리 생성"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)


def get_timestamp_filename(prefix: str = "results", ext: str = "json") -> str:
    """타임스탬프 포함 파일명 생성"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join(OUTPUT_DIR, f"{prefix}_{timestamp}.{ext}")


def get_api_key() -> Optional[str]:
    """
    API 키 획득 (우선순위: 환경변수 > Colab Secrets > 사용자 입력)
    """
    # 1. 환경변수 확인
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        print("🔑 환경변수에서 API 키 로드")
        return api_key

    # 2. Colab Secrets 확인
    try:
        import google.colab
        from google.colab import userdata
        api_key = userdata.get('OPENAI_API_KEY')
        if api_key:
            print("🔑 Colab Secrets에서 API 키 로드")
            return api_key
    except Exception:
        pass

    # 3. 사용자 입력
    print("\n" + "="*80)
    print("⚠️  OpenAI API 키 설정")
    print("="*80)
    print("\n옵션:")
    print("  1️⃣  API 키 입력 → LLM 분석 (GPT-4o-mini, 정교한 분석)")
    print("  2️⃣  Enter 키 → 규칙 기반 분석 (무료, 빠름)\n")

    try:
        api_key = input("🔑 API 키 입력: ").strip()
    except Exception:
        api_key = None
    return api_key if api_key else None


def print_header(title: str, emoji: str = "📋"):
    """헤더 출력"""
    print("\n" + "=" * 80)
    print(f"{emoji}  {title}")
    print("=" * 80 + "\n")


def save_results(
    results: List[AnalysisResult],
    filepath: Optional[str] = None,
    format: str = 'json'
) -> bool:
    """분석 결과 저장"""
    try:
        ensure_output_dir()

        if filepath is None:
            filepath = get_timestamp_filename("results", format)

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

        print(f"\n💾 결과 저장: {filepath}")
        return True

    except Exception as e:
        print(f"❌ 저장 실패: {e}")
        return False


def print_summary(
    results: List[AnalysisResult],
    total_time: Optional[float] = None,
    show_high_risk: bool = True
):
    """분석 요약 통계 출력"""
    if not results:
        print("⚠️  분석 결과가 없습니다\n")
        return

    print("\n" + "=" * 80)
    print("📊 분석 요약")
    print("=" * 80)

    # 기본 통계
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_score = 0

    for result in results:
        levels[result.risk_level] += 1
        total_score += result.risk_score

    print(f"\n✅ 총 분석: {len(results)}건")
    if total_time:
        avg_time = total_time / len(results)
        print(f"⏱️  총 시간: {total_time:.2f}초 (평균: {avg_time:.3f}초/건)")
    print(f"📊 평균 위험도: {total_score/len(results):.1f}/100\n")

    # 위험도 분포
    print("위험도 분포:")
    emoji_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = levels[level]
        if count > 0:
            emoji = emoji_map[level]
            percentage = (count / len(results)) * 100
            bar = "█" * int(percentage / 5)
            print(f"  {emoji} {level:8s}: {count:3d}건 ({percentage:5.1f}%) {bar}")

    # 고위험 케이스
    if show_high_risk:
        high_risk = [r for r in results if r.risk_level in ['CRITICAL', 'HIGH']]
        if high_risk:
            print(f"\n⚠️  고위험 케이스: {len(high_risk)}건")
            for i, r in enumerate(high_risk[:5], 1):
                preview = r.text[:60] + "..." if len(r.text) > 60 else r.text
                print(f"  {i}. [{r.risk_level}] {preview}")
                print(f"     위험도: {r.risk_score:.1f} | 위반: {len(r.violations)}건")

            if len(high_risk) > 5:
                print(f"  ... 외 {len(high_risk) - 5}건")

    print("\n" + "=" * 80 + "\n")


# ==================== 분석 모드 ====================

def batch_mode(
    policies: List[SecurityPolicy],
    config: dict,
    api_key: Optional[str]
):
    """배치 분석 모드"""
    print_header("배치 분석 모드", "📦")

    # 분석기 초기화
    analyzer = RAGSecurityAnalyzer(
        policies=policies,
        api_key=api_key,
        use_llm=config['use_llm'] and bool(api_key),
        use_embeddings=config['use_embeddings'],
        search_mode=config['search_mode'],
        verbose=config['verbose'],
        cache_size=config['cache_size']
    )

    # 테스트 케이스
    test_cases = [
        "다음 주 퇴사하는데, 반도체 설계도 USB에 백업해두려고 합니다.",
        "고객 개인정보 1만 건을 개인 이메일로 전송했습니다.",
        "협력업체와 배터리 배합비 공유하는데 NDA 안 맺었어요.",
        "일반 업무 보고서 작성했습니다.",
        "경쟁사로 이직하는데 고객 리스트 가져가도 되나요?",
        "회사 회계 자료를 외부 구글 드라이브로 공유했습니다.",
        "퇴사 예정자가 대량 다운로드를 시도했습니다.",
        "R&D 핵심 기술 문서를 메신저로 전송했습니다.",
        "고객사 담당자 연락처를 엑셀로 정리했습니다.",
        "신제품 출시 전략을 협력사와 논의했습니다."
    ]

    # 설정 정보 출력
    print(f"📊 분석 설정:")
    print(f"   • 케이스 수: {len(test_cases)}개")
    print(f"   • 검색 모드: {config['search_mode']}")
    print(f"   • LLM 분석: {'✅' if (config['use_llm'] and api_key) else '❌'}")
    print(f"   • 임베딩 검색: {'✅' if config['use_embeddings'] else '❌'}")
    print(f"   • 비동기 처리: {'✅' if config['async_batch'] else '❌'}")
    if config['async_batch']:
        print(f"   • 동시 실행: {config['max_concurrent']}개")
    print()

    # 분석 실행
    start_time = datetime.now()

    try:
        if config['async_batch']:
            # 안전한 비동기 실행 유틸 사용 (Jupyter/CLI 모두 대응)
            results = run_async_task(
                analyzer.analyze_batch_async(
                    test_cases,
                    max_concurrent=config['max_concurrent']
                )
            )

            # 비동기 실행 실패 시 동기 모드로 폴백
            if results is None:
                print("⚠️  비동기 실행 실패 - 동기 모드로 재시도...")
                results = analyzer.analyze_batch(test_cases)

        else:
            results = analyzer.analyze_batch(test_cases)
    except Exception as e:
        print(f"❌ 분석 실패: {e}")
        if config['async_batch']:
            print("⚠️  동기 모드로 재시도...")
            results = analyzer.analyze_batch(test_cases)
        else:
            analyzer.cleanup()
            return None

    total_time = (datetime.now() - start_time).total_seconds()

    # 결과 출력
    print("\n" + "=" * 80)
    print("📊 개별 분석 결과")
    print("=" * 80 + "\n")

    for i, result in enumerate(results, 1):
        print(f"[{i}/{len(results)}]")
        analyzer.print_result(result)

    # 요약 및 통계
    print_summary(results, total_time)
    analyzer.print_statistics()

    # 자동 저장
    if config['auto_save'] and results:
        save_results(results)

        # CSV도 저장
        csv_file = get_timestamp_filename("results", "csv")
        save_results(results, csv_file, format='csv')

    # 고위험 알림
    high_risk_count = sum(1 for r in results if r.risk_score >= config['min_risk_score_alert'])
    if high_risk_count > 0:
        print(f"\n🚨 경고: {high_risk_count}건의 고위험 케이스가 발견되었습니다!")

    # 정리
    analyzer.cleanup()

    return results


def interactive_mode(
    policies: List[SecurityPolicy],
    config: dict,
    api_key: Optional[str]
):
    """대화형 분석 모드"""
    print_header("대화형 분석 모드", "💬")

    # 분석기 초기화
    analyzer = RAGSecurityAnalyzer(
        policies=policies,
        api_key=api_key,
        use_llm=config['use_llm'] and bool(api_key),
        use_embeddings=config['use_embeddings'],
        search_mode=config['search_mode'],
        verbose=False,  # 대화형에서는 간결하게
        cache_size=config['cache_size']
    )

    print("💡 명령어:")
    print("  • [텍스트] : 분석 실행")
    print("  • stats    : 통계 보기")
    print("  • config   : 설정 보기")
    print("  • save     : 결과 저장")
    print("  • clear    : 화면 지우기")
    print("  • help     : 도움말")
    print("  • quit     : 종료\n")

    results = []

    while True:
        try:
            text = input("📝 입력> ").strip()

            if not text:
                continue

            # 명령어 처리
            if text.lower() in ['quit', 'exit', 'q']:
                print("\n👋 대화형 모드 종료")
                break

            elif text.lower() == 'stats':
                if results:
                    print_summary(results, show_high_risk=True)
                analyzer.print_statistics()
                continue

            elif text.lower() == 'config':
                print("\n⚙️  현재 설정:")
                for key, value in config.items():
                    print(f"  • {key}: {value}")
                print()
                continue

            elif text.lower() == 'save':
                if results:
                    save_results(results)
                else:
                    print("⚠️  저장할 결과가 없습니다")
                continue

            elif text.lower() == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            elif text.lower() == 'help':
                print("\n💡 사용 가능한 명령어:")
                print("  stats  - 분석 통계 출력")
                print("  config - 현재 설정 보기")
                print("  save   - 결과 저장")
                print("  clear  - 화면 지우기")
                print("  help   - 이 도움말")
                print("  quit   - 프로그램 종료\n")
                continue

            # 분석 실행
            print()
            result = analyzer.analyze(text)
            results.append(result)
            analyzer.print_result(result)

            # 고위험 경고
            if result.risk_score >= config['min_risk_score_alert']:
                print(f"⚠️  경고: 고위험 ({result.risk_score:.1f}점) 탐지!")

        except KeyboardInterrupt:
            print("\n\n⚠️  중단됨 (Ctrl+C)")
            break

        except Exception as e:
            print(f"❌ 오류: {e}\n")
            continue

    # 종료 처리
    if results:
        print(f"\n📊 세션 요약: 총 {len(results)}건 분석")

        save_choice = input("💾 결과를 저장하시겠습니까? (y/n): ").strip().lower()
        if save_choice == 'y':
            save_results(results)
            print_summary(results, show_high_risk=False)

    analyzer.print_statistics()
    analyzer.cleanup()


def file_mode(
    policies: List[SecurityPolicy],
    config: dict,
    api_key: Optional[str],
    input_file: str
):
    """파일 입력 분석 모드"""
    print_header(f"파일 분석 모드: {input_file}", "📄")

    # 파일 읽기
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            texts = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ 파일을 찾을 수 없습니다: {input_file}")
        return
    except Exception as e:
        print(f"❌ 파일 읽기 실패: {e}")
        return

    if not texts:
        print("⚠️  파일이 비어있습니다")
        return

    print(f"✅ {len(texts)}개 라인 로드 완료\n")

    # 분석기 초기화
    analyzer = RAGSecurityAnalyzer(
        policies=policies,
        api_key=api_key,
        use_llm=config['use_llm'] and bool(api_key),
        use_embeddings=config['use_embeddings'],
        search_mode=config['search_mode'],
        verbose=config['verbose'],
        cache_size=config['cache_size']
    )

    print(f"⚙️  설정:")
    print(f"   • 검색 모드: {config['search_mode']}")
    print(f"   • LLM: {'✅' if (config['use_llm'] and api_key) else '❌'}")
    print(f"   • 비동기: {'✅' if config['async_batch'] else '❌'}\n")

    # 분석 실행
    start_time = datetime.now()

    try:
        if config['async_batch']:
            results = run_async_task(
                analyzer.analyze_batch_async(
                    texts,
                    max_concurrent=config['max_concurrent']
                )
            )
            if results is None:
                print("⚠️  비동기 실행 실패 - 동기 모드로 재시도...")
                results = analyzer.analyze_batch(texts)
        else:
            results = analyzer.analyze_batch(texts)
    except Exception as e:
        print(f"❌ 분석 실패: {e}")
        return

    total_time = (datetime.now() - start_time).total_seconds()

    # 결과 출력 (간략하게)
    print("\n" + "=" * 80)
    print("📊 분석 결과 (요약)")
    print("=" * 80 + "\n")

    for i, result in enumerate(results, 1):
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[result.risk_level]
        preview = result.text[:50] + "..." if len(result.text) > 50 else result.text
        print(f"[{i:3d}] {emoji} {result.risk_score:5.1f} | {preview}")

    # 요약 및 통계
    print_summary(results, total_time)
    analyzer.print_statistics()

    # 결과 저장
    if config['auto_save']:
        save_results(results)

    analyzer.cleanup()


# ==================== 메인 실행 ====================

def parse_arguments():
    """커맨드 라인 인수 파싱"""
    parser = argparse.ArgumentParser(
        description="RAG 기반 보안 위험도 평가 시스템",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  python main.py                    # 대화형 모드 선택
  python main.py --batch            # 배치 모드
  python main.py --interactive      # 대화형 모드
  python main.py --file input.txt   # 파일 분석
  python main.py --config           # 설정 편집
        """
    )

    parser.add_argument('--batch', '-b', action='store_true', help='배치 분석 모드')
    parser.add_argument('--interactive', '-i', action='store_true', help='대화형 모드')
    parser.add_argument('--file', '-f', type=str, help='분석할 파일 경로')
    parser.add_argument('--config', '-c', action='store_true', help='설정 편집')
    parser.add_argument('--search-mode', choices=['embedding', 'keyword', 'hybrid'], help='검색 모드')
    parser.add_argument('--no-llm', action='store_true', help='LLM 비활성화')
    parser.add_argument('--no-async', action='store_true', help='비동기 비활성화')

    return parser.parse_args()


def edit_config(config: dict):
    """설정 편집 (대화형)"""
    print_header("설정 편집", "⚙️")

    print("현재 설정:")
    for i, (key, value) in enumerate(config.items(), 1):
        print(f"  {i}. {key}: {value}")

    print("\n변경할 항목 번호 입력 (Enter로 건너뛰기):")

    keys = list(config.keys())

    for i, key in enumerate(keys, 1):
        current = config[key]
        prompt = f"{i}. {key} [{current}]: "

        new_value = input(prompt).strip()

        if new_value:
            # 타입 변환
            if isinstance(current, bool):
                config[key] = new_value.lower() in ['true', 'yes', 'y', '1']
            elif isinstance(current, int):
                try:
                    config[key] = int(new_value)
                except:
                    print(f"  ⚠️  잘못된 값, {key} 유지")
            elif isinstance(current, float):
                try:
                    config[key] = float(new_value)
                except:
                    print(f"  ⚠️  잘못된 값, {key} 유지")
            else:
                config[key] = new_value

    save_config(config)
    print("\n✅ 설정이 저장되었습니다\n")


def select_mode() -> str:
    """실행 모드 선택"""
    print("\n" + "=" * 80)
    print("  🛡️  RAG 보안 위험도 평가 시스템")
    print("=" * 80)

    print("\n실행 모드 선택:")
    print("  1️⃣  배치 분석 (고정 테스트 케이스)")
    print("  2️⃣  대화형 분석 (실시간 입력)")
    print("  3️⃣  파일 분석 (텍스트 파일 일괄 처리)")
    print("  4️⃣  설정 편집")

    while True:
        choice = input("\n선택 (1-4): ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print("⚠️  1-4 사이의 숫자를 입력하세요")

def main():
    """메인 함수"""
    # 커맨드 라인 인수 파싱
    args = parse_arguments()

    # ✅ Jupyter/Colab 환경에서는 argparse 인자를 무시하도록 처리
    try:
        get_ipython()  # Jupyter 여부 확인
        IN_NOTEBOOK = True
    except NameError:
        IN_NOTEBOOK = False

    if IN_NOTEBOOK:
        # IPython이 자동 전달한 잘못된 인자 제거
        args.batch = False
        args.interactive = False
        args.file = None
        args.config = False

    # 설정 로드
    config = load_config()

    # 커맨드 라인 인수로 설정 오버라이드
    if args.search_mode:
        config['search_mode'] = args.search_mode
    if args.no_llm:
        config['use_llm'] = False
    if args.no_async:
        config['async_batch'] = False

    # 설정 편집 모드
    if args.config:
        edit_config(config)
        return 0

    try:
        # 정책 로드
        print("📚 보안 정책 로딩 중...")
        policies = load_policies(POLICIES_FILE)
        print(f"✅ {len(policies)}개 정책 로드 완료\n")

    except FileNotFoundError:
        print(f"❌ 정책 파일 오류: {POLICIES_FILE} 파일이 필요합니다")
        return 1
    except Exception as e:
        print(f"❌ 정책 로딩 오류: {e}")
        return 1

    # API 키 획득
    api_key = get_api_key()

    try:
        # ✅ Jupyter 환경이면 항상 select_mode() 실행
        if IN_NOTEBOOK:
            choice = select_mode()
            if choice == '1':
                batch_mode(policies, config, api_key)
            elif choice == '2':
                interactive_mode(policies, config, api_key)
            elif choice == '3':
                file_path = input("\n📄 입력 파일 경로: ").strip()
                if file_path:
                    file_mode(policies, config, api_key, file_path)
                else:
                    print("⚠️  파일 경로가 필요합니다")
                    return 1
            elif choice == '4':
                edit_config(config)
                return 0

        # ✅ 일반 CLI에서는 기존 로직 유지
        else:
            if args.batch:
                batch_mode(policies, config, api_key)
            elif args.interactive:
                interactive_mode(policies, config, api_key)
            elif args.file:
                file_mode(policies, config, api_key, args.file)
            else:
                choice = select_mode()
                if choice == '1':
                    batch_mode(policies, config, api_key)
                elif choice == '2':
                    interactive_mode(policies, config, api_key)
                elif choice == '3':
                    file_path = input("\n📄 입력 파일 경로: ").strip()
                    if file_path:
                        file_mode(policies, config, api_key, file_path)
                    else:
                        print("⚠️  파일 경로가 필요합니다")
                        return 1
                elif choice == '4':
                    edit_config(config)
                    return 0

        print("\n✅ 프로그램 정상 종료")
        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  사용자에 의해 중단됨")
        return 0

    except Exception as e:
        print(f"\n❌ 예상치 못한 오류: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

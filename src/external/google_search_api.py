"""
Google Search API連携

Google Custom Search APIとの連携機能を提供します。
"""

from typing import Dict, Any, List, Optional
from ..utils.exceptions import APIError
from ..utils.logger import get_logger
from ..utils.http_client import HTTPClient, RateLimiter


class GoogleSearchAPI:
    """Google Custom Search API連携クラス"""

    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: API設定
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.api_key = config.get('api_key')
        self.search_engine_id = config.get('search_engine_id')
        self.base_url = "https://www.googleapis.com/customsearch/v1"

        if not self.api_key or not self.search_engine_id:
            self.logger.warning("Google Search API credentials not configured")

        # レート制限設定（100 queries per day for free tier）
        rate_limiter = RateLimiter(calls_per_minute=10)

        # HTTPクライアント初期化
        self.http_client = HTTPClient(
            timeout=30,
            max_retries=3,
            rate_limiter=rate_limiter,
            user_agent='SecurityAuditTool/1.0'
        )

    def site_search(self, domain: str, query_terms: List[str]) -> Dict[str, Any]:
        """
        サイト内検索を実行

        Args:
            domain: 検索対象ドメイン
            query_terms: 検索キーワードリスト

        Returns:
            検索結果
        """
        if not self.api_key or not self.search_engine_id:
            return {
                'status': 'error',
                'error': 'Google Search API not configured'
            }

        results = {}

        try:
            for term in query_terms:
                query = f'site:{domain} "{term}"'
                search_result = self._search(query)
                results[term] = search_result

                # APIクォータ節約のため、結果が見つかった場合は詳細検索を停止
                if search_result.get('totalResults', 0) > 0:
                    self.logger.info(f"Found results for term '{term}' on {domain}")

            return {
                'status': 'success',
                'domain': domain,
                'results': results,
                'total_terms_searched': len(query_terms)
            }

        except Exception as e:
            self.logger.error(f"Google site search failed: {domain}", error=str(e))
            return {
                'status': 'error',
                'domain': domain,
                'error': str(e)
            }

    def check_sensitive_exposure(self, domain: str) -> Dict[str, Any]:
        """
        機密情報の露出をチェック

        Args:
            domain: チェック対象ドメイン

        Returns:
            チェック結果
        """
        sensitive_terms = [
            "index of",
            "login",
            "password",
            "config",
            "admin",
            "backup",
            "database",
            "error",
            "debug"
        ]

        search_results = self.site_search(domain, sensitive_terms)

        if search_results['status'] != 'success':
            return search_results

        # 結果分析
        exposed_terms = []
        total_results = 0

        for term, result in search_results['results'].items():
            if result.get('status') == 'success' and result.get('totalResults', 0) > 0:
                exposed_terms.append({
                    'term': term,
                    'count': result['totalResults'],
                    'sample_urls': [item.get('link', '') for item in result.get('items', [])[:3]]
                })
                total_results += result['totalResults']

        return {
            'status': 'success',
            'domain': domain,
            'has_sensitive_exposure': len(exposed_terms) > 0,
            'exposed_terms': exposed_terms,
            'total_sensitive_results': total_results,
            'risk_level': self._calculate_risk_level(exposed_terms)
        }

    def _search(self, query: str, start_index: int = 1, num_results: int = 10) -> Dict[str, Any]:
        """
        検索を実行

        Args:
            query: 検索クエリ
            start_index: 開始インデックス
            num_results: 取得結果数

        Returns:
            検索結果
        """
        try:
            params = {
                'key': self.api_key,
                'cx': self.search_engine_id,
                'q': query,
                'start': start_index,
                'num': min(num_results, 10)  # Google API limit
            }

            self.logger.debug(f"Google search query: {query}")

            response = self.http_client.get(self.base_url, params=params)

            if response.status_code == 200:
                data = response.json()

                return {
                    'status': 'success',
                    'query': query,
                    'totalResults': int(data.get('searchInformation', {}).get('totalResults', 0)),
                    'items': data.get('items', []),
                    'searchTime': data.get('searchInformation', {}).get('searchTime', 0)
                }

            elif response.status_code == 403:
                self.logger.warning("Google Search API quota exceeded or access denied")
                return {
                    'status': 'error',
                    'query': query,
                    'error': 'API quota exceeded or access denied'
                }

            else:
                self.logger.warning(f"Google Search API returned status {response.status_code}")
                return {
                    'status': 'error',
                    'query': query,
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"Google search failed: {query}", error=str(e))
            return {
                'status': 'error',
                'query': query,
                'error': str(e)
            }

    def _calculate_risk_level(self, exposed_terms: List[Dict[str, Any]]) -> str:
        """
        リスクレベルを計算

        Args:
            exposed_terms: 露出したキーワードリスト

        Returns:
            リスクレベル（HIGH, MEDIUM, LOW）
        """
        if not exposed_terms:
            return 'LOW'

        total_results = sum(term['count'] for term in exposed_terms)
        high_risk_terms = ['password', 'config', 'admin', 'database', 'backup']

        # 高リスクキーワードの露出チェック
        high_risk_exposure = any(
            term['term'] in high_risk_terms and term['count'] > 0
            for term in exposed_terms
        )

        if high_risk_exposure or total_results > 50:
            return 'HIGH'
        elif total_results > 10:
            return 'MEDIUM'
        else:
            return 'LOW'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'http_client'):
            self.http_client.close()

"""
DomSignal API連携

DomSignalサービスとの連携機能を提供します。
"""

from typing import Dict, Any, Optional
from urllib.parse import urlencode
from ..utils.exceptions import APIError
from ..utils.logger import get_logger
from ..utils.http_client import HTTPClient, RateLimiter


class DomSignalAPI:
    """DomSignal API連携クラス"""

    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: API設定
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.base_url = config.get('base_url', 'https://domsignal.com')
        rate_limit = config.get('rate_limit', 10)  # requests per minute

        # レート制限設定
        rate_limiter = RateLimiter(calls_per_minute=rate_limit)

        # HTTPクライアント初期化
        self.http_client = HTTPClient(
            timeout=30,
            max_retries=3,
            rate_limiter=rate_limiter,
            user_agent='SecurityAuditTool/1.0'
        )

    def vulnerability_scan(self, url: str) -> Dict[str, Any]:
        """
        脆弱性スキャンを実行

        Args:
            url: スキャン対象URL

        Returns:
            スキャン結果
        """
        try:
            endpoint = f"{self.base_url}/js-vulnerability-scanner"
            params = {'url': url}

            self.logger.debug(f"DomSignal vulnerability scan: {url}")

            response = self.http_client.get(endpoint, params=params)

            if response.status_code == 200:
                return {
                    'status': 'success',
                    'data': self._parse_vulnerability_response(response.text),
                    'raw_response': response.text[:1000]  # 最初の1000文字のみ保存
                }
            else:
                self.logger.warning(f"DomSignal API returned status {response.status_code}")
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"DomSignal vulnerability scan failed: {url}", error=str(e))
            return {
                'status': 'error',
                'error': str(e)
            }

    def tls_test(self, url: str) -> Dict[str, Any]:
        """
        TLSテストを実行

        Args:
            url: テスト対象URL

        Returns:
            テスト結果
        """
        try:
            endpoint = f"{self.base_url}/tls-test"
            params = {'url': url}

            self.logger.debug(f"DomSignal TLS test: {url}")

            response = self.http_client.get(endpoint, params=params)

            if response.status_code == 200:
                return {
                    'status': 'success',
                    'data': self._parse_tls_response(response.text),
                    'raw_response': response.text[:1000]
                }
            else:
                self.logger.warning(f"DomSignal TLS API returned status {response.status_code}")
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"DomSignal TLS test failed: {url}", error=str(e))
            return {
                'status': 'error',
                'error': str(e)
            }

    def security_headers_test(self, url: str) -> Dict[str, Any]:
        """
        セキュリティヘッダーテストを実行

        Args:
            url: テスト対象URL

        Returns:
            テスト結果
        """
        try:
            endpoint = f"{self.base_url}/secure-header-test"
            params = {'url': url}

            self.logger.debug(f"DomSignal security headers test: {url}")

            response = self.http_client.get(endpoint, params=params)

            if response.status_code == 200:
                return {
                    'status': 'success',
                    'data': self._parse_headers_response(response.text),
                    'raw_response': response.text[:1000]
                }
            else:
                self.logger.warning(f"DomSignal headers API returned status {response.status_code}")
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"DomSignal security headers test failed: {url}", error=str(e))
            return {
                'status': 'error',
                'error': str(e)
            }

    def _parse_vulnerability_response(self, response_text: str) -> Dict[str, Any]:
        """
        脆弱性スキャンレスポンスを解析

        Args:
            response_text: レスポンステキスト

        Returns:
            解析結果
        """
        try:
            # DomSignalのレスポンス形式に応じて解析
            # 実際のAPIレスポンス形式に合わせて実装が必要

            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response_text, 'html.parser')

            # 基本的な情報抽出
            results = {
                'vulnerabilities_found': False,
                'details': [],
                'libraries_detected': []
            }

            # 脆弱性情報の抽出（簡略化）
            # 実際の実装では、DomSignalの具体的なレスポンス形式に合わせる
            vulnerability_indicators = [
                'vulnerability', 'vulnerable', 'security issue', 'outdated'
            ]

            text_content = soup.get_text().lower()
            for indicator in vulnerability_indicators:
                if indicator in text_content:
                    results['vulnerabilities_found'] = True
                    results['details'].append(f"Potential issue detected: {indicator}")

            return results

        except Exception as e:
            self.logger.debug(f"Failed to parse vulnerability response", error=str(e))
            return {
                'vulnerabilities_found': False,
                'details': ['Response parsing failed'],
                'parse_error': str(e)
            }

    def _parse_tls_response(self, response_text: str) -> Dict[str, Any]:
        """
        TLSテストレスポンスを解析

        Args:
            response_text: レスポンステキスト

        Returns:
            解析結果
        """
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response_text, 'html.parser')

            results = {
                'tls13_supported': False,
                'tls11_disabled': True,
                'tls10_disabled': True,
                'grade': 'Unknown',
                'details': []
            }

            text_content = soup.get_text().lower()

            # TLS 1.3サポート検出
            if 'tls 1.3' in text_content or 'tlsv1.3' in text_content:
                results['tls13_supported'] = True

            # 古いTLSバージョンの検出
            if 'tls 1.1' in text_content or 'tlsv1.1' in text_content:
                results['tls11_disabled'] = False

            if 'tls 1.0' in text_content or 'tlsv1.0' in text_content:
                results['tls10_disabled'] = False

            # グレード抽出
            grade_indicators = ['grade a', 'grade b', 'grade c', 'grade d', 'grade f']
            for grade in grade_indicators:
                if grade in text_content:
                    results['grade'] = grade.split()[-1].upper()
                    break

            return results

        except Exception as e:
            self.logger.debug(f"Failed to parse TLS response", error=str(e))
            return {
                'tls13_supported': False,
                'tls11_disabled': True,
                'tls10_disabled': True,
                'parse_error': str(e)
            }

    def _parse_headers_response(self, response_text: str) -> Dict[str, Any]:
        """
        セキュリティヘッダーレスポンスを解析

        Args:
            response_text: レスポンステキスト

        Returns:
            解析結果
        """
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response_text, 'html.parser')

            results = {
                'headers_found': [],
                'headers_missing': [],
                'score': 0,
                'grade': 'Unknown'
            }

            text_content = soup.get_text().lower()

            # セキュリティヘッダーの検出
            security_headers = [
                'x-frame-options',
                'strict-transport-security',
                'content-security-policy',
                'x-content-type-options',
                'referrer-policy'
            ]

            for header in security_headers:
                if header in text_content:
                    results['headers_found'].append(header)
                else:
                    results['headers_missing'].append(header)

            # スコア計算（簡略化）
            total_headers = len(security_headers)
            found_headers = len(results['headers_found'])
            results['score'] = int((found_headers / total_headers) * 100)

            # グレード判定
            if results['score'] >= 90:
                results['grade'] = 'A'
            elif results['score'] >= 80:
                results['grade'] = 'B'
            elif results['score'] >= 70:
                results['grade'] = 'C'
            elif results['score'] >= 60:
                results['grade'] = 'D'
            else:
                results['grade'] = 'F'

            return results

        except Exception as e:
            self.logger.debug(f"Failed to parse headers response", error=str(e))
            return {
                'headers_found': [],
                'headers_missing': [],
                'score': 0,
                'parse_error': str(e)
            }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'http_client'):
            self.http_client.close()

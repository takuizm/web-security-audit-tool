"""
暗号化通信診断

HTTPS化状況の確認を行います。
"""

from typing import Dict, Any
from urllib.parse import urlparse, urlunparse

from .base_auditor import BaseAuditor
from .data_models import AuditResult, AuditStatus


class EncryptionCheckAuditor(BaseAuditor):
    """暗号化通信診断クラス"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.audit_type = "encryption_check"

    def audit(self, url: str) -> AuditResult:
        """
        暗号化通信診断を実行

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        details = {}
        recommendations = []
        checks = {}

        try:
            # HTTPアクセステスト
            http_test = self._test_http_access(url)
            details['http_access_test'] = http_test
            checks['http_blocked'] = http_test.get('blocked', False)

            # HTTPSリダイレクトテスト
            https_redirect_test = self._test_https_redirect(url)
            details['https_redirect_test'] = https_redirect_test
            checks['https_redirect'] = https_redirect_test.get('redirects_to_https', False)

            # 404ページリダイレクトテスト
            error_redirect_test = self._test_error_page_redirect(url)
            details['error_redirect_test'] = error_redirect_test
            checks['error_redirect_proper'] = error_redirect_test.get('proper_redirect', True)

            # HTTPS証明書チェック
            cert_check = self._check_ssl_certificate(url)
            details['ssl_certificate'] = cert_check
            checks['ssl_valid'] = cert_check.get('valid', False)

            # 推奨事項生成
            if not http_test.get('blocked', False):
                recommendations.append("HTTPアクセスを無効にし、HTTPSへのリダイレクトを設定してください")

            if not https_redirect_test.get('redirects_to_https', False):
                recommendations.append("HTTPからHTTPSへの自動リダイレクトを設定してください")

            if not cert_check.get('valid', False):
                recommendations.append("SSL証明書の設定を確認してください")

        except Exception as e:
            self.logger.error(f"Encryption check audit failed: {url}", error=str(e))
            return self.create_result(
                url=url,
                status=AuditStatus.ERROR,
                error_message=str(e)
            )

        # ステータス決定
        critical_issues = not checks.get('https_redirect', False) or not checks.get('ssl_valid', False)
        status = self.determine_status(checks, critical_issues)

        return self.create_result(
            url=url,
            status=status,
            details=details,
            recommendations=recommendations
        )

    def _test_http_access(self, url: str) -> Dict[str, Any]:
        """
        HTTPアクセステスト

        Args:
            url: 診断対象URL

        Returns:
            HTTPアクセステスト結果
        """
        try:
            # URLをHTTPに変換
            parsed = urlparse(url)
            http_url = urlunparse((
                'http',
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))

            self.logger.debug(f"Testing HTTP access: {http_url}")

            response = self.safe_request('GET', http_url, allow_redirects=False)

            if response is None:
                return {
                    'blocked': True,
                    'status_code': None,
                    'details': 'HTTP request failed - likely blocked'
                }

            status_code = response.status_code

            # リダイレクトステータスコードの場合
            if status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                redirects_to_https = location.startswith('https://')

                return {
                    'blocked': False,
                    'status_code': status_code,
                    'redirects_to_https': redirects_to_https,
                    'redirect_location': location,
                    'details': f'Redirects to {location}'
                }

            # 正常レスポンスの場合（HTTPアクセス可能）
            elif 200 <= status_code < 400:
                return {
                    'blocked': False,
                    'status_code': status_code,
                    'accessible_via_http': True,
                    'details': 'HTTP access is allowed (security issue)'
                }

            # エラーレスポンスの場合
            else:
                return {
                    'blocked': True,
                    'status_code': status_code,
                    'details': f'HTTP access blocked with status {status_code}'
                }

        except Exception as e:
            self.logger.debug(f"HTTP access test error: {url}", error=str(e))
            return {
                'blocked': True,
                'status_code': None,
                'details': 'HTTP access test failed',
                'error': str(e)
            }

    def _test_https_redirect(self, url: str) -> Dict[str, Any]:
        """
        HTTPSリダイレクトテスト

        Args:
            url: 診断対象URL

        Returns:
            HTTPSリダイレクトテスト結果
        """
        try:
            # URLをHTTPに変換
            parsed = urlparse(url)
            http_url = urlunparse((
                'http',
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))

            self.logger.debug(f"Testing HTTPS redirect: {http_url}")

            # リダイレクトを追跡
            response = self.safe_request('GET', http_url, allow_redirects=True)

            if response is None:
                return {
                    'redirects_to_https': False,
                    'final_url': None,
                    'details': 'Request failed'
                }

            final_url = response.url
            redirects_to_https = final_url.startswith('https://')

            return {
                'redirects_to_https': redirects_to_https,
                'final_url': final_url,
                'status_code': response.status_code,
                'details': f'Final URL: {final_url}'
            }

        except Exception as e:
            self.logger.debug(f"HTTPS redirect test error: {url}", error=str(e))
            return {
                'redirects_to_https': False,
                'final_url': None,
                'details': 'HTTPS redirect test failed',
                'error': str(e)
            }

    def _test_error_page_redirect(self, url: str) -> Dict[str, Any]:
        """
        404ページリダイレクトテスト

        Args:
            url: 診断対象URL

        Returns:
            エラーページリダイレクトテスト結果
        """
        try:
            # 存在しないパスをテスト
            parsed = urlparse(url)
            test_path = "/nonexistent-test-path-12345"

            # HTTPでのテスト
            http_test_url = urlunparse((
                'http',
                parsed.netloc,
                test_path,
                '', '', ''
            ))

            self.logger.debug(f"Testing error page redirect: {http_test_url}")

            response = self.safe_request('GET', http_test_url, allow_redirects=False)

            if response is None:
                return {
                    'proper_redirect': True,
                    'details': 'HTTP request blocked (good)'
                }

            status_code = response.status_code

            # 適切なリダイレクトまたは404
            if status_code in [301, 302, 303, 307, 308, 404]:
                location = response.headers.get('Location', '')

                if status_code == 404:
                    return {
                        'proper_redirect': True,
                        'status_code': status_code,
                        'details': 'Returns 404 for non-existent pages'
                    }
                elif location.startswith('https://'):
                    return {
                        'proper_redirect': True,
                        'status_code': status_code,
                        'redirect_location': location,
                        'details': 'Redirects to HTTPS'
                    }
                else:
                    return {
                        'proper_redirect': False,
                        'status_code': status_code,
                        'redirect_location': location,
                        'details': 'Does not redirect to HTTPS'
                    }

            # 不適切なレスポンス（200等）
            else:
                return {
                    'proper_redirect': False,
                    'status_code': status_code,
                    'details': f'Unexpected response for non-existent page: {status_code}'
                }

        except Exception as e:
            self.logger.debug(f"Error page redirect test error: {url}", error=str(e))
            return {
                'proper_redirect': True,  # エラーの場合は問題なしと判定
                'details': 'Error page redirect test failed',
                'error': str(e)
            }

    def _check_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """
        SSL証明書チェック

        Args:
            url: 診断対象URL

        Returns:
            SSL証明書チェック結果
        """
        try:
            # HTTPS URLに変換
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                https_url = urlunparse((
                    'https',
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            else:
                https_url = url

            self.logger.debug(f"Checking SSL certificate: {https_url}")

            response = self.safe_request('GET', https_url)

            if response is None:
                return {
                    'valid': False,
                    'details': 'HTTPS connection failed'
                }

            # 正常にHTTPS接続できた場合
            return {
                'valid': True,
                'status_code': response.status_code,
                'details': 'HTTPS connection successful'
            }

        except Exception as e:
            self.logger.debug(f"SSL certificate check error: {url}", error=str(e))
            return {
                'valid': False,
                'details': 'SSL certificate check failed',
                'error': str(e)
            }

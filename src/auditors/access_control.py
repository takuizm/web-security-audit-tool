"""
アクセス制御診断

検索エンジンインデックス化、サーバアクセス制限の確認を行います。
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from .base_auditor import BaseAuditor
from .data_models import AuditResult, AuditStatus


class AccessControlAuditor(BaseAuditor):
    """アクセス制御診断クラス"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.audit_type = "access_control"

        # 検索対象キーワード
        self.search_terms = [
            "index of",
            "login",
            "admin",
            "password",
            "config",
            "backup",
            "database",
            "test"
        ]

        # 危険なディレクトリパターン
        self.dangerous_paths = [
            "/admin",
            "/administrator",
            "/login",
            "/wp-admin",
            "/phpmyadmin",
            "/config",
            "/backup",
            "/test",
            "/dev",
            "/staging"
        ]

    def audit(self, url: str) -> AuditResult:
        """
        アクセス制御診断を実行

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        details = {}
        recommendations = []
        checks = {}

        try:
            # サイト内検索による情報漏洩チェック
            site_search_result = self._check_site_search_exposure(url)
            details['site_search'] = site_search_result
            checks['no_sensitive_indexed'] = not site_search_result.get('has_sensitive_content', False)

            # IPアドレス直接アクセスチェック
            ip_access_result = self._check_ip_direct_access(url)
            details['ip_access'] = ip_access_result
            checks['ip_access_blocked'] = ip_access_result.get('blocked', False)

            # サブドメインアクセスチェック
            subdomain_result = self._check_subdomain_access(url)
            details['subdomain_access'] = subdomain_result
            checks['subdomain_secure'] = subdomain_result.get('secure', True)

            # robots.txt チェック
            robots_result = self._check_robots_txt(url)
            details['robots_txt'] = robots_result
            checks['robots_configured'] = robots_result.get('configured', False)

            # 危険なパスへのアクセスチェック
            dangerous_paths_result = self._check_dangerous_paths(url)
            details['dangerous_paths'] = dangerous_paths_result
            checks['dangerous_paths_blocked'] = dangerous_paths_result.get('blocked', False)

            # 推奨事項生成
            if site_search_result.get('has_sensitive_content', False):
                recommendations.append("検索エンジンにインデックスされている機密情報を確認し、適切に制限してください")

            if not ip_access_result.get('blocked', False):
                recommendations.append("IPアドレスによる直接アクセスを制限してください")

            if not subdomain_result.get('secure', True):
                recommendations.append("テスト用サブドメインへのアクセスを制限してください")

            if not robots_result.get('configured', False):
                recommendations.append("robots.txtファイルを適切に設定してください")

            if not dangerous_paths_result.get('blocked', False):
                recommendations.append("管理画面や設定ファイルへのアクセスを制限してください")

        except Exception as e:
            self.logger.error(f"Access control audit failed: {url}", error=str(e))
            return self.create_result(
                url=url,
                status=AuditStatus.ERROR,
                error_message=str(e)
            )

        # ステータス決定
        critical_issues = any([
            site_search_result.get('has_sensitive_content', False),
            not ip_access_result.get('blocked', False),
            not dangerous_paths_result.get('blocked', False)
        ])

        status = self.determine_status(checks, critical_issues)

        return self.create_result(
            url=url,
            status=status,
            details=details,
            recommendations=recommendations
        )

    def _check_site_search_exposure(self, url: str) -> Dict[str, Any]:
        """
        サイト内検索による情報漏洩をチェック

        Args:
            url: 診断対象URL

        Returns:
            サイト内検索結果
        """
        try:
            domain = self.extract_domain(url)
            sensitive_findings = []

            # 簡略化された検索シミュレーション
            # 実際の実装では Google Custom Search API を使用

            # robots.txt から推測される機密ディレクトリ
            robots_url = f"https://{domain}/robots.txt"
            robots_response = self.safe_request('GET', robots_url)

            if robots_response and robots_response.status_code == 200:
                robots_content = robots_response.text

                # Disallow エントリから機密パスを抽出
                disallow_patterns = re.findall(r'Disallow:\s*(.+)', robots_content, re.IGNORECASE)

                for pattern in disallow_patterns:
                    pattern = pattern.strip()
                    if any(sensitive in pattern.lower() for sensitive in ['admin', 'private', 'config', 'backup']):
                        sensitive_findings.append(f"Robots.txt reveals sensitive path: {pattern}")

            # よくある機密ファイルの存在チェック
            common_files = [
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/database.sql',
                '/backup.zip',
                '/.git/config'
            ]

            for file_path in common_files:
                test_url = f"https://{domain}{file_path}"
                response = self.safe_request('HEAD', test_url)

                if response and response.status_code == 200:
                    sensitive_findings.append(f"Sensitive file accessible: {file_path}")

            return {
                'has_sensitive_content': len(sensitive_findings) > 0,
                'sensitive_findings': sensitive_findings,
                'total_findings': len(sensitive_findings)
            }

        except Exception as e:
            self.logger.debug(f"Site search exposure check failed: {url}", error=str(e))
            return {
                'has_sensitive_content': False,
                'sensitive_findings': [],
                'error': str(e)
            }

    def _check_ip_direct_access(self, url: str) -> Dict[str, Any]:
        """
        IPアドレス直接アクセスをチェック

        Args:
            url: 診断対象URL

        Returns:
            IPアクセスチェック結果
        """
        try:
            import socket

            domain = self.extract_domain(url).split(':')[0]  # ポート番号を除去

            # ドメインのIPアドレスを取得
            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                return {
                    'blocked': True,
                    'details': 'Domain resolution failed'
                }

            # IPアドレスで直接アクセステスト
            parsed = urlparse(url)
            ip_url = f"{parsed.scheme}://{ip_address}"
            if parsed.port:
                ip_url += f":{parsed.port}"

            self.logger.debug(f"Testing IP direct access: {ip_url}")

            response = self.safe_request('GET', ip_url, allow_redirects=False)

            if response is None:
                return {
                    'blocked': True,
                    'ip_address': ip_address,
                    'details': 'IP access blocked or failed'
                }

            status_code = response.status_code

            # 正常レスポンス（アクセス可能）
            if 200 <= status_code < 400:
                return {
                    'blocked': False,
                    'ip_address': ip_address,
                    'status_code': status_code,
                    'details': f'IP access allowed (status: {status_code})'
                }

            # エラーレスポンス（アクセス制限）
            else:
                return {
                    'blocked': True,
                    'ip_address': ip_address,
                    'status_code': status_code,
                    'details': f'IP access blocked (status: {status_code})'
                }

        except Exception as e:
            self.logger.debug(f"IP direct access check failed: {url}", error=str(e))
            return {
                'blocked': True,
                'details': 'IP access check failed',
                'error': str(e)
            }

    def _check_subdomain_access(self, url: str) -> Dict[str, Any]:
        """
        サブドメインアクセスをチェック

        Args:
            url: 診断対象URL

        Returns:
            サブドメインアクセス結果
        """
        try:
            domain = self.extract_domain(url)

            # よくあるテスト用サブドメイン
            test_subdomains = [
                'test',
                'dev',
                'staging',
                'admin',
                'api',
                'www2'
            ]

            accessible_subdomains = []

            for subdomain in test_subdomains:
                if '.' in domain:
                    # example.com -> test.example.com
                    test_domain = f"{subdomain}.{domain}"
                else:
                    continue

                test_url = f"https://{test_domain}"

                response = self.safe_request('HEAD', test_url)

                if response and response.status_code == 200:
                    accessible_subdomains.append(test_domain)

            return {
                'secure': len(accessible_subdomains) == 0,
                'accessible_subdomains': accessible_subdomains,
                'total_accessible': len(accessible_subdomains)
            }

        except Exception as e:
            self.logger.debug(f"Subdomain access check failed: {url}", error=str(e))
            return {
                'secure': True,
                'accessible_subdomains': [],
                'error': str(e)
            }

    def _check_robots_txt(self, url: str) -> Dict[str, Any]:
        """
        robots.txt をチェック

        Args:
            url: 診断対象URL

        Returns:
            robots.txt チェック結果
        """
        try:
            domain = self.extract_domain(url)
            robots_url = f"https://{domain}/robots.txt"

            response = self.safe_request('GET', robots_url)

            if response is None:
                return {
                    'configured': False,
                    'exists': False,
                    'details': 'robots.txt request failed'
                }

            if response.status_code == 404:
                return {
                    'configured': False,
                    'exists': False,
                    'details': 'robots.txt not found'
                }

            if response.status_code == 200:
                content = response.text.strip()

                if not content:
                    return {
                        'configured': False,
                        'exists': True,
                        'details': 'robots.txt exists but is empty'
                    }

                # 基本的な設定の確認
                has_user_agent = 'User-agent:' in content
                has_disallow = 'Disallow:' in content
                has_sitemap = 'Sitemap:' in content

                return {
                    'configured': has_user_agent and (has_disallow or has_sitemap),
                    'exists': True,
                    'has_user_agent': has_user_agent,
                    'has_disallow': has_disallow,
                    'has_sitemap': has_sitemap,
                    'content_length': len(content),
                    'details': 'robots.txt found and analyzed'
                }

            return {
                'configured': False,
                'exists': False,
                'status_code': response.status_code,
                'details': f'Unexpected status code: {response.status_code}'
            }

        except Exception as e:
            self.logger.debug(f"robots.txt check failed: {url}", error=str(e))
            return {
                'configured': False,
                'exists': False,
                'error': str(e)
            }

    def _check_dangerous_paths(self, url: str) -> Dict[str, Any]:
        """
        危険なパスへのアクセスをチェック

        Args:
            url: 診断対象URL

        Returns:
            危険パスチェック結果
        """
        try:
            domain = self.extract_domain(url)
            accessible_paths = []

            for path in self.dangerous_paths:
                test_url = f"https://{domain}{path}"

                response = self.safe_request('HEAD', test_url)

                if response and 200 <= response.status_code < 400:
                    accessible_paths.append({
                        'path': path,
                        'status_code': response.status_code
                    })

            return {
                'blocked': len(accessible_paths) == 0,
                'accessible_paths': accessible_paths,
                'total_accessible': len(accessible_paths),
                'total_tested': len(self.dangerous_paths)
            }

        except Exception as e:
            self.logger.debug(f"Dangerous paths check failed: {url}", error=str(e))
            return {
                'blocked': True,
                'accessible_paths': [],
                'error': str(e)
            }

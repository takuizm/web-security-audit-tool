"""
コンプライアンス評価モジュール

セキュリティ診断結果を1/0形式で評価します。
"""

from typing import Dict, Any, List
from ..auditors.data_models import BatchAuditResult, AuditResult


class ComplianceEvaluator:
    """コンプライアンス評価クラス"""

    def __init__(self):
        self.evaluation_criteria = {
            'S1-1': 'jQuery 3.5.0以上（未使用は「未」）',
            'S1-2': 'jQuery 3.5.0以上（未使用は0）',
            'S2': '非暗号化通信接続が許可されていない',
            'S3': 'TLS1.3が有効',
            'S4': 'TLS1.1以前が無効',
            'S6-1': 'index of(公開不要コンテンツno-index制御)',
            'S6-2': 'login(公開不要コンテンツno-index制御)',
            'S6-3': 'password(公開不要コンテンツno-index制御)',
            'S7': '公開不要サーバーアクセス制御',
            'S8-1': 'X-Frame-Options',
            'S8-2': 'Strict-Transport-Security',
            'S8-3': 'Content-Security-Policy'
        }

    def evaluate_batch_results(self, batch_result: BatchAuditResult) -> Dict[str, Dict[str, Any]]:
        """
        バッチ診断結果をコンプライアンス評価

        Args:
            batch_result: バッチ診断結果

        Returns:
            URL別のコンプライアンス評価結果
        """
        evaluation_results = {}

        # URL別にグループ化
        url_groups = {}
        for result in batch_result.results:
            if result.url not in url_groups:
                url_groups[result.url] = []
            url_groups[result.url].append(result)

        # 各URLを評価
        for url, results in url_groups.items():
            evaluation_results[url] = self._evaluate_single_site(url, results)

        return evaluation_results

    def _evaluate_single_site(self, url: str, results: List[AuditResult]) -> Dict[str, Any]:
        """
        単一サイトのコンプライアンス評価

        Args:
            url: 評価対象URL
            results: 診断結果リスト

        Returns:
            コンプライアンス評価結果
        """
        # 診断結果を種類別に分類
        result_by_type = {}
        for result in results:
            result_by_type[result.audit_type] = result

        evaluation = {
            'url': url,
            'evaluations': {},
            'details': {}
        }

        # S1-1: jQuery 3.5.0以上
        evaluation['evaluations']['S1-1'], evaluation['details']['S1-1'] = self._evaluate_jquery_version(
            result_by_type.get('component_vulnerability')
        )

        # S1-2: jQuery 3.5.0以上なら1、それ以下なら0
        evaluation['evaluations']['S1-2'], evaluation['details']['S1-2'] = self._evaluate_jquery_35_or_higher(
            result_by_type.get('component_vulnerability')
        )

        # S2: 非暗号化通信接続が許可されていない
        evaluation['evaluations']['S2'], evaluation['details']['S2'] = self._evaluate_encryption_check(
            result_by_type.get('encryption_check')
        )

        # S3: TLS1.3が有効
        evaluation['evaluations']['S3'], evaluation['details']['S3'] = self._evaluate_tls13_support(
            result_by_type.get('tls_security')
        )

        # S4: TLS1.1以前が無効
        evaluation['evaluations']['S4'], evaluation['details']['S4'] = self._evaluate_old_tls_disabled(
            result_by_type.get('tls_security')
        )

        # S6-1: index of制御
        evaluation['evaluations']['S6-1'], evaluation['details']['S6-1'] = self._evaluate_index_of_control(
            result_by_type.get('access_control')
        )

        # S6-2: login制御
        evaluation['evaluations']['S6-2'], evaluation['details']['S6-2'] = self._evaluate_login_control(
            result_by_type.get('access_control')
        )

        # S6-3: password制御
        evaluation['evaluations']['S6-3'], evaluation['details']['S6-3'] = self._evaluate_password_control(
            result_by_type.get('access_control')
        )

        # S7: 公開不要サーバーアクセス制御
        evaluation['evaluations']['S7'], evaluation['details']['S7'] = self._evaluate_server_access_control(
            result_by_type.get('access_control')
        )

        # S8-1: X-Frame-Options
        evaluation['evaluations']['S8-1'], evaluation['details']['S8-1'] = self._evaluate_x_frame_options(
            result_by_type.get('security_headers')
        )

        # S8-2: Strict-Transport-Security
        evaluation['evaluations']['S8-2'], evaluation['details']['S8-2'] = self._evaluate_hsts(
            result_by_type.get('security_headers')
        )

        # S8-3: Content-Security-Policy
        evaluation['evaluations']['S8-3'], evaluation['details']['S8-3'] = self._evaluate_csp(
            result_by_type.get('security_headers')
        )

        return evaluation

    def _evaluate_jquery_version(self, result: AuditResult) -> tuple:
        """jQuery バージョン評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        jquery_info = result.details.get('jquery', {})
        version = jquery_info.get('version')

        if not version:
            return 1, '未'  # 未使用は1とする

        try:
            # バージョン比較 (3.5.0以上かチェック)
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                patch = int(version_parts[2]) if len(version_parts) > 2 else 0

                if major > 3 or (major == 3 and minor > 5) or (major == 3 and minor == 5 and patch >= 0):
                    return 1, f'{version}'
                else:
                    return 0, f'{version}'
        except (ValueError, IndexError):
            return 0, f'{version}（バージョン解析エラー）'

        return 0, f'{version}'

    def _evaluate_jquery_35_or_higher(self, result: AuditResult) -> tuple:
        """jQuery 3.5.0以上評価（S1-2用）"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        jquery_info = result.details.get('jquery', {})
        version = jquery_info.get('version')

        if not version:
            return 0, '未使用'  # 未使用は0とする（S1-1と異なる）

        try:
            # バージョン比較 (3.5.0以上かチェック)
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                patch = int(version_parts[2]) if len(version_parts) > 2 else 0

                if major > 3 or (major == 3 and minor > 5) or (major == 3 and minor == 5 and patch >= 0):
                    return 1, f'{version}'
                else:
                    return 0, f'{version}'
        except (ValueError, IndexError):
            return 0, f'{version}（バージョン解析エラー）'

        return 0, f'{version}'

    def _evaluate_encryption_check(self, result: AuditResult) -> tuple:
        """暗号化通信評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        http_test = result.details.get('http_access_test', {})
        https_redirect = result.details.get('https_redirect_test', {})

        # HTTPアクセスがブロックされているか、HTTPSにリダイレクトされるか
        http_blocked = http_test.get('blocked', False)
        redirects_to_https = https_redirect.get('redirects_to_https', False)

        if http_blocked or redirects_to_https:
            return 1, 'HTTPアクセス制限済み'
        else:
            return 0, 'HTTPアクセス可能'

    def _evaluate_tls13_support(self, result: AuditResult) -> tuple:
        """TLS1.3サポート評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        tls_support = result.details.get('tls_version_support', {})
        tls13_info = tls_support.get('TLSv1.3', {})

        if tls13_info.get('supported', False):
            version = tls13_info.get('version', 'TLSv1.3')
            return 1, version
        else:
            return 0, 'TLS1.3未サポート'

    def _evaluate_old_tls_disabled(self, result: AuditResult) -> tuple:
        """古いTLS無効化評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        tls_support = result.details.get('tls_version_support', {})

        tls10_supported = tls_support.get('TLSv1.0', {}).get('supported', False)
        tls11_supported = tls_support.get('TLSv1.1', {}).get('supported', False)

        if not tls10_supported and not tls11_supported:
            return 1, 'TLS1.1以前無効'
        else:
            enabled_versions = []
            if tls10_supported:
                enabled_versions.append('TLS1.0')
            if tls11_supported:
                enabled_versions.append('TLS1.1')
            return 0, f'有効: {", ".join(enabled_versions)}'

    def _evaluate_index_of_control(self, result: AuditResult) -> tuple:
        """index of制御評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        # 個別キーワード検索結果を確認
        search_results = result.details.get('keyword_search_results', {})
        index_of_result = search_results.get('index of', {})

        # 新しい詳細検索結果がある場合
        if index_of_result:
            found_count = index_of_result.get('total_results', 0)
            if found_count == 0:
                return 1, 'index of制御済み'
            else:
                return 0, f'index of検出({found_count}件)'

        # フォールバック: 従来の方式
        site_search = result.details.get('site_search', {})
        sensitive_findings = site_search.get('sensitive_findings', [])

        # robots.txtや直接ファイルアクセスでの検出
        index_of_indicators = [
            'index of',
            'directory listing',
            'parent directory',
            'apache',  # Apacheのディレクトリリスティング
            'nginx'    # Nginxのディレクトリリスティング
        ]

        index_of_found = any(
            any(indicator in finding.lower() for indicator in index_of_indicators)
            for finding in sensitive_findings
        )

        if not index_of_found:
            return 1, 'index of制御済み'
        else:
            return 0, 'index of検出'

    def _evaluate_login_control(self, result: AuditResult) -> tuple:
        """login制御評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        # 個別キーワード検索結果を確認
        search_results = result.details.get('keyword_search_results', {})
        login_result = search_results.get('login', {})

        # 新しい詳細検索結果がある場合
        if login_result:
            found_count = login_result.get('total_results', 0)
            if found_count == 0:
                return 1, 'login制御済み'
            else:
                return 0, f'login検出({found_count}件)'

        # フォールバック: 従来の方式
        site_search = result.details.get('site_search', {})
        sensitive_findings = site_search.get('sensitive_findings', [])
        dangerous_paths = result.details.get('dangerous_paths', {})
        accessible_paths = dangerous_paths.get('accessible_paths', [])

        # loginページへの直接アクセス可能性をチェック
        login_accessible = any(
            'login' in path.get('path', '').lower()
            for path in accessible_paths
        )

        # robots.txtでのlogin関連パス露出
        login_in_robots = any('login' in finding.lower() for finding in sensitive_findings)

        if not login_accessible and not login_in_robots:
            return 1, 'login制御済み'
        else:
            issues = []
            if login_accessible:
                issues.append('loginページアクセス可能')
            if login_in_robots:
                issues.append('robots.txtでlogin露出')
            return 0, ', '.join(issues)

    def _evaluate_password_control(self, result: AuditResult) -> tuple:
        """password制御評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        # 個別キーワード検索結果を確認
        search_results = result.details.get('keyword_search_results', {})
        password_result = search_results.get('password', {})

        # 新しい詳細検索結果がある場合
        if password_result:
            found_count = password_result.get('total_results', 0)
            if found_count == 0:
                return 1, 'password制御済み'
            else:
                return 0, f'password検出({found_count}件)'

        # フォールバック: 従来の方式
        site_search = result.details.get('site_search', {})
        sensitive_findings = site_search.get('sensitive_findings', [])

        # password関連ファイルの検出
        password_indicators = [
            'password',
            '.env',  # 環境変数ファイル
            'config.php',  # 設定ファイル
            'wp-config',  # WordPress設定
            'database.sql',  # データベースダンプ
            'backup'  # バックアップファイル
        ]

        password_found = any(
            any(indicator in finding.lower() for indicator in password_indicators)
            for finding in sensitive_findings
        )

        if not password_found:
            return 1, 'password制御済み'
        else:
            return 0, 'password関連ファイル検出'

    def _evaluate_server_access_control(self, result: AuditResult) -> tuple:
        """サーバーアクセス制御評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        ip_access = result.details.get('ip_access', {})
        subdomain_access = result.details.get('subdomain_access', {})
        dangerous_paths = result.details.get('dangerous_paths', {})

        # IPアクセスがブロックされているか
        ip_blocked = ip_access.get('blocked', False)

        # サブドメインが安全か
        subdomain_secure = subdomain_access.get('secure', True)

        # 危険なパスがブロックされているか
        paths_blocked = dangerous_paths.get('blocked', False)

        if ip_blocked and subdomain_secure and paths_blocked:
            return 1, 'アクセス制御済み'
        else:
            issues = []
            if not ip_blocked:
                issues.append('IP直接アクセス可能')
            if not subdomain_secure:
                issues.append('危険サブドメイン')
            if not paths_blocked:
                issues.append('危険パスアクセス可能')
            return 0, ', '.join(issues)

    def _evaluate_x_frame_options(self, result: AuditResult) -> tuple:
        """X-Frame-Options評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        headers = result.details.get('security_headers', {})
        xfo_info = headers.get('X-Frame-Options', {})

        if xfo_info.get('configured', False):
            return 1, f'設定済み: {xfo_info.get("value", "")}'
        else:
            return 0, '未設定'

    def _evaluate_hsts(self, result: AuditResult) -> tuple:
        """Strict-Transport-Security評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        headers = result.details.get('security_headers', {})
        hsts_info = headers.get('Strict-Transport-Security', {})

        if hsts_info.get('configured', False):
            return 1, f'設定済み: {hsts_info.get("value", "")}'
        else:
            return 0, '未設定'

    def _evaluate_csp(self, result: AuditResult) -> tuple:
        """Content-Security-Policy評価"""
        if not result or result.status.value == 'ERROR':
            return 0, '診断エラー'

        headers = result.details.get('security_headers', {})
        csp_info = headers.get('Content-Security-Policy', {})

        if csp_info.get('configured', False):
            return 1, f'設定済み'
        else:
            return 0, '未設定'

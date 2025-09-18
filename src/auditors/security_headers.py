"""
セキュリティヘッダー診断

HTTPレスポンスヘッダーによるセキュリティ対策の確認を行います。
"""

from typing import Dict, Any, List, Optional

from .base_auditor import BaseAuditor
from .data_models import AuditResult, AuditStatus


class SecurityHeadersAuditor(BaseAuditor):
    """セキュリティヘッダー診断クラス"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.audit_type = "security_headers"

        # 必須セキュリティヘッダー
        self.required_headers = {
            'X-Frame-Options': {
                'description': 'クリックジャッキング攻撃を防ぐ',
                'valid_values': ['DENY', 'SAMEORIGIN'],
                'weight': 25
            },
            'Strict-Transport-Security': {
                'description': 'HTTPS接続を強制する',
                'valid_patterns': [r'max-age=\d+'],
                'weight': 30
            },
            'Content-Security-Policy': {
                'description': 'XSS攻撃等を防ぐ',
                'required_directives': ['default-src'],
                'weight': 25
            },
            'X-Content-Type-Options': {
                'description': 'MIMEタイプスニッフィングを防ぐ',
                'valid_values': ['nosniff'],
                'weight': 10
            },
            'Referrer-Policy': {
                'description': 'リファラー情報の制御',
                'valid_values': ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin'],
                'weight': 5
            },
            'X-XSS-Protection': {
                'description': 'XSS保護機能（レガシー）',
                'valid_values': ['1; mode=block', '0'],
                'weight': 5
            }
        }

    def audit(self, url: str) -> AuditResult:
        """
        セキュリティヘッダー診断を実行

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        details = {}
        recommendations = []
        checks = {}

        try:
            # HTTPレスポンスヘッダー取得
            response = self.safe_request('GET', url)

            if response is None:
                return self.create_result(
                    url=url,
                    status=AuditStatus.ERROR,
                    error_message="Failed to fetch HTTP response"
                )

            headers = response.headers
            details['response_headers'] = dict(headers)
            details['status_code'] = response.status_code

            # 各セキュリティヘッダーをチェック
            header_results = {}

            for header_name, header_config in self.required_headers.items():
                result = self._check_security_header(headers, header_name, header_config)
                header_results[header_name] = result
                checks[f"{header_name.lower().replace('-', '_')}_configured"] = result.get('configured', False)

            details['security_headers'] = header_results

            # 追加のセキュリティチェック
            additional_checks = self._perform_additional_checks(headers)
            details['additional_checks'] = additional_checks

            # 推奨事項生成
            for header_name, result in header_results.items():
                if not result.get('configured', False):
                    recommendations.append(f"{header_name} ヘッダーを設定してください")
                elif result.get('issues'):
                    for issue in result['issues']:
                        recommendations.append(f"{header_name}: {issue}")

            # 追加の推奨事項
            if additional_checks.get('server_header_exposed', False):
                recommendations.append("Serverヘッダーの情報を最小限にしてください")

            if additional_checks.get('powered_by_exposed', False):
                recommendations.append("X-Powered-Byヘッダーを削除してください")

        except Exception as e:
            self.logger.error(f"Security headers audit failed: {url}", error=str(e))
            return self.create_result(
                url=url,
                status=AuditStatus.ERROR,
                error_message=str(e)
            )

        # ステータス決定
        critical_headers_missing = not all([
            checks.get('x_frame_options_configured', False),
            checks.get('strict_transport_security_configured', False),
            checks.get('content_security_policy_configured', False)
        ])

        status = self.determine_status(checks, critical_headers_missing)

        return self.create_result(
            url=url,
            status=status,
            details=details,
            recommendations=recommendations
        )

    def _check_security_header(self, headers: Dict[str, str], header_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        個別セキュリティヘッダーをチェック

        Args:
            headers: HTTPレスポンスヘッダー
            header_name: ヘッダー名
            config: ヘッダー設定

        Returns:
            ヘッダーチェック結果
        """
        header_value = headers.get(header_name, '').strip()

        if not header_value:
            return {
                'configured': False,
                'value': None,
                'issues': [f'{header_name} ヘッダーが設定されていません']
            }

        issues = []

        # 有効な値のチェック
        if 'valid_values' in config:
            if header_value not in config['valid_values']:
                issues.append(f'推奨されない値です: {header_value}')

        # パターンマッチング
        if 'valid_patterns' in config:
            import re
            pattern_matched = any(re.search(pattern, header_value) for pattern in config['valid_patterns'])
            if not pattern_matched:
                issues.append(f'推奨されないフォーマットです: {header_value}')

        # CSP特有のチェック
        if header_name == 'Content-Security-Policy':
            csp_issues = self._check_csp_policy(header_value)
            issues.extend(csp_issues)

        # HSTS特有のチェック
        if header_name == 'Strict-Transport-Security':
            hsts_issues = self._check_hsts_policy(header_value)
            issues.extend(hsts_issues)

        return {
            'configured': True,
            'value': header_value,
            'issues': issues,
            'score': 100 if not issues else max(0, 100 - len(issues) * 20)
        }

    def _check_csp_policy(self, csp_value: str) -> List[str]:
        """
        Content-Security-Policy の詳細チェック

        Args:
            csp_value: CSP ヘッダー値

        Returns:
            問題点のリスト
        """
        issues = []

        # 危険な設定のチェック
        if "'unsafe-inline'" in csp_value:
            issues.append("'unsafe-inline' の使用は推奨されません")

        if "'unsafe-eval'" in csp_value:
            issues.append("'unsafe-eval' の使用は推奨されません")

        if "*" in csp_value and "data:" not in csp_value:
            issues.append("ワイルドカード (*) の使用は推奨されません")

        # 必要なディレクティブのチェック
        required_directives = ['default-src', 'script-src', 'style-src']
        for directive in required_directives:
            if directive not in csp_value:
                issues.append(f"{directive} ディレクティブの設定を検討してください")

        return issues

    def _check_hsts_policy(self, hsts_value: str) -> List[str]:
        """
        Strict-Transport-Security の詳細チェック

        Args:
            hsts_value: HSTS ヘッダー値

        Returns:
            問題点のリスト
        """
        issues = []

        import re

        # max-age の値をチェック
        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))

            # 推奨最小値は1年（31536000秒）
            if max_age < 31536000:
                issues.append(f"max-age が短すぎます ({max_age} 秒)")
        else:
            issues.append("max-age が設定されていません")

        # includeSubDomains の推奨
        if 'includeSubDomains' not in hsts_value:
            issues.append("includeSubDomains の設定を検討してください")

        # preload の推奨
        if 'preload' not in hsts_value:
            issues.append("preload の設定を検討してください")

        return issues

    def _perform_additional_checks(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        追加のセキュリティチェック

        Args:
            headers: HTTPレスポンスヘッダー

        Returns:
            追加チェック結果
        """
        results = {}

        # Server ヘッダーの情報露出チェック
        server_header = headers.get('Server', '')
        if server_header:
            # バージョン情報が含まれているかチェック
            import re
            version_pattern = r'\d+\.\d+(\.\d+)?'
            has_version = bool(re.search(version_pattern, server_header))

            results['server_header_exposed'] = has_version
            results['server_header_value'] = server_header
        else:
            results['server_header_exposed'] = False

        # X-Powered-By ヘッダーの情報露出チェック
        powered_by = headers.get('X-Powered-By', '')
        results['powered_by_exposed'] = bool(powered_by)
        if powered_by:
            results['powered_by_value'] = powered_by

        # Set-Cookie のセキュリティ属性チェック
        set_cookie_headers = headers.get('Set-Cookie', '')
        if set_cookie_headers:
            cookie_security = self._check_cookie_security(set_cookie_headers)
            results['cookie_security'] = cookie_security

        # MIME スニッフィング対策
        content_type = headers.get('Content-Type', '')
        x_content_type = headers.get('X-Content-Type-Options', '')
        results['mime_sniffing_protected'] = x_content_type.lower() == 'nosniff'

        return results

    def _check_cookie_security(self, cookie_header: str) -> Dict[str, Any]:
        """
        Cookie のセキュリティ属性をチェック

        Args:
            cookie_header: Set-Cookie ヘッダー値

        Returns:
            Cookie セキュリティチェック結果
        """
        return {
            'has_secure': 'Secure' in cookie_header,
            'has_httponly': 'HttpOnly' in cookie_header,
            'has_samesite': 'SameSite=' in cookie_header,
            'cookie_header': cookie_header
        }

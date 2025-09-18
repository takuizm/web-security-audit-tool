"""
SecurityTrails API連携

SecurityTrails APIとの連携機能を提供します。
"""

from typing import Dict, Any, List, Optional
from ..utils.exceptions import APIError
from ..utils.logger import get_logger
from ..utils.http_client import HTTPClient, RateLimiter


class SecurityTrailsAPI:
    """SecurityTrails API連携クラス"""

    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: API設定
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.api_key = config.get('api_key')
        self.base_url = "https://api.securitytrails.com/v1"

        if not self.api_key:
            self.logger.warning("SecurityTrails API key not configured")

        # レート制限設定（Free tier: 50 queries per month）
        rate_limiter = RateLimiter(calls_per_minute=2)

        # HTTPクライアント初期化
        self.http_client = HTTPClient(
            timeout=30,
            max_retries=3,
            rate_limiter=rate_limiter,
            user_agent='SecurityAuditTool/1.0'
        )

    def get_dns_trails(self, domain: str) -> Dict[str, Any]:
        """
        DNS履歴情報を取得

        Args:
            domain: 対象ドメイン

        Returns:
            DNS履歴情報
        """
        if not self.api_key:
            return {
                'status': 'error',
                'error': 'SecurityTrails API key not configured'
            }

        try:
            # ドメインからサブドメインを除去
            domain = self._extract_root_domain(domain)

            endpoint = f"{self.base_url}/domain/{domain}"
            headers = {
                'APIKEY': self.api_key,
                'Content-Type': 'application/json'
            }

            self.logger.debug(f"SecurityTrails DNS lookup: {domain}")

            response = self.http_client.get(endpoint, headers=headers)

            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'domain': domain,
                    'data': self._parse_dns_data(data)
                }

            elif response.status_code == 403:
                self.logger.warning("SecurityTrails API access denied")
                return {
                    'status': 'error',
                    'error': 'API access denied or quota exceeded'
                }

            elif response.status_code == 404:
                self.logger.info(f"Domain not found in SecurityTrails: {domain}")
                return {
                    'status': 'error',
                    'error': 'Domain not found'
                }

            else:
                self.logger.warning(f"SecurityTrails API returned status {response.status_code}")
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"SecurityTrails DNS lookup failed: {domain}", error=str(e))
            return {
                'status': 'error',
                'domain': domain,
                'error': str(e)
            }

    def get_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        サブドメイン情報を取得

        Args:
            domain: 対象ドメイン

        Returns:
            サブドメイン情報
        """
        if not self.api_key:
            return {
                'status': 'error',
                'error': 'SecurityTrails API key not configured'
            }

        try:
            domain = self._extract_root_domain(domain)

            endpoint = f"{self.base_url}/domain/{domain}/subdomains"
            headers = {
                'APIKEY': self.api_key,
                'Content-Type': 'application/json'
            }

            self.logger.debug(f"SecurityTrails subdomain lookup: {domain}")

            response = self.http_client.get(endpoint, headers=headers)

            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])

                # 危険なサブドメインの検出
                dangerous_subdomains = self._identify_dangerous_subdomains(subdomains)

                return {
                    'status': 'success',
                    'domain': domain,
                    'total_subdomains': len(subdomains),
                    'subdomains': subdomains[:50],  # 最初の50個のみ
                    'dangerous_subdomains': dangerous_subdomains,
                    'has_dangerous_subdomains': len(dangerous_subdomains) > 0
                }

            elif response.status_code == 403:
                return {
                    'status': 'error',
                    'error': 'API access denied or quota exceeded'
                }

            elif response.status_code == 404:
                return {
                    'status': 'error',
                    'error': 'Domain not found'
                }

            else:
                return {
                    'status': 'error',
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }

        except Exception as e:
            self.logger.error(f"SecurityTrails subdomain lookup failed: {domain}", error=str(e))
            return {
                'status': 'error',
                'domain': domain,
                'error': str(e)
            }

    def check_domain_security(self, domain: str) -> Dict[str, Any]:
        """
        ドメインのセキュリティ状況をチェック

        Args:
            domain: 対象ドメイン

        Returns:
            セキュリティチェック結果
        """
        results = {
            'domain': domain,
            'dns_info': {},
            'subdomain_info': {},
            'security_issues': [],
            'risk_level': 'LOW'
        }

        try:
            # DNS情報取得
            dns_result = self.get_dns_trails(domain)
            results['dns_info'] = dns_result

            # サブドメイン情報取得
            subdomain_result = self.get_subdomains(domain)
            results['subdomain_info'] = subdomain_result

            # セキュリティ問題の分析
            security_issues = []

            # 危険なサブドメインの検出
            if subdomain_result.get('has_dangerous_subdomains', False):
                dangerous_subs = subdomain_result.get('dangerous_subdomains', [])
                security_issues.append({
                    'type': 'dangerous_subdomains',
                    'description': 'Potentially dangerous subdomains detected',
                    'details': dangerous_subs
                })

            # 多数のサブドメインの検出（攻撃対象面の拡大）
            total_subdomains = subdomain_result.get('total_subdomains', 0)
            if total_subdomains > 100:
                security_issues.append({
                    'type': 'large_attack_surface',
                    'description': f'Large number of subdomains detected ({total_subdomains})',
                    'details': f'{total_subdomains} subdomains found'
                })

            results['security_issues'] = security_issues
            results['risk_level'] = self._calculate_domain_risk_level(results)

            return {
                'status': 'success',
                'results': results
            }

        except Exception as e:
            self.logger.error(f"Domain security check failed: {domain}", error=str(e))
            return {
                'status': 'error',
                'domain': domain,
                'error': str(e)
            }

    def _extract_root_domain(self, domain: str) -> str:
        """
        ルートドメインを抽出

        Args:
            domain: ドメイン（サブドメイン含む可能性あり）

        Returns:
            ルートドメイン
        """
        # ポート番号を除去
        if ':' in domain:
            domain = domain.split(':')[0]

        # 基本的なルートドメイン抽出（簡略化）
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def _parse_dns_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        DNS データを解析

        Args:
            data: SecurityTrails DNS データ

        Returns:
            解析結果
        """
        parsed = {
            'current_dns': data.get('current_dns', {}),
            'alexa_rank': data.get('alexa_rank'),
            'hostname': data.get('hostname'),
            'subdomains_count': data.get('subdomain_count', 0)
        }

        # A レコード情報
        current_dns = data.get('current_dns', {})
        if 'a' in current_dns:
            parsed['a_records'] = current_dns['a']['values']

        # MX レコード情報
        if 'mx' in current_dns:
            parsed['mx_records'] = current_dns['mx']['values']

        return parsed

    def _identify_dangerous_subdomains(self, subdomains: List[str]) -> List[str]:
        """
        危険なサブドメインを特定

        Args:
            subdomains: サブドメインリスト

        Returns:
            危険なサブドメインリスト
        """
        dangerous_patterns = [
            'admin', 'administrator', 'root', 'test', 'testing',
            'dev', 'development', 'staging', 'stage', 'beta',
            'internal', 'private', 'secure', 'vpn', 'ftp',
            'mail', 'email', 'webmail', 'mx', 'smtp',
            'api', 'rest', 'service', 'micro',
            'db', 'database', 'sql', 'mysql', 'postgres',
            'backup', 'bak', 'old', 'temp', 'tmp'
        ]

        dangerous_subdomains = []

        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()
            for pattern in dangerous_patterns:
                if pattern in subdomain_lower:
                    dangerous_subdomains.append(subdomain)
                    break

        return dangerous_subdomains

    def _calculate_domain_risk_level(self, results: Dict[str, Any]) -> str:
        """
        ドメインのリスクレベルを計算

        Args:
            results: 分析結果

        Returns:
            リスクレベル（HIGH, MEDIUM, LOW）
        """
        risk_score = 0

        # セキュリティ問題数
        security_issues = results.get('security_issues', [])
        risk_score += len(security_issues) * 10

        # 危険なサブドメイン数
        subdomain_info = results.get('subdomain_info', {})
        dangerous_subdomains = subdomain_info.get('dangerous_subdomains', [])
        risk_score += len(dangerous_subdomains) * 5

        # 総サブドメイン数
        total_subdomains = subdomain_info.get('total_subdomains', 0)
        if total_subdomains > 100:
            risk_score += 20
        elif total_subdomains > 50:
            risk_score += 10

        # リスクレベル判定
        if risk_score >= 40:
            return 'HIGH'
        elif risk_score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'http_client'):
            self.http_client.close()

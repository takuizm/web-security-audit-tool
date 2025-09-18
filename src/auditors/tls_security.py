"""
TLSセキュリティ診断

TLS1.3サポート、TLS1.1以前の無効化確認を行います。
"""

import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse

from .base_auditor import BaseAuditor
from .data_models import AuditResult, AuditStatus


class TLSSecurityAuditor(BaseAuditor):
    """TLSセキュリティ診断クラス"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.audit_type = "tls_security"

        # TLSバージョンマッピング
        self.tls_versions = {
            ssl.PROTOCOL_TLS: "TLS",
            ssl.PROTOCOL_TLSv1: "TLSv1.0",
            ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
            ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
        }

        # TLSv1.3は別途チェック
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            self.tls_versions[ssl.PROTOCOL_TLSv1_3] = "TLSv1.3"

    def audit(self, url: str) -> AuditResult:
        """
        TLSセキュリティ診断を実行

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        details = {}
        recommendations = []
        checks = {}

        try:
            # URL解析
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return self.create_result(
                    url=url,
                    status=AuditStatus.NG,
                    details={'error': 'Not an HTTPS URL'},
                    recommendations=['HTTPSを使用してください']
                )

            hostname = parsed.hostname
            port = parsed.port or 443

            # TLSバージョンサポートチェック
            tls_support = self._check_tls_versions(hostname, port)
            details['tls_version_support'] = tls_support

            # TLS1.3サポート確認
            checks['tls13_supported'] = tls_support.get('TLSv1.3', {}).get('supported', False)

            # TLS1.1以前が無効確認
            old_tls_disabled = not any([
                tls_support.get('TLSv1.0', {}).get('supported', False),
                tls_support.get('TLSv1.1', {}).get('supported', False)
            ])
            checks['old_tls_disabled'] = old_tls_disabled

            # 証明書情報取得
            cert_info = self._get_certificate_info(hostname, port)
            details['certificate_info'] = cert_info
            checks['cert_valid'] = cert_info.get('valid', False)

            # 暗号スイート情報
            cipher_info = self._get_cipher_info(hostname, port)
            details['cipher_info'] = cipher_info
            checks['strong_ciphers'] = cipher_info.get('has_strong_ciphers', False)

            # 推奨事項生成
            if not checks['tls13_supported']:
                recommendations.append("TLS1.3のサポートを有効にしてください")

            if not checks['old_tls_disabled']:
                recommendations.append("TLS1.1以前のバージョンを無効にしてください")

            if not checks['strong_ciphers']:
                recommendations.append("強力な暗号スイートの設定を確認してください")

        except Exception as e:
            self.logger.error(f"TLS security audit failed: {url}", error=str(e))
            return self.create_result(
                url=url,
                status=AuditStatus.ERROR,
                error_message=str(e)
            )

        # ステータス決定
        critical_issues = not checks.get('old_tls_disabled', True)
        status = self.determine_status(checks, critical_issues)

        return self.create_result(
            url=url,
            status=status,
            details=details,
            recommendations=recommendations
        )

    def _check_tls_versions(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        TLSバージョンサポートをチェック

        Args:
            hostname: ホスト名
            port: ポート番号

        Returns:
            TLSバージョンサポート情報
        """
        results = {}

        # TLS1.3チェック（Python 3.7+）
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['TLSv1.3'] = {
                        'supported': True,
                        'cipher': ssock.cipher(),
                        'version': ssock.version()
                    }
        except Exception as e:
            results['TLSv1.3'] = {
                'supported': False,
                'error': str(e)
            }

        # TLS1.2チェック
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['TLSv1.2'] = {
                        'supported': True,
                        'cipher': ssock.cipher(),
                        'version': ssock.version()
                    }
        except Exception as e:
            results['TLSv1.2'] = {
                'supported': False,
                'error': str(e)
            }

        # TLS1.1チェック（非推奨）- より柔軟なアプローチ
        try:
            # 方法1: 厳密なバージョン指定
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_1
            context.maximum_version = ssl.TLSVersion.TLSv1_1

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['TLSv1.1'] = {
                        'supported': True,
                        'cipher': ssock.cipher(),
                        'version': ssock.version(),
                        'method': 'direct_version_check'
                    }
        except Exception as e:
            # 方法2: レガシー互換性チェック
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers('ALL:@SECLEVEL=0')  # より緩い暗号設定

                # TLS1.1を含む範囲で接続テスト
                context.minimum_version = ssl.TLSVersion.TLSv1_1
                context.maximum_version = ssl.TLSVersion.TLSv1_2

                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        negotiated_version = ssock.version()
                        if negotiated_version == 'TLSv1.1':
                            results['TLSv1.1'] = {
                                'supported': True,
                                'cipher': ssock.cipher(),
                                'version': negotiated_version,
                                'method': 'legacy_compatibility_check'
                            }
                        else:
                            results['TLSv1.1'] = {
                                'supported': False,
                                'error': f'Server negotiated {negotiated_version} instead of TLSv1.1',
                                'method': 'legacy_compatibility_check'
                            }
            except Exception as e2:
                results['TLSv1.1'] = {
                    'supported': False,
                    'error': str(e),
                    'fallback_error': str(e2),
                    'method': 'both_methods_failed'
                }

        # TLS1.0チェック（非推奨）- より柔軟なアプローチ
        try:
            # 方法1: 厳密なバージョン指定
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['TLSv1.0'] = {
                        'supported': True,
                        'cipher': ssock.cipher(),
                        'version': ssock.version(),
                        'method': 'direct_version_check'
                    }
        except Exception as e:
            # 方法2: レガシー互換性チェック
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers('ALL:@SECLEVEL=0')  # より緩い暗号設定

                # TLS1.0を含む範囲で接続テスト
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1_1

                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        negotiated_version = ssock.version()
                        if negotiated_version == 'TLSv1':
                            results['TLSv1.0'] = {
                                'supported': True,
                                'cipher': ssock.cipher(),
                                'version': negotiated_version,
                                'method': 'legacy_compatibility_check'
                            }
                        else:
                            results['TLSv1.0'] = {
                                'supported': False,
                                'error': f'Server negotiated {negotiated_version} instead of TLSv1.0',
                                'method': 'legacy_compatibility_check'
                            }
            except Exception as e2:
                results['TLSv1.0'] = {
                    'supported': False,
                    'error': str(e),
                    'fallback_error': str(e2),
                    'method': 'both_methods_failed'
                }

        return results

    def _get_certificate_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        証明書情報を取得

        Args:
            hostname: ホスト名
            port: ポート番号

        Returns:
            証明書情報
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        'valid': True,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                    }

        except Exception as e:
            self.logger.debug(f"Certificate info retrieval failed: {hostname}:{port}", error=str(e))
            return {
                'valid': False,
                'error': str(e)
            }

    def _get_cipher_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        暗号スイート情報を取得

        Args:
            hostname: ホスト名
            port: ポート番号

        Returns:
            暗号スイート情報
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()

                    if cipher:
                        cipher_name = cipher[0]
                        cipher_version = cipher[1]
                        cipher_bits = cipher[2]

                        # 強力な暗号スイートの判定（簡略化）
                        strong_ciphers = [
                            'ECDHE-RSA-AES256-GCM-SHA384',
                            'ECDHE-RSA-AES128-GCM-SHA256',
                            'ECDHE-ECDSA-AES256-GCM-SHA384',
                            'ECDHE-ECDSA-AES128-GCM-SHA256',
                            'TLS_AES_256_GCM_SHA384',
                            'TLS_AES_128_GCM_SHA256',
                            'TLS_CHACHA20_POLY1305_SHA256'
                        ]

                        has_strong_ciphers = any(strong in cipher_name for strong in ['AES256-GCM', 'AES128-GCM', 'CHACHA20'])

                        return {
                            'cipher_name': cipher_name,
                            'cipher_version': cipher_version,
                            'cipher_bits': cipher_bits,
                            'has_strong_ciphers': has_strong_ciphers
                        }

            return {
                'has_strong_ciphers': False,
                'error': 'No cipher information available'
            }

        except Exception as e:
            self.logger.debug(f"Cipher info retrieval failed: {hostname}:{port}", error=str(e))
            return {
                'has_strong_ciphers': False,
                'error': str(e)
            }

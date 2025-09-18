"""
カスタム例外クラス

システム固有の例外を定義します。
"""


class SecurityAuditException(Exception):
    """セキュリティ診断システム基底例外"""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(SecurityAuditException):
    """設定関連エラー"""
    pass


class NetworkError(SecurityAuditException):
    """ネットワーク関連エラー"""
    pass


class APIError(SecurityAuditException):
    """外部API関連エラー"""

    def __init__(self, message: str, api_name: str = None, status_code: int = None, details: dict = None):
        super().__init__(message, details)
        self.api_name = api_name
        self.status_code = status_code


class ValidationError(SecurityAuditException):
    """バリデーション関連エラー"""
    pass


class AuditError(SecurityAuditException):
    """診断実行関連エラー"""

    def __init__(self, message: str, url: str = None, audit_type: str = None, details: dict = None):
        super().__init__(message, details)
        self.url = url
        self.audit_type = audit_type


class InputError(SecurityAuditException):
    """入力データ関連エラー"""
    pass


class OutputError(SecurityAuditException):
    """出力処理関連エラー"""
    pass

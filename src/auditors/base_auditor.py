"""
基底診断クラス

すべての診断項目の基底となるクラスを定義します。
"""

import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from .data_models import AuditResult, AuditStatus
from ..utils.exceptions import AuditError, ValidationError
from ..utils.logger import get_logger, AuditLogger
from ..utils.http_client import HTTPClient
from ..utils.validator import URLValidator


class BaseAuditor(ABC):
    """
    診断項目基底クラス

    すべての診断項目はこのクラスを継承して実装します。
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: 設定データ
        """
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.audit_logger = AuditLogger(self.__class__.__name__)

        # HTTP クライアント初期化
        self.http_client = HTTPClient(
            timeout=config.get('timeout_seconds', 30),
            max_retries=config.get('retry_count', 3),
            user_agent=config.get('user_agent', 'SecurityAuditTool/1.0')
        )

        # 診断タイプ名（サブクラスで設定）
        self.audit_type = self.__class__.__name__.replace('Auditor', '').lower()

    @abstractmethod
    def audit(self, url: str) -> AuditResult:
        """
        診断を実行します。（サブクラスで実装）

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        pass

    def execute_audit(self, url: str) -> AuditResult:
        """
        診断実行のラッパーメソッド

        共通的な前後処理（時間測定、ログ出力、例外処理など）を行います。

        Args:
            url: 診断対象URL

        Returns:
            診断結果
        """
        start_time = time.time()

        try:
            # URL検証
            URLValidator.validate_url(url)

            # 診断開始ログ
            self.audit_logger.audit_start(url, self.audit_type)

            # 診断実行
            result = self.audit(url)

            # 実行時間設定
            execution_time = time.time() - start_time
            result.execution_time = execution_time

            # 診断完了ログ
            self.audit_logger.audit_complete(
                url, self.audit_type, result.status.value, execution_time
            )

            return result

        except ValidationError as e:
            execution_time = time.time() - start_time
            error_msg = f"Validation error: {str(e)}"

            self.audit_logger.audit_error(url, self.audit_type, error_msg, execution_time)

            return AuditResult(
                audit_type=self.audit_type,
                url=url,
                status=AuditStatus.ERROR,
                execution_time=execution_time,
                error_message=error_msg
            )

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Unexpected error: {str(e)}"

            self.logger.error(f"Audit failed for {url}", error=error_msg, audit_type=self.audit_type)
            self.audit_logger.audit_error(url, self.audit_type, error_msg, execution_time)

            return AuditResult(
                audit_type=self.audit_type,
                url=url,
                status=AuditStatus.ERROR,
                execution_time=execution_time,
                error_message=error_msg
            )

    def validate_url(self, url: str) -> bool:
        """
        URL妥当性チェック

        Args:
            url: チェック対象URL

        Returns:
            True if valid

        Raises:
            ValidationError: URLが無効な場合
        """
        return URLValidator.validate_url(url)

    def safe_request(self, method: str, url: str, **kwargs) -> Optional[Any]:
        """
        安全なHTTPリクエスト実行

        Args:
            method: HTTPメソッド
            url: リクエストURL
            **kwargs: リクエストパラメータ

        Returns:
            レスポンスオブジェクト（エラー時はNone）
        """
        try:
            if method.upper() == 'GET':
                return self.http_client.get(url, **kwargs)
            elif method.upper() == 'POST':
                return self.http_client.post(url, **kwargs)
            elif method.upper() == 'HEAD':
                return self.http_client.head(url, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

        except Exception as e:
            self.logger.warning(f"HTTP request failed: {url}", error=str(e))
            return None

    def extract_domain(self, url: str) -> str:
        """
        URLからドメイン名を抽出

        Args:
            url: URL

        Returns:
            ドメイン名
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return url

    def create_result(
        self,
        url: str,
        status: AuditStatus,
        details: Optional[Dict[str, Any]] = None,
        recommendations: Optional[list] = None,
        error_message: Optional[str] = None
    ) -> AuditResult:
        """
        診断結果オブジェクトを作成

        Args:
            url: 診断対象URL
            status: 診断ステータス
            details: 詳細情報
            recommendations: 推奨事項リスト
            error_message: エラーメッセージ

        Returns:
            診断結果オブジェクト
        """
        return AuditResult(
            audit_type=self.audit_type,
            url=url,
            status=status,
            details=details or {},
            recommendations=recommendations or [],
            error_message=error_message
        )

    def determine_status(self, checks: Dict[str, bool], has_critical_issues: bool = False) -> AuditStatus:
        """
        チェック結果に基づいてステータスを決定

        Args:
            checks: チェック項目と結果のマッピング
            has_critical_issues: 重大な問題があるかどうか

        Returns:
            診断ステータス
        """
        if has_critical_issues:
            return AuditStatus.NG

        # 全てのチェックが成功している場合
        if all(checks.values()):
            return AuditStatus.OK

        # 一部のチェックが失敗している場合
        failed_checks = sum(1 for passed in checks.values() if not passed)
        total_checks = len(checks)

        if failed_checks == 0:
            return AuditStatus.OK
        elif failed_checks <= total_checks / 3:  # 1/3以下の失敗
            return AuditStatus.WARNING
        else:
            return AuditStatus.NG

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'http_client'):
            self.http_client.close()

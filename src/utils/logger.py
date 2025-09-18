"""
ログ管理モジュール

構造化ログと標準ログの統合管理を行います。
"""

import logging
import sys
from pathlib import Path
from typing import Optional
import structlog
from datetime import datetime


def configure_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_size_mb: int = 100,
    backup_count: int = 5
) -> None:
    """
    ログ設定を初期化します。

    Args:
        log_level: ログレベル (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: ログファイルパス
        max_size_mb: ログファイル最大サイズ(MB)
        backup_count: バックアップファイル数
    """
    # ログディレクトリ作成
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

    # ログレベル設定
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # ハンドラー設定
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding='utf-8'
        )
        handlers.append(file_handler)

    # 基本ログ設定
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
        force=True
    )

    # 構造化ログ設定
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    構造化ログインスタンスを取得します。

    Args:
        name: ロガー名（通常は __name__ を使用）

    Returns:
        構造化ログインスタンス
    """
    return structlog.get_logger(name)


class AuditLogger:
    """診断専用ログ管理クラス"""

    def __init__(self, name: str):
        self.logger = get_logger(name)
        self.start_time = datetime.now()

    def audit_start(self, url: str, audit_type: str) -> None:
        """診断開始ログ"""
        self.logger.info(
            "Audit started",
            url=url,
            audit_type=audit_type,
            timestamp=datetime.now().isoformat()
        )

    def audit_complete(self, url: str, audit_type: str, status: str, execution_time: float) -> None:
        """診断完了ログ"""
        self.logger.info(
            "Audit completed",
            url=url,
            audit_type=audit_type,
            status=status,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat()
        )

    def audit_error(self, url: str, audit_type: str, error: str, execution_time: float) -> None:
        """診断エラーログ"""
        self.logger.error(
            "Audit failed",
            url=url,
            audit_type=audit_type,
            error=error,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat()
        )

    def batch_start(self, total_urls: int) -> None:
        """バッチ処理開始ログ"""
        self.logger.info(
            "Batch audit started",
            total_urls=total_urls,
            timestamp=datetime.now().isoformat()
        )

    def batch_progress(self, completed: int, total: int, current_url: str) -> None:
        """バッチ処理進捗ログ"""
        progress = (completed / total) * 100
        self.logger.info(
            "Batch audit progress",
            completed=completed,
            total=total,
            progress=f"{progress:.1f}%",
            current_url=current_url,
            timestamp=datetime.now().isoformat()
        )

    def batch_complete(self, total_urls: int, successful: int, failed: int, total_time: float) -> None:
        """バッチ処理完了ログ"""
        self.logger.info(
            "Batch audit completed",
            total_urls=total_urls,
            successful=successful,
            failed=failed,
            success_rate=f"{(successful/total_urls)*100:.1f}%",
            total_time=total_time,
            timestamp=datetime.now().isoformat()
        )

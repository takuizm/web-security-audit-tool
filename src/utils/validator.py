"""
バリデーション機能

入力データの検証を行います。
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from .exceptions import ValidationError


class URLValidator:
    """URL検証クラス"""

    # 有効なスキーム
    VALID_SCHEMES = {'http', 'https'}

    # 無効なドメインパターン
    INVALID_DOMAINS = {
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
    }

    @classmethod
    def validate_url(cls, url: str) -> bool:
        """
        URLの妥当性を検証します。

        Args:
            url: 検証するURL

        Returns:
            True if valid, False otherwise

        Raises:
            ValidationError: URLが無効な場合
        """
        if not url or not isinstance(url, str):
            raise ValidationError("URL must be a non-empty string")

        url = url.strip()
        if not url:
            raise ValidationError("URL cannot be empty")

        # URL重複チェック
        if url.count('://') > 1:
            raise ValidationError(f"Invalid URL format: Multiple protocols detected: {url}")

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {e}")

        # スキーム検証
        if parsed.scheme.lower() not in cls.VALID_SCHEMES:
            raise ValidationError(f"Invalid scheme: {parsed.scheme}. Must be http or https")

        # ホスト名検証
        if not parsed.netloc:
            raise ValidationError("URL must have a valid hostname")

        # ローカルホスト除外
        hostname = parsed.netloc.split(':')[0].lower()
        if hostname in cls.INVALID_DOMAINS:
            raise ValidationError(f"Local addresses are not allowed: {hostname}")

        # プライベートIPアドレス除外
        if cls._is_private_ip(hostname):
            raise ValidationError(f"Private IP addresses are not allowed: {hostname}")

        return True

    @staticmethod
    def _is_private_ip(hostname: str) -> bool:
        """プライベートIPアドレスかどうかを判定"""
        # 簡単なプライベートIPチェック
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.'
        ]

        for pattern in private_patterns:
            if re.match(pattern, hostname):
                return True
        return False


class CSVValidator:
    """CSV入力データ検証クラス"""

    REQUIRED_COLUMNS = ['url']
    OPTIONAL_COLUMNS = ['site_name', 'priority', 'notes']
    MAX_ROWS = 1000

    @classmethod
    def validate_csv_data(cls, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        CSVデータを検証します。

        Args:
            data: CSV行データのリスト

        Returns:
            検証済みデータ

        Raises:
            ValidationError: データが無効な場合
        """
        if not data:
            raise ValidationError("CSV data cannot be empty")

        if len(data) > cls.MAX_ROWS:
            raise ValidationError(f"Too many rows: {len(data)}. Maximum is {cls.MAX_ROWS}")

        # ヘッダー検証
        if data:
            headers = set(data[0].keys())
            missing_required = set(cls.REQUIRED_COLUMNS) - headers
            if missing_required:
                raise ValidationError(f"Missing required columns: {missing_required}")

        validated_data = []
        for i, row in enumerate(data):
            try:
                validated_row = cls._validate_row(row, i + 1)
                validated_data.append(validated_row)
            except ValidationError as e:
                raise ValidationError(f"Row {i + 1}: {e}")

        return validated_data

    @classmethod
    def _validate_row(cls, row: Dict[str, Any], row_number: int) -> Dict[str, Any]:
        """個別行の検証"""
        validated_row = {}

        # URL検証（必須）
        url = str(row.get('url', '')).strip()
        if not url:
            raise ValidationError(f"URL is required in row {row_number}")

        URLValidator.validate_url(url)
        validated_row['url'] = url

        # サイト名（オプション）
        site_name = str(row.get('site_name', '')).strip()
        validated_row['site_name'] = site_name if site_name else cls._extract_domain(url)

        # 優先度（オプション）
        priority = str(row.get('priority', '')).strip()
        if priority and priority not in ['高', '中', '低', 'high', 'medium', 'low']:
            priority = '中'  # デフォルト値
        validated_row['priority'] = priority or '中'

        # 備考（オプション）
        notes = str(row.get('notes', '')).strip()
        validated_row['notes'] = notes

        return validated_row

    @staticmethod
    def _extract_domain(url: str) -> str:
        """URLからドメイン名を抽出"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return url


class ConfigValidator:
    """設定データ検証クラス"""

    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> None:
        """
        設定データを検証します。

        Args:
            config: 設定データ

        Raises:
            ValidationError: 設定が無効な場合
        """
        # 必須セクション確認
        required_sections = ['audit', 'logging']
        for section in required_sections:
            if section not in config:
                raise ValidationError(f"Missing required config section: {section}")

        # audit設定検証
        audit_config = config.get('audit', {})
        cls._validate_audit_config(audit_config)

        # logging設定検証
        logging_config = config.get('logging', {})
        cls._validate_logging_config(logging_config)

    @classmethod
    def _validate_audit_config(cls, audit_config: Dict[str, Any]) -> None:
        """audit設定の検証"""
        # parallel_workers
        workers = audit_config.get('parallel_workers', 5)
        if not isinstance(workers, int) or workers < 1 or workers > 20:
            raise ValidationError("parallel_workers must be between 1 and 20")

        # timeout_seconds
        timeout = audit_config.get('timeout_seconds', 30)
        if not isinstance(timeout, int) or timeout < 5 or timeout > 300:
            raise ValidationError("timeout_seconds must be between 5 and 300")

        # retry_count
        retry = audit_config.get('retry_count', 3)
        if not isinstance(retry, int) or retry < 0 or retry > 10:
            raise ValidationError("retry_count must be between 0 and 10")

    @classmethod
    def _validate_logging_config(cls, logging_config: Dict[str, Any]) -> None:
        """logging設定の検証"""
        # level
        level = logging_config.get('level', 'INFO')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level not in valid_levels:
            raise ValidationError(f"Invalid logging level: {level}. Must be one of {valid_levels}")

        # max_size_mb
        max_size = logging_config.get('max_size_mb', 100)
        if not isinstance(max_size, int) or max_size < 1 or max_size > 1000:
            raise ValidationError("max_size_mb must be between 1 and 1000")

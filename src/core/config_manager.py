"""
設定管理モジュール

システム設定の読み込み、検証、管理を行います。
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from ..utils.exceptions import ConfigurationError
from ..utils.validator import ConfigValidator
from ..utils.logger import get_logger


class ConfigManager:
    """設定管理クラス"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Args:
            config_path: 設定ファイルパス（Noneの場合はデフォルトパス使用）
        """
        self.logger = get_logger(__name__)
        self.config_path = config_path or self._get_default_config_path()
        self._config_data = None
        self._load_config()

    def _get_default_config_path(self) -> str:
        """デフォルト設定ファイルパスを取得"""
        # プロジェクトルートからの相対パス
        project_root = Path(__file__).parent.parent.parent
        return str(project_root / "config" / "config.yaml")

    def _load_config(self) -> None:
        """設定ファイルを読み込み、検証します"""
        config_file = Path(self.config_path)

        if not config_file.exists():
            raise ConfigurationError(f"Config file not found: {self.config_path}")

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)

            if not raw_config:
                raise ConfigurationError("Config file is empty")

            # 環境変数の置換
            self._config_data = self._substitute_env_vars(raw_config)

            # 設定検証
            ConfigValidator.validate_config(self._config_data)

            self.logger.info(f"Configuration loaded successfully from {self.config_path}")

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML format: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}")

    def _substitute_env_vars(self, config: Any) -> Any:
        """
        設定値内の環境変数を置換します。

        ${VAR_NAME} 形式の環境変数を実際の値に置換します。

        Args:
            config: 設定データ

        Returns:
            環境変数が置換された設定データ
        """
        if isinstance(config, dict):
            return {k: self._substitute_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._substitute_env_vars(item) for item in config]
        elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
            env_var = config[2:-1]
            env_value = os.environ.get(env_var)
            if env_value is None:
                self.logger.warning(f"Environment variable not found: {env_var}")
                return config  # 元の値を返す
            return env_value
        else:
            return config

    def get(self, key: str, default: Any = None) -> Any:
        """
        設定値を取得します。

        Args:
            key: 設定キー（ドット記法対応 例: "audit.timeout_seconds"）
            default: デフォルト値

        Returns:
            設定値
        """
        keys = key.split('.')
        value = self._config_data

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        設定セクション全体を取得します。

        Args:
            section: セクション名

        Returns:
            セクションの設定データ
        """
        return self._config_data.get(section, {})

    def reload(self) -> None:
        """設定ファイルを再読み込みします"""
        self.logger.info("Reloading configuration")
        self._load_config()

    @property
    def config_data(self) -> Dict[str, Any]:
        """設定データ全体を取得"""
        return self._config_data.copy()

    # よく使用される設定値への便利メソッド

    @property
    def parallel_workers(self) -> int:
        """並行処理数を取得"""
        return self.get('audit.parallel_workers', 5)

    @property
    def timeout_seconds(self) -> int:
        """タイムアウト時間を取得"""
        return self.get('audit.timeout_seconds', 30)

    @property
    def retry_count(self) -> int:
        """リトライ回数を取得"""
        return self.get('audit.retry_count', 3)

    @property
    def enabled_auditors(self) -> list:
        """有効な診断項目リストを取得"""
        return self.get('audit.enabled_auditors', [])

    @property
    def log_level(self) -> str:
        """ログレベルを取得"""
        return self.get('logging.level', 'INFO')

    @property
    def log_file(self) -> str:
        """ログファイルパスを取得"""
        return self.get('logging.file', 'logs/audit.log')

    @property
    def output_formats(self) -> list:
        """出力形式リストを取得"""
        return self.get('output.formats', ['json', 'html', 'csv'])

    def get_external_api_config(self, api_name: str) -> Dict[str, Any]:
        """
        外部API設定を取得します。

        Args:
            api_name: API名

        Returns:
            API設定データ
        """
        return self.get(f'external_apis.{api_name}', {})

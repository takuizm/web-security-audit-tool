"""
入力処理モジュール

CSV ファイルの読み込みと検証を行います。
"""

import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd

from ..auditors.data_models import TargetSite
from ..utils.exceptions import InputError, ValidationError
from ..utils.validator import CSVValidator
from ..utils.logger import get_logger


class InputProcessor:
    """入力処理クラス"""

    def __init__(self):
        self.logger = get_logger(__name__)

    def load_urls(self, file_path: str) -> List[TargetSite]:
        """
        CSV ファイルから URL リストを読み込み

        Args:
            file_path: CSV ファイルパス

        Returns:
            TargetSite オブジェクトのリスト

        Raises:
            InputError: ファイル読み込みエラー
            ValidationError: データ検証エラー
        """
        try:
            file_path_obj = Path(file_path)

            if not file_path_obj.exists():
                raise InputError(f"Input file not found: {file_path}")

            if not file_path_obj.suffix.lower() == '.csv':
                raise InputError(f"Input file must be CSV format: {file_path}")

            self.logger.info(f"Loading URLs from: {file_path}")

            # CSV ファイル読み込み
            raw_data = self._read_csv_file(file_path_obj)

            if not raw_data:
                raise InputError("CSV file is empty")

            # データ検証
            validated_data = CSVValidator.validate_csv_data(raw_data)

            # TargetSite オブジェクト作成
            target_sites = []
            for row in validated_data:
                target_site = TargetSite(
                    url=row['url'],
                    site_name=row.get('site_name', ''),
                    priority=row.get('priority', '中'),
                    notes=row.get('notes', '')
                )
                target_sites.append(target_site)

            self.logger.info(f"Successfully loaded {len(target_sites)} URLs")
            return target_sites

        except (ValidationError, InputError):
            raise
        except Exception as e:
            self.logger.error(f"Failed to load URLs from {file_path}", error=str(e))
            raise InputError(f"Failed to load input file: {e}")

    def _read_csv_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        CSV ファイルを読み込み

        Args:
            file_path: CSV ファイルパス

        Returns:
            CSV データ（辞書のリスト）
        """
        try:
            # pandas を使用してCSV読み込み（エンコーディング自動判定）
            encodings = ['utf-8', 'shift_jis', 'cp932', 'utf-8-sig']

            for encoding in encodings:
                try:
                    df = pd.read_csv(file_path, encoding=encoding)
                    break
                except UnicodeDecodeError:
                    continue
            else:
                # 全てのエンコーディングで失敗した場合
                raise InputError("Unable to decode CSV file. Please check file encoding.")

            # NaN 値を空文字に変換
            df = df.fillna('')

            # 辞書のリストに変換
            data = df.to_dict('records')

            self.logger.debug(f"Read {len(data)} rows from CSV file")
            return data

        except pd.errors.EmptyDataError:
            raise InputError("CSV file is empty")
        except pd.errors.ParserError as e:
            raise InputError(f"CSV parsing error: {e}")
        except Exception as e:
            self.logger.error(f"CSV file reading failed", error=str(e))
            raise InputError(f"Failed to read CSV file: {e}")

    def validate_file_format(self, file_path: str) -> bool:
        """
        ファイル形式を検証

        Args:
            file_path: ファイルパス

        Returns:
            True if valid format
        """
        try:
            file_path_obj = Path(file_path)

            # 存在チェック
            if not file_path_obj.exists():
                return False

            # 拡張子チェック
            if file_path_obj.suffix.lower() != '.csv':
                return False

            # ファイルサイズチェック（100MB制限）
            if file_path_obj.stat().st_size > 100 * 1024 * 1024:
                return False

            # 基本的な CSV 形式チェック
            try:
                with open(file_path_obj, 'r', encoding='utf-8') as f:
                    # 最初の数行を読んで CSV 形式かチェック
                    sample = f.read(1024)
                    if not sample:
                        return False

                    # カンマ区切りの確認
                    lines = sample.split('\n')[:5]  # 最初の5行
                    for line in lines:
                        if line.strip() and ',' not in line:
                            return False

                return True

            except Exception:
                return False

        except Exception:
            return False

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        ファイル情報を取得

        Args:
            file_path: ファイルパス

        Returns:
            ファイル情報
        """
        try:
            file_path_obj = Path(file_path)

            if not file_path_obj.exists():
                return {'exists': False}

            stat = file_path_obj.stat()

            # CSV の行数とカラム数を取得
            try:
                df = pd.read_csv(file_path_obj, nrows=0)  # ヘッダーのみ読み込み
                columns = list(df.columns)

                # 全行数取得（効率的な方法）
                with open(file_path_obj, 'r', encoding='utf-8') as f:
                    row_count = sum(1 for _ in f) - 1  # ヘッダー行を除く

            except Exception:
                columns = []
                row_count = 0

            return {
                'exists': True,
                'size_bytes': stat.st_size,
                'size_mb': round(stat.st_size / (1024 * 1024), 2),
                'modified_time': stat.st_mtime,
                'row_count': row_count,
                'columns': columns,
                'column_count': len(columns)
            }

        except Exception as e:
            self.logger.error(f"Failed to get file info: {file_path}", error=str(e))
            return {'exists': False, 'error': str(e)}

    def preview_data(self, file_path: str, max_rows: int = 5) -> Dict[str, Any]:
        """
        データのプレビューを取得

        Args:
            file_path: ファイルパス
            max_rows: 最大行数

        Returns:
            プレビューデータ
        """
        try:
            df = pd.read_csv(file_path, nrows=max_rows)
            df = df.fillna('')

            return {
                'success': True,
                'columns': list(df.columns),
                'data': df.to_dict('records'),
                'total_columns': len(df.columns),
                'preview_rows': len(df)
            }

        except Exception as e:
            self.logger.error(f"Failed to preview data: {file_path}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

"""
メインアプリケーション

Webセキュリティ診断自動化システムのエントリーポイントです。
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from .core.config_manager import ConfigManager
from .core.audit_engine import AuditEngine
from .core.input_processor import InputProcessor
from .core.output_generator import OutputGenerator
from .utils.logger import configure_logging, get_logger
from .utils.exceptions import SecurityAuditException


class SecurityAuditApplication:
    """メインアプリケーションクラス"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Args:
            config_path: 設定ファイルパス
        """
        try:
            # 設定管理初期化
            self.config_manager = ConfigManager(config_path)

            # ログ設定
            configure_logging(
                log_level=self.config_manager.log_level,
                log_file=self.config_manager.log_file,
                max_size_mb=self.config_manager.get('logging.max_size_mb', 100),
                backup_count=self.config_manager.get('logging.backup_count', 5)
            )

            self.logger = get_logger(__name__)
            self.logger.info("Security Audit Application initialized")

            # コンポーネント初期化
            self.audit_engine = AuditEngine(self.config_manager)
            self.input_processor = InputProcessor()
            self.output_generator = OutputGenerator(self.config_manager.config_data)

        except Exception as e:
            print(f"Failed to initialize application: {e}")
            sys.exit(1)

    def run(self, input_file: str, output_dir: str = "output") -> bool:
        """
        診断実行メイン処理

        Args:
            input_file: 入力CSVファイルパス
            output_dir: 出力ディレクトリ

        Returns:
            成功時True、失敗時False
        """
        try:
            self.logger.info(
                "Starting security audit",
                input_file=input_file,
                output_dir=output_dir
            )

            # 設定検証
            config_validation = self.audit_engine.validate_auditor_config()
            if not config_validation['valid']:
                self.logger.error(
                    "Invalid auditor configuration",
                    invalid_auditors=config_validation['invalid_auditors']
                )
                return False

            # 入力ファイル読み込み
            self.logger.info("Loading target sites from input file")
            target_sites = self.input_processor.load_urls(input_file)

            if not target_sites:
                self.logger.error("No target sites found in input file")
                return False

            self.logger.info(f"Loaded {len(target_sites)} target sites")

            # 診断実行
            self.logger.info("Starting batch audit execution")
            batch_result = self.audit_engine.audit_batch(target_sites)

            # 結果出力
            self.logger.info("Generating output reports")
            output_files = self.output_generator.generate_reports(batch_result, output_dir)

            # 結果サマリー
            self.logger.info(
                "Security audit completed successfully",
                total_sites=batch_result.total_sites,
                successful_audits=batch_result.successful_audits,
                failed_audits=batch_result.failed_audits,
                success_rate=f"{batch_result.success_rate:.1f}%",
                execution_time=f"{batch_result.total_execution_time:.1f}s",
                output_files=len(output_files)
            )

            # コンソールサマリー出力
            self._print_summary(batch_result, output_files)

            return True

        except SecurityAuditException as e:
            self.logger.error(f"Security audit failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during audit: {e}")
            return False

    def audit_single_url(self, url: str, output_dir: str = "output") -> bool:
        """
        単一URL診断

        Args:
            url: 診断対象URL
            output_dir: 出力ディレクトリ

        Returns:
            成功時True、失敗時False
        """
        try:
            self.logger.info(f"Starting single URL audit: {url}")

            # 診断実行
            results = self.audit_engine.audit_single_url(url)

            # BatchAuditResult 形式に変換
            from .auditors.data_models import BatchAuditResult
            batch_result = BatchAuditResult()
            batch_result.total_sites = 1

            for result in results:
                batch_result.add_result(result)

            batch_result.complete()

            # 結果出力
            output_files = self.output_generator.generate_reports(batch_result, output_dir)

            self.logger.info(
                "Single URL audit completed",
                url=url,
                results_count=len(results),
                output_files=len(output_files)
            )

            return True

        except Exception as e:
            self.logger.error(f"Single URL audit failed: {url}", error=str(e))
            return False

    def _print_summary(self, batch_result, output_files: list) -> None:
        """
        コンソールにサマリーを出力

        Args:
            batch_result: バッチ診断結果
            output_files: 出力ファイルリスト
        """
        print("\n" + "=" * 60)
        print("診断結果サマリー")
        print("=" * 60)
        print(f"対象サイト数: {batch_result.total_sites}")
        print(f"成功: {batch_result.successful_audits}")
        print(f"失敗: {batch_result.failed_audits}")
        print(f"成功率: {batch_result.success_rate:.1f}%")
        print(f"実行時間: {batch_result.total_execution_time:.1f}秒")
        print(f"生成ファイル数: {len(output_files)}")

        if output_files:
            print("\n生成されたファイル:")
            for file_path in output_files:
                print(f"  - {file_path}")

        # サイト別サマリー
        summary = batch_result.get_summary_by_site()
        if summary:
            print("\nサイト別結果:")
            for url, site_summary in summary.items():
                status_icon = {
                    'OK': '✓',
                    'NG': '✗',
                    'WARNING': '!',
                    'ERROR': '?'
                }.get(site_summary['overall_status'], '?')

                print(f"  {status_icon} {url} ({site_summary['overall_status']})")

        print("=" * 60)


def create_argument_parser() -> argparse.ArgumentParser:
    """コマンドライン引数パーサーを作成"""
    parser = argparse.ArgumentParser(
        description='Webセキュリティ診断自動化システム',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  %(prog)s targets.csv -o output
  %(prog)s targets.csv -c config/custom.yaml
  %(prog)s --url https://example.com -o single_audit
        """
    )

    # 入力オプション
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        'input_file',
        nargs='?',
        help='入力CSVファイルパス'
    )
    group.add_argument(
        '--url',
        help='単一URL診断'
    )

    # 出力オプション
    parser.add_argument(
        '-o', '--output',
        default='output',
        help='出力ディレクトリ (デフォルト: output)'
    )

    # 設定オプション
    parser.add_argument(
        '-c', '--config',
        help='設定ファイルパス (デフォルト: config/config.yaml)'
    )

    # その他のオプション
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='詳細ログ出力'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='実行前チェックのみ（実際の診断は行わない）'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser


def main() -> None:
    """メインエントリーポイント"""
    parser = create_argument_parser()
    args = parser.parse_args()

    # 引数検証
    if not args.url and not args.input_file:
        parser.error("入力CSVファイルまたは --url オプションが必要です")

    try:
        # アプリケーション初期化
        app = SecurityAuditApplication(args.config)

        # Dry run モード
        if args.dry_run:
            print("Dry run mode - 設定チェックのみ実行")
            config_validation = app.audit_engine.validate_auditor_config()

            if config_validation['valid']:
                print("設定は正常です")
                print(f"有効な診断項目: {config_validation['enabled_auditors']}")
                if config_validation['warnings']:
                    print(f"警告: {config_validation['warnings']}")
            else:
                print("設定エラー:")
                print(f"無効な診断項目: {config_validation['invalid_auditors']}")
                sys.exit(1)
            return

        # 実行
        if args.url:
            # 単一URL診断
            success = app.audit_single_url(args.url, args.output)
        else:
            # バッチ診断
            # 入力ファイル存在チェック
            if not Path(args.input_file).exists():
                print(f"エラー: 入力ファイルが見つかりません: {args.input_file}")
                sys.exit(1)

            success = app.run(args.input_file, args.output)

        # 終了コード設定
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n診断が中断されました")
        sys.exit(130)
    except Exception as e:
        print(f"予期しないエラーが発生しました: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

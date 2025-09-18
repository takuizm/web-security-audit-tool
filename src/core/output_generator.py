"""
出力生成モジュール

診断結果のレポート生成を行います。
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template

from ..auditors.data_models import BatchAuditResult, AuditResult
from ..utils.exceptions import OutputError
from ..utils.logger import get_logger
from .compliance_evaluator import ComplianceEvaluator


class OutputGenerator:
    """出力生成クラス"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(__name__)

        # 出力形式設定
        self.output_formats = config.get('output.formats', ['json', 'html', 'csv'])
        self.template_dir = config.get('output.template_dir', 'templates')

        # コンプライアンス評価器
        self.compliance_evaluator = ComplianceEvaluator()

        # Jinja2 環境設定
        try:
            template_path = Path(__file__).parent.parent.parent / self.template_dir
            if template_path.exists():
                self.jinja_env = Environment(loader=FileSystemLoader(str(template_path)))
            else:
                self.jinja_env = Environment(loader=FileSystemLoader('.'))
        except Exception as e:
            self.logger.warning(f"Template directory not found, using string templates: {e}")
            self.jinja_env = None

    def generate_reports(self, batch_result: BatchAuditResult, output_dir: str) -> List[str]:
        """
        診断結果レポートを生成

        Args:
            batch_result: バッチ診断結果
            output_dir: 出力ディレクトリ

        Returns:
            生成されたファイルパスのリスト
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            generated_files = []

            # 各形式でレポート生成
            for format_type in self.output_formats:
                try:
                    if format_type == 'json':
                        file_path = self._generate_json_report(batch_result, output_path)
                    elif format_type == 'html':
                        file_path = self._generate_html_report(batch_result, output_path)
                    elif format_type == 'csv':
                        file_path = self._generate_csv_report(batch_result, output_path)
                    else:
                        self.logger.warning(f"Unsupported output format: {format_type}")
                        continue

                    if file_path:
                        generated_files.append(str(file_path))
                        self.logger.info(f"Generated {format_type.upper()} report: {file_path}")

                except Exception as e:
                    self.logger.error(f"Failed to generate {format_type} report", error=str(e))

            # サマリーファイル生成
            summary_file = self._generate_summary_file(batch_result, output_path)
            if summary_file:
                generated_files.append(str(summary_file))

            # コンプライアンス評価レポート生成
            compliance_file = self._generate_compliance_report(batch_result, output_path)
            if compliance_file:
                generated_files.append(str(compliance_file))

            self.logger.info(f"Generated {len(generated_files)} report files")
            return generated_files

        except Exception as e:
            self.logger.error(f"Report generation failed", error=str(e))
            raise OutputError(f"Failed to generate reports: {e}")

    def _generate_json_report(self, batch_result: BatchAuditResult, output_path: Path) -> Path:
        """
        JSON レポート生成

        Args:
            batch_result: バッチ診断結果
            output_path: 出力パス

        Returns:
            生成されたファイルパス
        """
        file_path = output_path / "security_audit_results.json"

        # JSON データ作成
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'total_sites': batch_result.total_sites,
                'successful_audits': batch_result.successful_audits,
                'failed_audits': batch_result.failed_audits,
                'success_rate': batch_result.success_rate,
                'total_execution_time': batch_result.total_execution_time
            },
            'summary': batch_result.get_summary_by_site(),
            'results': [result.to_dict() for result in batch_result.results]
        }

        # JSON ファイル出力
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        return file_path

    def _generate_html_report(self, batch_result: BatchAuditResult, output_path: Path) -> Path:
        """
        HTML レポート生成

        Args:
            batch_result: バッチ診断結果
            output_path: 出力パス

        Returns:
            生成されたファイルパス
        """
        file_path = output_path / "security_audit_report.html"

        # テンプレートデータ準備
        template_data = {
            'metadata': {
                'generated_at': datetime.now().strftime('%Y年%m月%d日 %H:%M:%S'),
                'total_sites': batch_result.total_sites,
                'successful_audits': batch_result.successful_audits,
                'failed_audits': batch_result.failed_audits,
                'success_rate': round(batch_result.success_rate, 1),
                'total_execution_time': round(batch_result.total_execution_time, 1)
            },
            'summary': batch_result.get_summary_by_site(),
            'results': batch_result.results
        }

        # HTML テンプレート
        html_template = self._get_html_template()

        # テンプレート処理
        if self.jinja_env and html_template:
            try:
                template = self.jinja_env.from_string(html_template)
                html_content = template.render(**template_data)
            except Exception as e:
                self.logger.warning(f"Template rendering failed, using fallback: {e}")
                html_content = self._generate_simple_html_report(template_data)
        else:
            html_content = self._generate_simple_html_report(template_data)

        # HTML ファイル出力
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return file_path

    def _generate_csv_report(self, batch_result: BatchAuditResult, output_path: Path) -> Path:
        """
        CSV レポート生成

        Args:
            batch_result: バッチ診断結果
            output_path: 出力パス

        Returns:
            生成されたファイルパス
        """
        file_path = output_path / "security_audit_summary.csv"

        # CSV データ作成
        csv_data = []
        summary = batch_result.get_summary_by_site()

        for url, site_summary in summary.items():
            # URL別のサマリー行
            row = {
                'URL': url,
                'サイト名': self._get_site_name_for_url(url, batch_result.results),
                '総合ステータス': site_summary['overall_status'],
                '診断項目数': site_summary['total_audits'],
                '実行時間（秒）': round(site_summary['execution_time'], 1),
                'OK数': site_summary['status_counts'].get('OK', 0),
                'NG数': site_summary['status_counts'].get('NG', 0),
                'WARNING数': site_summary['status_counts'].get('WARNING', 0),
                'ERROR数': site_summary['status_counts'].get('ERROR', 0)
            }

            # 各診断項目の結果を追加
            url_results = [r for r in batch_result.results if r.url == url]
            for result in url_results:
                audit_type_key = f"{result.audit_type}_status"
                row[audit_type_key] = result.status.value

            csv_data.append(row)

        # DataFrame 作成して CSV 出力
        df = pd.DataFrame(csv_data)
        df.to_csv(file_path, index=False, encoding='utf-8-sig')  # Excel で読みやすくするため BOM 付き

        return file_path

    def _generate_summary_file(self, batch_result: BatchAuditResult, output_path: Path) -> Optional[Path]:
        """
        サマリーファイル生成

        Args:
            batch_result: バッチ診断結果
            output_path: 出力パス

        Returns:
            生成されたファイルパス
        """
        try:
            file_path = output_path / "audit_summary.txt"

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("Webセキュリティ診断結果サマリー\n")
                f.write("=" * 50 + "\n\n")

                f.write(f"実行日時: {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}\n")
                f.write(f"対象サイト数: {batch_result.total_sites}\n")
                f.write(f"成功: {batch_result.successful_audits}\n")
                f.write(f"失敗: {batch_result.failed_audits}\n")
                f.write(f"成功率: {batch_result.success_rate:.1f}%\n")
                f.write(f"総実行時間: {batch_result.total_execution_time:.1f}秒\n\n")

                # サイト別サマリー
                f.write("サイト別結果:\n")
                f.write("-" * 30 + "\n")

                summary = batch_result.get_summary_by_site()
                for url, site_summary in summary.items():
                    f.write(f"URL: {url}\n")
                    f.write(f"  ステータス: {site_summary['overall_status']}\n")
                    f.write(f"  診断項目数: {site_summary['total_audits']}\n")
                    f.write(f"  OK: {site_summary['status_counts'].get('OK', 0)}, ")
                    f.write(f"NG: {site_summary['status_counts'].get('NG', 0)}, ")
                    f.write(f"WARNING: {site_summary['status_counts'].get('WARNING', 0)}, ")
                    f.write(f"ERROR: {site_summary['status_counts'].get('ERROR', 0)}\n")
                    f.write("\n")

            return file_path

        except Exception as e:
            self.logger.error(f"Summary file generation failed", error=str(e))
            return None

    def _get_html_template(self) -> str:
        """
        HTML テンプレートを取得

        Returns:
            HTML テンプレート文字列
        """
        # 簡単な HTML テンプレート（実際の実装ではより詳細なテンプレートを使用）
        return """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webセキュリティ診断レポート</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .summary-item { display: inline-block; margin: 10px 20px 10px 0; }
        .summary-item strong { color: #007bff; }
        .site-result { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .site-url { font-size: 1.2em; font-weight: bold; color: #333; }
        .status-ok { color: #28a745; }
        .status-ng { color: #dc3545; }
        .status-warning { color: #ffc107; }
        .status-error { color: #6c757d; }
        .audit-details { margin-top: 10px; }
        .audit-item { margin: 5px 0; padding: 5px 10px; background-color: #f8f9fa; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Webセキュリティ診断レポート</h1>

        <div class="summary">
            <h2>実行サマリー</h2>
            <div class="summary-item"><strong>実行日時:</strong> {{ metadata.generated_at }}</div>
            <div class="summary-item"><strong>対象サイト数:</strong> {{ metadata.total_sites }}</div>
            <div class="summary-item"><strong>成功:</strong> {{ metadata.successful_audits }}</div>
            <div class="summary-item"><strong>失敗:</strong> {{ metadata.failed_audits }}</div>
            <div class="summary-item"><strong>成功率:</strong> {{ metadata.success_rate }}%</div>
            <div class="summary-item"><strong>実行時間:</strong> {{ metadata.total_execution_time }}秒</div>
        </div>

        <h2>サイト別結果</h2>
        {% for url, site_summary in summary.items() %}
        <div class="site-result">
            <div class="site-url">{{ url }}</div>
            <div>
                <strong>ステータス:</strong>
                <span class="status-{{ site_summary.overall_status.lower() }}">{{ site_summary.overall_status }}</span>
            </div>

            <div class="audit-details">
                <strong>診断項目別結果:</strong>
                {% for result in results %}
                    {% if result.url == url %}
                    <div class="audit-item">
                        <strong>{{ result.audit_type }}:</strong>
                        <span class="status-{{ result.status.value.lower() }}">{{ result.status.value }}</span>
                        {% if result.recommendations %}
                        <ul>
                        {% for recommendation in result.recommendations %}
                            <li>{{ recommendation }}</li>
                        {% endfor %}
                        </ul>
                        {% endif %}
                    </div>
                    {% endif %}
                {% endfor %}
            </div>
        </div>
        {% endfor %}

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em;">
            <p>このレポートは Webセキュリティ診断自動化システム v1.0 によって生成されました。</p>
        </div>
    </div>
</body>
</html>
        """

    def _generate_simple_html_report(self, template_data: Dict[str, Any]) -> str:
        """
        シンプルな HTML レポート生成（フォールバック）

        Args:
            template_data: テンプレートデータ

        Returns:
            HTML 文字列
        """
        html = """<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Webセキュリティ診断レポート</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 15px; margin: 20px 0; }
        .site { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
        .ok { color: green; }
        .ng { color: red; }
        .warning { color: orange; }
        .error { color: gray; }
    </style>
</head>
<body>
    <h1>Webセキュリティ診断レポート</h1>

    <div class="summary">
        <h2>サマリー</h2>
        <p>実行日時: """ + template_data['metadata']['generated_at'] + """</p>
        <p>対象サイト数: """ + str(template_data['metadata']['total_sites']) + """</p>
        <p>成功率: """ + str(template_data['metadata']['success_rate']) + """%</p>
    </div>

    <h2>結果詳細</h2>
"""

        for url, summary in template_data['summary'].items():
            html += f"""
        <div class="site">
            <h3>{url}</h3>
            <p>ステータス: <span class="{summary['overall_status'].lower()}">{summary['overall_status']}</span></p>
        </div>
"""

        html += """
</body>
</html>"""

        return html

    def _generate_compliance_report(self, batch_result: BatchAuditResult, output_path: Path) -> Optional[Path]:
        """
        コンプライアンス評価レポート生成（1/0評価形式）

        Args:
            batch_result: バッチ診断結果
            output_path: 出力パス

        Returns:
            生成されたファイルパス
        """
        try:
            file_path = output_path / "security_compliance_evaluation.csv"

            # コンプライアンス評価実行
            compliance_results = self.compliance_evaluator.evaluate_batch_results(batch_result)

            # CSV データ作成
            csv_data = []

            for url, evaluation in compliance_results.items():
                row = {
                    'URL': url,
                    'サイト名': self._get_site_name_for_url(url, batch_result.results)
                }

                # 各評価項目を追加
                evaluations = evaluation['evaluations']
                details = evaluation['details']

                # S1-1: jQuery バージョン情報も含める
                row['S1-1'] = evaluations['S1-1']
                row['S1-1_詳細'] = details['S1-1']

                # S1-2: 手動設定項目
                row['S1-2'] = evaluations['S1-2']
                row['S1-2_詳細'] = details['S1-2']

                # S2: 暗号化通信
                row['S2'] = evaluations['S2']
                row['S2_詳細'] = details['S2']

                # S3: TLS1.3（バージョン情報も含める）
                row['S3'] = evaluations['S3']
                row['S3_詳細'] = details['S3']

                # S4: TLS1.1以前無効
                row['S4'] = evaluations['S4']
                row['S4_詳細'] = details['S4']

                # S6: アクセス制御
                row['S6-1'] = evaluations['S6-1']
                row['S6-1_詳細'] = details['S6-1']
                row['S6-2'] = evaluations['S6-2']
                row['S6-2_詳細'] = details['S6-2']
                row['S6-3'] = evaluations['S6-3']
                row['S6-3_詳細'] = details['S6-3']

                # S7: サーバーアクセス制御
                row['S7'] = evaluations['S7']
                row['S7_詳細'] = details['S7']

                # S8: セキュリティヘッダー
                row['S8-1'] = evaluations['S8-1']
                row['S8-1_詳細'] = details['S8-1']
                row['S8-2'] = evaluations['S8-2']
                row['S8-2_詳細'] = details['S8-2']
                row['S8-3'] = evaluations['S8-3']
                row['S8-3_詳細'] = details['S8-3']

                # 総合評価（合格項目数/全項目数）
                total_items = len([k for k in evaluations.keys() if k != 'S1-2'])  # S1-2は手動項目のため除外
                passed_items = sum([v for k, v in evaluations.items() if k != 'S1-2'])
                row['合格項目数'] = passed_items
                row['総項目数'] = total_items
                row['合格率'] = f"{(passed_items/total_items)*100:.1f}%" if total_items > 0 else "0%"

                csv_data.append(row)

            # DataFrame 作成して CSV 出力
            df = pd.DataFrame(csv_data)

            # カラム順序を調整
            column_order = ['URL', 'サイト名']

            # 評価項目順に追加
            evaluation_items = ['S1-1', 'S1-2', 'S2', 'S3', 'S4', 'S6-1', 'S6-2', 'S6-3', 'S7', 'S8-1', 'S8-2', 'S8-3']
            for item in evaluation_items:
                column_order.extend([item, f'{item}_詳細'])

            column_order.extend(['合格項目数', '総項目数', '合格率'])

            # カラム順序でDataFrameを並び替え
            df = df.reindex(columns=column_order)

            # CSV 出力（Excel で読みやすくするため BOM 付き）
            df.to_csv(file_path, index=False, encoding='utf-8-sig')

            self.logger.info(f"Generated compliance evaluation report: {file_path}")
            return file_path

        except Exception as e:
            self.logger.error(f"Compliance report generation failed", error=str(e))
            return None

    def _get_site_name_for_url(self, url: str, results: List[AuditResult]) -> str:
        """
        URL に対応するサイト名を取得

        Args:
            url: URL
            results: 診断結果リスト

        Returns:
            サイト名
        """
        # 最初に見つかった結果からサイト名を抽出
        for result in results:
            if result.url == url and hasattr(result, 'site_name'):
                return getattr(result, 'site_name', '')

        # 見つからない場合はドメイン名を返す
        from urllib.parse import urlparse
        try:
            return urlparse(url).netloc
        except Exception:
            return url

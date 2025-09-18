"""
診断エンジンモジュール

セキュリティ診断の実行を統括管理します。
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import time

from ..auditors.data_models import TargetSite, AuditResult, BatchAuditResult
from ..auditors.component_vulnerability import ComponentVulnerabilityAuditor
from ..auditors.encryption_check import EncryptionCheckAuditor
from ..auditors.tls_security import TLSSecurityAuditor
from ..auditors.access_control import AccessControlAuditor
from ..auditors.security_headers import SecurityHeadersAuditor
from ..utils.exceptions import AuditError
from ..utils.logger import get_logger, AuditLogger


class AuditEngine:
    """診断エンジンクラス"""

    def __init__(self, config_manager):
        """
        Args:
            config_manager: 設定管理インスタンス
        """
        self.config = config_manager
        self.logger = get_logger(__name__)
        self.audit_logger = AuditLogger(__name__)

        # 診断項目クラスマッピング
        self.auditor_classes = {
            'component_vulnerability': ComponentVulnerabilityAuditor,
            'encryption_check': EncryptionCheckAuditor,
            'tls_security': TLSSecurityAuditor,
            'access_control': AccessControlAuditor,
            'security_headers': SecurityHeadersAuditor
        }

        # 有効な診断項目
        self.enabled_auditors = self.config.enabled_auditors

        # 並行処理設定
        self.max_workers = self.config.parallel_workers

        self.logger.info(f"AuditEngine initialized with {len(self.enabled_auditors)} auditors")

    def audit_single_site(self, target_site: TargetSite) -> List[AuditResult]:
        """
        単一サイトの診断を実行

        Args:
            target_site: 診断対象サイト

        Returns:
            診断結果リスト
        """
        self.logger.info(f"Starting audit for site: {target_site.url}")

        results = []

        for auditor_name in self.enabled_auditors:
            if auditor_name not in self.auditor_classes:
                self.logger.warning(f"Unknown auditor: {auditor_name}")
                continue

            try:
                # 診断インスタンス作成
                auditor_class = self.auditor_classes[auditor_name]
                auditor_config = self.config.config_data.copy()

                with auditor_class(auditor_config) as auditor:
                    # 診断実行
                    result = auditor.execute_audit(target_site.url)
                    results.append(result)

            except Exception as e:
                self.logger.error(f"Auditor {auditor_name} failed for {target_site.url}", error=str(e))

                # エラー結果を作成
                error_result = AuditResult(
                    audit_type=auditor_name,
                    url=target_site.url,
                    status="ERROR",
                    score=0,
                    error_message=str(e)
                )
                results.append(error_result)

        self.logger.info(f"Completed audit for site: {target_site.url} ({len(results)} results)")
        return results

    def audit_batch(self, target_sites: List[TargetSite]) -> BatchAuditResult:
        """
        バッチ診断を実行

        Args:
            target_sites: 診断対象サイトリスト

        Returns:
            バッチ診断結果
        """
        batch_result = BatchAuditResult()
        batch_result.total_sites = len(target_sites)

        self.audit_logger.batch_start(len(target_sites))

        try:
            if self.max_workers == 1:
                # シーケンシャル実行
                results = self._execute_sequential(target_sites, batch_result)
            else:
                # 並行実行
                results = self._execute_parallel(target_sites, batch_result)

            # 結果を BatchAuditResult に追加
            for result_list in results:
                for result in result_list:
                    batch_result.add_result(result)

            batch_result.complete()

            self.audit_logger.batch_complete(
                batch_result.total_sites,
                batch_result.successful_audits,
                batch_result.failed_audits,
                batch_result.total_execution_time
            )

            return batch_result

        except Exception as e:
            self.logger.error("Batch audit failed", error=str(e))
            batch_result.complete()
            raise AuditError(f"Batch audit failed: {e}")

    def _execute_sequential(self, target_sites: List[TargetSite], batch_result: BatchAuditResult) -> List[List[AuditResult]]:
        """
        シーケンシャル実行

        Args:
            target_sites: 診断対象サイトリスト
            batch_result: バッチ結果（進捗更新用）

        Returns:
            診断結果リスト
        """
        results = []

        for i, target_site in enumerate(target_sites):
            self.audit_logger.batch_progress(i, len(target_sites), target_site.url)

            try:
                site_results = self.audit_single_site(target_site)
                results.append(site_results)

            except Exception as e:
                self.logger.error(f"Site audit failed: {target_site.url}", error=str(e))
                # エラー結果を作成
                error_results = []
                for auditor_name in self.enabled_auditors:
                    error_result = AuditResult(
                        audit_type=auditor_name,
                        url=target_site.url,
                        status="ERROR",
                        score=0,
                        error_message=str(e)
                    )
                    error_results.append(error_result)
                results.append(error_results)

        return results

    def _execute_parallel(self, target_sites: List[TargetSite], batch_result: BatchAuditResult) -> List[List[AuditResult]]:
        """
        並行実行

        Args:
            target_sites: 診断対象サイトリスト
            batch_result: バッチ結果（進捗更新用）

        Returns:
            診断結果リスト
        """
        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 全サイトの診断タスクを投入
            future_to_site = {
                executor.submit(self.audit_single_site, site): site
                for site in target_sites
            }

            # 完了したタスクから結果を取得
            for future in as_completed(future_to_site):
                target_site = future_to_site[future]
                completed += 1

                self.audit_logger.batch_progress(completed, len(target_sites), target_site.url)

                try:
                    site_results = future.result()
                    results.append(site_results)

                except Exception as e:
                    self.logger.error(f"Site audit failed: {target_site.url}", error=str(e))
                    # エラー結果を作成
                    error_results = []
                    for auditor_name in self.enabled_auditors:
                        error_result = AuditResult(
                            audit_type=auditor_name,
                            url=target_site.url,
                            status="ERROR",
                            score=0,
                            error_message=str(e)
                        )
                        error_results.append(error_result)
                    results.append(error_results)

        return results

    def audit_single_url(self, url: str, audit_types: Optional[List[str]] = None) -> List[AuditResult]:
        """
        単一URLの診断を実行

        Args:
            url: 診断対象URL
            audit_types: 実行する診断タイプ（Noneの場合は全て）

        Returns:
            診断結果リスト
        """
        target_site = TargetSite(url=url)

        if audit_types:
            # 指定された診断タイプのみ実行
            original_enabled = self.enabled_auditors
            self.enabled_auditors = [t for t in audit_types if t in self.auditor_classes]

            try:
                results = self.audit_single_site(target_site)
            finally:
                self.enabled_auditors = original_enabled

            return results
        else:
            return self.audit_single_site(target_site)

    def get_available_auditors(self) -> List[str]:
        """
        利用可能な診断項目リストを取得

        Returns:
            診断項目名のリスト
        """
        return list(self.auditor_classes.keys())

    def validate_auditor_config(self) -> Dict[str, Any]:
        """
        診断項目の設定を検証

        Returns:
            検証結果
        """
        validation_result = {
            'valid': True,
            'available_auditors': list(self.auditor_classes.keys()),
            'enabled_auditors': self.enabled_auditors,
            'invalid_auditors': [],
            'warnings': []
        }

        # 有効な診断項目の検証
        for auditor_name in self.enabled_auditors:
            if auditor_name not in self.auditor_classes:
                validation_result['invalid_auditors'].append(auditor_name)
                validation_result['valid'] = False

        # 警告
        if not self.enabled_auditors:
            validation_result['warnings'].append('No auditors enabled')

        if self.max_workers > 10:
            validation_result['warnings'].append(f'High parallel worker count: {self.max_workers}')

        return validation_result

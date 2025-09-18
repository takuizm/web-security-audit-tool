"""
データモデル

診断結果や関連データの構造を定義します。
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class AuditStatus(Enum):
    """診断ステータス"""
    OK = "OK"
    NG = "NG"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Priority(Enum):
    """優先度"""
    HIGH = "高"
    MEDIUM = "中"
    LOW = "低"


@dataclass
class AuditResult:
    """
    診断結果データクラス

    個別の診断項目の結果を格納します。
    """
    audit_type: str
    url: str
    status: AuditStatus
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None

    def __post_init__(self):
        """初期化後の処理"""
        # ステータスが文字列の場合はEnumに変換
        if isinstance(self.status, str):
            try:
                self.status = AuditStatus(self.status)
            except ValueError:
                self.status = AuditStatus.ERROR

    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        data = asdict(self)
        data['status'] = self.status.value
        data['timestamp'] = self.timestamp.isoformat()
        return data

    def is_success(self) -> bool:
        """成功かどうかを判定"""
        return self.status in [AuditStatus.OK, AuditStatus.WARNING]

    def add_recommendation(self, recommendation: str) -> None:
        """推奨事項を追加"""
        if recommendation and recommendation not in self.recommendations:
            self.recommendations.append(recommendation)

    def add_detail(self, key: str, value: Any) -> None:
        """詳細情報を追加"""
        self.details[key] = value


@dataclass
class TargetSite:
    """
    診断対象サイト情報
    """
    url: str
    site_name: str = ""
    priority: Priority = Priority.MEDIUM
    notes: str = ""

    def __post_init__(self):
        """初期化後の処理"""
        # サイト名が空の場合はURLから生成
        if not self.site_name:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.site_name = parsed.netloc

        # 優先度が文字列の場合はEnumに変換
        if isinstance(self.priority, str):
            priority_map = {
                '高': Priority.HIGH,
                '中': Priority.MEDIUM,
                '低': Priority.LOW,
                'high': Priority.HIGH,
                'medium': Priority.MEDIUM,
                'low': Priority.LOW
            }
            self.priority = priority_map.get(self.priority.lower(), Priority.MEDIUM)

    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            'url': self.url,
            'site_name': self.site_name,
            'priority': self.priority.value,
            'notes': self.notes
        }


@dataclass
class BatchAuditResult:
    """
    バッチ診断結果データクラス

    複数サイトの診断結果をまとめて管理します。
    """
    results: List[AuditResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_sites: int = 0
    successful_audits: int = 0
    failed_audits: int = 0

    def add_result(self, result: AuditResult) -> None:
        """結果を追加"""
        self.results.append(result)
        if result.is_success():
            self.successful_audits += 1
        else:
            self.failed_audits += 1

    def complete(self) -> None:
        """バッチ処理完了"""
        self.end_time = datetime.now()

    @property
    def total_execution_time(self) -> float:
        """総実行時間（秒）"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def success_rate(self) -> float:
        """成功率（%）"""
        if self.total_sites == 0:
            return 0.0
        return (self.successful_audits / self.total_sites) * 100

    def get_results_by_url(self, url: str) -> List[AuditResult]:
        """指定URLの結果を取得"""
        return [r for r in self.results if r.url == url]

    def get_results_by_audit_type(self, audit_type: str) -> List[AuditResult]:
        """指定診断タイプの結果を取得"""
        return [r for r in self.results if r.audit_type == audit_type]

    def get_failed_results(self) -> List[AuditResult]:
        """失敗した結果のみを取得"""
        return [r for r in self.results if not r.is_success()]

    def get_summary_by_site(self) -> Dict[str, Dict[str, Any]]:
        """サイト別サマリーを取得"""
        summary = {}

        # URLごとにグループ化
        url_groups = {}
        for result in self.results:
            if result.url not in url_groups:
                url_groups[result.url] = []
            url_groups[result.url].append(result)

        # 各URLのサマリー計算
        for url, results in url_groups.items():
            status_counts = {}
            for result in results:
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1

            # 全体ステータス判定
            if status_counts.get('ERROR', 0) > 0:
                overall_status = AuditStatus.ERROR
            elif status_counts.get('NG', 0) > 0:
                overall_status = AuditStatus.NG
            elif status_counts.get('WARNING', 0) > 0:
                overall_status = AuditStatus.WARNING
            else:
                overall_status = AuditStatus.OK

            summary[url] = {
                'total_audits': len(results),
                'overall_status': overall_status.value,
                'status_counts': status_counts,
                'execution_time': sum(r.execution_time for r in results)
            }

        return summary

    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'total_sites': self.total_sites,
            'successful_audits': self.successful_audits,
            'failed_audits': self.failed_audits,
            'total_execution_time': self.total_execution_time,
            'success_rate': round(self.success_rate, 1),
            'results': [r.to_dict() for r in self.results],
            'summary_by_site': self.get_summary_by_site()
        }

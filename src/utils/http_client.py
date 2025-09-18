"""
HTTP通信クライアント

安全で再利用可能なHTTPクライアント機能を提供します。
"""

import time
import requests
from typing import Dict, Any, Optional, Union
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from .exceptions import NetworkError
from .logger import get_logger


class RateLimiter:
    """レート制限管理クラス"""

    def __init__(self, calls_per_minute: int = 60):
        """
        Args:
            calls_per_minute: 1分間あたりの最大呼び出し回数
        """
        self.calls_per_minute = calls_per_minute
        self.min_interval = 60.0 / calls_per_minute
        self.last_call_time = 0.0

    def wait_if_needed(self) -> None:
        """必要に応じて待機します"""
        current_time = time.time()
        time_since_last_call = current_time - self.last_call_time

        if time_since_last_call < self.min_interval:
            wait_time = self.min_interval - time_since_last_call
            time.sleep(wait_time)

        self.last_call_time = time.time()


class HTTPClient:
    """HTTP通信クライアントクラス"""

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        rate_limiter: Optional[RateLimiter] = None,
        user_agent: str = "SecurityAuditTool/1.0"
    ):
        """
        Args:
            timeout: タイムアウト時間（秒）
            max_retries: 最大リトライ回数
            backoff_factor: リトライ間隔の係数
            rate_limiter: レート制限管理インスタンス
            user_agent: User-Agentヘッダー
        """
        self.timeout = timeout
        self.rate_limiter = rate_limiter
        self.logger = get_logger(__name__)

        # セッション設定
        self.session = requests.Session()

        # デフォルトヘッダー
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # リトライ戦略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        # アダプター設定
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> requests.Response:
        """
        GET リクエストを実行します。

        Args:
            url: リクエストURL
            params: クエリパラメータ
            headers: 追加ヘッダー
            allow_redirects: リダイレクト許可
            **kwargs: その他のrequestsパラメータ

        Returns:
            レスポンスオブジェクト

        Raises:
            NetworkError: 通信エラーが発生した場合
        """
        return self._request('GET', url, params=params, headers=headers,
                           allow_redirects=allow_redirects, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> requests.Response:
        """
        POST リクエストを実行します。

        Args:
            url: リクエストURL
            data: フォームデータ
            json: JSONデータ
            headers: 追加ヘッダー
            **kwargs: その他のrequestsパラメータ

        Returns:
            レスポンスオブジェクト

        Raises:
            NetworkError: 通信エラーが発生した場合
        """
        return self._request('POST', url, data=data, json=json, headers=headers, **kwargs)

    def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> requests.Response:
        """
        HEAD リクエストを実行します。

        Args:
            url: リクエストURL
            headers: 追加ヘッダー
            allow_redirects: リダイレクト許可
            **kwargs: その他のrequestsパラメータ

        Returns:
            レスポンスオブジェクト

        Raises:
            NetworkError: 通信エラーが発生した場合
        """
        return self._request('HEAD', url, headers=headers,
                           allow_redirects=allow_redirects, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        内部リクエスト実行メソッド

        Args:
            method: HTTPメソッド
            url: リクエストURL
            **kwargs: requestsパラメータ

        Returns:
            レスポンスオブジェクト

        Raises:
            NetworkError: 通信エラーが発生した場合
        """
        # レート制限チェック
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()

        # タイムアウト設定
        kwargs.setdefault('timeout', self.timeout)

        # 追加ヘッダーのマージ
        headers = kwargs.get('headers', {})
        if headers:
            merged_headers = self.session.headers.copy()
            merged_headers.update(headers)
            kwargs['headers'] = merged_headers

        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)

            self.logger.debug(
                f"Request completed",
                method=method,
                url=url,
                status_code=response.status_code,
                response_time=response.elapsed.total_seconds()
            )

            return response

        except requests.exceptions.Timeout as e:
            self.logger.error(f"Request timeout: {url}", error=str(e))
            raise NetworkError(f"Request timeout: {url}", details={'error': str(e)})

        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error: {url}", error=str(e))
            raise NetworkError(f"Connection error: {url}", details={'error': str(e)})

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {url}", error=str(e))
            raise NetworkError(f"Request failed: {url}", details={'error': str(e)})

    def close(self) -> None:
        """セッションを閉じます"""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

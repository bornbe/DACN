"""
Kiểm thử phòng chống DNS Rebinding và phân giải DNS ngoài Loopback - Yêu cầu #2.
Mock hoàn toàn `socket.gethostbyname` để kiểm chứng offline.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from core.security.target_validator import SSRFBlockedError, validate_target_url
from core.utils.safe_http_client import SafeHTTPClient


def test_dns_resolving_to_non_loopback_is_rejected_immediately():
    """Hostname `.localhost` nhưng phân giải DNS trả về IP public/private/metadata phải bị từ chối."""
    for bad_ip in ("93.184.216.34", "192.168.1.254", "10.0.0.5", "169.254.169.254"):
        with patch("socket.gethostbyname", return_value=bad_ip) as mock_dns:
            with pytest.raises(SSRFBlockedError):
                validate_target_url("http://evil.localhost:8080/api")
            mock_dns.assert_called_once_with("evil.localhost")


def test_dns_rebinding_detected_between_validation_and_connection():
    """
    Kịch bản DNS Rebinding:
    - Lần phân giải thứ 1 (khi validate URL ban đầu) trả về `127.0.0.1` (hợp lệ).
    - Lần phân giải thứ 2 (ngay trước khi gắn socket/gửi HTTP request) đổi sang `192.168.1.100` (Private IP).
    SafeHTTPClient phải phát hiện và chặn trước khi `session.request` được gọi.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.headers = {}
    client = SafeHTTPClient(session=mock_session)

    with patch("socket.gethostbyname", side_effect=["127.0.0.1", "192.168.1.100"]) as mock_dns:
        with pytest.raises(SSRFBlockedError, match="192.168.1.100"):
            client.get("http://rebind.localhost:8080/secret")
        assert mock_dns.call_count == 2

    mock_session.request.assert_not_called()


def test_dns_rebinding_on_redirect_hop_is_blocked():
    """
    Kịch bản Redirect + DNS Rebinding:
    - Hop 1 tới `http://app.localhost:8080/start` phân giải `127.0.0.1` ở cả 2 bước và trả về 302 `/next`.
    - Hop 2 tới `http://app.localhost:8080/next` đổi kết quả phân giải DNS sang `169.254.169.254`.
    SafeHTTPClient phải chặn ngay ở Hop 2 và không gửi request thứ hai.
    """
    redirect_resp = requests.Response()
    redirect_resp.status_code = 302
    redirect_resp.headers["Location"] = "/next"

    mock_session = MagicMock(spec=requests.Session)
    mock_session.headers = {}
    mock_session.request.return_value = redirect_resp
    client = SafeHTTPClient(session=mock_session)

    with patch(
        "socket.gethostbyname",
        side_effect=["127.0.0.1", "127.0.0.1", "169.254.169.254"],
    ):
        with pytest.raises(SSRFBlockedError, match="169.254.169.254"):
            client.get("http://app.localhost:8080/start")

    # Chỉ duy nhất request đầu tiên được gửi; hop thứ hai bị chặn trước khi kết nối
    assert mock_session.request.call_count == 1

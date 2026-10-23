"""
Bóc tách tham số GET/POST và Form HTML, chuẩn hóa thành EndpointDescriptor - Issue #2.2.
Mỗi EndpointDescriptor mô tả một bề mặt tấn công (Attack Surface) gồm URL, phương thức
và danh sách tham số đầu vào, cung cấp trực tiếp cho các module Scanner (SQLi, XSS...).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from core.crawler.url_parser import URLParser


@dataclass
class EndpointDescriptor:
    """
    Cấu trúc dữ liệu chuẩn hóa mô tả một điểm cuối (endpoint) có thể kiểm thử.
    - url:    Địa chỉ xử lý yêu cầu (với GET là URL gốc, với Form là thuộc tính action).
    - method: Phương thức HTTP ('GET' hoặc 'POST').
    - params: Từ điển {tên tham số: giá trị mẫu} - chính là các điểm tiêm payload.
    - source: Nguồn phát hiện ('query' nếu lấy từ URL, 'form' nếu lấy từ thẻ <form>).
    - depth:  Độ sâu của trang nơi tìm thấy endpoint này.
    """

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    source: str = "form"
    depth: int = 0

    def __post_init__(self) -> None:
        self.method = (self.method or "GET").upper()

    @property
    def params_schema(self) -> dict[str, str]:
        """Trả về cấu trúc tham số, tương thích với trường params_schema của CrawledEndpoint."""
        return dict(self.params)

    def signature(self) -> str:
        """Khóa định danh duy nhất (method + url + tên các tham số) để lọc endpoint trùng lặp."""
        param_names = ",".join(sorted(self.params.keys()))
        return f"{self.method} {self.url} [{param_names}]"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "source": self.source,
            "depth": self.depth,
        }


class FormParser:
    """Phân tích cú pháp HTML để bóc tách các thẻ <form> và tham số đầu vào."""

    # Các loại input không mang dữ liệu người dùng nhập, bỏ qua khi dựng tham số
    IGNORED_INPUT_TYPES: frozenset[str] = frozenset({"submit", "button", "reset", "image", "file"})

    def __init__(self, url_parser: "URLParser") -> None:
        self.url_parser = url_parser

    def parse_forms(self, html: str, page_url: str, depth: int = 0) -> list[EndpointDescriptor]:
        """
        Bóc tách toàn bộ thẻ <form> trong trang, trả về danh sách EndpointDescriptor.
        Mỗi form được phân tích action (endpoint), method (GET/POST) và các trường nhập liệu.
        """
        soup = BeautifulSoup(html, "html.parser")
        endpoints: list[EndpointDescriptor] = []

        for form in soup.find_all("form"):
            action = form.get("action")
            # Form không có action -> gửi về chính trang hiện tại
            target_url = self.url_parser.to_absolute(action, page_url) if action else page_url
            if not target_url or not self.url_parser.is_in_scope(target_url):
                continue

            method = (form.get("method") or "GET").strip().upper()
            params = self._extract_input_fields(form)

            endpoints.append(
                EndpointDescriptor(
                    url=target_url,
                    method=method,
                    params=params,
                    source="form",
                    depth=depth,
                )
            )
        return endpoints

    def _extract_input_fields(self, form: Any) -> dict[str, str]:
        """Thu thập các trường <input>, <textarea>, <select> có thuộc tính name trong một form."""
        params: dict[str, str] = {}

        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue

            tag_name = tag.name.lower()
            if tag_name == "input":
                input_type = (tag.get("type") or "text").lower()
                if input_type in self.IGNORED_INPUT_TYPES:
                    continue
                params[name] = tag.get("value", "")
            elif tag_name == "textarea":
                params[name] = tag.get_text(strip=True)
            elif tag_name == "select":
                option = tag.find("option", selected=True) or tag.find("option")
                params[name] = option.get("value", "") if option else ""

        return params

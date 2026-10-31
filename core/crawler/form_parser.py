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

# Form HTML chỉ hỗ trợ GET/POST; method khác được trình duyệt xử lý như GET.
VALID_FORM_METHODS: frozenset[str] = frozenset({"GET", "POST"})
# Giá trị method override (hidden `_method`) làm form POST thực chất thay đổi trạng thái theo method khác
OVERRIDE_METHODS: frozenset[str] = frozenset({"PUT", "DELETE", "PATCH"})


@dataclass
class EndpointDescriptor:
    """
    Cấu trúc dữ liệu chuẩn hóa mô tả một điểm cuối (endpoint) có thể kiểm thử.
    - url:    Địa chỉ xử lý yêu cầu (với GET là URL gốc, với Form là thuộc tính action).
    - method: Phương thức HTTP ('GET' hoặc 'POST').
    - params: Từ điển {tên tham số: giá trị mẫu} - chính là các điểm tiêm payload.
    - source: Nguồn phát hiện ('query' nếu lấy từ URL, 'form' nếu lấy từ thẻ <form>).
    - depth:  Độ sâu của trang nơi tìm thấy endpoint này.
    - page_url: URL trang HTML chứa form (nếu có), để scanner đối chiếu lại nội dung form.
    - method_override: Method thực tế khi form POST có hidden `_method=PUT/DELETE/PATCH` (None nếu không có).
    """

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    source: str = "form"
    depth: int = 0
    page_url: str | None = None
    method_override: str | None = None

    def __post_init__(self) -> None:
        self.method = (self.method or "GET").upper()
        if self.method_override:
            self.method_override = self.method_override.upper()

    @property
    def effective_method(self) -> str:
        """Method có hiệu lực ở tầng ứng dụng: method override nếu có, ngược lại là method HTTP."""
        return self.method_override or self.method

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
            "method_override": self.method_override,
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
            action = (form.get("action") or "").strip()
            # Form không có action (hoặc action rỗng) -> gửi về chính trang hiện tại
            try:
                target_url = (
                    self.url_parser.to_absolute(action, page_url) if action else self.url_parser.normalize(page_url)
                )
            except ValueError:
                continue
            if not target_url or not self.url_parser.is_in_scope(target_url):
                continue

            method = (form.get("method") or "GET").strip().upper()
            if method not in VALID_FORM_METHODS:
                method = "GET"
            params = self._extract_input_fields(form, soup)

            method_override = None
            if method == "POST":
                for name, value in params.items():
                    if name.lower() == "_method" and value.strip().upper() in OVERRIDE_METHODS:
                        method_override = value.strip().upper()
                        break

            endpoints.append(
                EndpointDescriptor(
                    url=target_url,
                    method=method,
                    params=params,
                    source="form",
                    depth=depth,
                    page_url=page_url,
                    method_override=method_override,
                )
            )
        return endpoints

    def _extract_input_fields(self, form: Any, soup: Any = None) -> dict[str, str]:
        """
        Thu thập các trường <input>, <textarea>, <select> có thuộc tính name trong một form,
        gồm cả trường hidden và các trường nằm ngoài thẻ <form> nhưng gắn qua thuộc tính form="id".
        """
        params: dict[str, str] = {}

        tags = list(form.find_all(["input", "textarea", "select"]))
        form_id = form.get("id")
        if soup is not None and form_id:
            tags += soup.find_all(["input", "textarea", "select"], attrs={"form": form_id})

        for tag in tags:
            name = tag.get("name")
            if not name:
                continue

            tag_name = tag.name.lower()
            if tag_name == "input":
                input_type = (tag.get("type") or "text").strip().lower()
                if input_type in self.IGNORED_INPUT_TYPES:
                    continue
                if input_type in ("checkbox", "radio"):
                    # Không có thuộc tính value thì trình duyệt gửi "on"; radio ưu tiên phần tử được chọn
                    if input_type == "radio" and name in params and not tag.has_attr("checked"):
                        continue
                    params[name] = tag.get("value", "on")
                    continue
                params[name] = tag.get("value", "")
            elif tag_name == "textarea":
                params[name] = tag.get_text(strip=True)
            elif tag_name == "select":
                option = tag.find("option", selected=True) or tag.find("option")
                if option is None:
                    params[name] = ""
                else:
                    params[name] = option.get("value", option.get_text(strip=True))

        return params

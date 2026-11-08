"""
Issue #3.5
Scanner dò phản chiếu đầu vào (Reflected XSS) bằng token định danh + ký tự probe không thực thi.
Chỉ kết luận cần đánh giá khi ký tự đặc biệt phản chiếu chưa mã hóa trong phản hồi HTML.
Không chèn mã thực thi hoặc đánh giá JavaScript.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from core.scanners.base_scanner import BaseScanner, Finding

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor


class XSSScanner(BaseScanner):
    """Phân loại phản chiếu: bỏ qua non-HTML/đã escape; gắn nhãn 'cần đánh giá' cho phản chiếu rủi ro."""

    category = "xss"
    name = "xss"

    # Ký tự probe tách riêng khỏi token định danh
    PROBE = "<>\"'"

    def __init__(self, *args: Any, canary_token: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.canary_token = canary_token

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        """Thử phản chiếu token + probe trên từng tham số."""
        method = endpoint.method.upper()
        if method not in ("GET", "POST") or not endpoint.params:
            return []

        findings: list[Finding] = []
        for parameter in endpoint.params:
            token = self.canary_token or f"xss{secrets.token_hex(8)}"
            canary = token + self.PROBE
            values = dict(endpoint.params)
            values[parameter] = canary
            argument = "params" if method == "GET" else "data"
            response = self.send(method, endpoint.url, **{argument: values})
            if response is None:
                return []

            finding = self.analyze_response(response, endpoint.url, parameter, token, canary)
            if finding is not None:
                findings.append(finding)
        return findings

    def analyze_response(
        self, response: Any, url: str, parameter: str, token: str, canary: str
    ) -> Finding | None:
        """Trả Finding nếu token phản chiếu kèm ký tự nguy hiểm chưa mã hóa trong HTML."""
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "html" not in content_type:
            return None

        body = response.text
        index = body.find(token)
        while index >= 0:
            tail = body[index + len(token) : index + len(token) + len(self.PROBE)]
            raw = set(tail) & set(self.PROBE)
            context = self._reflection_context(body, index)
            if self._is_risky(context, raw):
                start = max(0, index - 100)
                end = min(len(body), index + len(canary) + 100)
                return self.make_finding(
                    vuln_name="Unencoded Input Reflection (Needs Review)",
                    target_url=url,
                    severity="LOW",
                    parameter=parameter,
                    payload=canary,
                    evidence=(
                        f"Ngữ cảnh {context}; ký tự chưa mã hóa: {''.join(sorted(raw))}; "
                        f"cần đánh giá thủ công (chưa xác nhận thực thi JS): {body[start:end]}"
                    ),
                )
            index = body.find(token, index + len(token))
        return None

    @staticmethod
    def _is_risky(context: str, raw: set[str]) -> bool:
        if context == "attribute":
            return bool(raw & {'"', "'"})
        if context == "JavaScript":
            return bool(raw & {'"', "'", "<"})
        return bool(raw & {"<", ">"})

    @staticmethod
    def _reflection_context(body: str, index: int) -> str:
        """Ước lượng ngữ cảnh HTML nơi canary được phản chiếu."""
        prefix = body[:index]
        lower_prefix = prefix.lower()
        if lower_prefix.rfind("<script") > lower_prefix.rfind("</script"):
            return "JavaScript"

        tag_start = prefix.rfind("<")
        tag_end = prefix.rfind(">")
        if tag_start > tag_end:
            quote: str | None = None
            for character in prefix[tag_start + 1 :]:
                if quote is not None:
                    if character == quote:
                        quote = None
                elif character in ("'", '"'):
                    quote = character
            if quote is not None:
                return "attribute"
        return "HTML"

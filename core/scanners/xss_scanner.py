"""
Issue #3.5
Scanner dò Reflected XSS bằng canary duy nhất và kiểm tra phản chiếu chưa mã hóa.
Không chèn mã thực thi hoặc đánh giá JavaScript.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from core.scanners.base_scanner import BaseScanner, Finding

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor


class XSSScanner(BaseScanner):
    """Phát hiện canary XSS được phản chiếu nguyên bản trong phản hồi HTTP."""

    category = "xss"
    name = "xss"

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        """Thử phản chiếu một canary không thực thi trên từng tham số."""
        method = endpoint.method.upper()
        if method not in ("GET", "POST") or not endpoint.params:
            return []

        findings: list[Finding] = []
        for parameter in endpoint.params:
            canary = f"xss{secrets.token_hex(8)}<>\"'"
            values = dict(endpoint.params)
            values[parameter] = canary
            argument = "params" if method == "GET" else "data"
            response = self.send(method, endpoint.url, **{argument: values})
            if response is None:
                return []

            body = response.text
            index = body.find(canary)
            if index < 0:
                continue

            context = self._reflection_context(body, index)
            start = max(0, index - 100)
            end = min(len(body), index + len(canary) + 100)
            excerpt = body[start:end]
            findings.append(
                self.make_finding(
                    vuln_name="Reflected XSS",
                    target_url=endpoint.url,
                    severity="MEDIUM",
                    parameter=parameter,
                    payload=canary,
                    evidence=f"Ngữ cảnh {context}; phản chiếu chưa mã hóa: {excerpt}",
                )
            )
        return findings

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
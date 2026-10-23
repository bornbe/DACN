"""
Gói Crawler: thu thập liên kết BFS và bóc tách bề mặt tấn công (Issue #2.1, #2.2).
"""

from core.crawler.bfs_crawler import BFSCrawler, CrawlResult
from core.crawler.form_parser import EndpointDescriptor, FormParser
from core.crawler.url_parser import URLParser

__all__ = [
    "BFSCrawler",
    "CrawlResult",
    "EndpointDescriptor",
    "FormParser",
    "URLParser",
]

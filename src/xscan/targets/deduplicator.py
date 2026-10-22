"""
Target Deduplicator
===================
Deterministic deduplication of targets.

Handles common duplicate patterns:
  - https://example.com and https://example.com/
  - https://example.com:443 and https://example.com
  - https://Example.COM and https://example.com
  - URL encoding variations

The deduplicator is conservative: it prefers to keep duplicates
rather than aggressively remove potentially distinct targets.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Callable

from xscan.targets.models import NormalizedTarget, TargetSet
from xscan.targets.normalizer import URLNormalizer

logger = logging.getLogger(__name__)


class DeduplicationResult:
    """
    Result of deduplication.

    Tracks:
      - Original count
      - Unique count
      - Duplicates removed
      - Duplicate groups (for audit)
    """

    def __init__(
        self,
        original_count: int,
        unique_count: int,
        duplicates: list[dict[str, Any]],
    ) -> None:
        self.original_count = original_count
        self.unique_count = unique_count
        self.duplicates = duplicates
        self.duplicate_count = original_count - unique_count

    def summary(self) -> dict[str, Any]:
        return {
            "original_count": self.original_count,
            "unique_count": self.unique_count,
            "duplicate_count": self.duplicate_count,
            "duplicate_groups": len(self.duplicates),
        }


class TargetDeduplicator:
    """
    Deduplicates targets based on normalized URL.

    Usage::

        dedup = TargetDeduplicator()
        result = dedup.deduplicate(target_set)

        # Or just the filter function
        unique_urls = dedup.filter_urls(url_list)
    """

    def __init__(
        self,
        normalizer: URLNormalizer | None = None,
        log_duplicates: bool = True,
    ) -> None:
        self._normalizer = normalizer or URLNormalizer()
        self._log_duplicates = log_duplicates

    def deduplicate(self, target_set: TargetSet) -> DeduplicationResult:
        """
        Deduplicate targets in place.

        Removes duplicate targets from the set, keeping the first occurrence.
        Returns a DeduplicationResult with statistics.
        """
        seen: dict[str, NormalizedTarget] = OrderedDict()
        duplicates: list[dict[str, Any]] = []
        original_count = len(target_set)

        for target in list(target_set.targets):
            norm_url = target.normalized_url

            if norm_url in seen:
                # Duplicate found
                original = seen[norm_url]
                dup_info = {
                    "normalized_url": norm_url,
                    "kept": {
                        "target_id": original.target_id,
                        "original_url": original.original_url,
                        "source_line": original.source_line,
                    },
                    "removed": {
                        "target_id": target.target_id,
                        "original_url": target.original_url,
                        "source_line": target.source_line,
                    },
                }
                duplicates.append(dup_info)

                if self._log_duplicates:
                    logger.debug(
                        "Duplicate target: %s (line %d) duplicates line %d",
                        norm_url[:60],
                        target.source_line,
                        original.source_line,
                    )

                # Remove from set
                target_set.targets.remove(target)
                if target.target_id in target_set._target_index:
                    del target_set._target_index[target.target_id]
            else:
                seen[norm_url] = target

        return DeduplicationResult(
            original_count=original_count,
            unique_count=len(target_set),
            duplicates=duplicates,
        )

    def filter_urls(self, urls: list[str]) -> list[str]:
        """
        Filter a list of URLs to unique ones.

        Returns URLs in order of first occurrence.
        """
        seen: set[str] = set()
        result: list[str] = []

        for url in urls:
            norm_result = self._normalizer.normalize(url)
            if not norm_result.valid:
                continue

            norm_url = norm_result.normalized_url
            if norm_url not in seen:
                seen.add(norm_url)
                result.append(url)

        return result

    def find_duplicates(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Find duplicate URLs in a list.

        Returns a dict mapping normalized URL to list of original URLs.
        """
        groups: dict[str, list[str]] = {}

        for url in urls:
            norm_result = self._normalizer.normalize(url)
            if not norm_result.valid:
                continue

            norm_url = norm_result.normalized_url
            if norm_url not in groups:
                groups[norm_url] = []
            groups[norm_url].append(url)

        # Return only groups with duplicates
        return {k: v for k, v in groups.items() if len(v) > 1}

    def count_unique(self, urls: list[str]) -> int:
        """Count unique URLs in a list."""
        seen: set[str] = set()
        for url in urls:
            norm_result = self._normalizer.normalize(url)
            if norm_result.valid:
                seen.add(norm_result.normalized_url)
        return len(seen)


def deduplicate_urls(urls: list[str], **options: Any) -> list[str]:
    """
    Convenience function to deduplicate a list of URLs.

    Returns unique URLs in order of first occurrence.
    """
    dedup = TargetDeduplicator(**options)
    return dedup.filter_urls(urls)

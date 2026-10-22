"""
Target Loader
=============
Loads targets from various sources and produces a TargetSet.

Supported sources:
  - Single URL (CLI argument)
  - URL file (one URL per line)
  - Stdin (one URL per line)
  - Previous scan results
  - Crawler output (future)

Flow:
  1. Load raw URLs from source
  2. Normalize each URL
  3. Deduplicate
  4. Pass through Scope + Policy validation
  5. Return TargetSet with all metadata
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path

from xscan.core.scope.engine import ScopeEngine
from xscan.core.scope.policy import PolicyEngine
from xscan.errors import TargetLoadError
from xscan.targets.models import (
    NormalizedTarget,
    TargetQueue,
    TargetSet,
    TargetSource,
    TargetSourceType,
    TargetStatus,
)
from xscan.targets.normalizer import URLNormalizer

logger = logging.getLogger(__name__)


class TargetLoader:
    """
    Loads and processes targets from various sources.

    Usage::

        loader = TargetLoader()
        target_set = loader.load_from_file("urls.txt", scope=scope_engine)
        queue = loader.to_queue(target_set)
    """

    def __init__(
        self,
        normalizer: URLNormalizer | None = None,
        validate_scope: bool = True,
        progress_cb: Callable[[str], None] | None = None,
    ) -> None:
        self._normalizer = normalizer or URLNormalizer()
        self._validate_scope = validate_scope
        self._progress = progress_cb or (lambda msg: None)

    # ------------------------------------------------------------------
    # Main loading methods
    # ------------------------------------------------------------------

    def load_single_url(
        self,
        url: str,
        *,
        scope: ScopeEngine | None = None,
        policy: PolicyEngine | None = None,
        assessment_id: str = "",
    ) -> TargetSet:
        """Load a single URL as a target set."""
        source = TargetSource.single_url(url)
        target_set = TargetSet(
            assessment_id=assessment_id,
            source=source,
        )

        target = self._process_url(url, source, line=0, scope=scope, policy=policy)
        if target:
            target_set.add(target)

        return target_set

    def load_from_file(
        self,
        path: str,
        *,
        scope: ScopeEngine | None = None,
        policy: PolicyEngine | None = None,
        assessment_id: str = "",
    ) -> TargetSet:
        """
        Load targets from a file (one URL per line).

        Handles:
          - Comments (lines starting with #)
          - Empty lines
          - Trailing comments
        """
        file_path = Path(path)
        if not file_path.exists():
            raise TargetLoadError(f"Target file not found: {path}")

        source = TargetSource.url_file(path)
        target_set = TargetSet(
            assessment_id=assessment_id,
            source=source,
        )

        self._progress(f"Loading targets from {path}...")

        line_num = 0
        loaded = 0
        blocked = 0

        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line_num += 1
                url = self._clean_line(line)
                if not url:
                    continue

                target = self._process_url(
                    url, source, line=line_num, scope=scope, policy=policy
                )
                if target:
                    if not target_set.add(target):
                        continue  # duplicate URL, already counted
                    if target.status == TargetStatus.BLOCKED:
                        blocked += 1
                    else:
                        loaded += 1

        self._progress(
            f"Loaded {loaded} targets from {path}"
            + (f", {blocked} blocked by scope" if blocked else "")
        )

        return target_set

    def load_from_stdin(
        self,
        *,
        scope: ScopeEngine | None = None,
        policy: PolicyEngine | None = None,
        assessment_id: str = "",
    ) -> TargetSet:
        """
        Load targets from stdin (one URL per line).

        Reads until EOF. Useful for piping:
          cat urls.txt | xscan xss --stdin
          curl -s https://example.com/urls | xscan xss --stdin
        """
        source = TargetSource.stdin()
        target_set = TargetSet(
            assessment_id=assessment_id,
            source=source,
        )

        self._progress("Reading targets from stdin...")

        line_num = 0
        loaded = 0
        blocked = 0

        for line in sys.stdin:
            line_num += 1
            url = self._clean_line(line)
            if not url:
                continue

            target = self._process_url(
                url, source, line=line_num, scope=scope, policy=policy
            )
            if target:
                if target.status == TargetStatus.BLOCKED:
                    blocked += 1
                else:
                    loaded += 1
                target_set.add(target)

        self._progress(
            f"Loaded {loaded} targets from stdin"
            + (f", {blocked} blocked by scope" if blocked else "")
        )

        return target_set

    def load_from_source(
        self,
        source: TargetSource,
        *,
        scope: ScopeEngine | None = None,
        policy: PolicyEngine | None = None,
        assessment_id: str = "",
    ) -> TargetSet:
        """
        Load targets from a TargetSource.

        Dispatches to the appropriate method based on source type.
        """
        if source.type == TargetSourceType.SINGLE_URL:
            return self.load_single_url(
                source.location,
                scope=scope,
                policy=policy,
                assessment_id=assessment_id,
            )
        elif source.type == TargetSourceType.URL_FILE:
            return self.load_from_file(
                source.location,
                scope=scope,
                policy=policy,
                assessment_id=assessment_id,
            )
        elif source.type == TargetSourceType.STDIN:
            return self.load_from_stdin(
                scope=scope,
                policy=policy,
                assessment_id=assessment_id,
            )
        else:
            raise TargetLoadError(
                f"Unsupported source type: {source.type}"
            )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def deduplicate(self, urls: list[str]) -> list[tuple[str, int]]:
        """
        Deduplicate a list of URLs.

        Returns list of (normalized_url, original_index) tuples.
        Preserves first occurrence order.
        """
        seen: dict[str, int] = {}
        result: list[tuple[str, int]] = []

        for idx, url in enumerate(urls):
            norm_result = self._normalizer.normalize(url)
            if not norm_result.valid:
                logger.debug("Skipping invalid URL: %s", url)
                continue

            norm_url = norm_result.normalized_url
            if norm_url not in seen:
                seen[norm_url] = idx
                result.append((norm_url, idx))

        return result

    # ------------------------------------------------------------------
    # Queue creation
    # ------------------------------------------------------------------

    def to_queue(self, target_set: TargetSet) -> TargetQueue:
        """Convert a TargetSet to a TargetQueue for execution."""
        queue = TargetQueue(assessment_id=target_set.assessment_id)

        for target in target_set:
            # Skip blocked targets
            if target.status == TargetStatus.BLOCKED:
                continue
            queue.add(target)

        return queue

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _clean_line(self, line: str) -> str:
        """Clean a line from a file/stdin."""
        # Strip whitespace
        line = line.strip()
        # Skip empty lines
        if not line:
            return ""
        # Skip comments
        if line.startswith("#"):
            return ""
        # Remove trailing comments
        if "#" in line:
            line = line.split("#")[0].strip()
        return line

    def _process_url(
        self,
        url: str,
        source: TargetSource,
        line: int,
        scope: ScopeEngine | None,
        policy: PolicyEngine | None,
    ) -> NormalizedTarget | None:
        """Process a single URL: normalize, validate, create target."""
        # Normalize
        norm_result = self._normalizer.normalize(url)
        if not norm_result.valid:
            logger.warning("Invalid URL (line %d): %s — %s", line, url, norm_result.error)
            return None

        # Create target
        target = NormalizedTarget(
            original_url=url,
            normalized_url=norm_result.normalized_url,
            scheme=norm_result.scheme,
            hostname=norm_result.hostname,
            port=norm_result.port,
            path=norm_result.path,
            query=norm_result.query,
            fragment=norm_result.fragment,
            source=source,
            source_line=line,
        )

        # Scope validation
        if self._validate_scope and scope:
            if not scope.is_allowed(norm_result.normalized_url):
                reason = f"URL outside authorized scope: {norm_result.normalized_url}"
                logger.info("Scope blocked: %s", norm_result.normalized_url)
                target.status = TargetStatus.BLOCKED
                target.scope_valid = False
                target.scope_rejection_reason = reason
                return target

        # Policy validation (if provided)
        if policy:
            try:
                policy.assert_permitted(
                    "target_load",
                    {"url": norm_result.normalized_url, "source": source.type.value}
                )
            except Exception as e:
                reason = f"Policy violation: {e}"
                logger.info("Policy blocked: %s — %s", norm_result.normalized_url, e)
                target.status = TargetStatus.BLOCKED
                target.scope_valid = False
                target.scope_rejection_reason = reason
                return target

        # Valid target
        target.scope_valid = True
        target.status = TargetStatus.PENDING
        return target

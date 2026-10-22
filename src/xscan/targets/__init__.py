"""
XScan Targets Package
=====================
Target input, normalization, deduplication, and queue management.

Components:
  - TargetSource: Abstraction for input sources (single URL, file, stdin)
  - NormalizedTarget: URL with stable identity and metadata
  - TargetSet: Collection of targets for an assessment
  - TargetQueue: Execution state tracking
  - TargetLoader: Load targets from various sources
  - URLNormalizer: Deterministic URL normalization
  - TargetDeduplicator: Remove duplicate targets

Flow:
  Input → TargetLoader → Normalize → Deduplicate → Scope/Policy → TargetQueue → DAG
"""
from xscan.targets.models import (
    TargetSource,
    TargetSourceType,
    NormalizedTarget,
    TargetSet,
    TargetQueue,
    TargetQueueEntry,
    TargetStatus,
)
from xscan.targets.loader import TargetLoader
from xscan.targets.normalizer import URLNormalizer, normalize_url, NormalizationResult
from xscan.targets.deduplicator import TargetDeduplicator, deduplicate_urls, DeduplicationResult

__all__ = [
    # Models
    "TargetSource",
    "TargetSourceType",
    "NormalizedTarget",
    "TargetSet",
    "TargetQueue",
    "TargetQueueEntry",
    "TargetStatus",
    # Loader
    "TargetLoader",
    # Normalizer
    "URLNormalizer",
    "normalize_url",
    "NormalizationResult",
    # Deduplicator
    "TargetDeduplicator",
    "deduplicate_urls",
    "DeduplicationResult",
]

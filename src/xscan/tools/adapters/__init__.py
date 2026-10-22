"""Tool adapters — each wraps one binary through ExecutionRuntime."""
from xscan.tools.adapters.base import ToolAdapterBase
from xscan.tools.adapters.subfinder import SubfinderAdapter
from xscan.tools.adapters.assetfinder import AssetfinderAdapter
from xscan.tools.adapters.amass import AmassAdapter
from xscan.tools.adapters.httpx_probe import HttpxProbeAdapter
from xscan.tools.adapters.ffuf import FfufAdapter

__all__ = [
    "ToolAdapterBase",
    "SubfinderAdapter",
    "AssetfinderAdapter",
    "AmassAdapter",
    "HttpxProbeAdapter",
    "FfufAdapter",
]

"""
export.py — Export discovered URLs, endpoints, and assets to files.

Provides interactive prompts and export functions for:
  - Discovered subdomains (JSON/CSV)
  - Live hosts (JSON/CSV)
  - Endpoints (JSON/CSV)
  - Directory discovery results (JSON/CSV)
"""
from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Any


def prompt_save_location(
    data_type: str,
    default_name: str = "",
    formats: list[str] | None = None,
) -> str | None:
    """
    Prompt user for save location and format.
    
    Args:
        data_type: e.g., "subdomains", "endpoints", "paths"
        default_name: default filename without extension
        formats: list of supported formats (default: ["json", "csv"])
    
    Returns:
        Full path with extension, or None if user cancels
    """
    if formats is None:
        formats = ["json", "csv"]
    
    # Determine default filename
    if not default_name:
        default_name = f"xscan_{data_type}"
    
    # Prompt user
    print(f"\n[*] {data_type.title()} discovered. Save results?")
    print(f"    Default location: ./{default_name}.json")
    print(f"    Supported formats: {', '.join(formats)}")
    
    user_input = input("\n[?] Enter filename (e.g., 'results.json') or press Enter to skip: ").strip()
    
    if not user_input:
        print("    [skipped]")
        return None
    
    # Validate extension
    path = Path(user_input)
    if not path.suffix:
        path = path.with_suffix(".json")
    elif path.suffix[1:].lower() not in formats:
        print(f"    [!] Unsupported format: {path.suffix}. Using .json instead.")
        path = path.with_suffix(".json")
    
    # Resolve path (use current directory if relative)
    if not path.is_absolute():
        path = Path.cwd() / path
    
    # Create parent directories if needed
    path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"    [✓] Will save to: {path}")
    return str(path)


def export_subdomains(
    assets: list[dict],
    filepath: str,
) -> bool:
    """
    Export discovered subdomains to file.
    
    Args:
        assets: List of ReconAsset dicts
        filepath: Destination path
    
    Returns:
        True on success, False on error
    """
    try:
        path = Path(filepath)
        
        if path.suffix.lower() == ".json":
            data = {
                "type": "subdomains",
                "count": len(assets),
                "assets": assets,
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif path.suffix.lower() == ".csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Hostname", "Status", "Sources", "In-Scope", "Scope-Reason"])
                for asset in assets:
                    writer.writerow([
                        asset.get("hostname", "?"),
                        "LIVE" if asset.get("live") else "DEAD",
                        ", ".join(asset.get("sources", [])),
                        "Yes" if asset.get("in_scope") else "No",
                        asset.get("scope_reason", ""),
                    ])
        else:
            print(f"[!] Unsupported format: {path.suffix}")
            return False
        
        print(f"[✓] Exported {len(assets)} subdomains to {path}")
        return True
    except Exception as e:
        print(f"[!] Error exporting subdomains: {e}")
        return False


def export_endpoints(
    endpoints: list[dict],
    filepath: str,
) -> bool:
    """
    Export discovered endpoints to file.
    
    Args:
        endpoints: List of Endpoint dicts
        filepath: Destination path
    
    Returns:
        True on success, False on error
    """
    try:
        path = Path(filepath)
        
        if path.suffix.lower() == ".json":
            data = {
                "type": "endpoints",
                "count": len(endpoints),
                "endpoints": endpoints,
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif path.suffix.lower() == ".csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Hostname", "Path", "Parameters", "Sources"])
                for ep in endpoints:
                    writer.writerow([
                        ep.get("url", "?"),
                        ep.get("hostname", "?"),
                        ep.get("path", ""),
                        ", ".join(ep.get("parameters", [])),
                        ", ".join(ep.get("sources", [])),
                    ])
        else:
            print(f"[!] Unsupported format: {path.suffix}")
            return False
        
        print(f"[✓] Exported {len(endpoints)} endpoints to {path}")
        return True
    except Exception as e:
        print(f"[!] Error exporting endpoints: {e}")
        return False


def export_paths(
    paths: list[dict],
    filepath: str,
) -> bool:
    """
    Export discovered paths (from ffuf) to file.
    
    Args:
        paths: List of DiscoveredPath dicts
        filepath: Destination path
    
    Returns:
        True on success, False on error
    """
    try:
        path = Path(filepath)
        
        if path.suffix.lower() == ".json":
            data = {
                "type": "discovered_paths",
                "count": len(paths),
                "paths": paths,
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif path.suffix.lower() == ".csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Status", "Size", "Lines", "Words"])
                for p in paths:
                    writer.writerow([
                        p.get("url", "?"),
                        p.get("status_code", "?"),
                        p.get("size", ""),
                        p.get("lines", ""),
                        p.get("words", ""),
                    ])
        else:
            print(f"[!] Unsupported format: {path.suffix}")
            return False
        
        print(f"[✓] Exported {len(paths)} paths to {path}")
        return True
    except Exception as e:
        print(f"[!] Error exporting paths: {e}")
        return False


def export_full_report(
    report_data: dict[str, Any],
    filepath: str,
) -> bool:
    """
    Export complete scan report to file.
    
    Args:
        report_data: Full report dictionary
        filepath: Destination path
    
    Returns:
        True on success, False on error
    """
    try:
        path = Path(filepath)
        
        if path.suffix.lower() == ".json":
            path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        else:
            print(f"[!] Full report export only supports JSON format")
            return False
        
        print(f"[✓] Exported full report to {path}")
        return True
    except Exception as e:
        print(f"[!] Error exporting report: {e}")
        return False

"""
CTF/Intentional Vulnerability Detection
========================================
Identifies capture-the-flag games and intentional vulnerability contexts
from URL patterns, domain names, and content hints.

This allows the LLM planner to adjust strategy when scanning known-vulnerable
targets (CTF games, DVWA, HackTheBox, etc.) vs. real-world applications.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass
class CTFContext:
    """Detected CTF/intentional vulnerability context."""
    is_ctf: bool
    platform: str | None = None  # "htb", "ctflearn", "dvwa", "webgoat", etc.
    confidence: float = 0.0  # 0.0 to 1.0
    hints: list[str] = None  # e.g., ["htb-ip", "dvwa-pattern", "flag-format"]

    def __post_init__(self) -> None:
        if self.hints is None:
            self.hints = []

    def summary(self) -> str:
        """Human-readable summary of detected context."""
        if not self.is_ctf:
            return "Production application (no CTF patterns detected)"
        parts = [f"CTF/Intentional context detected (confidence: {self.confidence:.0%})"]
        if self.platform:
            parts.append(f"Platform: {self.platform}")
        if self.hints:
            parts.append(f"Hints: {', '.join(self.hints)}")
        return " — ".join(parts)


# Regex patterns for common CTF platforms and domains
_HTB_PATTERN = re.compile(r"(?:hackthebox|htb)\.", re.IGNORECASE)
_CTF_LEARN_PATTERN = re.compile(r"ctflearn", re.IGNORECASE)
_DVWA_PATTERN = re.compile(r"dvwa|damn.*vulnerable", re.IGNORECASE)
_WEBGOAT_PATTERN = re.compile(r"webgoat|webwolf", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"owasp", re.IGNORECASE)
_JUICE_SHOP_PATTERN = re.compile(r"juice.*shop|juiceshop", re.IGNORECASE)
_DAMN_VULNERABLE_PATTERN = re.compile(r"damn.?vulnerable|dvl", re.IGNORECASE)
_FLAG_IN_URL = re.compile(r"flag|ctf|challenge|vulnerable|exploit", re.IGNORECASE)

# IP patterns for local/lab environments
_HTB_IP_PATTERN = re.compile(r"^10\.10\.\d+\.\d+$")  # HackTheBox lab network
_LOCAL_IP_PATTERN = re.compile(r"^(127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)")
_DOCKER_IP_PATTERN = re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\.")

# Port hints
_COMMON_CTF_PORTS = {3000, 5000, 8000, 8080, 8443, 8888, 9000, 9999}
_DEVELOPMENT_PORTS = {3000, 5000, 8080, 8000}


def detect_ctf_context(url: str, technologies: list[str] | None = None) -> CTFContext:
    """
    Detect if the target is a CTF game or intentional vulnerability context.

    Args:
        url: Target URL
        technologies: List of detected technologies (e.g., ["django", "node.js"])

    Returns:
        CTFContext with detection results
    """
    if not url:
        return CTFContext(is_ctf=False)

    try:
        parsed = urlparse(url)
    except Exception:
        return CTFContext(is_ctf=False)

    domain = parsed.hostname or ""
    path = parsed.path.lower()
    port = parsed.port

    hints: list[str] = []
    scores: list[tuple[float, str]] = []

    # Check domain patterns
    if _HTB_PATTERN.search(domain):
        scores.append((0.95, "htb"))
        hints.append("hackthebox-domain")
    elif _CTF_LEARN_PATTERN.search(domain):
        scores.append((0.95, "ctflearn"))
        hints.append("ctflearn-domain")
    elif _DVWA_PATTERN.search(domain):
        scores.append((0.90, "dvwa"))
        hints.append("dvwa-pattern")
    elif _WEBGOAT_PATTERN.search(domain):
        scores.append((0.90, "webgoat"))
        hints.append("webgoat-pattern")
    elif _JUICE_SHOP_PATTERN.search(domain):
        scores.append((0.90, "juice-shop"))
        hints.append("juice-shop-pattern")

    # Check path patterns
    if _FLAG_IN_URL.search(path):
        scores.append((0.60, "flag-in-path"))
        hints.append("flag-keywords-in-path")

    if _OWASP_PATTERN.search(domain) or _OWASP_PATTERN.search(path):
        scores.append((0.75, "owasp"))
        hints.append("owasp-training-context")

    # Check IP patterns
    ip = parsed.hostname or ""
    if _HTB_IP_PATTERN.match(ip):
        scores.append((0.85, "htb-ip"))
        hints.append("htb-lab-ip-range")
    elif _LOCAL_IP_PATTERN.match(ip):
        scores.append((0.50, "local-ip"))
        hints.append("local-or-lab-environment")
    elif _DOCKER_IP_PATTERN.match(ip):
        scores.append((0.55, "docker-ip"))
        hints.append("docker-container-ip")

    # Check port hints
    if port and port in _COMMON_CTF_PORTS:
        if port in _DEVELOPMENT_PORTS:
            scores.append((0.40, "dev-port"))
            hints.append(f"development-port-{port}")
        else:
            scores.append((0.35, "ctf-port"))
            hints.append(f"common-ctf-port-{port}")

    # Check technologies for common CTF frameworks
    if technologies:
        tech_lower = [t.lower() for t in technologies]
        if any("django" in t for t in tech_lower):
            scores.append((0.20, "django-common-in-ctf"))
        if any("flask" in t for t in tech_lower):
            scores.append((0.20, "flask-common-in-ctf"))
        if any("node" in t for t in tech_lower):
            scores.append((0.15, "node-common-in-ctf"))

    # Calculate final confidence (max of scores, with diminishing returns for multiple hints)
    if not scores:
        return CTFContext(is_ctf=False, confidence=0.0)

    max_confidence = max(s[0] for s in scores)
    platform_name = next((s[1] for s in scores if s[0] > 0.70), None)

    # Add slight boost if multiple hints detected (but cap at 0.99)
    bonus = min(0.15 * (len(scores) - 1), 0.20)
    final_confidence = min(max_confidence + bonus, 0.99)

    return CTFContext(
        is_ctf=final_confidence >= 0.40,  # 40% confidence threshold for CTF detection
        platform=platform_name,
        confidence=final_confidence,
        hints=list(set(hints)),  # Deduplicate
    )


def get_ctf_planner_hint(ctx: CTFContext) -> str:
    """
    Generate a hint for the LLM planner when CTF context is detected.

    This is injected into the system prompt to help the planner focus on
    finding the vulnerability rather than being conservative.
    """
    if not ctx.is_ctf:
        return ""

    hint = (
        "NOTE: This target appears to be a CTF challenge or intentional "
        "vulnerability scenario (confidence: {:.0%}). ".format(ctx.confidence)
    )

    if ctx.platform:
        hint += f"Platform: {ctx.platform}. "

    hint += (
        "Assume vulnerabilities EXIST and focus on finding them efficiently. "
        "Do not be conservative — test aggressive payloads and unusual patterns. "
        "The target is designed to be vulnerable."
    )

    return hint


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "http://10.10.14.5:8080/dvwa/vulnerabilities/xss_r/",
        "https://hackthebox.com/challenges/web",
        "https://shop.post.ch/shop",
        "http://localhost:3000/challenge/flag",
        "http://192.168.1.100:5000/xss",
    ]

    for url in test_urls:
        ctx = detect_ctf_context(url, technologies=["Django", "Node.js"])
        print(f"\n{url}")
        print(f"  {ctx.summary()}")
        if ctx.is_ctf:
            print(f"  Planner hint: {get_ctf_planner_hint(ctx)}")

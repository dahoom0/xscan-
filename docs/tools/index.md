# Tool Management

XScan manages external security tools installed into `~/.xscan/bin/`.

---

## Commands

```bash
xscan tools list              # List all tools and status
xscan tools install katana    # Install a tool
xscan tools install katana httpx dnsx   # Install multiple
xscan tools check katana      # Health-check a tool
xscan tools check --all       # Health-check all tools
xscan tools inspect katana    # Full details for a tool
xscan tools update            # Update all tools
xscan tools update katana     # Update a specific tool
xscan tools remove katana     # Remove a tool
```

---

## Inspect output

```
Tool: katana

Capability:
  web_crawler

Status:
  installed ✓

Version:
  1.1.0

Binary:
  ~/.xscan/bin/katana

Used by:
  crawl
  xss-deep
  full-audit

Health:
  ✓

Install:
  xscan tools install katana

Documentation:
  xscan help crawler
```

---

## Core tool catalogue

| Tool          | Capability           | Install command                    |
|---------------|----------------------|------------------------------------|
| `katana`      | web_crawler          | `xscan tools install katana`       |
| `httpx`       | http_probe           | `xscan tools install httpx`        |
| `dnsx`        | dns_resolution       | `xscan tools install dnsx`         |
| `amass`       | subdomain_enum       | `xscan tools install amass`        |
| `subfinder`   | subdomain_enum       | `xscan tools install subfinder`    |
| `nuclei`      | vuln_scan            | `xscan tools install nuclei`       |
| `ffuf`        | fuzzing              | `xscan tools install ffuf`         |
| `waybackurls` | url_discovery        | `xscan tools install waybackurls`  |
| `dalfox`      | xss_scan             | `xscan tools install dalfox`       |
| `playwright`  | browser              | `pip install playwright && playwright install` |

---

## Environment-aware listing

`xscan tools list` shows live status:

```
Installed:
  katana      ✓  v1.1.0
  httpx       ✓  v0.21.0
  dnsx        ✓  v1.2.0

Available but not installed:
  amass
  subfinder
  nuclei
```

---

## Related topics

- `xscan help doctor`
- `xscan help commands/install`
- `xscan help getting-started`

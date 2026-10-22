"""Hard-coded default values — never user-configurable paths."""
from pathlib import Path

XSCAN_HOME = Path.home() / ".xscan"
DB_PATH = XSCAN_HOME / "xscan.db"
LOG_DIR = XSCAN_HOME / "logs"
SESSION_DIR = XSCAN_HOME / "sessions"
SKILLS_DIR = XSCAN_HOME / "skills"
RESEARCH_CACHE_DIR = XSCAN_HOME / "research-cache"
CONFIG_FILE = XSCAN_HOME / "config.toml"

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_LLM_MODEL = "qwen3:14b"
DEFAULT_PROFILE = "balanced"
DEFAULT_HTTP_TIMEOUT = 15
DEFAULT_LLM_TIMEOUT = 120
MAX_CRAWL_PAGES_FAST = 20
MAX_CRAWL_PAGES_BALANCED = 60
MAX_CRAWL_PAGES_DEEP = 150

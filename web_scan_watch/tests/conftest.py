import sys
from pathlib import Path

# `src/` is a package under web_scan_watch/, and the entry point
# scan_watcher.py also lives in web_scan_watch/. Putting web_scan_watch/ on
# sys.path lets tests use `from src import config` / `from src.config import ...`
# and `import scan_watcher`.
PKG_DIR = Path(__file__).resolve().parent.parent  # web_scan_watch/
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

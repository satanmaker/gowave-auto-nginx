#!/usr/bin/env python3
"""Launch the interactive local Live VPS E2E controller."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.operator import main

if __name__ == "__main__":
    raise SystemExit(main())

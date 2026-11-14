"""Geriye dönük uyumluluk: `python osint_tool.py` eskisi gibi menüyü açar."""

import sys

from pwrosint.cli import main

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Executable entry point - see pka/cli.py and README.md."""

import sys

if __name__ == "__main__":
    try:
        from pka.cli import main
    except ImportError as e:
        print(f"error: {e}\n"
              "set up the project venv:  python3.11 -m venv .venv && "
              ".venv/bin/pip install -r requirements.txt",
              file=sys.stderr)
        sys.exit(1)
    sys.exit(main())

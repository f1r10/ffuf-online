#!/usr/bin/env python3
"""DEMO STAND-IN for `kiterunner` (``kr``) — NOT the real tool.

Prints a valid but empty JSON array of discovered API routes.
Performs no network activity.
"""

import sys


def main() -> int:
    print("[]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""DEMO STAND-IN for `gau` — NOT the real tool.

Prints representative historical URLs (one per line). Performs no network
activity.
"""

import sys

DEMO = [
    "https://api.example.com/api/v2/users?id=1",
    "https://api.example.com/api/v2/orders",
]


def main() -> int:
    for line in DEMO:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""DEMO STAND-IN for `ffuf` — NOT the real tool.

Prints a valid but empty ``ffuf -of json`` report (no discovered paths).
Performs no network activity.
"""

import sys

DEMO = '{"commandline":"ffuf -u https://api.example.com/FUZZ -w /wordlists/default.txt","results":[]}'


def main() -> int:
    print(DEMO)
    return 0


if __name__ == "__main__":
    sys.exit(main())

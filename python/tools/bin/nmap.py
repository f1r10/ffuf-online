#!/usr/bin/env python3
"""DEMO STAND-IN for `nmap` — NOT the real tool.

Prints a valid but empty Nmap XML document (no open ports).
Performs no network activity.
"""

import sys

DEMO = '<?xml version="1.0" encoding="UTF-8"?>\n<nmaprun scanner="nmap" args="nmap -oX - -Pn api.example.com"></nmaprun>'


def main() -> int:
    print(DEMO)
    return 0


if __name__ == "__main__":
    sys.exit(main())

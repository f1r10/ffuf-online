#!/usr/bin/env python3
"""DEMO STAND-IN for `feroxbuster` — NOT the real tool.

Prints a valid but empty ``feroxbuster --json`` stream (a single statistics
record, no responses). Performs no network activity.
"""

import sys

DEMO = '{"type":"statistics","url":"https://api.example.com","responses":0}'


def main() -> int:
    print(DEMO)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""DEMO STAND-IN for `dnsx` — NOT the real tool.

Prints representative ``dnsx -json`` output for the fixed demo host
``api.example.com``. Performs no network activity.
"""

import sys

DEMO = [
    '{"host":"api.example.com","a":["93.184.216.34"],"aaaa":[],"cname":[],"status_code":"NOERROR"}',
    '{"host":"www.example.com","a":["93.184.216.34"],"aaaa":[],"cname":[],"status_code":"NOERROR"}',
]


def main() -> int:
    for line in DEMO:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

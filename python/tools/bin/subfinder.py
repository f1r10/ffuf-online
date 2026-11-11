#!/usr/bin/env python3
"""DEMO STAND-IN for `subfinder` — NOT the real tool.

This script exists only so the end-to-end pipeline can run when
``TOOL_RUNNER=local`` and the real ProjectDiscovery binaries are not installed.
It accepts the same argv as the real tool and prints representative
subfinder ``-json`` output for a fixed demo target (``example.com``).
It performs **no** network activity.
"""

import sys

DEMO = [
    {"host": "api.example.com", "input": "example.com", "source": "crtsh"},
    {"host": "www.example.com", "input": "example.com", "source": "crtsh"},
]


def main() -> int:
    for record in DEMO:
        print('{"host": "%s", "input": "%s", "source": "%s"}' % (record["host"], record["input"], record["source"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

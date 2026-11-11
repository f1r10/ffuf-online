#!/usr/bin/env python3
"""DEMO STAND-IN for `katana` — NOT the real tool.

Prints representative ``katana -json`` output, including the API endpoint
``https://api.example.com/api/v2/users`` and a JavaScript file. Performs no
network activity.
"""

import sys

DEMO = [
    '{"timestamp":"2026-11-11T10:00:00Z","url":"https://api.example.com/api/v2/users","method":"GET","tag":"a","source":"https://api.example.com/","attribute":"href","status_code":200}',
    '{"timestamp":"2026-11-11T10:00:01Z","url":"https://api.example.com/static/app.js","method":"GET","tag":"script","source":"https://api.example.com/","attribute":"src","status_code":200}',
]


def main() -> int:
    for line in DEMO:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

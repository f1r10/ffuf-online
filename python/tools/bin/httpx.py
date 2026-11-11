#!/usr/bin/env python3
"""DEMO STAND-IN for `httpx` — NOT the real tool.

Prints representative ``httpx -json`` output: the live HTTP service
``https://api.example.com``. Performs no network activity.
"""

import sys

DEMO = [
    {"url": "https://api.example.com", "input": "api.example.com", "host": "api.example.com",
     "port": 443, "status_code": 200, "title": "Example API",
     "tech": ["nginx", "Express"], "webserver": "nginx", "content_length": 1234, "failed": False},
]


def main() -> int:
    for r in DEMO:
        print(
            '{"url":"%s","input":"%s","host":"%s","port":%d,"status_code":%d,'
            '"title":"%s","tech":["nginx","Express"],"webserver":"%s",'
            '"content_length":%d,"failed":false}'
            % (r["url"], r["input"], r["host"], r["port"], r["status_code"], r["title"], r["webserver"], r["content_length"])
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

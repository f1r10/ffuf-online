#!/usr/bin/env python3
"""DEMO STAND-IN for `nuclei` — NOT the real tool.

Prints one representative ``nuclei -jsonl`` candidate finding on the demo API
endpoint. A template match is a *candidate*, never a confirmed vulnerability.
Performs no network activity.
"""

import sys

DEMO = (
    '{"template-id":"exposed-api-swagger","info":{"name":"Exposed API Swagger UI",'
    '"severity":"low","tags":["exposure","api"]},"type":"http","host":"api.example.com",'
    '"matched-at":"https://api.example.com/api/v2/users?id=1","ip":"93.184.216.34",'
    '"timestamp":"2026-11-11T10:00:02Z"}'
)


def main() -> int:
    print(DEMO)
    return 0


if __name__ == "__main__":
    sys.exit(main())

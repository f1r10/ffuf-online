#!/usr/bin/env python3
"""DEMO STAND-IN for `arjun` — NOT the real tool.

Prints representative ``arjun -j`` output containing the discovered
``user_id`` parameter on the demo API endpoint. Performs no network activity.
"""

import sys

DEMO = '{"https://api.example.com/api/v2/users": {"GET": {"params": ["user_id"], "status": 200}}}'


def main() -> int:
    print(DEMO)
    return 0


if __name__ == "__main__":
    sys.exit(main())

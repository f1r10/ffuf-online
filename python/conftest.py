"""Make ``python/`` importable when pytest is invoked from this directory.

The packages ``ffuf_intel`` and ``adapters`` live directly under ``python/`` so
that ``python -m pytest -q`` (run from ``python/``) resolves them without an
install step.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

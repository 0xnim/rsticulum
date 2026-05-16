"""pytest configuration for RNS test suite."""

import sys
from pathlib import Path

# Add the test suite directory to sys.path so 'from lib...' works
_suite_dir = Path(__file__).parent
if str(_suite_dir) not in sys.path:
    sys.path.insert(0, str(_suite_dir))

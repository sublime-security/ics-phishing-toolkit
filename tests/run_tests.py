#!/usr/bin/env python3
"""Test runner that configures the Python path and runs all tests."""

import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).parent.parent
src_dir = repo_root / "src"
sys.path.insert(0, str(src_dir))

if __name__ == "__main__":
    loader = unittest.TestLoader()

    start_dir = "."
    tests = loader.discover(start_dir)

    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(tests)

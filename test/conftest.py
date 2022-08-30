import os
import sys

import pytest

# pytest configure
PARENT_PATH = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
SOURCE_PATH = PARENT_PATH.rsplit("/", 1)[0]
print(f"test_target_path:= {SOURCE_PATH}")
sys.path.append(f"{SOURCE_PATH}")

# move to test directory
os.chdir("./purus")

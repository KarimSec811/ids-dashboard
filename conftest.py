import json, os
from pathlib import Path

def pytest_configure(config):
    os.environ.setdefault("IDS_DISABLE_RDNS", "1")
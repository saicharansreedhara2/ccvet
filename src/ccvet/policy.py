"""Loads the shipped default policy (simple program-name lists). User
override loading (project/global policy.yaml layered on top) is Phase 3 —
this module is deliberately just the shipped defaults for now.
"""

from pathlib import Path

import yaml

_DEFAULT_PATH = Path(__file__).parent / "data" / "default_policy.yaml"


def load_default() -> dict:
    with open(_DEFAULT_PATH) as f:
        return yaml.safe_load(f)

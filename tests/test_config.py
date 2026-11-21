"""config.json must stay lint-clean; the linter must keep catching the original config's defects."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT))

from lint_config import lint  # noqa: E402


def test_shipped_config_is_clean():
    errors, warns = lint(json.loads((ROOT / "config.json").read_text()))
    assert errors == [] and warns == []


def test_the_original_config_defects_are_still_detected():
    errors, warns = lint(json.loads((ROOT / "eval" / "config.original.json").read_text()))
    text = " ".join(errors)
    assert "ipsweep" in text and "can never fire" in text          # contradictory zero_fields vs range
    assert "T1499.004" in text                                     # id/name mismatch
    assert any("RFC 6298" in w for w in warns)                     # 0.5 s grace below the SYN retransmit timer

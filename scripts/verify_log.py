"""Verify the retained hash chain for one structured JSON Lines log."""

import argparse
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from simulation.logging.jsonl import verify_log


def main() -> int:
    """Return a process status suitable for automation and CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "log", type=Path, help="base log path, e.g. logs/attack_log.jsonl"
    )
    args = parser.parse_args()
    result = verify_log(args.log)
    print(
        f"{'VALID' if result.valid else 'INVALID'}: {result.message} ({result.entries} entries)"
    )
    if result.line is not None:
        print(f"Failure at retained entry {result.line}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

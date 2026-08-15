#!/usr/bin/env python3
"""Shared stdin/JSON entry point for Palo Alto Networks actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.panos_client import PanosPackError, execute_action


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise PanosPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        json.dump(execute_action(operation, params), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("paloalto action failed: invalid JSON action parameters", file=sys.stderr)
    except PanosPackError as exc:
        print(f"paloalto action failed: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        # Unknown exceptions can contain request data, credentials, or XML bodies.
        print(f"paloalto action failed: {type(exc).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

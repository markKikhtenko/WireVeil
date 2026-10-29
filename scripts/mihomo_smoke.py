#!/usr/bin/env python3
"""Manual offline-friendly smoke test for the real bundled Mihomo runtime.

The dummy endpoints are intentionally unreachable.  Success means that Mihomo
validated the generated YAML, exposed its authenticated local API, performed
real HTTPS attempts, classified the failures, and stopped cleanly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import mihomo_checker


def _yaml(proxy: dict[str, object]) -> str:
    return yaml.safe_dump({"proxies": [proxy]}, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    duplicate = {
        "name": "duplicate-a",
        "type": "ss",
        "server": "127.0.0.1",
        "port": 9,
        "cipher": "aes-128-gcm",
        "password": "local-smoke-only",
    }
    variant = dict(duplicate, name="variant", port=10)
    sources = (
        mihomo_checker.SourceSpec("src-smoke-a", "Smoke A", "text", _yaml(duplicate)),
        mihomo_checker.SourceSpec("src-smoke-broken", "Broken", "text", "proxies: [broken"),
        mihomo_checker.SourceSpec("src-smoke-b", "Smoke B", "text", _yaml(dict(duplicate, name="duplicate-b"))),
        mihomo_checker.SourceSpec("src-smoke-variant", "Smoke variant", "text", _yaml(variant)),
    )
    report = mihomo_checker.BatchRunner().run(
        binary=args.binary,
        source_specs=sources,
        selected_services=("ChatGPT",),
        attempts=2,
        timeout_ms=1_000,
        workers=2,
    )
    payload = mihomo_checker.report_payload(report)
    print(json.dumps(payload["totals"], ensure_ascii=False, sort_keys=True))
    print(f"engine={payload['engine']['version']}")
    print(f"broken_source={payload['sources'][1]['error_code']}")
    duplicate_result = next(item for item in payload["nodes"] if len(item["source_ids"]) == 2)
    print(f"deduplicated_sources={len(duplicate_result['source_ids'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

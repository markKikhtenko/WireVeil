#!/usr/bin/env python3
"""Offline scalability benchmark for the Mihomo parser, sampler and Tk table.

No subscription is downloaded and all proxy credentials are synthetic.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from unittest import mock

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import mihomo_checker


def synthetic_yaml(count: int) -> str:
    proxies = [
        {
            "name": f"Synthetic {index}",
            "type": "vless",
            "server": f"n{index}.example.test",
            "port": 443,
            "uuid": f"00000000-0000-4000-8000-{index:012d}",
        }
        for index in range(count)
    ]
    return yaml.safe_dump({"proxies": proxies}, sort_keys=False)


def backend_benchmark(count: int) -> tuple[dict[str, object], list[mihomo_checker.NodeResult]]:
    spec = mihomo_checker.SourceSpec("src-000000000000", "Synthetic", "text", "")
    payload = synthetic_yaml(count)
    tracemalloc.start()
    started = time.perf_counter()
    parsed = mihomo_checker.parse_source_text(spec, payload)
    nodes = mihomo_checker.merge_nodes([parsed])
    selected, sampling = mihomo_checker.representative_sample(
        nodes, limit=min(500, count), seed="benchmark"
    )
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if len(nodes) != count:
        raise RuntimeError(f"expected {count} nodes, parsed {len(nodes)} ({parsed.error_code})")
    results = [
        mihomo_checker.NodeResult(
            node,
            overall_status="not_tested",
            error_code="SAMPLE_LIMIT",
            error_category="not_tested",
        )
        for node in nodes
    ]
    return (
        {
            "nodes": count,
            "yaml_bytes": len(payload.encode("utf-8")),
            "parse_dedup_sample_seconds": round(elapsed, 4),
            "peak_memory_mib": round(peak / (1024 * 1024), 2),
            "sampled": sampling["selected_nodes"],
        },
        results,
    )


def ui_benchmark(results: list[mihomo_checker.NodeResult]) -> dict[str, object]:
    import tkinter as tk

    from mihomo_tab import MihomoCheckerTab

    root = tk.Tk()
    root.withdraw()
    with (
        mock.patch("mihomo_tab.mihomo_checker.load_source_specs", return_value=[]),
        mock.patch.object(MihomoCheckerTab, "_save_ui_settings"),
    ):
        tab = MihomoCheckerTab(root)
        tab.sources = [
            mihomo_checker.SourceSpec("src-000000000000", "Synthetic", "text", "")
        ]
        started = time.perf_counter()
        for position in range(0, len(results), 200):
            tab._update_node_rows(results[position : position + 200])
            root.update_idletasks()
        elapsed = time.perf_counter() - started
        row_count = len(tab.node_tree.get_children(""))
        tab.close()
    root.destroy()
    return {
        "tree_rows": row_count,
        "tree_batch_update_seconds": round(elapsed, 4),
        "batch_size": 200,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("counts", nargs="*", type=int, default=[5_000, 10_000, 20_000])
    parser.add_argument("--ui", action="store_true", help="also populate a real Tk Treeview")
    args = parser.parse_args()
    measurements = []
    for count in args.counts:
        backend, results = backend_benchmark(count)
        if args.ui:
            backend["ui"] = ui_benchmark(results)
        measurements.append(backend)
    print(json.dumps(measurements, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

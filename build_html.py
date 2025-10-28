#!/usr/bin/env python3
"""Interactive generator for the CyberNewsFeed HTML dashboard."""
from __future__ import annotations

import json
from pathlib import Path

from cybernewsfeed.config import ensure_config, prompt_runtime_path
from cybernewsfeed.html_builder import build_html


def main() -> None:
    print("CyberNewsFeed HTML builder")
    print("==========================\n")
    config = ensure_config()

    default_json = config.get("json_output") or "cybersec_news.json"
    default_html = config.get("html_output") or "index.html"
    default_template = config.get("template_path") or ""
    default_assets = config.get("assets_dir") or ""

    json_path = prompt_runtime_path(
        "Which JSON feed should be rendered?",
        default=default_json,
    )
    if json_path is None or not json_path.exists():
        if json_path is None:
            json_path = Path(default_json)
        if not json_path.exists():
            raise SystemExit(f"JSON file not found: {json_path}")

    output_path = prompt_runtime_path(
        "Where should the HTML dashboard be written?",
        default=default_html,
    )
    if output_path is None:
        output_path = Path(default_html)

    template_path = prompt_runtime_path(
        "Template override (press Enter to use the default template)",
        default=default_template or None,
        allow_empty=True,
    )
    assets_dir = prompt_runtime_path(
        "Assets directory override (press Enter to use bundled assets)",
        default=default_assets or None,
        allow_empty=True,
    )

    with json_path.open("r", encoding="utf-8") as handle:
        articles = json.load(handle)

    build_html(
        articles,
        output_path,
        template_path=template_path,
        assets_dir=assets_dir,
    )


if __name__ == "__main__":
    main()

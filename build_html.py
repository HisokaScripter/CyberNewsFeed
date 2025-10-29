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

    default_json = Path(config.get("json_output") or "cybersec_news.json")
    default_html = Path(config.get("html_output") or "index.html")

    default_json_dir = default_json.parent if default_json.parent != Path("") else Path.cwd()
    default_html_dir = default_html.parent if default_html.parent != Path("") else Path.cwd()
    json_filename = default_json.name or "cybersec_news.json"
    html_filename = default_html.name or "index.html"

    json_input = prompt_runtime_path(
        "Directory containing the JSON feed (or provide the JSON file path directly)",
        default=default_json_dir,
    )

    if json_input.is_file():
        json_path = json_input
    else:
        json_path = json_input / json_filename

    if not json_path.exists():
        fallback = json_input if json_input.is_file() else json_input / json_filename
        raise SystemExit(f"JSON file not found: {fallback}")

    output_input = prompt_runtime_path(
        "Directory where the HTML dashboard should be written (or provide the HTML file path)",
        default=default_html_dir,
    )

    if output_input.is_file() or output_input.suffix.lower() == ".html":
        output_path = output_input
    else:
        output_path = output_input / html_filename

    with json_path.open("r", encoding="utf-8") as handle:
        articles = json.load(handle)

    build_html(articles, output_path)


if __name__ == "__main__":
    main()

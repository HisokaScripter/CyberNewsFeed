#!/usr/bin/env python3
"""Generate the HTML dashboard from a JSON article feed."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cybernewsfeed.html_builder import build_html


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Cyber News Feed HTML from an article JSON file.")
    parser.add_argument(
        "json_path",
        type=Path,
        help="Path to the JSON file produced by fetch_articles.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Destination for the generated HTML file. Defaults to index.html in the project root.",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=None,
        help="Optional custom HTML template path to override the default.",
    )
    parser.add_argument(
        "--assets",
        type=Path,
        default=None,
        help="Optional directory containing styles.css and app.js assets.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.json_path.exists():
        raise SystemExit(f"JSON file not found: {args.json_path}")
    with args.json_path.open("r", encoding="utf-8") as handle:
        articles = json.load(handle)
    output = args.output or Path("index.html")
    build_html(articles, output, template_path=args.template, assets_dir=args.assets)


if __name__ == "__main__":
    main()

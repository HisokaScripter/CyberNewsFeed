#!/usr/bin/env python3
"""Command line entry point for scraping and exporting Cyber News articles."""
from __future__ import annotations

import argparse
from pathlib import Path

from cybernewsfeed.scraper import CyberSecScraper


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scrape cybersecurity news feeds and export structured JSON.")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for the JSON export. Defaults to cybersec_news.json in the project root.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional CSV export path. When omitted no CSV file is written.",
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a concise summary of the scraped articles once completed.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scraper = CyberSecScraper(
        auto_generate_html=False,
        data_file=args.output,
    )
    scraper.scrape_all()
    scraper.save_to_json(args.output)
    if args.csv:
        scraper.save_to_csv(args.csv)
    if args.print_summary:
        scraper.print_summary()


if __name__ == "__main__":
    main()

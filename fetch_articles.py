#!/usr/bin/env python3
"""Interactive entry point for scraping and exporting Cyber News articles."""
from __future__ import annotations

from pathlib import Path

from cybernewsfeed.config import ensure_config, prompt_runtime_path, prompt_runtime_yes_no
from cybernewsfeed.scraper import CyberSecScraper


def main() -> None:
    print("CyberNewsFeed scraper")
    print("======================\n")
    config = ensure_config()

    default_json = config.get("json_output") or "cybersec_news.json"
    default_csv = config.get("csv_output") or ""
    default_summary = bool(config.get("print_summary", False))

    json_path = prompt_runtime_path(
        "Where should the JSON export be saved?",
        default=default_json,
    )
    if json_path is None:
        json_path = Path(default_json)
    csv_path = prompt_runtime_path(
        "Optional CSV export path (press Enter to skip)",
        default=default_csv or None,
        allow_empty=True,
    )
    print_summary = prompt_runtime_yes_no(
        "Print a concise summary of the scraped articles?",
        default=default_summary,
    )

    scraper = CyberSecScraper(
        auto_generate_html=False,
        data_file=json_path,
    )
    scraper.scrape_all()
    scraper.save_to_json(json_path)
    if csv_path:
        scraper.save_to_csv(csv_path)
    if print_summary:
        scraper.print_summary()

    print("\nScraping complete.")


if __name__ == "__main__":
    main()
 

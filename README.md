# CyberNewsFeed

CyberNewsFeed is a Python toolkit for collecting, enriching, and presenting the latest cybersecurity news. It scrapes a large catalog of industry RSS feeds, optionally augments the stories with AI-generated summaries and indicators, and renders a searchable single-page dashboard that can be hosted anywhere.

## Features

- **Wide feed coverage** – ships with dozens of curated threat intelligence, vendor, and government RSS feeds, plus support for loading additional dark web sources.
- **Content normalization** – deduplicates articles, extracts metadata, and converts HTML into markdown/plain text for downstream processing.
- **AI enrichment (optional)** – integrates with [LM Studio](https://lmstudio.ai/) models to summarize articles and surface CVEs, IOCs, TTPs, and threat actor mentions.
- **Automated dashboard** – turns the scraped dataset into an interactive static site (`index.html`) with filtering, search, and enrichment statistics.
- **Flexible exports** – write results to JSON (default) and CSV, then regenerate the dashboard at any time.

## Requirements

- Python 3.10+
- `requests`, `feedparser`, `beautifulsoup4`, `markdownify`
- Optional: `cloudscraper` (for sites behind Cloudflare), `lmstudio` (for local LLM summaries)

Install the dependencies in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install requests feedparser beautifulsoup4 markdownify cloudscraper lmstudio
```

If you do not need Cloudflare bypassing or AI enrichment you can omit the optional packages.

## Repository layout

```
cybernewsfeed/        Core package with the scraper and HTML builder utilities
  assets/             JavaScript and CSS bundled into the generated dashboard
  templates/          Jinja-style HTML template used during rendering
build_html.py         CLI for turning a JSON export into index.html
fetch_articles.py     CLI entry point for scraping and exporting feeds
index.html            Example output produced by `build_html.py`
```

## Usage

### 1. Scrape the feeds

Run the scraper to collect the latest articles. By default it writes `cybersec_news.json` in the project root and updates `index.html` every few articles when `auto_generate_html` is enabled.

```bash
python fetch_articles.py --print-summary
```

Optional flags:

- `--output PATH` – custom JSON destination
- `--csv PATH` – also export a CSV copy
- `--print-summary` – log a feed summary to stdout

The scraper stores fingerprints of processed articles in `ParsedArticles.txt` to avoid duplicates between runs. If you want to rebuild from scratch, delete that file first.

### 2. Render (or re-render) the dashboard

You can rebuild the static dashboard at any time from a JSON export:

```bash
python build_html.py cybersec_news.json --output index.html
```

Additional options:

- `--template PATH` – provide a custom HTML template
- `--assets DIR` – point to a directory containing `styles.css` and `app.js`

The generated `index.html` is fully static, so you can open it locally in a browser or host it on any static site provider.

## Optional configuration

- **TOR routing:** set the `TOR_PROXY` environment variable (defaults to `socks5h://127.0.0.1:9050`) if you want the dark web feeds to go through a different proxy.
- **LM Studio model:** adjust `CyberSecScraper.aiModel` in `cybernewsfeed/scraper.py` to match a locally available model. When the `lmstudio` package is not installed, AI enrichment is skipped automatically.
- **Feed customization:** extend the `Feeds` or `DarkWebFeeds` dictionaries in `cybernewsfeed/scraper.py` to add or remove sources.

## Development tips

- The HTML builder omits raw article bodies from the output for privacy; only metadata and summaries are embedded in the dashboard cards.
- Static assets live in `cybernewsfeed/assets/`. Update `styles.css` and `app.js` to tweak the UI, then rerun `build_html.py`.
- Use `python -m cybernewsfeed.scraper` in a REPL or notebook to experiment with individual helper methods if desired.

## License

This project currently does not declare a license. Please verify usage terms before redistribution.


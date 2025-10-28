# CyberNewsFeed

CyberNewsFeed is a Python-powered news harvester that keeps you up to date on cybersecurity stories. Think of it as a scriptable "threat intel newspaper": it reads dozens of curated RSS feeds, keeps only the newest articles, optionally summarizes them with a local AI model, and turns the results into a shareable HTML dashboard.

## Overview for first-time readers

1. **Collect articles** – `fetch_articles.py` downloads the latest headlines and metadata from security blogs, vendors, CERT advisories, and (optionally) dark web sources.
2. **Enrich the content** – when LM Studio is available, the scraper summarizes each story and extracts useful entities (CVEs, IOCs, threat actors). If the AI tooling is missing, the scripts fall back to raw metadata without failing.
3. **Publish the feed** – the gathered dataset is saved to JSON/CSV and can be rendered into a static, searchable `index.html` dashboard with `build_html.py`.

Because everything is static, you can host the generated dashboard on any static site provider or open it locally without additional services.

## Quick example

Below is a minimal end-to-end run that you can reproduce immediately after cloning the repo. It collects articles, saves them to the default `cybersec_news.json`, and rebuilds the dashboard:

```bash
python fetch_articles.py --print-summary
python build_html.py cybersec_news.json --output index.html
```

After the commands finish, you will have:

- `cybersec_news.json` – machine-readable article data saved (and reused) by the scraper.
- `index.html` – an interactive dashboard you can open in a browser.
- `cybersec_news.parsed.txt` (or the legacy `ParsedArticles.txt`) – a cache of article fingerprints that prevents duplicates on subsequent runs (delete it to rescan everything).

A shortened snippet from the JSON file looks like this:

```json
{
  "title": "CISA warns of new critical Fortinet vulnerability",
  "link": "https://example.com/cisa-fortinet-alert",
  "published": "2024-04-16T14:32:00Z",
  "source": "CISA Alerts",
  "summary": "CISA urges Fortinet customers to patch CVE-2024-12345 because ...",
  "indicators": ["CVE-2024-12345"],
  "threat_actors": ["Unknown"],
  "tags": ["Fortinet", "Patch"]
}
```

> **Tip:** if you do not see the optional `summary`, `indicators`, or `threat_actors` keys, install LM Studio and re-run the scraper to enable AI enrichment.

## Resuming and incremental updates

Running `python fetch_articles.py` multiple times will continue building on the existing dataset:

- The scraper loads `cybersec_news.json` (or the file provided via `--output`) at startup and keeps previously saved articles.
- Newly discovered items are appended, while duplicates are skipped using the `.parsed.txt` cache file.
- You can pause and resume long scraping sessions—the JSON file and cache are persisted after every successful article.

If you want to maintain separate feeds, supply a different output path:

```bash
python fetch_articles.py --output data/darkweb.json
python build_html.py data/darkweb.json --output darkweb.html
```

Each custom JSON file gets its own companion cache (for example `data/darkweb.parsed.txt`), so rerunning the scraper with the same `--output` path resumes exactly where it left off.

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

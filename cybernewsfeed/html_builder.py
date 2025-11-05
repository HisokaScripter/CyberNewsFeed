"""HTML rendering utilities for the Cyber News Feed project."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from string import Template
from typing import Mapping, Sequence


def _normalise_cve_records(value: object) -> list[dict[str, str]]:
    """Coerce a raw CVE collection into labelled records."""

    records: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_record(label: str, url: str | None = None) -> None:
        clean_label = str(label).strip()
        if not clean_label:
            return

        clean_url = None
        if isinstance(url, str):
            stripped = url.strip()
            if stripped:
                clean_url = stripped

        marker = (clean_label.lower(), (clean_url or "").lower())
        if marker in seen:
            return

        record: dict[str, str] = {"label": clean_label}
        if clean_url:
            record["url"] = clean_url
        records.append(record)
        seen.add(marker)

    def handle(entry: object) -> None:
        if entry is None:
            return

        if isinstance(entry, str):
            for part in re.split(r"[,;\n]+", entry):
                add_record(part)
            return

        if isinstance(entry, Mapping):
            label: str | None = None
            for key in ("cve", "CVE", "id", "name", "label", "value", "title", "text"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    label = value
                    break
            if not label:
                for candidate in entry.values():
                    if isinstance(candidate, str) and candidate.strip().upper().startswith("CVE-"):
                        label = candidate
                        break

            url: str | None = None
            for key in ("url", "link", "href"):
                candidate = entry.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    url = candidate
                    break

            if label:
                add_record(label, url)
            else:
                description = entry.get("description") or entry.get("summary")
                if isinstance(description, str) and description.strip():
                    add_record(description, url)
                else:
                    add_record(json.dumps(entry, ensure_ascii=False, sort_keys=True))

            for nested_key in ("items", "values", "entries"):
                if nested_key in entry:
                    handle(entry[nested_key])
            return

        if isinstance(entry, (list, tuple, set)):
            for item in entry:
                handle(item)
            return

        add_record(entry)

    handle(value)
    return records


def _copy_assets(output_dir: Path, assets_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for asset_name in ("styles.css", "app.js"):
        source = assets_dir / asset_name
        if not source.exists():
            raise FileNotFoundError(f"Missing asset: {source}")
        shutil.copyfile(source, output_dir / asset_name)


def build_html(
    articles: Sequence[Mapping[str, object]],
    output_path,
    *,
    template_path: Path | None = None,
    assets_dir: Path | None = None,
) -> Path:
    """Render the interactive HTML dashboard from parsed article data."""

    base_dir = Path(__file__).resolve().parent
    template_path = Path(template_path) if template_path else base_dir / "templates" / "index.html"
    assets_dir = Path(assets_dir) if assets_dir else base_dir / "assets"

    output_path = Path(output_path)
    output_dir = output_path.parent

    sanitized_articles = []
    for article in articles:
        if not isinstance(article, Mapping):
            continue

        sanitized = dict(article)
        cve_records = _normalise_cve_records(article.get("CVEs"))
        sanitized["cve_items"] = cve_records
        cve_labels = [record["label"] for record in cve_records]
        sanitized["CVEs"] = cve_labels
        if not sanitized.get("cves"):
            sanitized["cves"] = cve_labels

        sanitized_articles.append(sanitized)

    articles_json = json.dumps(sanitized_articles, ensure_ascii=False)
    articles_json = articles_json.replace('</', '<' + '\\' + '/')

    template = Template(template_path.read_text(encoding="utf-8"))

    _copy_assets(output_dir, assets_dir)

    html = template.substitute(articles_json=articles_json)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    print(f"✓ Saved HTML to {output_path}")
    return output_path

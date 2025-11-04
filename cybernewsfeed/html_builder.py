"""HTML rendering utilities for the Cyber News Feed project."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from string import Template
from typing import Mapping, Sequence


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
        if isinstance(article, Mapping):
            sanitized_articles.append(dict(article))

    articles_json = json.dumps(sanitized_articles, ensure_ascii=False)
    articles_json = articles_json.replace('</', '<' + '\\' + '/')

    template = Template(template_path.read_text(encoding="utf-8"))

    _copy_assets(output_dir, assets_dir)

    html = template.substitute(articles_json=articles_json)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    print(f"✓ Saved HTML to {output_path}")
    return output_path

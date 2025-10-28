import argparse
import json
from pathlib import Path

from dashboard_builder import DEFAULT_CATEGORY_PRIORITY, build_html_context, render_index_html


def load_articles(json_path: Path) -> list:
    if not json_path.exists():
        print(f"Warning: data file {json_path} not found; generating an empty dashboard.")
        return []
    try:
        with json_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Unable to parse {json_path}: {exc}")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Render index.html from a saved JSON payload")
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        default=base_dir / "cybersec_news.json",
        help="Path to the JSON data produced by the scraper (default: ./cybersec_news.json)",
    )
    parser.add_argument(
        "--template",
        dest="template_path",
        type=Path,
        default=base_dir / "templates" / "index_template.html",
        help="HTML template path (default: ./templates/index_template.html)",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        type=Path,
        default=base_dir / "index.html",
        help="Output HTML path (default: ./index.html)",
    )

    args = parser.parse_args()

    articles = load_articles(args.json_path)
    context = build_html_context(articles, DEFAULT_CATEGORY_PRIORITY)
    html = render_index_html(context, args.template_path)

    args.output_path.parent.mkdir(parents=True, exist_ok=True)
    args.output_path.write_text(html, encoding="utf-8")
    print(f"✓ Wrote dashboard to {args.output_path}")


if __name__ == "__main__":
    main()

import json
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from html import escape
from pathlib import Path
from typing import Iterable, List

DEFAULT_CATEGORY_PRIORITY = [
    "Zero Day",
    "Active Exploitation",
    "Vulnerabilities",
    "Ransomware",
    "APT Activity",
    "General",
]


def _raw_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _ensure_list(value) -> List:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(',') if part.strip()]
        return parts
    return [value]


def _slugify(value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return "general"
    slug = "".join(ch if ch.isalnum() else "-" for ch in value)
    slug = "-".join(part for part in slug.split("-") if part)
    return slug or "general"


def _attr(value) -> str:
    if value is None:
        return ""
    return escape(str(value), quote=True)


def sanitize_articles(articles: Iterable[dict]) -> List[dict]:
    sanitized = []
    for article in articles or []:
        cleaned = dict(article)
        cleaned.pop("contents", None)
        sanitized.append(cleaned)
    return sanitized


def build_html_context(articles, category_priority=None):
    sanitized_articles = sanitize_articles(articles)

    category_seed = list(category_priority or DEFAULT_CATEGORY_PRIORITY)
    category_order = []
    seen_categories = set()
    for label in category_seed:
        if label not in seen_categories:
            seen_categories.add(label)
            category_order.append(label)

    cards_by_category = defaultdict(list)
    sources = set()

    def _prepare_card(payload):
        idx, article = payload
        source_entries = article.get("sources") or []
        source_names = []
        for entry in source_entries:
            if isinstance(entry, dict):
                name_value = _raw_text(entry.get("name", ""))
            else:
                name_value = _raw_text(entry)
            if not name_value:
                continue
            name_value = name_value.strip()
            if name_value:
                source_names.append(name_value)
        source_names = list(dict.fromkeys(source_names))
        source_raw = _raw_text(article.get("source", ""))
        fallback_source = source_raw.strip() or "Unknown Source"
        filter_sources = [fallback_source]
        source_label = fallback_source
        dataset_sources = "|".join(filter_sources)
        source_attr = _attr(dataset_sources)
        date_label = escape(_raw_text(article.get("date", "")).strip())
        summary_text = _raw_text(article.get("AI-Summary", "")).strip()
        if not summary_text:
            summary_text = "No AI summary available yet."
        summary_snippet = summary_text if len(summary_text) <= 280 else summary_text[:277].rstrip() + "…"
        summary_snippet = escape(summary_snippet)

        tags_text = _raw_text(article.get("tags", "")).strip()
        tags_markup = escape(tags_text) if tags_text else ""

        cves_list = _ensure_list(article.get("CVEs"))
        threatactors_list = _ensure_list(article.get("ThreatActors"))
        ttps_list = _ensure_list(article.get("TTPs"))
        iocs_list = _ensure_list(article.get("iocs"))

        cve_count = len(cves_list)
        actor_count = len(threatactors_list)
        ttp_count = len(ttps_list)
        ioc_count = len(iocs_list)

        categories = article.get("categories") or []
        primary_category = article.get("primary_category") or (categories[0] if categories else "General")
        if not categories:
            categories = [primary_category]

        category_slugs = [_slugify(cat) for cat in categories]
        primary_slug = _slugify(primary_category)

        stats = []
        stats.append(f"<span class=\"feed-card__category\">{escape(primary_category)}</span>")
        if cve_count:
            stats.append(f"<span class=\"feed-card__stat\">CVEs · {cve_count}</span>")
        if actor_count:
            stats.append(f"<span class=\"feed-card__stat\">Threat Actors · {actor_count}</span>")
        if ttp_count:
            stats.append(f"<span class=\"feed-card__stat\">TTPs · {ttp_count}</span>")
        if ioc_count:
            stats.append(f"<span class=\"feed-card__stat\">IOCs · {ioc_count}</span>")
        if tags_markup:
            stats.append(f"<span class=\"feed-card__tagline\">{tags_markup}</span>")

        footer_markup = (
            "".join(stats)
            if stats
            else "<span class=\"feed-card__stat feed-card__stat--muted\">No enrichment metadata available</span>"
        )

        search_values = [
            _raw_text(article.get("title", "")),
            summary_text,
            _raw_text(article.get("notes", "")),
            tags_text,
            fallback_source,
            " ".join(source_names),
            " ".join(threatactors_list),
            " ".join(ttps_list),
            " ".join(iocs_list),
        ]
        search_blob = " ".join(value for value in search_values if value).lower()

        card_html = (
            f"<article class=\"feed-card\" data-index=\"{idx}\" tabindex=\"0\""
            f" data-primary-category=\"{primary_slug}\""
            f" data-category-label=\"{_attr(primary_category)}\""
            f" data-categories=\"{_attr(' '.join(category_slugs) or primary_slug)}\""
            f" data-category-labels=\"{_attr('|'.join(categories))}\""
            f" data-source=\"{source_attr}\""
            f" data-has-cves=\"{'true' if cve_count else 'false'}\""
            f" data-has-actors=\"{'true' if actor_count else 'false'}\""
            f" data-has-iocs=\"{'true' if ioc_count else 'false'}\""
            f" data-has-ttps=\"{'true' if ttp_count else 'false'}\""
            f" data-tags=\"{_attr(tags_text.lower())}\""
            f" data-search=\"{_attr(search_blob)}\">"
            f"<div class=\"feed-card__meta\">"
            f"<span class=\"feed-card__source\">{escape(source_label)}</span>"
            f"<span class=\"feed-card__date\">{date_label}</span>"
            f"</div>"
            f"<p class=\"feed-card__summary\">{summary_snippet}</p>"
            f"<div class=\"feed-card__footer\">{footer_markup}</div>"
            f"</article>"
        )

        return {
            "idx": idx,
            "card_html": card_html,
            "primary_category": primary_category,
            "categories": categories,
            "filter_sources": filter_sources,
        }

    build_inputs = list(enumerate(sanitized_articles))
    if build_inputs:
        max_workers = min(32, max(1, (os.cpu_count() or 1) * 2))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            card_results = list(executor.map(_prepare_card, build_inputs))
    else:
        card_results = []

    for result in card_results:
        primary_category = result["primary_category"]
        categories = result["categories"] or [primary_category]
        for cat in categories:
            if cat not in seen_categories:
                seen_categories.add(cat)
                category_order.append(cat)
        if primary_category not in seen_categories:
            seen_categories.add(primary_category)
            category_order.append(primary_category)
        cards_by_category[primary_category].append(result["card_html"])
        for src_name in result["filter_sources"]:
            if src_name:
                sources.add(src_name)

    available_categories = [cat for cat in category_order if cards_by_category.get(cat)]

    card_sections = []
    for category in available_categories:
        items = cards_by_category.get(category) or []
        if not items:
            continue
        slug = _slugify(category)
        section_cards = "\n          ".join(items)
        section_markup = (
            f"<section class=\"card-category\" data-category-section=\"{slug}\">\n"
            f"  <header class=\"card-category__header\">\n"
            f"    <h2 class=\"card-category__title\">{escape(category)}</h2>\n"
            f"    <span class=\"card-category__count\">{len(items)} item{'s' if len(items) != 1 else ''}</span>\n"
            f"  </header>\n"
            f"  <div class=\"card-list\">\n          {section_cards}\n  </div>\n"
            f"</section>"
        )
        card_sections.append(section_markup)

    cards_markup = (
        "\n        ".join(card_sections)
        if card_sections
        else "<p class=\"card-empty\">No articles available yet.</p>"
    )

    article_count = len(sanitized_articles)
    article_count_label = f"{article_count} item{'s' if article_count != 1 else ''}"

    sources = sorted(s for s in sources if s)
    source_size = min(max(len(sources), 1), 8)
    source_options = (
        "\n            ".join(
            f"<option value=\"{_attr(source)}\">{escape(source)}</option>" for source in sources
        )
        if sources
        else "<option value=\"\" disabled>No sources available</option>"
    )

    category_filter_markup = (
        "\n            ".join(
            f"<label class=\"filter-panel__checkbox\">"
            f"<input type=\"checkbox\" name=\"category\" value=\"{_attr(_slugify(category))}\" data-label=\"{_attr(category)}\" checked>"
            f"<span>{escape(category)}</span>"
            f"</label>"
            for category in available_categories
        )
        if available_categories
        else "<p class=\"filter-panel__empty\">No category filters available.</p>"
    )

    articles_json = json.dumps(sanitized_articles, ensure_ascii=False)
    articles_json = articles_json.replace("</", "<" + "\\" + "/")

    return {
        "cards_markup": cards_markup,
        "article_count_label": article_count_label,
        "category_filter_markup": category_filter_markup,
        "source_options": source_options,
        "source_size": str(source_size),
        "articles_json": articles_json,
    }


def render_index_html(context, template_path) -> str:
    template_path = Path(template_path)
    template_text = template_path.read_text(encoding="utf-8")
    rendered = template_text
    for key, value in context.items():
        placeholder = f"{{{{{key}}}}}"
        rendered = rendered.replace(placeholder, str(value))
    return rendered

import gzip
import hashlib
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
try:
    import cloudscraper
    _HAS_CLOUDSCRAPER = True
except Exception:
    _HAS_CLOUDSCRAPER = False
import requests, csv, json, time, random
from html import escape
from bs4 import BeautifulSoup
import feedparser
from datetime import datetime
try:
    import lmstudio as lms
    _HAS_LMSTUDIO = True
except Exception:  # pragma: no cover - optional dependency may be absent in CI
    lms = None
    _HAS_LMSTUDIO = False
import re
from markdownify import markdownify as md
from pathlib import Path

from .html_builder import build_html

class CyberSecScraper:
    def __init__(
        self,
        *,
        auto_generate_html: bool = True,
        data_file: Path | None = None,
        parsed_articles_file: Path | None = None,
    ):
        self.sess = requests.Session()
        self.sess.headers.update({
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, identity",
            "Connection": "keep-alive",
            "DNT": "1",
        })
        self.prompt = """You are a cybersecurity summarization and extraction engine.
            Task:
            Provide a concise cybersecurity-focused summary of the full article contents while preserving critical technical detail.

            Output:
            Return a single valid JSON object (no extra text).
            Include these fields exactly:

            {
            "summary": string,
            "iocs": [string] | null,
            "ttps": [string] | null,
            "tags": [string] | null,
            "threat_actors": [string (Name:Country)] | null,
            "cves": [
                {
                "cve": string,
                "cvss": number | null,
                "patch_available": boolean | null,
                "weaponization_stage": "Disclosure(4)" | "ProofOfConcept(1)" | "ExploitLikely(12)" | "Exploited(277)" | null,
                "exploited": boolean | null,
                "mapped_mitre_ids": [string] | null,
                "yara": [string] | null,
                "sigma": [string] | null
                }
            ] | null,
            "notes": string | null,
            "source_url": string | null,
            "confidence": {
                "summary": number(0-1),
                "iocs": number(0-1),
                "ttps": number(0-1),
                "threat_actors": number(0-1),
                "cves": number(0-1),
                "notes": number(0-1)
            }
            }

            Rules:
            - If data is missing, use null or empty array/string.
            - Populate "tags" with 3-8 concise topical labels when possible (null if none).
            - Confidence must reflect extraction certainty (0–1).
            - Ensure valid JSON format with double quotes, no trailing commas, and no explanation text.
        """
        self.aiModel = "qwen/qwen3-4b-2507"
        base_dir = Path(__file__).resolve().parent.parent
        self.data_file = Path(data_file) if data_file else base_dir / "cybersec_news.json"
        self.html_output_file = base_dir / "index.html"
        self.darkweb_feeds_file = base_dir / "darkweb_feeds.json"
        self.articles = []
        self.article_index_by_fingerprint = {}
        if parsed_articles_file:
            self.parsed_articles_file = Path(parsed_articles_file)
        else:
            legacy_cache = base_dir / "ParsedArticles.txt"
            candidate_cache = self.data_file.with_suffix(".parsed.txt")
            if legacy_cache.exists() and not candidate_cache.exists():
                self.parsed_articles_file = legacy_cache
            else:
                if candidate_cache == self.data_file:
                    candidate_cache = legacy_cache
                self.parsed_articles_file = candidate_cache
        self.parsed_articles = self._load_parsed_articles()
        self.html_update_interval = 10
        self._articles_since_html = 0
        self.tor_proxy = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
        self.tor_session = None
        self._tor_disabled = False
        self.auto_generate_html = auto_generate_html
        self.category_priority = [
            "Zero Day",
            "Active Exploitation",
            "Vulnerabilities",
            "Ransomware",
            "APT Activity",
            "General",
        ]
        self.Feeds = {
            "The Hacker News": {"url": "https://feeds.feedburner.com/TheHackersNews?format=xml"},
            "Bleeping Computer": {"url": "https://www.bleepingcomputer.com/feed/"},
            "Dark Reading": {"url": "https://www.darkreading.com/rss.xml"},
            "SecurityWeek": {"url": "https://www.securityweek.com/feed/"},
            "Krebs on Security": {"url": "https://krebsonsecurity.com/feed/"},
            "Threatpost": {"url": "https://threatpost.com/feed/"},
            "SC Media Threats": {"url": "https://www.scmagazine.com/rss/category/threats"},
            "CISA Alerts": {"url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
            "CISA Current Activity": {"url": "https://www.cisa.gov/uscert/ncas/current-activity.xml"},
            "CISA Bulletins": {"url": "https://www.cisa.gov/uscert/ncas/bulletins.xml"},
            "US-CERT Vulnerability Notes": {"url": "https://kb.cert.org/vuls/rss/rss.xml"},
            "NVD NIST": {"url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
            "Microsoft Security Response Center": {"url": "https://msrc-blog.microsoft.com/feed/"},
            "Cisco Talos": {"url": "https://blog.talosintelligence.com/feeds/posts/default"},
            "CrowdStrike": {"url": "https://www.crowdstrike.com/blog/feed/"},
            "Unit 42": {"url": "https://unit42.paloaltonetworks.com/feed/"},
            "Mandiant": {"url": "https://www.mandiant.com/resources/blog/rss.xml"},
            "Proofpoint": {"url": "https://www.proofpoint.com/us/blog/rss.xml"},
            "Sophos News": {"url": "https://news.sophos.com/en-us/feed/"},
            "ESET WeLiveSecurity": {"url": "https://www.welivesecurity.com/feed/"},
            "Check Point Research": {"url": "https://research.checkpoint.com/feed/"},
            "Rapid7": {"url": "https://www.rapid7.com/blog/rss/"},
            "Recorded Future": {"url": "https://www.recordedfuture.com/blog/rss"},
            "Bitdefender Labs": {"url": "https://www.bitdefender.com/blog/api/rss/labs/"},
            "Google Cloud Security": {"url": "https://cloud.google.com/blog/topics/inside-google-cloud/feed"},
            "AWS Security": {"url": "https://aws.amazon.com/blogs/security/feed/"},
            "IBM Security Intelligence": {"url": "https://securityintelligence.com/feed/"},
            "Naked Security by Sophos": {"url": "https://nakedsecurity.sophos.com/feed/"},
            "Fortinet Blog": {"url": "https://www.fortinet.com/blog/rss"},
            "Malwarebytes Labs": {"url": "https://www.malwarebytes.com/blog/feed"},
            "Trend Micro Research": {"url": "https://www.trendmicro.com/vinfo/us/security/rss"},
            "Zero Day Initiative": {"url": "https://www.zerodayinitiative.com/blog?format=rss"},
            "Qualys": {"url": "https://blog.qualys.com/feed"},
            "VMware Security Advisories": {"url": "https://www.vmware.com/security/advisories.xml"},
            "Oracle Critical Patch Updates": {"url": "https://www.oracle.com/a/ocom/docs/rss/oracle-critical-patch-updates.xml"},
            "SAP Security Patch Day": {"url": "https://wiki.scn.sap.com/wiki/pages/viewrecentblogposts.action?key=266488969"},
            "F5 Security Advisories": {"url": "https://support.f5.com/csp/rss/feed.xml"},
            "Juniper Security Advisories": {"url": "https://services.netscreen.com/documentation/JuniperNetworksSecurityAdvisories.xml"},
            "Cisco Security Advisories": {"url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"},
            "Adobe Security Bulletins": {"url": "https://helpx.adobe.com/security/atom.xml"},
            "Google Chrome Releases": {"url": "https://chromereleases.googleblog.com/feeds/posts/default"},
            "USENIX Security": {"url": "https://www.usenix.org/aggregator/security/feed"},
            "CERT-EU": {"url": "https://cert.europa.eu/publico/updates-en.atom"},
            "GovCERT.ch": {"url": "https://www.govcert.admin.ch/blog/feed/"},
            "Australian Cyber Security Centre": {"url": "https://www.cyber.gov.au/acsc/view-all-content/alerts/rss.xml"},
            "Canadian Centre for Cyber Security": {"url": "https://www.cyber.gc.ca/en/rss/advisories-alerts"},
            "ENISA": {"url": "https://www.enisa.europa.eu/rss/news"},
            "SANS Internet Storm Center": {"url": "https://isc.sans.edu/rssfeed.xml"},
            "Red Canary": {"url": "https://redcanary.com/feed/"},
            "The DFIR Report": {"url": "https://thedfirreport.com/feed/"},
            "Security Affairs": {"url": "https://securityaffairs.com/category/hacking/feed"},
            "CyberWire": {"url": "https://thecyberwire.com/feeds/rss"},
            "Cisco Security Blog": {"url": "https://blogs.cisco.com/security/feed"},
            "Palo Alto Networks News": {"url": "https://www.paloaltonetworks.com/resources/rss"},
            "IC3 Alerts": {"url": "https://www.ic3.gov/RSS/RecentIncidents.xml"},
            "UK NCSC": {"url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"},
            "ANSSI CERT-FR": {"url": "https://www.cert.ssi.gouv.fr/feed/"},
        }
        self.DarkWebFeeds = self._load_darkweb_feeds()
        self.urls = {
            "Huntress Blog": "https://www.huntress.com/blog"
        }
        self._load_existing_articles()
    
    def _decode_html(self, resp):
        """
        Do NOT manually decompress. Force servers to send identity/gzip only,
        then just decode the bytes to text.
        """
        enc = resp.encoding or requests.utils.get_encoding_from_headers(resp.headers) or "utf-8"
        try:
            return resp.content.decode(enc, errors="replace")
        except Exception:
            try:
                return resp.content.decode("utf-8", errors="replace")
            except Exception:
                return resp.text
                
    def _sleep(self):
        time.sleep(random.uniform(0.8, 1.6))

    def _backoff_sleep(self, attempt):
        delay = (1.5 ** attempt) + random.uniform(0, 0.5)
        time.sleep(min(delay, 8.0))

    def _load_darkweb_feeds(self):
        feeds = {
            "Darknet Live": {"url": "https://darknetlive.com/feed/", "category": "darkweb", "requires_tor": False},
            "Privacy Affairs (Dark Web)": {"url": "https://www.privacyaffairs.com/category/dark-web/feed/", "category": "darkweb", "requires_tor": False},
            "Tor Project Security Advisories": {"url": "https://blog.torproject.org/rss/", "category": "darkweb", "requires_tor": False},
        }
        if not self.darkweb_feeds_file.exists():
            return feeds
        try:
            with self.darkweb_feeds_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:
            print(f"Warning: Could not load optional dark web feeds ({self.darkweb_feeds_file}): {exc}")
            return feeds

        if isinstance(data, dict):
            items = data.items()
        elif isinstance(data, list):
            items = ((entry.get("name"), entry) for entry in data if isinstance(entry, dict))
        else:
            print("Warning: Unsupported format in dark web feed configuration – expected dict or list.")
            return feeds

        for name, entry in items:
            if not name or not isinstance(entry, dict):
                continue
            url = entry.get("url")
            if not url:
                continue
            feeds[name] = {
                "url": url,
                "category": entry.get("category", "darkweb"),
                "requires_tor": bool(entry.get("requires_tor", ".onion" in url)),
            }
        return feeds

    def _load_parsed_articles(self):
        parsed = set()
        try:
            if not self.parsed_articles_file.exists():
                self.parsed_articles_file.parent.mkdir(parents=True, exist_ok=True)
                self.parsed_articles_file.touch()
                return parsed
            with self.parsed_articles_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed.add(line)
        except Exception as exc:
            print(f"Warning: Could not read parsed articles file: {exc}")
        return parsed

    def _load_existing_articles(self):
        if not self.data_file.exists():
            return
        try:
            with self.data_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            print(f"Warning: Could not load existing articles: {exc}")
            return

        if not isinstance(data, list):
            print("Warning: Existing article store is not a list – ignoring contents.")
            return

        normalised = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            article = self._normalise_article(entry)
            fingerprint = article.get("fingerprint")
            if fingerprint:
                self.article_index_by_fingerprint[fingerprint] = len(normalised)
            normalised.append(article)

            identifier = self._article_identifier(
                article.get("source"),
                article.get("title"),
                article.get("article")
            )
            if identifier and identifier not in self.parsed_articles:
                self._record_parsed_article(identifier)

        self.articles = normalised
        if self.articles:
            print(f"Loaded {len(self.articles)} articles from {self.data_file}")

    def _article_identifier(self, source, title, link):
        if link:
            return link.strip()
        if title:
            return f"{source}:{title.strip()}"
        return None

    def _record_parsed_article(self, identifier):
        if not identifier or identifier in self.parsed_articles:
            return
        self.parsed_articles.add(identifier)
        try:
            self.parsed_articles_file.parent.mkdir(parents=True, exist_ok=True)
            with self.parsed_articles_file.open("a", encoding="utf-8") as f:
                f.write(identifier + "\n")
        except Exception as exc:
            print(f"Warning: Could not update parsed articles file: {exc}")

    def _ensure_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (tuple, set)):
            return list(value)
        if value == "":
            return []
        return [value]

    def _ordered_unique(self, iterable, key=None):
        seen = set()
        output = []
        for item in iterable:
            marker = key(item) if key else item
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
        return output

    def _normalise_categories(self, categories):
        if not categories:
            categories = []
        cleaned = []
        for category in categories:
            if not category:
                continue
            cleaned.append(str(category).strip())
        cleaned = [c for c in cleaned if c]
        cleaned = self._ordered_unique(cleaned)

        def category_sort_key(label):
            try:
                return self.category_priority.index(label)
            except ValueError:
                return len(self.category_priority)

        cleaned.sort(key=lambda label: (category_sort_key(label), label))
        if not cleaned:
            cleaned.append("General")
        return cleaned

    def _normalise_tags(self, value):
        if not value:
            return ""
        tokens = []
        if isinstance(value, list):
            candidates = value
        else:
            raw = str(value)
            candidates = re.split(r"[|,]", raw)
            if len(candidates) == 1:
                candidates = re.split(r"\s{2,}", raw)
        for candidate in candidates:
            if isinstance(candidate, str):
                parts = [candidate.strip()]
            else:
                parts = [str(candidate).strip()]
            for part in parts:
                if part:
                    tokens.append(part)
        unique = self._ordered_unique(tokens, key=lambda item: item.lower())
        return " | ".join(unique)

    def _fingerprint_article(self, title, body):
        text = f"{title or ''} \n {body or ''}"
        text = re.sub(r"\s+", " ", text).strip().lower()
        if not text:
            return None
        snippet = text[:4000]
        return hashlib.sha256(snippet.encode("utf-8", "ignore")).hexdigest()

    def _normalise_article(self, raw_article):
        article = dict(raw_article)
        link = article.get("article") or article.get("link") or ""
        source_value = article.get("source")
        sources = article.get("sources")
        if not sources:
            if isinstance(source_value, str) and source_value.strip():
                sources = [{"name": source_value.strip(), "url": link}]
            else:
                sources = []
        else:
            normalised_sources = []
            for entry in sources:
                if isinstance(entry, dict):
                    name = entry.get("name") or entry.get("source")
                    url = entry.get("url") or entry.get("link") or link
                    if name:
                        normalised_sources.append({"name": name.strip(), "url": url})
                elif isinstance(entry, str) and entry.strip():
                    normalised_sources.append({"name": entry.strip(), "url": link})
            sources = normalised_sources
        if not sources:
            fallback = "Unknown"
            if isinstance(source_value, str) and source_value.strip():
                fallback = source_value.strip()
            sources = [{"name": fallback, "url": link}]
        article["sources"] = sources
        source_names = [src.get("name") for src in sources if src.get("name")]
        article["source"] = ", ".join(source_names) if source_names else (source_value or "Unknown")
        if not article.get("article") and sources:
            article["article"] = sources[0].get("url") or link
        article.pop("link", None)

        article["ThreatActors"] = self._ordered_unique(
            [str(value).strip() for value in self._ensure_list(article.get("ThreatActors")) if str(value).strip()],
            key=lambda value: value.lower(),
        )
        article["TTPs"] = self._ordered_unique(
            [str(value).strip() for value in self._ensure_list(article.get("TTPs")) if str(value).strip()],
            key=lambda value: value.lower(),
        )
        article["iocs"] = self._ordered_unique(
            [str(value).strip() for value in self._ensure_list(article.get("iocs")) if str(value).strip()],
            key=lambda value: value.lower(),
        )

        cves = []
        seen_cves = set()
        for entry in self._ensure_list(article.get("CVEs")):
            if isinstance(entry, dict):
                marker = entry.get("cve") or json.dumps(entry, sort_keys=True)
                marker_key = marker.lower() if isinstance(marker, str) else marker
                if marker_key in seen_cves:
                    continue
                seen_cves.add(marker_key)
                cves.append(entry)
            elif entry:
                marker_key = str(entry).lower()
                if marker_key in seen_cves:
                    continue
                seen_cves.add(marker_key)
                cves.append(entry)
        article["CVEs"] = cves

        article["tags"] = self._normalise_tags(article.get("tags"))
        article["categories"] = self._normalise_categories(article.get("categories"))
        article["primary_category"] = article["categories"][0] if article["categories"] else "General"
        article["notes"] = str(article.get("notes") or "")
        article["AI-Summary"] = str(article.get("AI-Summary") or "")
        article["contents"] = str(article.get("contents") or "")
        article["date"] = str(article.get("date") or "")

        fingerprint = article.get("fingerprint")
        if not fingerprint:
            fingerprint = self._fingerprint_article(article.get("title"), article.get("contents"))
            if fingerprint:
                article["fingerprint"] = fingerprint
        return article

    def _merge_sources(self, existing, new):
        changed = False
        existing_sources = existing.get("sources") or []
        new_sources = new.get("sources") or []
        if not isinstance(existing_sources, list):
            existing_sources = []
        for src in new_sources:
            if not isinstance(src, dict):
                continue
            name = (src.get("name") or src.get("source") or "").strip()
            url = (src.get("url") or src.get("link") or "").strip()
            if not name and not url:
                continue
            marker = (name.lower(), url)
            if any(
                (
                    (existing_src.get("name") or "").lower(),
                    (existing_src.get("url") or "").strip(),
                )
                == marker
                for existing_src in existing_sources
            ):
                continue
            existing_sources.append({"name": name or None, "url": url or None})
            changed = True
        if changed:
            existing["sources"] = existing_sources
            names = [src.get("name") for src in existing_sources if src.get("name")]
            if names:
                existing["source"] = ", ".join(names)
            if not existing.get("article") and existing_sources:
                existing["article"] = existing_sources[0].get("url")
        return changed

    def _merge_list_field(self, existing, new, key):
        existing_list = existing.get(key) or []
        if not isinstance(existing_list, list):
            existing_list = self._ensure_list(existing_list)
        new_list = new.get(key) or []
        if not isinstance(new_list, list):
            new_list = self._ensure_list(new_list)
        combined = existing_list + new_list
        combined = [item for item in combined if item]
        normalised = []
        seen = set()
        for item in combined:
            if isinstance(item, dict):
                marker = json.dumps(item, sort_keys=True)
            else:
                marker = str(item).lower()
            if marker in seen:
                continue
            seen.add(marker)
            normalised.append(item)
        if normalised != existing_list:
            existing[key] = normalised
            return True
        return False

    def _merge_text_field(self, existing, new, key, prefer_longer=True):
        current = existing.get(key) or ""
        incoming = new.get(key) or ""
        if not incoming:
            return False
        if not current:
            existing[key] = incoming
            return True
        if prefer_longer and len(incoming) > len(current):
            existing[key] = incoming
            return True
        return False

    def _merge_tags(self, existing, new):
        merged = self._normalise_tags(" | ".join(filter(None, [existing.get("tags"), new.get("tags")])) )
        if merged != existing.get("tags"):
            existing["tags"] = merged
            return True
        return False

    def _merge_categories(self, existing, new):
        combined = self._normalise_categories((existing.get("categories") or []) + (new.get("categories") or []))
        if combined != existing.get("categories"):
            existing["categories"] = combined
            existing["primary_category"] = combined[0]
            return True
        return False

    def _merge_cves(self, existing, new):
        existing_cves = existing.get("CVEs") or []
        new_cves = new.get("CVEs") or []
        if not isinstance(existing_cves, list):
            existing_cves = self._ensure_list(existing_cves)
        if not isinstance(new_cves, list):
            new_cves = self._ensure_list(new_cves)
        combined = existing_cves + new_cves
        output = []
        seen = set()
        for entry in combined:
            if isinstance(entry, dict):
                marker = entry.get("cve") or json.dumps(entry, sort_keys=True)
                marker_key = marker.lower() if isinstance(marker, str) else marker
            else:
                marker_key = str(entry).lower()
            if marker_key in seen:
                continue
            seen.add(marker_key)
            output.append(entry)
        if output != existing_cves:
            existing["CVEs"] = output
            return True
        return False

    def _merge_article(self, existing, new):
        changed = False
        changed = self._merge_sources(existing, new) or changed
        changed = self._merge_list_field(existing, new, "ThreatActors") or changed
        changed = self._merge_list_field(existing, new, "TTPs") or changed
        changed = self._merge_list_field(existing, new, "iocs") or changed
        changed = self._merge_cves(existing, new) or changed
        changed = self._merge_tags(existing, new) or changed
        changed = self._merge_categories(existing, new) or changed
        changed = self._merge_text_field(existing, new, "AI-Summary") or changed
        changed = self._merge_text_field(existing, new, "notes", prefer_longer=True) or changed
        if new.get("contents") and (not existing.get("contents") or len(new.get("contents")) > len(existing.get("contents"))):
            existing["contents"] = new.get("contents")
            changed = True
        if not existing.get("date") and new.get("date"):
            existing["date"] = new.get("date")
            changed = True
        if not existing.get("AI-Summary") and new.get("AI-Summary"):
            existing["AI-Summary"] = new.get("AI-Summary")
            changed = True
        return changed

    def _merge_or_add_article(self, article):
        fingerprint = article.get("fingerprint") or self._fingerprint_article(article.get("title"), article.get("contents"))
        if not fingerprint:
            return False
        article["fingerprint"] = fingerprint
        index = self.article_index_by_fingerprint.get(fingerprint)
        if index is not None:
            existing = self.articles[index]
            if self._merge_article(existing, article):
                self.articles[index] = existing
                return True
            return False
        self.articles.append(article)
        self.article_index_by_fingerprint[fingerprint] = len(self.articles) - 1
        return True

    def _get_session(self, use_tor=False):
        if use_tor:
            if self._tor_disabled:
                return None
            if self.tor_session is None:
                session = requests.Session()
                session.headers.update(self.sess.headers)
                session.proxies.update({"http": self.tor_proxy, "https": self.tor_proxy})
                self.tor_session = session
            return self.tor_session
        return self.sess

    def _fetch_url(self, url, use_tor=False, timeout=20, headers=None):
        session = self._get_session(use_tor=use_tor)
        if session is None:
            if use_tor and not self._tor_disabled:
                print("Tor session unavailable – skipping request.")
            return None
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True, headers=headers)
            response.raise_for_status()
            return response
        except Exception as exc:
            if use_tor:
                print(f"Failed to retrieve {url} via Tor: {exc}")
                if not getattr(exc, "response", None):
                    self._tor_disabled = True
            else:
                print(f"Failed to retrieve {url}: {exc}")
            return None

    def _parse_feed(self, url, requires_tor=False):
        if not url:
            return feedparser.FeedParserDict(entries=[])
        needs_tor = requires_tor or ".onion" in url
        if needs_tor and self._tor_disabled:
            print(f"Skipping Tor-only feed {url} because Tor proxy is unavailable.")
            return feedparser.FeedParserDict(entries=[])
        if needs_tor:
            response = self._fetch_url(url, use_tor=True)
            if not response:
                return feedparser.FeedParserDict(entries=[])
            return feedparser.parse(response.content)
        try:
            feed = feedparser.parse(url)
            if getattr(feed, "entries", None):
                return feed
            if getattr(feed, "bozo", False):
                response = self._fetch_url(url, use_tor=requires_tor)
                if response:
                    return feedparser.parse(response.content)
            return feed
        except Exception as exc:
            print(f"Direct feed parsing failed for {url}: {exc}")
            response = self._fetch_url(url, use_tor=requires_tor)
            if response:
                return feedparser.parse(response.content)
            return feedparser.FeedParserDict(entries=[])

    def _persist_progress(self, force_html=False):
        try:
            self.save_to_json()
            if not self.auto_generate_html:
                return
            if force_html or not self.html_output_file.exists():
                self.save_to_html()
                self._articles_since_html = 0
                return

            self._articles_since_html += 1
            if self._articles_since_html >= self.html_update_interval:
                self.save_to_html()
                self._articles_since_html = 0
        except Exception as exc:
            print(f"Warning: Could not persist progress: {exc}")

    def _categorize_article(self, title, summary, body, tags, cves, actors):
        text_blobs = [title or "", summary or "", body or "", tags or ""]
        haystack = " ".join(text_blobs).lower()
        categories = []

        if any(keyword in haystack for keyword in ("zero day", "zero-day", "0day", "0-day", "zeroday")):
            categories.append("Zero Day")

        if any(keyword in haystack for keyword in (
            "actively exploited", "active exploitation", "exploited in the wild",
            "in the wild", "being exploited", "active attack", "exploitation ongoing"
        )):
            categories.append("Active Exploitation")

        if cves or "cve" in haystack or "vulnerab" in haystack:
            categories.append("Vulnerabilities")

        if "ransomware" in haystack:
            categories.append("Ransomware")

        actor_tokens = [actor.lower() for actor in actors or []]
        if any(
            token.startswith("apt") or "advanced persistent threat" in token or token in haystack
            for token in actor_tokens
        ) or any(keyword in haystack for keyword in (
            "nation-state", "lazarus", "sandworm", "fin", "unc", "threat actor"
        )):
            categories.append("APT Activity")

        # Ensure uniqueness and stable order
        seen = set()
        ordered = []
        for category in categories:
            if category not in seen:
                seen.add(category)
                ordered.append(category)

        if not ordered:
            ordered.append("General")

        return ordered

    def _summarize(self, text):
        if not _HAS_LMSTUDIO:
            raise RuntimeError(
                "The 'lmstudio' package is required for AI summarisation. "
                "Install lmstudio to enable this feature."
            )

        model = lms.llm(self.aiModel)
        return model.respond(self.prompt + text)
    
    def _extractCVEs(self, text):
        import re
        pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(pattern, text)
    
    def _isExploited(self, text):
        exploited_keywords = [
            "actively exploited", "recently exploited", "in the wild", "exploitation observed",
            "exploited in attacks", "being exploited", "under active attack", "exploitation campaign"
        ]
        text_lower = text.lower()
        return any(kw in text_lower for kw in exploited_keywords)
    
    def _HasPatch(self, text):
        patch_keywords = [
            "patch available", "security update", "vendor released a patch",
            "update issued", "fix released", "patched version", "software update"
        ]
        text_lower = text.lower()
        return any(kw in text_lower for kw in patch_keywords)

    def _sanitize_html_to_text(self, value):
        if not value:
            return ""
        try:
            return BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
        except Exception:
            return str(value)

    def _normalise_whitespace(self, text):
        if not text:
            return ""
        text = re.sub(r"[\u200b\u200c\u200d\ufeff]", " ", text)
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r" ?\n ?", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _condense_article_text(self, text, max_chars=6000):
        """Reduce the amount of text sent to the AI while keeping salient details."""
        if not text:
            return ""

        paragraphs = [para.strip() for para in re.split(r"\n{2,}", text) if para.strip()]
        if not paragraphs:
            return text[:max_chars]

        keyword_weights = {
            "cve-": 6,
            "zero-day": 5,
            "zeroday": 5,
            "exploit": 4,
            "exploitation": 4,
            "ransomware": 4,
            "apt": 4,
            "advanced persistent threat": 4,
            "backdoor": 3,
            "malware": 3,
            "vulnerability": 3,
            "patch": 2,
            "mitre": 2,
            "cisa": 2,
            "indicator": 2,
            "ioc": 2,
        }
        indicator_patterns = [
            r"CVE-\d{4}-\d{4,7}",
            r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
            r"[0-9a-fA-F]{32,}",
            r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ]

        scored = []
        for idx, para in enumerate(paragraphs):
            lower = para.lower()
            score = 1.0 + min(len(para), 800) / 800.0  # prefer fuller paragraphs
            for keyword, weight in keyword_weights.items():
                if keyword in lower:
                    score += weight
            for pattern in indicator_patterns:
                if re.search(pattern, para, re.IGNORECASE):
                    score += 2
            scored.append((idx, score, para))

        # Always include the opening paragraph even if its score is low.
        mandatory_indices = {0}

        selected = []
        remaining_chars = max_chars

        for idx, score, para in sorted(scored, key=lambda item: (-item[1], item[0])):
            if idx in mandatory_indices or remaining_chars > 0:
                if len(para) <= remaining_chars or idx in mandatory_indices:
                    selected.append((idx, para))
                    remaining_chars -= len(para) + 2  # account for spacing
            if remaining_chars <= 0:
                break

        if not selected:
            selected = [(idx, para) for idx, _, para in scored[:3]]

        selected.sort(key=lambda item: item[0])
        condensed = "\n\n".join(para for _, para in selected)

        if len(condensed) < max_chars and len(condensed) < len(text):
            # append additional context in chronological order until limit reached
            used_indices = {idx for idx, _ in selected}
            for idx, para in enumerate(paragraphs):
                if idx in used_indices:
                    continue
                addition = ("\n\n" if condensed else "") + para
                if len(condensed) + len(addition) > max_chars:
                    break
                condensed += addition
                used_indices.add(idx)

        if condensed:
            return condensed[:max_chars].rstrip()
        return text[:max_chars]

    def _extract_full_article_text(self, url, referer=None, existing_text=""):
        if not url:
            return existing_text
        html = self.maybe_fetch_html(url, referer=referer)
        if not html:
            return existing_text
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["script", "style", "noscript", "iframe", "svg", "canvas", "form", "header", "footer", "nav", "aside"]):
            tag.decompose()

        candidates = []
        selectors = [
            "article",
            "main",
            "div[class*='content']",
            "div[class*='article']",
            "div[class*='post']",
            "section[class*='content']",
            "section[class*='article']",
            "section[class*='post']",
            "div[id*='content']",
            "div[id*='article']",
            "div[id*='post']",
        ]
        for selector in selectors:
            for node in soup.select(selector):
                if node not in candidates:
                    candidates.append(node)
        if not candidates:
            body = soup.body or soup
            if body:
                candidates.append(body)

        def collect_text(node):
            blocks = []
            for element in node.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "blockquote", "pre", "code"]):
                text = element.get_text(" ", strip=True)
                if text:
                    blocks.append(text)
            if not blocks:
                text = node.get_text(" ", strip=True)
                return text.strip()
            return "\n".join(blocks).strip()

        longest_text = existing_text or ""
        for candidate in candidates:
            extracted = collect_text(candidate)
            if extracted and len(extracted) > len(longest_text):
                longest_text = extracted

        if not longest_text:
            return existing_text
        if existing_text and len(longest_text) < len(existing_text) * 0.6:
            return existing_text
        return longest_text

    def _normalise_date(self, entry):
        for attr in ("published_parsed", "updated_parsed", "created_parsed"):
            struct = entry.get(attr)
            if struct:
                try:
                    return datetime(*struct[:6]).isoformat()
                except Exception:
                    continue
        for attr in ("published", "updated", "created"):
            value = entry.get(attr)
            if value:
                return value
        return ""

    def maybe_fetch_html(self, url, referer=None, max_attempts=3, debug=False):
        if not url:
            return None
        use_tor = ".onion" in url
        scraper = cloudscraper.create_scraper() if _HAS_CLOUDSCRAPER and not use_tor else None
        headers = self.sess.headers.copy()
        if referer:
            headers["Referer"] = referer
        attempt = 0
        while attempt < max_attempts:
            try:
                if use_tor:
                    resp = self._fetch_url(url, use_tor=True, timeout=25, headers=headers)
                elif scraper is not None:
                    resp = scraper.get(url, headers=headers, timeout=15)
                else:
                    resp = self._fetch_url(url, use_tor=False, timeout=15, headers=headers)
                if resp and getattr(resp, "status_code", 200) == 200:
                    return self._decode_html(resp)
                if debug:
                    status = getattr(resp, "status_code", "?") if resp else "no-response"
                    print(f"Warning: Received status code {status} for URL: {url}")
            except Exception as e:
                if debug:
                    print(f"Error fetching URL {url}: {e}")
            attempt += 1
            self._backoff_sleep(attempt)

    def ingest_huntress(self):
        source = "Huntress Blog"
        url = self.urls[source]
        #print(url)
        html = self.maybe_fetch_html(url)
        soup = BeautifulSoup(html, "html.parser")
        #print(soup.prettify())
        with open("huntress_blog.html", "w", encoding="utf-8") as f:
            f.write(soup.prettify())

    def ingest_feed(self, source, feed_info=None):
        feed_meta = feed_info or self.Feeds.get(source) or self.DarkWebFeeds.get(source)
        if feed_meta is None:
            print(f"Skipping feed {source}: configuration missing")
            return
        if isinstance(feed_meta, str):
            feed_url = feed_meta
            requires_tor = ".onion" in (feed_url or "")
        else:
            feed_url = feed_meta.get("url") if isinstance(feed_meta, dict) else None
            requires_tor = bool(feed_meta.get("requires_tor", ".onion" in (feed_url or ""))) if isinstance(feed_meta, dict) else False
        if not feed_url:
            print(f"Skipping feed {source}: missing URL")
            return

        feed = self._parse_feed(feed_url, requires_tor=requires_tor)
        if getattr(feed, "bozo", False):
            print(f"Warning: Feed parsing issue detected for {source} ({feed_url}): {getattr(feed, 'bozo_exception', '')}")

        entries = getattr(feed, "entries", [])
        if not entries:
            print(f"No entries discovered for {source} (URL: {feed_url})")
            return

        for entry in entries:
            print("-"*120)
            print("Article count: ", len(self.articles)+1)
            print("Source: ", source )
            title = (entry.get("title") or "").strip()
            print("Title: ", title)
            #if count <= 0:
            #    return
            #count -= 1
            link = (entry.get("link") or "").strip()
            published = self._normalise_date(entry)
            identifier = self._article_identifier(source, title, link)
            if identifier and identifier in self.parsed_articles:
                print(f"Skipping previously parsed article: {title}")
                continue
            body_segments = []
            summary_html = entry.get("summary") or entry.get("description")
            if summary_html:
                body_segments.append(self._sanitize_html_to_text(summary_html))
            entry_content = entry.get("content") or []
            for content in entry_content:
                if isinstance(content, dict):
                    value = content.get("value")
                else:
                    value = getattr(content, "value", None)
                if value:
                    body_segments.append(self._sanitize_html_to_text(value))
            body = "\n".join(segment for segment in body_segments if segment)
            body = self._normalise_whitespace(body)
            if link:
                enriched = self._extract_full_article_text(link, referer=feed_url, existing_text=body)
                body = self._normalise_whitespace(enriched)
            if not body:
                self._sleep()
                continue

            ai_payload = {}
            ai_summary_text = ""
            condensed_body = self._condense_article_text(body)
            try:
                ai_response = self._summarize(condensed_body)
                raw_content = getattr(ai_response, "content", ai_response)
                if not isinstance(raw_content, str):
                    raw_content = json.dumps(raw_content)
                ai_payload = json.loads(raw_content)
            except Exception as exc:
                print(f"AI summarisation failed for {title}: {exc}")
                ai_payload = {}
            if not isinstance(ai_payload, dict):
                ai_payload = {}

            ai_summary_text = ai_payload.get("summary") or ""
            threatactors = ai_payload.get("threat_actors") or []
            iocs = ai_payload.get("iocs") or []
            ttps = ai_payload.get("ttps") or []
            cves = ai_payload.get("cves") or []
            notes = ai_payload.get("notes") or ""

            if not ai_summary_text and body:
                ai_summary_text = body[:400].strip()
                if len(body) > 400:
                    ai_summary_text = ai_summary_text.rstrip() + "…"
            if not ai_summary_text:
                ai_summary_text = "Summary unavailable."

            def _coerce_list(value):
                if value is None:
                    return []
                if isinstance(value, list):
                    return value
                if isinstance(value, (set, tuple)):
                    return list(value)
                return [value]

            threatactors = _coerce_list(threatactors)
            iocs = _coerce_list(iocs)
            ttps = _coerce_list(ttps)
            cves = _coerce_list(cves)
            notes = notes if isinstance(notes, str) else str(notes)
            print("Summary: ", ai_summary_text)
            print("Threat Actors: ", threatactors)
            print("IOCs: ", iocs)
            print("TTPs: ", ttps)
            print("CVEs: ", cves)
            print("Notes: ", notes)
            print("Source: ", link)
            tags_payload = ai_payload.get("tags")
            tags = self._normalise_tags(tags_payload)
            print("Tags: ", tags_payload)

            categories = self._categorize_article(title, ai_summary_text, body, tags, cves, threatactors)

            article_record = {
                "source": source,
                "sources": [{"name": source, "url": link}],
                "title": title,
                "CVEs": cves,
                "date": published,
                "notes": notes,
                "article": link,
                "AI-Summary": ai_summary_text,
                "iocs": iocs,
                "ThreatActors": threatactors,
                "TTPs": ttps,
                "contents": body,
                "tags": tags,
                "categories": categories,
            }
            article_record = self._normalise_article(article_record)
            changed = self._merge_or_add_article(article_record)
            if identifier:
                self._record_parsed_article(identifier)
            if changed:
                self._persist_progress()
            self._sleep()

    def scrape_TheHackerNews(self):    self.ingest_feed("The Hacker News")
    def scrape_BleepingComputer(self): self.ingest_feed("Bleeping Computer")
    def scrape_DarkReading(self):      self.ingest_feed("Dark Reading")
    def scrape_Huntress(self):         self.ingest_huntress()
    def scrape_all(self):
        print("Starting cybersecurity news scrape...\n")
        combined_feeds = []
        combined_feeds.extend(self.Feeds.items())
        combined_feeds.extend(self.DarkWebFeeds.items())
        for source, meta in combined_feeds:
            try:
                self.ingest_feed(source, meta)
            except Exception as exc:
                print(f"Error ingesting {source}: {exc}")
        self._persist_progress(force_html=True)
        print(f"\n✓ Total articles scraped: {len(self.articles)}")
        return self.articles

    @staticmethod
    def sendMail(FROM, TO, SUB, TXT, SRV):
        import smtplib
        message = f"Subject: {SUB}\n\n{TXT}"
        server = smtplib.SMTP(SRV)
        server.sendmail(FROM, TO, message)
        server.quit()

    def save_to_json(self, filename=None):
        if not self.articles:
            print("No articles to save!")
            return
        target = Path(filename) if filename else self.data_file
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('w', encoding='utf-8') as f:
            json.dump(self.articles, f, indent=2, ensure_ascii=False)
        print(f"✓ Saved JSON to {target}")

    def save_to_csv(self, filename=None):
        target = Path(filename) if filename else Path(datetime.now().strftime('cybersec_news_%Y%m%d_%H%M%S.csv'))
        if not self.articles:
            print("No articles to save!")
            return
        fieldnames = [
            'source', 'sources', 'title', 'CVEs', 'date', 'notes', 'article',
            'AI-Summary', 'iocs', 'ThreatActors', 'TTPs', 'contents', 'tags'
        ]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for article in self.articles:
                row = {}
                for field in fieldnames:
                    value = article.get(field)
                    if field == 'sources':
                        sources_value = article.get('sources') or []
                        if isinstance(sources_value, list):
                            formatted = []
                            for entry in sources_value:
                                if isinstance(entry, dict):
                                    name = (entry.get('name') or '').strip()
                                    url = (entry.get('url') or '').strip()
                                    if name and url:
                                        formatted.append(f"{name} ({url})")
                                    elif url:
                                        formatted.append(url)
                                    elif name:
                                        formatted.append(name)
                                elif entry:
                                    formatted.append(str(entry))
                            value = '; '.join(formatted)
                        else:
                            value = str(sources_value)
                    elif isinstance(value, (list, dict)):
                        value = json.dumps(value, ensure_ascii=False)
                    row[field] = value
                writer.writerow(row)
        print(f"✓ Saved CSV to {target}")

    def save_to_html(self, filename=None):
        if not self.articles:
            print("No articles to save!")
            return
        target = Path(filename) if filename else self.html_output_file
        build_html(self.articles, target)

    def print_summary(self):
        if not self.articles:
            print("No articles found!"); return
        print("\n" + "="*80)
        print("CYBERSECURITY NEWS SUMMARY")
        print("="*80 + "\n")
        for i, a in enumerate(self.articles[:100], 1):
            source_label = a.get('source') or 'Unknown source'
            title_label = a.get('title') or 'Untitled'
            print(f"{i}. [{source_label}] {title_label}")
            primary_link = a.get('article')
            if not primary_link:
                sources = a.get('sources') or []
                for entry in sources:
                    if isinstance(entry, dict) and entry.get('url'):
                        primary_link = entry['url']
                        break
            if primary_link:
                print(f"   {primary_link}")
            summary_preview = (a.get('AI-Summary') or '')[:150]
            if summary_preview:
                print(f"   {summary_preview}...\n")


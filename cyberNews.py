import gzip
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
import lmstudio as lms
import json,re
from markdownify import markdownify as md
from pathlib import Path

class CyberSecScraper:
    def __init__(self):
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
            Summarize the input in ≤100 words, focusing strictly on cybersecurity content.

            Output:
            Return a single valid JSON object (no extra text).  
            Include these fields exactly:

            {
            "summary": string,
            "iocs": [string] | null,
            "ttps": [string] | null,
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
            - Confidence must reflect extraction certainty (0–1).
            - Ensure valid JSON format with double quotes, no trailing commas, and no explanation text.
        """
        self.aiModel = "qwen/qwen3-4b-2507"
        base_dir = Path(__file__).resolve().parent
        self.data_file = base_dir / "cybersec_news.json"
        self.html_output_file = base_dir / "index.html"
        self.articles = []
        self.parsed_articles_file = base_dir / "ParsedArticles.txt"
        self.parsed_articles = self._load_parsed_articles()
        self._load_existing_articles()
        self.html_update_interval = 10
        self._articles_since_html = 0
        self.KeyWords = [
            " cybersecurity ", " infosec ", " cyber attack ", " threat ", " exploit ", " vulnerability ",
            " patch ", " malware ", " ransomware ", " phishing ", " spyware ", " trojan ", " botnet ",
            " data breach ", " encryption ", " zero-day ", " zero day ", " backdoor ", " payload ", " IOC ", " MITRE ",
            " CVE ", " CISA ", " alert ", " exposure ",
            " APT ", " nation-state ", " Lazarus ", " Sandworm ", " FIN7 ", " UNC ", " TA ", " threat actor ",
            " campaign ", " TTP ", " C2 ", " beacon ", " exfiltration ", " persistence ",
            " lateral movement ", " initial access ", " privilege escalation ", " defense evasion ",
            " forensics ", " incident response ", " timeline ", " volatile data ", " triage ", " memory dump ",
            " prefetch ", " SRUM ", " jumplist ", " shellbags ", " MFT ", " registry ", " evidence ",
            " acquisition ", " imaging ", " chain of custody ", " analysis ", " SIEM ", " Sentinel ",
            " Splunk ", " Volatility ", " forensic artifact ", " log analysis ", " timeline reconstruction ",
            " SOC ", " detection ", " logging ", " EDR ", " XDR ", " MDR ", " alerting ", " correlation ",
            " automation ", " SOAR ", " endpoint ", " network ", " firewall ", " IDS ", " IPS ", " honeypot ",
            " defender ", " sentinelone ", " crowdstrike ", " elastic ", " detection rule ", " telemetry ",
            " PoC ", " RCE ", " LPE ", " buffer overflow ", " injection ", " CVSS ",
            " patch Tuesday ", " Metasploit ", " fuzzing ", " sandbox ", " patch management ",
            " bug bounty ", " responsible disclosure ", " vulnerability research ",
            " reverse engineering ", " disassembly ", " static analysis ", " dynamic analysis ", " IDA Pro ",
            " Ghidra ", " strings ", " yara ", " unpacking ", " obfuscation ", " deobfuscation ",
            " C2 traffic ", " command and control ", " API hooking ", " process injection ", " PE file ",
            " persistence mechanism ", " malware family ", " unpacker ", " signature ", " behavioral analysis ",
            " pentest ", " penetration test ", " red team ", " blue team ", " purple team ", " recon ",
            " enumeration ", " Cobalt Strike ", " mimikatz ", " bloodhound ", " nmap ", " burpsuite ",
            " phishing campaign ", " attack simulation ", " adversary emulation ", " foothold ", " post exploitation ",
            " packet capture ", " Wireshark ", " DNS ", " HTTPS ", " TLS ", " MITM ", " VPN ", " cloud ",
            " AWS ", " Azure ", " GCP ", " Kubernetes ", " Docker ", " IAM ", " zero trust ", " SASE ",
            " compliance ", " NIST ", " ISO ", " CIS ", " SOC2 ", " audit ", " GDPR ", " HIPAA ", " CCPA ",
            " DORA ", " policy ", " standard ", " regulation ", " procedure ", " risk management ",
            " AI ", " LLM ", " machine learning ", " adversarial ML ", " prompt injection ", " supply chain attack ",
            " #MITRE ", " #CVE ", " #TTP ", " #IOC ", " #APTGroup ", " #ThreatIntel ", " #Ransomware ",
            " #Malware ", " #Exploit ", " #DFIR ", " #Detection ", " #CloudSecurity ", " #AIThreats ",
            " #Policy ", " #Compliance ", " #Phishing ", " #SOC ", " #IncidentResponse "
        ]
        self.Feeds = {
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews?format=xml",
            "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
            "Dark Reading": "https://www.darkreading.com/rss.xml",
            "SecurityWeek": "https://www.securityweek.com/feed/",
            "Krebs on Security": "https://krebsonsecurity.com/feed/",
            "Threatpost": "https://threatpost.com/feed/",
            "SC Media Threats": "https://www.scmagazine.com/rss/category/threats",
            "CISA Alerts": "https://www.cisa.gov/uscert/ncas/alerts.xml",
            "CISA Current Activity": "https://www.cisa.gov/uscert/ncas/current-activity.xml",
            "CISA Bulletins": "https://www.cisa.gov/uscert/ncas/bulletins.xml",
            "US-CERT Vulnerability Notes": "https://kb.cert.org/vuls/rss/rss.xml",
            "NVD NIST": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "Microsoft Security Response Center": "https://msrc-blog.microsoft.com/feed/",
            "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
            "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
            "Unit 42": "https://unit42.paloaltonetworks.com/feed/",
            "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
            "Proofpoint": "https://www.proofpoint.com/us/blog/rss.xml",
            "Sophos News": "https://news.sophos.com/en-us/feed/",
            "ESET WeLiveSecurity": "https://www.welivesecurity.com/feed/",
            "Check Point Research": "https://research.checkpoint.com/feed/",
            "Rapid7": "https://www.rapid7.com/blog/rss/",
            "Recorded Future": "https://www.recordedfuture.com/blog/rss",
            "Bitdefender Labs": "https://www.bitdefender.com/blog/api/rss/labs/",
            "Google Cloud Security": "https://cloud.google.com/blog/topics/inside-google-cloud/feed",
            "AWS Security": "https://aws.amazon.com/blogs/security/feed/",
            "IBM Security Intelligence": "https://securityintelligence.com/feed/",
            "Naked Security by Sophos": "https://nakedsecurity.sophos.com/feed/",
            "Fortinet Blog": "https://www.fortinet.com/blog/rss",
            "Malwarebytes Labs": "https://www.malwarebytes.com/blog/feed",
            "Trend Micro Research": "https://www.trendmicro.com/vinfo/us/security/rss",
            "Zero Day Initiative": "https://www.zerodayinitiative.com/blog?format=rss",
            "Qualys": "https://blog.qualys.com/feed",
            "VMware Security Advisories": "https://www.vmware.com/security/advisories.xml",
            "Oracle Critical Patch Updates": "https://www.oracle.com/a/ocom/docs/rss/oracle-critical-patch-updates.xml",
            "SAP Security Patch Day": "https://wiki.scn.sap.com/wiki/pages/viewrecentblogposts.action?key=266488969",
            "F5 Security Advisories": "https://support.f5.com/csp/rss/feed.xml",
            "Juniper Security Advisories": "https://services.netscreen.com/documentation/JuniperNetworksSecurityAdvisories.xml",
            "Cisco Security Advisories": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
            "Adobe Security Bulletins": "https://helpx.adobe.com/security/atom.xml",
            "Google Chrome Releases": "https://chromereleases.googleblog.com/feeds/posts/default",
            "USENIX Security": "https://www.usenix.org/aggregator/security/feed",
            "CERT-EU": "https://cert.europa.eu/publico/updates-en.atom",
            "GovCERT.ch": "https://www.govcert.admin.ch/blog/feed/",
            "Australian Cyber Security Centre": "https://www.cyber.gov.au/acsc/view-all-content/alerts/rss.xml",
            "Canadian Centre for Cyber Security": "https://www.cyber.gc.ca/en/rss/advisories-alerts",
            "ENISA": "https://www.enisa.europa.eu/rss/news"
        }
        self.urls = {
            "Huntress Blog": "https://www.huntress.com/blog"
        }
    
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

    def _load_parsed_articles(self):
        parsed = set()
        try:
            if not self.parsed_articles_file.exists():
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

        self.articles = data
        print(f"Loaded {len(self.articles)} articles from {self.data_file}")

        for article in self.articles:
            identifier = self._article_identifier(
                article.get("source"),
                article.get("title"),
                article.get("article") or article.get("link"),
            )
            if identifier and identifier not in self.parsed_articles:
                self._record_parsed_article(identifier)

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
            with self.parsed_articles_file.open("a", encoding="utf-8") as f:
                f.write(identifier + "\n")
        except Exception as exc:
            print(f"Warning: Could not update parsed articles file: {exc}")

    def _persist_progress(self, force_html=False):
        try:
            self.save_to_json()
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

    def _tag(self, title, body):
        hay = f" {title.lower()} \n {body.lower()} "
        found = [k for k in self.KeyWords if k.strip().lower() in hay]
        seen, out = set(), []
        for k in found:
            ks = k.strip().lower()
            if ks not in seen:
                seen.add(ks); out.append(k)
        return " ".join(out)

    def maybe_fetch_html(self, url, referer=None, max_attempts=3, debug=False):
        scraper = cloudscraper.create_scraper()
        headers = self.sess.headers.copy()
        if referer:
            headers["Referer"] = referer
        attempt = 0
        while attempt < max_attempts:
            try:
                if _HAS_CLOUDSCRAPER:
                    resp = scraper.get(url, headers=headers, timeout=15)
                else:
                    resp = self.sess.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    html = self._decode_html(resp)
                    return html
                else:
                    if debug:
                        print(f"Warning: Received status code {resp.status_code} for URL: {url}")
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

    def ingest_feed(self, source):
        try:
            feed = feedparser.parse(self.Feeds[source])
        except Exception as exc:
            print(f"Failed to parse feed {source}: {exc}")
            return

        entries = getattr(feed, "entries", [])
        if not entries:
            print(f"No entries discovered for {source} (URL: {self.Feeds[source]})")
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
            if not body and link:
                html = self.maybe_fetch_html(link, referer=self.Feeds[source], debug=True)
                if html:
                    soup = BeautifulSoup(html, "html.parser")
                    elements = soup.select('article p, article li, article h1, article h2, article h3, article h4, article h5, article h6')
                    if not elements:
                        elements = soup.find_all(['p', 'li'])
                    body = "\n".join(el.get_text(" ", strip=True) for el in elements if el.get_text(strip=True))
            if not body:
                self._sleep()
                continue
            body = body.strip()
            if not body:
                self._sleep()
                continue

            ai_payload = {}
            ai_summary_text = ""
            try:
                ai_response = self._summarize(body[:6000])
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
            tags = self._tag(title, body + "\n" + ai_summary_text)

            categories = self._categorize_article(title, ai_summary_text, body, tags, cves, threatactors)
            primary_category = categories[0] if categories else "General"

            self.articles.append({
                    "source": source,
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
                    "primary_category": primary_category
                })
            if identifier:
                self._record_parsed_article(identifier)
            self._persist_progress()
            self._sleep()

    def scrape_TheHackerNews(self):    self.ingest_feed("The Hacker News")
    def scrape_BleepingComputer(self): self.ingest_feed("Bleeping Computer")
    def scrape_DarkReading(self):      self.ingest_feed("Dark Reading")
    def scrape_Huntress(self):         self.ingest_huntress()
    def scrape_all(self):
        print("Starting cybersecurity news scrape...\n")
        for source in self.Feeds:
            try:
                self.ingest_feed(source)
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

    def save_to_csv(self):
        filename = datetime.now().strftime('cybersec_news_%Y%m%d_%H%M%S.csv')
        if not self.articles:
            print("No articles to save!"); return
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'source','title','CVEs','date','notes','article','AI-Summary','iocs','ThreatActors','TTPs','contents','tags'
            ])
            writer.writeheader(); writer.writerows(self.articles)
        print(f"✓ Saved to {filename}")

    def save_to_html(self, filename=None):
        if not self.articles:
            print("No articles to save!"); return

        target = Path(filename) if filename else self.html_output_file
        target.parent.mkdir(parents=True, exist_ok=True)

        def _raw_text(value):
            if value is None:
                return ""
            if isinstance(value, list):
                return ", ".join(str(v) for v in value)
            if isinstance(value, dict):
                return json.dumps(value, ensure_ascii=False)
            return str(value)

        def _ensure_list(value):
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

        def _slugify(value):
            value = (value or "").strip().lower()
            if not value:
                return "general"
            slug = "".join(ch if ch.isalnum() else "-" for ch in value)
            slug = "-".join(part for part in slug.split("-") if part)
            return slug or "general"

        def _attr(value):
            if value is None:
                return ""
            return escape(str(value), quote=True)

        category_seed = [
            "Zero Day",
            "Active Exploitation",
            "Vulnerabilities",
            "Ransomware",
            "APT Activity",
            "General",
        ]
        category_order = []
        seen_categories = set()
        for label in category_seed:
            if label not in seen_categories:
                seen_categories.add(label)
                category_order.append(label)

        cards_by_category = {label: [] for label in category_order}
        sources = set()

        for idx, article in enumerate(self.articles):
            source_raw = _raw_text(article.get('source', 'Unknown Source')) or 'Unknown Source'
            source_label = source_raw.strip() or 'Unknown Source'
            source_attr = _attr(source_label)
            date_label = escape(_raw_text(article.get('date', '')).strip())
            summary_text = _raw_text(article.get('AI-Summary', '')).strip()
            if not summary_text:
                summary_text = 'No AI summary available yet.'
            summary_snippet = summary_text if len(summary_text) <= 280 else summary_text[:277].rstrip() + '…'
            summary_snippet = escape(summary_snippet)

            tags_text = _raw_text(article.get('tags', '')).strip()
            tags_markup = escape(tags_text) if tags_text else ''

            cves_list = _ensure_list(article.get('CVEs'))
            threatactors_list = _ensure_list(article.get('ThreatActors'))
            ttps_list = _ensure_list(article.get('TTPs'))
            iocs_list = _ensure_list(article.get('iocs'))

            cve_count = len(cves_list)
            actor_count = len(threatactors_list)
            ttp_count = len(ttps_list)
            ioc_count = len(iocs_list)

            categories = article.get('categories') or []
            primary_category = article.get('primary_category') or (categories[0] if categories else 'General')
            if not categories:
                categories = [primary_category]

            for cat in categories:
                if cat not in seen_categories:
                    seen_categories.add(cat)
                    category_order.append(cat)
            if primary_category not in seen_categories:
                seen_categories.add(primary_category)
                category_order.append(primary_category)

            category_slugs = [_slugify(cat) for cat in categories]
            primary_slug = _slugify(primary_category)
            if primary_category not in cards_by_category:
                cards_by_category[primary_category] = []

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

            footer_markup = ''.join(stats) if stats else "<span class=\"feed-card__stat feed-card__stat--muted\">No enrichment metadata available</span>"

            search_values = [
                _raw_text(article.get('title', '')),
                summary_text,
                _raw_text(article.get('notes', '')),
                _raw_text(article.get('contents', '')),
                tags_text,
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

            cards_by_category[primary_category].append(card_html)
            sources.add(source_label)

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

        cards_markup = "\n        ".join(card_sections) if card_sections else "<p class=\"card-empty\">No articles available yet.</p>"
        article_count = len(self.articles)
        article_count_label = f"{article_count} item{'s' if article_count != 1 else ''}"

        sources = sorted(s for s in sources if s)
        source_size = min(max(len(sources), 1), 8)
        source_options = "\n            ".join(
            f"<option value=\"{_attr(source)}\">{escape(source)}</option>" for source in sources
        ) if sources else "<option value=\"\" disabled>No sources available</option>"

        category_filter_markup = "\n            ".join(
            f"<label class=\"filter-panel__checkbox\">"
            f"<input type=\"checkbox\" name=\"category\" value=\"{_attr(_slugify(category))}\" data-label=\"{_attr(category)}\" checked>"
            f"<span>{escape(category)}</span>"
            f"</label>"
            for category in available_categories
        ) if available_categories else "<p class=\"filter-panel__empty\">No category filters available.</p>"

        articles_json = json.dumps(self.articles, ensure_ascii=False)
        articles_json = articles_json.replace('</', '<' + '\\' + '/')

        css = """
:root {
  color-scheme: dark;
  --surface-primary: #0f172a;
  --surface-elevated: rgba(30, 41, 59, 0.85);
  --surface-border: rgba(148, 163, 184, 0.18);
  --accent: #38bdf8;
  --accent-muted: rgba(56, 189, 248, 0.18);
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-subtle: #64748b;
  --font-base: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  font-family: var(--font-base);
  background: radial-gradient(circle at 20% 20%, rgba(56, 189, 248, 0.12), transparent 45%),
              radial-gradient(circle at 80% 0%, rgba(99, 102, 241, 0.15), transparent 50%),
              var(--surface-primary);
  color: var(--text-primary);
  display: flex;
  flex-direction: column;
}

header {
  padding: clamp(1.25rem, 2vw, 2.5rem) clamp(1.25rem, 4vw, 3rem) 1rem;
}

.page-title {
  margin: 0;
  font-size: clamp(1.65rem, 2.5vw, 2.35rem);
  font-weight: 600;
  letter-spacing: 0.01em;
}

.page-subtitle {
  margin-top: 0.35rem;
  font-size: clamp(0.95rem, 1.5vw, 1.05rem);
  color: var(--text-secondary);
  max-width: 70ch;
}

main {
  flex: 1;
  display: flex;
  flex-direction: row;
  gap: clamp(1rem, 2vw, 2rem);
  padding: 0 clamp(1.25rem, 3vw, 3rem) clamp(1.5rem, 4vw, 3rem);
  overflow: hidden;
}

.card-column {
  flex: 0 0 38%;
  max-width: 520px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  border-right: 1px solid var(--surface-border);
  padding-right: clamp(1rem, 2vw, 1.5rem);
}

.card-column__header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.75rem;
}

.card-column__title {
  font-size: 0.95rem;
  letter-spacing: 0.08em;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-secondary);
}

.card-column__count {
  font-size: 0.85rem;
  color: var(--text-subtle);
}

.filter-panel {
  margin-top: clamp(0.75rem, 1vw, 1rem);
  margin-bottom: clamp(1rem, 2vw, 1.5rem);
  display: flex;
  flex-direction: column;
  gap: clamp(0.9rem, 1.3vw, 1.35rem);
  padding: clamp(1rem, 2vw, 1.35rem);
  background: linear-gradient(135deg, rgba(15, 23, 42, 0.85), rgba(15, 23, 42, 0.65));
  border-radius: 20px;
  border: 1px solid rgba(148, 163, 184, 0.14);
  box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.35);
}

.filter-panel__group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-panel__label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-secondary);
}

.filter-panel__input,
.filter-panel__select {
  width: 100%;
  padding: 0.6rem 0.75rem;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.65);
  color: var(--text-primary);
  font-size: 0.9rem;
  font-family: inherit;
}

.filter-panel__input:focus,
.filter-panel__select:focus {
  border-color: var(--accent);
  outline: none;
  box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
}

.filter-panel__select {
  min-height: clamp(3rem, 6vw, 8rem);
}

.filter-panel__hint {
  margin: 0;
  font-size: 0.72rem;
  color: var(--text-subtle);
}

.filter-panel__hint code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  background: rgba(148, 163, 184, 0.2);
  color: var(--accent);
  padding: 0.1rem 0.3rem;
  border-radius: 6px;
}

.filter-panel__checkboxes {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.filter-panel__checkboxes--toggles {
  gap: 0.6rem;
}

.filter-panel__checkbox {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.35rem 0.65rem;
  border-radius: 999px;
  background: rgba(51, 65, 85, 0.45);
  border: 1px solid rgba(148, 163, 184, 0.25);
  font-size: 0.78rem;
  color: var(--text-secondary);
  letter-spacing: 0.02em;
}

.filter-panel__checkbox input {
  accent-color: var(--accent);
}

.filter-panel__empty {
  margin: 0;
  font-size: 0.82rem;
  color: var(--text-subtle);
}

.filter-panel__group--toggles {
  gap: 0.35rem;
}

.filter-toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
  background: rgba(15, 23, 42, 0.55);
  padding: 0.35rem 0.6rem;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.2);
  width: fit-content;
}

.filter-toggle input {
  accent-color: var(--accent);
}

.filter-panel__actions {
  display: flex;
  justify-content: flex-end;
}

#filter-reset {
  padding: 0.5rem 1rem;
  border-radius: 999px;
  border: 1px solid rgba(56, 189, 248, 0.4);
  background: transparent;
  color: var(--accent);
  font-weight: 600;
  font-size: 0.82rem;
  letter-spacing: 0.02em;
  cursor: pointer;
  transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
}

#filter-reset:hover,
#filter-reset:focus-visible {
  background: rgba(56, 189, 248, 0.2);
  color: #0f172a;
  outline: none;
}

.card-groups {
  display: flex;
  flex-direction: column;
  gap: clamp(1rem, 1.8vw, 1.5rem);
  flex: 1;
  overflow-y: auto;
  padding-right: clamp(0.15rem, 1vw, 0.35rem);
}

.card-category {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.card-category__header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.card-category__title {
  margin: 0;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-secondary);
}

.card-category__count {
  font-size: 0.75rem;
  color: var(--text-subtle);
}

.card-category[hidden] {
  display: none !important;
}

.card-empty {
  font-size: 0.95rem;
  color: var(--text-secondary);
  margin: 0;
  padding: 0.5rem 0;
}

.card-list {
  display: flex;
  flex-direction: column;
  gap: clamp(0.75rem, 1.1vw, 1.15rem);
}

.feed-card {
  background: linear-gradient(135deg, rgba(30, 41, 59, 0.92), rgba(15, 23, 42, 0.92));
  border: 1px solid transparent;
  border-radius: 18px;
  padding: clamp(1rem, 2vw, 1.35rem);
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
  cursor: pointer;
  box-shadow: 0 18px 40px rgba(8, 15, 30, 0.55);
  transition: border-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
  outline: none;
}

.feed-card:hover,
.feed-card:focus-visible {
  border-color: var(--accent);
  transform: translateY(-4px);
  box-shadow: 0 22px 46px rgba(14, 32, 59, 0.55);
}

.feed-card--active {
  border-color: var(--accent);
  background: linear-gradient(135deg, rgba(8, 145, 178, 0.18), rgba(15, 23, 42, 0.92));
}

.feed-card__meta {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 0.75rem;
  color: var(--text-secondary);
  font-size: 0.85rem;
  letter-spacing: 0.01em;
}

.feed-card__source {
  font-weight: 600;
  color: var(--text-primary);
}

.feed-card__date {
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.feed-card__summary {
  margin: 0;
  font-size: clamp(0.95rem, 1.2vw, 1.05rem);
  line-height: 1.6;
  color: var(--text-primary);
}

.feed-card__footer {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 0.5rem;
  align-items: center;
}

.feed-card__category {
  font-size: 0.72rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--accent);
  background: rgba(56, 189, 248, 0.16);
  border-radius: 999px;
  padding: 0.25rem 0.65rem;
}

.feed-card__stat {
  font-size: 0.78rem;
  padding: 0.35rem 0.65rem;
  border-radius: 999px;
  background: rgba(148, 163, 184, 0.14);
  color: var(--text-secondary);
  letter-spacing: 0.02em;
}

.feed-card__stat--muted {
  background: rgba(51, 65, 85, 0.35);
  color: var(--text-subtle);
}

.feed-card__tagline {
  font-size: 0.75rem;
  color: var(--accent);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.detail-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding-bottom: clamp(1rem, 2.5vw, 2rem);
  min-width: 0;
}

.detail-panel__surface {
  background: linear-gradient(180deg, rgba(15, 23, 42, 0.92), rgba(15, 23, 42, 0.7));
  border-radius: 24px;
  border: 1px solid rgba(148, 163, 184, 0.12);
  padding: clamp(1.25rem, 2vw, 2rem);
  display: flex;
  flex-direction: column;
  gap: clamp(1.25rem, 1.5vw, 1.75rem);
  height: 100%;
  overflow: hidden;
  box-shadow: inset 0 0 0 1px rgba(148, 163, 184, 0.05);
}

.detail-panel__placeholder {
  margin: auto;
  text-align: center;
  max-width: 32ch;
  color: var(--text-secondary);
  font-size: 1rem;
  line-height: 1.7;
}

.detail-panel__content {
  display: flex;
  flex-direction: column;
  gap: clamp(1.25rem, 1.6vw, 1.85rem);
  overflow: hidden;
  flex: 1;
}

.detail-panel__header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  flex-wrap: wrap;
}

.detail-panel__meta {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.detail-panel__title {
  margin: 0;
  font-size: clamp(1.1rem, 1.8vw, 1.35rem);
  font-weight: 600;
  color: var(--text-primary);
}

.detail-panel__meta-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: baseline;
}

.detail-panel__source {
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--text-primary);
}

.detail-panel__date {
  font-size: 0.85rem;
  color: var(--text-secondary);
  font-variant-numeric: tabular-nums;
}

.detail-panel__link {
  padding: 0.55rem 1rem;
  border-radius: 999px;
  text-decoration: none;
  font-size: 0.85rem;
  font-weight: 600;
  background: rgba(56, 189, 248, 0.16);
  color: var(--accent);
  border: 1px solid rgba(56, 189, 248, 0.35);
  transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease;
}

.detail-panel__link:hover,
.detail-panel__link:focus-visible {
  background: rgba(56, 189, 248, 0.35);
  color: #0f172a;
  border-color: rgba(56, 189, 248, 0.55);
  outline: none;
}

.detail-panel__link.is-disabled {
  pointer-events: none;
  opacity: 0.45;
  border-color: rgba(148, 163, 184, 0.25);
  background: rgba(51, 65, 85, 0.35);
  color: var(--text-secondary);
}

.detail-panel__section {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.detail-panel__section h2,
.detail-panel__section h3 {
  margin: 0;
  font-size: 0.95rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-secondary);
}

.detail-panel__text {
  margin: 0;
  font-size: clamp(0.95rem, 1.15vw, 1.05rem);
  line-height: 1.75;
  color: var(--text-primary);
  white-space: pre-wrap;
}

.detail-panel__pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}

.detail-panel__pill {
  padding: 0.35rem 0.65rem;
  border-radius: 999px;
  background: rgba(56, 189, 248, 0.12);
  border: 1px solid rgba(56, 189, 248, 0.25);
  font-size: 0.78rem;
  letter-spacing: 0.02em;
  color: var(--accent);
}

.detail-panel__empty {
  font-size: 0.82rem;
  color: var(--text-subtle);
  font-style: italic;
}

.detail-panel__cve-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.detail-panel__cve {
  padding: 0.65rem 0.75rem;
  border-radius: 14px;
  border: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(30, 41, 59, 0.6);
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.detail-panel__cve-id {
  font-weight: 600;
  font-size: 0.9rem;
}

.detail-panel__cve-meta,
.detail-panel__cve-mitre {
  font-size: 0.78rem;
  color: var(--text-secondary);
}

.detail-panel__fulltext {
  padding: clamp(0.9rem, 1vw, 1.15rem);
  border-radius: 18px;
  border: 1px solid rgba(51, 65, 85, 0.65);
  background: rgba(15, 23, 42, 0.7);
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.85rem;
  line-height: 1.7;
  max-height: 28vh;
  overflow: auto;
  white-space: pre-wrap;
}

.detail-panel__fulltext::-webkit-scrollbar,
.card-groups::-webkit-scrollbar,
.card-list::-webkit-scrollbar {
  width: 10px;
}

.detail-panel__fulltext::-webkit-scrollbar-thumb,
.card-groups::-webkit-scrollbar-thumb,
.card-list::-webkit-scrollbar-thumb {
  background: rgba(148, 163, 184, 0.35);
  border-radius: 999px;
}

.detail-panel__fulltext::-webkit-scrollbar-track,
.card-groups::-webkit-scrollbar-track,
.card-list::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.35);
}

@media (max-width: 1080px) {
  main {
    flex-direction: column;
    padding: 0 clamp(1rem, 4vw, 2rem) clamp(1.5rem, 4vw, 3rem);
  }

  .card-column {
    flex: 1 1 auto;
    max-width: none;
    border-right: none;
    border-bottom: 1px solid var(--surface-border);
    padding-right: 0;
    padding-bottom: 1.5rem;
  }

  .detail-panel__fulltext {
    max-height: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: 0.001ms !important;
    animation-duration: 0.001ms !important;
  }
}
        """.strip()

        js = """
(function() {
  const dataNode = document.getElementById('article-data');
  if (!dataNode) {
    return;
  }
  let articles = [];
  try {
    articles = JSON.parse(dataNode.textContent || '[]');
  } catch (error) {
    console.error('Unable to parse article payload:', error);
    return;
  }

  const cards = Array.from(document.querySelectorAll('.feed-card'));
  const detailPanel = document.querySelector('.detail-panel');
  if (!detailPanel) {
    return;
  }
  const placeholder = detailPanel.querySelector('.detail-panel__placeholder');
  const content = detailPanel.querySelector('.detail-panel__content');

  const refs = {
    title: detailPanel.querySelector('[data-detail="title"]'),
    source: detailPanel.querySelector('[data-detail="source"]'),
    date: detailPanel.querySelector('[data-detail="date"]'),
    link: detailPanel.querySelector('[data-detail="article"]'),
    summary: detailPanel.querySelector('[data-detail="AI-Summary"]'),
    notes: detailPanel.querySelector('[data-detail="notes"]'),
    iocs: detailPanel.querySelector('[data-detail="iocs"]'),
    ttps: detailPanel.querySelector('[data-detail="TTPs"]'),
    actors: detailPanel.querySelector('[data-detail="ThreatActors"]'),
    cves: detailPanel.querySelector('[data-detail="CVEs"]'),
    contents: detailPanel.querySelector('[data-detail="contents"]')
  };

  function clearNode(node) {
    if (!node) {
      return;
    }
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function ensureArray(value) {
    if (Array.isArray(value)) {
      return value.filter((item) => item !== null && item !== undefined && item !== '');
    }
    if (value === null || value === undefined || value === '') {
      return [];
    }
    return [value];
  }

  function createPill(text) {
    const pill = document.createElement('span');
    pill.className = 'detail-panel__pill';
    pill.textContent = text;
    return pill;
  }

  function renderPills(container, values, emptyLabel) {
    if (!container) {
      return;
    }
    clearNode(container);
    const items = ensureArray(values);
    if (!items.length) {
      const empty = document.createElement('span');
      empty.className = 'detail-panel__empty';
      empty.textContent = emptyLabel;
      container.appendChild(empty);
      return;
    }
    items.forEach((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const pill = createPill(Object.values(item).join(' · '));
        container.appendChild(pill);
      } else {
        const pill = createPill(String(item));
        container.appendChild(pill);
      }
    });
  }

  function renderCves(container, values) {
    if (!container) {
      return;
    }
    clearNode(container);
    const items = ensureArray(values);
    if (!items.length) {
      const empty = document.createElement('li');
      empty.className = 'detail-panel__empty';
      empty.textContent = 'No CVEs reported.';
      container.appendChild(empty);
      return;
    }
    items.forEach((entry) => {
      const item = document.createElement('li');
      item.className = 'detail-panel__cve';
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        const id = document.createElement('div');
        id.className = 'detail-panel__cve-id';
        id.textContent = entry.cve || 'Unknown CVE';
        item.appendChild(id);

        const metaBits = [];
        if (entry.cvss || entry.cvss === 0) {
          metaBits.push(`CVSS ${entry.cvss}`);
        }
        if (typeof entry.exploited === 'boolean') {
          metaBits.push(entry.exploited ? 'Exploited' : 'Not confirmed exploited');
        }
        if (typeof entry.patch_available === 'boolean') {
          metaBits.push(entry.patch_available ? 'Patch available' : 'Patch unavailable');
        }
        if (entry.weaponization_stage) {
          metaBits.push(entry.weaponization_stage);
        }
        if (metaBits.length) {
          const meta = document.createElement('div');
          meta.className = 'detail-panel__cve-meta';
          meta.textContent = metaBits.join(' • ');
          item.appendChild(meta);
        }
        if (Array.isArray(entry.mapped_mitre_ids) && entry.mapped_mitre_ids.length) {
          const mitre = document.createElement('div');
          mitre.className = 'detail-panel__cve-mitre';
          mitre.textContent = `MITRE: ${entry.mapped_mitre_ids.join(', ')}`;
          item.appendChild(mitre);
        }
      } else {
        item.textContent = String(entry);
      }
      container.appendChild(item);
    });
  }

  function setText(node, value, fallback) {
    if (!node) {
      return;
    }
    const text = value === null || value === undefined || String(value).trim() === '' ? fallback : String(value);
    node.textContent = text;
  }

  function setFullText(node, value, fallback) {
    if (!node) {
      return;
    }
    if (value === null || value === undefined || String(value).trim() === '') {
      node.textContent = fallback;
    } else {
      node.textContent = String(value);
    }
  }

  function updateDetail(article) {
    if (!article) {
      return;
    }
    if (placeholder) {
      placeholder.style.display = 'none';
    }
    if (content) {
      content.hidden = false;
    }
    setText(refs.title, article.title || '', 'Untitled');
    setText(refs.source, article.source || 'Unknown source', 'Unknown source');
    setText(refs.date, article.date || '', 'Date unavailable');
    if (refs.link) {
      const href = article.article || '';
      if (href) {
        refs.link.href = href;
        refs.link.classList.remove('is-disabled');
        refs.link.textContent = 'Open original article';
      } else {
        refs.link.removeAttribute('href');
        refs.link.classList.add('is-disabled');
        refs.link.textContent = 'Link unavailable';
      }
    }
    setFullText(refs.summary, article['AI-Summary'], 'No AI summary available.');
    setFullText(refs.notes, article.notes, 'No analyst notes provided.');
    renderPills(refs.actors, article.ThreatActors, 'No threat actors identified.');
    renderPills(refs.ttps, article.TTPs, 'No tactics or techniques listed.');
    renderPills(refs.iocs, article.iocs, 'No indicators extracted.');
    renderCves(refs.cves, article.CVEs);
    setFullText(refs.contents, article.contents, 'No raw content captured for this item.');
  }


  let activeCard = null;
  const countLabel = document.querySelector('[data-count-label]') || document.querySelector('.card-column__count');
  const categorySections = Array.from(document.querySelectorAll('[data-category-section]'));
  const filterPanel = document.getElementById('feed-filter-panel');
  if (filterPanel) {
    filterPanel.addEventListener('submit', (event) => event.preventDefault());
  }
  const filters = {
    search: document.getElementById('filter-search'),
    source: document.getElementById('filter-source'),
    categories: Array.from(document.querySelectorAll('input[name="category"]')),
    cves: document.getElementById('filter-has-cves'),
    actors: document.getElementById('filter-has-actors'),
    iocs: document.getElementById('filter-has-iocs'),
    ttps: document.getElementById('filter-has-ttps')
  };
  const resetButton = document.getElementById('filter-reset');
  const defaultPlaceholderHTML = placeholder ? placeholder.innerHTML : '';

  function selectCard(card) {
    if (!card || card.hidden) {
      return;
    }
    if (activeCard) {
      activeCard.classList.remove('feed-card--active');
    }
    activeCard = card;
    activeCard.classList.add('feed-card--active');
    const index = Number(card.getAttribute('data-index'));
    const article = Number.isFinite(index) ? articles[index] : null;
    if (placeholder) {
      placeholder.style.display = 'none';
      placeholder.innerHTML = defaultPlaceholderHTML;
    }
    if (content) {
      content.hidden = false;
    }
    updateDetail(article);
  }

  function parseTokens(value) {
    if (!value) {
      return [];
    }
    const matches = value.match(/"[^"]+"|\S+/g) || [];
    return matches.map((token) => token.replace(/^"|"$/g, ''));
  }

  function matchesSearch(card, tokens) {
    if (!tokens.length) {
      return true;
    }
    const searchField = (card.dataset.search || '').toLowerCase();
    const sourceField = (card.dataset.source || '').toLowerCase();
    const categoryLabels = (card.dataset.categoryLabels || '').toLowerCase();
    const categorySlugs = (card.dataset.categories || '').toLowerCase();
    const tagsField = (card.dataset.tags || '').toLowerCase();

    return tokens.every((rawToken) => {
      const token = rawToken.toLowerCase();
      if (!token) {
        return true;
      }
      if (token.startsWith('source:')) {
        const query = token.slice(7).trim();
        return !query || sourceField.includes(query);
      }
      if (token.startsWith('category:')) {
        const query = token.slice(9).trim();
        if (!query) {
          return true;
        }
        const slugMatches = categorySlugs.split(' ').filter(Boolean);
        return slugMatches.includes(query) || categoryLabels.includes(query);
      }
      if (token.startsWith('tag:')) {
        const query = token.slice(4).trim();
        return !query || tagsField.includes(query);
      }
      return searchField.includes(token);
    });
  }

  function applyFilters() {
    const categoryCheckboxes = filters.categories || [];
    const activeCategoryValues = categoryCheckboxes
      .filter((checkbox) => checkbox.checked)
      .map((checkbox) => checkbox.value);
    const shouldFilterByCategory = activeCategoryValues.length > 0 && activeCategoryValues.length < categoryCheckboxes.length;
    const selectedSources = Array.from(filters.source?.selectedOptions || [])
      .map((option) => option.value)
      .filter((value) => value);
    const tokens = parseTokens(filters.search?.value.trim() || '');
    const requireCves = Boolean(filters.cves?.checked);
    const requireActors = Boolean(filters.actors?.checked);
    const requireIocs = Boolean(filters.iocs?.checked);
    const requireTtps = Boolean(filters.ttps?.checked);

    let visibleCount = 0;
    let firstVisibleCard = null;

    cards.forEach((card) => {
      const dataset = card.dataset || {};
      const categories = (dataset.categories || '').split(' ').filter(Boolean);
      const hasCategory = !shouldFilterByCategory || categories.some((value) => activeCategoryValues.includes(value));
      const matchesSource = !selectedSources.length || selectedSources.includes(dataset.source || '');
      const hasCves = dataset.hasCves === 'true';
      const hasActors = dataset.hasActors === 'true';
      const hasIocs = dataset.hasIocs === 'true';
      const hasTtps = dataset.hasTtps === 'true';
      const searchMatch = matchesSearch(card, tokens);

      let visible = hasCategory && matchesSource && searchMatch;
      if (requireCves && !hasCves) visible = false;
      if (requireActors && !hasActors) visible = false;
      if (requireIocs && !hasIocs) visible = false;
      if (requireTtps && !hasTtps) visible = false;

      card.hidden = !visible;

      if (visible) {
        visibleCount += 1;
        if (!firstVisibleCard) {
          firstVisibleCard = card;
        }
      }
    });

    categorySections.forEach((section) => {
      const visibleCards = Array.from(section.querySelectorAll('.feed-card')).filter((card) => !card.hidden);
      const visibleInSection = visibleCards.length;
      const countNode = section.querySelector('.card-category__count');
      if (countNode) {
        countNode.textContent = `${visibleInSection} item${visibleInSection === 1 ? '' : 's'}`;
      }
      section.hidden = visibleInSection === 0;
    });

    if (countLabel) {
      countLabel.textContent = `${visibleCount} item${visibleCount === 1 ? '' : 's'}`;
    }

    if (visibleCount === 0) {
      if (content) {
        content.hidden = true;
      }
      if (placeholder) {
        placeholder.innerHTML = '<p>No articles match your filters yet. Adjust your filters or try a different search term.</p>';
        placeholder.style.display = 'block';
      }
      if (activeCard) {
        activeCard.classList.remove('feed-card--active');
        activeCard = null;
      }
      return;
    }

    if (placeholder) {
      placeholder.innerHTML = defaultPlaceholderHTML;
      placeholder.style.display = 'none';
    }

    if (activeCard && activeCard.hidden) {
      activeCard.classList.remove('feed-card--active');
      activeCard = null;
    }

    if (!activeCard && firstVisibleCard) {
      selectCard(firstVisibleCard);
    }
  }

  cards.forEach((card) => {
    card.addEventListener('click', () => selectCard(card));
    card.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectCard(card);
      }
    });
  });

  const filterInputs = [
    filters.search,
    filters.source,
    filters.cves,
    filters.actors,
    filters.iocs,
    filters.ttps,
    ...(filters.categories || [])
  ].filter(Boolean);

  filterInputs.forEach((input) => {
    const eventName = input === filters.search ? 'input' : 'change';
    input.addEventListener(eventName, () => applyFilters());
  });

  if (resetButton) {
    resetButton.addEventListener('click', () => {
      if (filters.search) {
        filters.search.value = '';
      }
      if (filters.source) {
        Array.from(filters.source.options).forEach((option) => {
          option.selected = false;
        });
      }
      (filters.categories || []).forEach((checkbox) => {
        checkbox.checked = true;
      });
      if (filters.cves) filters.cves.checked = false;
      if (filters.actors) filters.actors.checked = false;
      if (filters.iocs) filters.iocs.checked = false;
      if (filters.ttps) filters.ttps.checked = false;
      applyFilters();
    });
  }

  applyFilters();

})();
        """.strip()

        html_doc = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Cybersecurity News Feed</title>
  <style>
{css}
  </style>
</head>
<body>
  <header>
    <h1 class=\"page-title\">Cybersecurity Intelligence Briefing</h1>
    <p class=\"page-subtitle\">Review AI-powered digests of the latest security headlines. Select a card to reveal the enriched intelligence, indicators, and primary source material.</p>
  </header>
  <main>
    <section class=\"card-column\" aria-label=\"Summarised articles\">
      <div class=\"card-column__header\">
        <span class=\"card-column__title\">AI summaries</span>
        <span class=\"card-column__count\" data-count-label>{article_count_label}</span>
      </div>
      <form class=\"filter-panel\" id=\"feed-filter-panel\" aria-label=\"Feed filters\" autocomplete=\"off\">
        <div class=\"filter-panel__group filter-panel__group--search\">
          <label class=\"filter-panel__label\" for=\"filter-search\">Search</label>
          <input class=\"filter-panel__input\" type=\"search\" id=\"filter-search\" name=\"search\" placeholder=\"Search summaries, notes, actors…\">
          <p class=\"filter-panel__hint\">Supports tokens such as <code>source:</code>, <code>category:</code>, and <code>tag:</code>.</p>
        </div>
        <div class=\"filter-panel__group\">
          <span class=\"filter-panel__label\">Categories</span>
          <div class=\"filter-panel__checkboxes\">
            {category_filter_markup}
          </div>
        </div>
        <div class=\"filter-panel__group\">
          <label class=\"filter-panel__label\" for=\"filter-source\">Sources</label>
          <select class=\"filter-panel__select\" id=\"filter-source\" name=\"source\" multiple size=\"{source_size}\">
            {source_options}
          </select>
          <p class=\"filter-panel__hint\">Hold Ctrl/Cmd to select multiple sources.</p>
        </div>
        <div class=\"filter-panel__group filter-panel__group--toggles\">
          <span class=\"filter-panel__label\">Data enrichment</span>
          <div class=\"filter-panel__checkboxes filter-panel__checkboxes--toggles\">
            <label class=\"filter-toggle\"><input type=\"checkbox\" id=\"filter-has-cves\"> CVEs only</label>
            <label class=\"filter-toggle\"><input type=\"checkbox\" id=\"filter-has-actors\"> Threat actors only</label>
            <label class=\"filter-toggle\"><input type=\"checkbox\" id=\"filter-has-iocs\"> IOCs only</label>
            <label class=\"filter-toggle\"><input type=\"checkbox\" id=\"filter-has-ttps\"> TTPs only</label>
          </div>
        </div>
        <div class=\"filter-panel__actions\">
          <button type=\"button\" id=\"filter-reset\">Reset filters</button>
        </div>
      </form>
      <div class=\"card-groups\">
        {cards_markup}
      </div>
    </section>
    <aside class=\"detail-panel\" aria-live=\"polite\" aria-label=\"Article detail\">
      <div class=\"detail-panel__surface\">
        <div class=\"detail-panel__placeholder\">
          <p>Select a summary on the left to explore full intelligence, enrichment data, and source material.</p>
        </div>
          <div class=\"detail-panel__content\" hidden>
            <div class=\"detail-panel__header\">
              <div class=\"detail-panel__meta\">
                <h2 class=\"detail-panel__title\" data-detail=\"title\"></h2>
                <div class=\"detail-panel__meta-row\">
                  <span class=\"detail-panel__source\" data-detail=\"source\"></span>
                  <span class=\"detail-panel__date\" data-detail=\"date\"></span>
                </div>
              </div>
              <a class=\"detail-panel__link\" data-detail=\"article\" target=\"_blank\" rel=\"noopener noreferrer\">Open original article</a>
          </div>
          <section class=\"detail-panel__section\">
            <h2>AI summary</h2>
            <p class=\"detail-panel__text\" data-detail=\"AI-Summary\"></p>
          </section>
          <section class=\"detail-panel__section\">
            <h3>Threat actors</h3>
            <div class=\"detail-panel__pill-list\" data-detail=\"ThreatActors\"></div>
          </section>
          <section class=\"detail-panel__section\">
            <h3>Techniques &amp; procedures</h3>
            <div class=\"detail-panel__pill-list\" data-detail=\"TTPs\"></div>
          </section>
          <section class=\"detail-panel__section\">
            <h3>Indicators of compromise</h3>
            <div class=\"detail-panel__pill-list\" data-detail=\"iocs\"></div>
          </section>
          <section class=\"detail-panel__section\">
            <h3>CVEs</h3>
            <ul class=\"detail-panel__cve-list\" data-detail=\"CVEs\"></ul>
          </section>
          <section class=\"detail-panel__section\">
            <h3>Analyst notes</h3>
            <p class=\"detail-panel__text\" data-detail=\"notes\"></p>
          </section>
          <section class=\"detail-panel__section\">
            <h3>Full content</h3>
            <div class=\"detail-panel__fulltext\" data-detail=\"contents\"></div>
          </section>
        </div>
      </div>
    </aside>
  </main>
  <script id=\"article-data\" type=\"application/json\">{articles_json}</script>
  <script>
{js}
  </script>
</body>
</html>
"""

        with target.open('w', encoding='utf-8') as f:
            f.write(html_doc)
        print(f"✓ Saved HTML to {target}")


    def save_to_json(self, filename=None):
        if not self.articles:
            print("No articles to save!"); return
        target = Path(filename) if filename else self.data_file
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('w', encoding='utf-8') as f:
            json.dump(self.articles, f, indent=2, ensure_ascii=False)
        print(f"✓ Saved JSON to {target}")

    def print_summary(self):
        if not self.articles:
            print("No articles found!"); return
        print("\n" + "="*80)
        print("CYBERSECURITY NEWS SUMMARY")
        print("="*80 + "\n")
        for i, a in enumerate(self.articles[:100], 1):
            print(f"{i}. [{a['source']}] {a['title']}")
            print(f"   {a['link']}")
            print(f"   {a['AI-Summary'][:150]}...\n")

if __name__ == "__main__":
    s = CyberSecScraper()
    s.scrape_all()
    s.save_to_csv()
    s.save_to_html()
    print("\n✓ Done!")

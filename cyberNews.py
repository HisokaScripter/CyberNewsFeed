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
        self.articles = []
        base_dir = Path(__file__).resolve().parent
        self.parsed_articles_file = base_dir / "ParsedArticles.txt"
        self.parsed_articles = self._load_parsed_articles()
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
            "Dark Reading": "https://www.darkreading.com/rss.xml"
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
        feed = feedparser.parse(self.Feeds[source])
        for entry in feed.entries:
            print("-"*120)
            print("Article count: ", len(self.articles)+1)
            print("Source: ", source )
            print("Title: ", getattr(entry, "title", ""))
            #if count <= 0:
            #    return
            #count -= 1
            title = getattr(entry, "title", "")
            link = getattr(entry, "link", "")
            published = getattr(entry, "published", getattr(entry, "updated", ""))
            identifier = self._article_identifier(source, title, link)
            if identifier and identifier in self.parsed_articles:
                print(f"Skipping previously parsed article: {title}")
                continue
            body = ""
            '''
            #if hasattr(entry, "summary"):
                body = BeautifulSoup(entry.summary, "html.parser").get_text(" ", strip=True)
            if not body and hasattr(entry, "content"):
                try:
                    body = BeautifulSoup(entry.content[0].value, "html.parser").get_text(" ", strip=True)
                except Exception:
                    pass
            '''
            if not body and link:
                html = self.maybe_fetch_html(link, referer=self.Feeds[source], debug=True)
                if html:
                    soup = BeautifulSoup(html, "html.parser")
                    #Body and headers strings
                    bodyandheadersstrings = soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
                    body = ""
                    for element in bodyandheadersstrings:
                        body += element.get_text(" ", strip=True) + "\n"
            if not body:
                self._sleep()
                continue
            summary = self._summarize(body)
            content = summary.content

            data = json.loads(content)
            summary = data.get("summary", "N/A")
            threatactors = data.get("threat_actors", [])
            iocs = data.get("iocs", [])
            ttps = data.get("ttps", [])
            cves = data.get("cves", [])
            notes = data.get("notes", "")
            print("Summary: ", summary)
            print("Threat Actors: ", threatactors)
            print("IOCs: ", iocs)
            print("TTPs: ", ttps)
            print("CVEs: ", cves)
            print("Notes: ", notes)
            print("Source: ", link)
            tags = self._tag(title, str(summary))

            self.articles.append({
                    "source": source,
                    "CVEs": cves,
                    "date": published,
                    "notes": notes,
                    "article": link,
                    "AI-Summary": summary,
                    "iocs": iocs,
                    "ThreatActors": threatactors,
                    "TTPs": ttps,
                    "contents": body,
                    "tags": tags
                })
            if identifier:
                self._record_parsed_article(identifier)
            self._sleep()

    def scrape_TheHackerNews(self):    self.ingest_feed("The Hacker News")
    def scrape_BleepingComputer(self): self.ingest_feed("Bleeping Computer")
    def scrape_DarkReading(self):      self.ingest_feed("Dark Reading")
    def scrape_Huntress(self):         self.ingest_huntress()
    def scrape_all(self):
        print("Starting cybersecurity news scrape...\n")
        self.scrape_BleepingComputer()
        self.scrape_TheHackerNews()
        self.scrape_DarkReading()
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
                'source','CVEs','date','notes','article','AI-Summary','iocs','ThreatActors','TTPs','contents','tags'
            ])
            writer.writeheader(); writer.writerows(self.articles)
        print(f"✓ Saved to {filename}")

    def save_to_html(self):
        if not self.articles:
            print("No articles to save!"); return

        filename = datetime.now().strftime('cybersec_news_%Y%m%d_%H%M%S.html')
        columns = ['source','CVEs','date','notes','article','AI-Summary','iocs','ThreatActors','TTPs','contents','tags']

        def _raw_text(value):
            if value is None:
                return ""
            if isinstance(value, list):
                return ", ".join(str(v) for v in value)
            if isinstance(value, dict):
                return json.dumps(value, ensure_ascii=False)
            return str(value)

        def _fmt_cell(value):
            return escape(_raw_text(value))

        def _wrap_cell(content, raw_text):
            safe_full = escape(raw_text, quote=True)
            return (
                f"<td data-full-text=\"{safe_full}\">"
                "<div class=\"cell-inner\">"
                f"<div class=\"cell-content\">{content}</div>"
                "<button type=\"button\" class=\"expand-button\" title=\"View full content\">View full</button>"
                "</div>"
                "</td>"
            )

        table_rows = []
        for article in self.articles:
            cells = []
            for col in columns:
                value = article.get(col, "")
                if col == 'article' and value:
                    safe_url = escape(str(value), quote=True)
                    content = f"<a href=\"{safe_url}\" target=\"_blank\" rel=\"noopener noreferrer\">{safe_url}</a>"
                    cell = _wrap_cell(content, _raw_text(value))
                else:
                    cell = _wrap_cell(_fmt_cell(value), _raw_text(value))
                cells.append(cell)
            table_rows.append(f"<tr>{''.join(cells)}</tr>")

        html_doc = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Cybersecurity News Feed</title>
  <link rel=\"stylesheet\" href=\"https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css\">
  <style>
    body {{ font-family: Arial, sans-serif; padding: 1.5rem; background: #0f172a; color: #e2e8f0; }}
    h1 {{ text-align: center; margin-bottom: 1.5rem; }}
    table.dataTable {{ border-collapse: collapse; width: 100%; table-layout: fixed; }}
    table.dataTable thead th {{ background: #1e293b; color: #f8fafc; }}
    table.dataTable tbody tr:nth-child(odd) {{ background: #1e293b; }}
    table.dataTable tbody tr:nth-child(even) {{ background: #0f172a; }}
    table.dataTable tbody td {{
      color: #e2e8f0;
      vertical-align: top;
      position: relative;
    }}
    table.dataTable thead th {{
      position: relative;
      user-select: none;
    }}
    .cell-inner {{
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      position: relative;
    }}
    .cell-content {{
      max-height: 150px;
      overflow: hidden;
      padding-right: 0.5rem;
      display: block;
      line-height: 1.4;
      position: relative;
    }}
    .cell-content::after {{
      content: "";
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 24px;
      background: linear-gradient(to bottom, rgba(15, 23, 42, 0) 0%, rgba(15, 23, 42, 0.95) 100%);
      pointer-events: none;
    }}
    td:not(.is-truncated) .cell-content::after {{
      display: none;
    }}
    td, th {{
      width: 220px;
      max-width: 500px;
      overflow: hidden;
    }}
    .expand-button {{
      display: none;
      align-self: flex-end;
      background: #38bdf8;
      color: #0f172a;
      border: none;
      border-radius: 999px;
      font-size: 0.75rem;
      padding: 0.35rem 0.9rem;
      cursor: pointer;
      font-weight: 600;
      transition: background 0.2s ease-in-out, color 0.2s ease-in-out;
    }}
    .expand-button:hover,
    .expand-button:focus {{
      background: #0ea5e9;
      color: #f8fafc;
      outline: none;
    }}
    td.is-truncated .expand-button {{
      display: inline-flex;
    }}
    .detail-modal {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }}
    .detail-modal.is-visible {{
      display: flex;
    }}
    .detail-modal__backdrop {{
      position: absolute;
      inset: 0;
      background: rgba(15, 23, 42, 0.85);
    }}
    .detail-modal__dialog {{
      position: relative;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 0.75rem;
      padding: 1.5rem;
      max-width: min(960px, 90vw);
      max-height: min(720px, 90vh);
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.7);
      overflow: hidden;
    }}
    .detail-modal__dialog h2 {{
      margin-top: 0;
      margin-bottom: 1rem;
    }}
    .detail-modal__content {{
      background: #1e293b;
      border-radius: 0.75rem;
      padding: 1rem;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: calc(90vh - 6rem);
      overflow: auto;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    }}
    .detail-modal__close {{
      position: absolute;
      top: 0.75rem;
      right: 0.75rem;
      border: none;
      background: transparent;
      color: #94a3b8;
      font-size: 1.75rem;
      line-height: 1;
      cursor: pointer;
      padding: 0.25rem;
    }}
    .detail-modal__close:hover,
    .detail-modal__close:focus {{
      color: #e2e8f0;
      outline: none;
    }}
    .column-resizer {{
      position: absolute;
      top: 0;
      right: 0;
      width: 6px;
      cursor: col-resize;
      user-select: none;
      height: 100%;
    }}
    .column-resizer::after {{
      content: "";
      position: absolute;
      top: 0;
      bottom: 0;
      left: 2px;
      width: 2px;
      background: rgba(148, 163, 184, 0.5);
      opacity: 0;
      transition: opacity 0.2s ease-in-out;
    }}
    th:hover .column-resizer::after {{
      opacity: 1;
    }}
    a {{ color: #38bdf8; }}
  </style>
</head>
<body>
  <h1>Cybersecurity News Feed</h1>
  <table id=\"cyber-news\" class=\"display\">
    <thead>
      <tr>{''.join(f'<th>{escape(col)}</th>' for col in columns)}</tr>
    </thead>
    <tbody>
      {''.join(table_rows)}
    </tbody>
  </table>
  <div id=\"detail-modal\" class=\"detail-modal\" role=\"dialog\" aria-modal=\"true\" aria-hidden=\"true\" tabindex=\"-1\">
    <div class=\"detail-modal__backdrop\" data-close-modal></div>
    <div class=\"detail-modal__dialog\">
      <button type=\"button\" class=\"detail-modal__close\" aria-label=\"Close\" data-close-modal>&times;</button>
      <h2>Full Entry</h2>
      <pre class=\"detail-modal__content\"></pre>
    </div>
  </div>
  <script src=\"https://code.jquery.com/jquery-3.7.1.min.js\"></script>
  <script src=\"https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js\"></script>
  <script>
    $(document).ready(function() {{
      const table = $('#cyber-news').DataTable({{
        pageLength: 25,
        order: [[2, 'desc']],
        responsive: true,
        autoWidth: false
      }});

      const $modal = $('#detail-modal');
      const $modalContent = $modal.find('.detail-modal__content');
      let previousFocus = null;

      function openModal(text) {{
        if (!text) {{
          return;
        }}
        previousFocus = document.activeElement;
        $modalContent.text(text);
        $modal.attr('aria-hidden', 'false').addClass('is-visible');
        $modal.focus();
      }}

      function closeModal() {{
        $modal.attr('aria-hidden', 'true').removeClass('is-visible');
        $modalContent.text('');
        if (previousFocus && typeof previousFocus.focus === 'function') {{
          previousFocus.focus();
        }}
        previousFocus = null;
      }}

      function markOverflowCells() {{
        $('#cyber-news tbody td').each(function() {{
          const content = $(this).find('.cell-content')[0];
          if (!content) {{
            return;
          }}
          const isOverflowing = content.scrollHeight - content.clientHeight > 1;
          $(this).toggleClass('is-truncated', isOverflowing);
        }});
      }}

      markOverflowCells();
      table.on('draw.dt', markOverflowCells);

      function setColumnWidth(index, width) {{
        const widthPx = `${{Math.max(width, 120)}}px`;
        $(table.column(index).header()).css('width', widthPx);
        table.column(index).nodes().to$().css('width', widthPx);
      }}

      table.columns().every(function(index) {{
        const header = $(this.header());
        const initialWidth = header.outerWidth() || 220;
        setColumnWidth(index, initialWidth);
        const resizer = $('<span class="column-resizer" title="Drag to resize"></span>');
        header.append(resizer);

        resizer.on('mousedown', function(event) {{
          event.preventDefault();
          event.stopPropagation();
          const startX = event.pageX;
          const startWidth = header.outerWidth();

          $(document).on('mousemove.columnResize', function(moveEvent) {{
            const delta = moveEvent.pageX - startX;
            setColumnWidth(index, startWidth + delta);
          }});

          $(document).on('mouseup.columnResize', function() {{
            $(document).off('.columnResize');
            markOverflowCells();
          }});
        }});
      }});

      $('#cyber-news tbody').on('click', '.expand-button', function(event) {{
        event.preventDefault();
        event.stopPropagation();
        const fullText = $(this).closest('td').data('full-text') || '';
        openModal(fullText);
      }});

      $('#cyber-news tbody').on('dblclick', 'td', function(event) {{
        if ($(event.target).is('a, button')) {{
          return;
        }}
        const fullText = $(this).data('full-text') || '';
        openModal(fullText);
      }});

      $modal.on('click', '[data-close-modal]', function(event) {{
        event.preventDefault();
        closeModal();
      }});

      $(document).on('keydown', function(event) {{
        if (event.key === 'Escape' && $modal.hasClass('is-visible')) {{
          closeModal();
        }}
      }});
    }});
  </script>
</body>
</html>
"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_doc)
        print(f"✓ Saved to {filename}")

    def save_to_json(self, filename='cybersec_news.json'):
        if not self.articles:
            print("No articles to save!"); return
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.articles, f, indent=2, ensure_ascii=False)
        print(f"✓ Saved to {filename}")

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
    print("Starting cybersecurity news scrape...\n")
    s.scrape_TheHackerNews()
    s.scrape_BleepingComputer()
    s.scrape_DarkReading()
    #s.scrape_Huntress()
    s.save_to_csv()
    s.save_to_html()
    print("\n✓ Done!")

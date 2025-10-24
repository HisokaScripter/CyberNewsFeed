import gzip
import os
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
        self.parsed_articles_file = "parsed_articles"
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
@@ -71,50 +75,72 @@ class CyberSecScraper:
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

    def _ensure_parsed_articles_file(self):
        if not os.path.exists(self.parsed_articles_file):
            with open(self.parsed_articles_file, "w", encoding="utf-8"):
                pass

    def _load_parsed_articles(self):
        self._ensure_parsed_articles_file()
        try:
            with open(self.parsed_articles_file, "r", encoding="utf-8") as f:
                return {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            return set()

    def _mark_article_parsed(self, identifier):
        if not identifier:
            return
        if identifier in self.parsed_articles:
            return
        self.parsed_articles.add(identifier)
        with open(self.parsed_articles_file, "a", encoding="utf-8") as f:
            f.write(identifier + "\n")

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
    
@@ -152,50 +178,53 @@ class CyberSecScraper:
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
        #count = 1 # how many articles to process per feed
        feed = feedparser.parse(self.Feeds[source])
        for entry in feed.entries:
           # if count <= 0:
            #    return
            #count -= 1
            title = getattr(entry, "title")
            link = getattr(entry, "link")
            published = getattr(entry, "published", getattr(entry, "updated"))
            body = ""
            if link in self.parsed_articles:
                print(f"Skipping already parsed article: {link}")
                continue
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
            structured = summary.structured
            parsed = summary.parsed
@@ -207,85 +236,273 @@ class CyberSecScraper:
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
            self._mark_article_parsed(link)
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
                f"<div class=\"cell-content\">{content}</div>"
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
    td, th {{
      width: 220px;
      max-width: 500px;
      overflow: hidden;
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
          }});
        }});
      }});

      $('#cyber-news tbody').on('dblclick', 'td', function(event) {{
        if ($(event.target).is('a')) {{
          return;
        }}
        const fullText = $(this).data('full-text') || '';
        const detailWindow = window.open('', '_blank', 'noopener');
        if (detailWindow) {{
          const safeText = $('<div>').text(fullText).html();
          detailWindow.document.write(`<!DOCTYPE html><html lang="en"><head><title>Cell Details</title><meta charset="utf-8"><style>body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 1.5rem; }} pre {{ white-space: pre-wrap; word-break: break-word; background: #1e293b; padding: 1rem; border-radius: 0.75rem; max-width: 90vw; max-height: 90vh; overflow: auto; }}</style></head><body><h2>Full Entry</h2><pre>${{safeText}}</pre></body></html>`);
          detailWindow.document.close();
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
    s.scrape_Huntress()
    s.save_to_csv()
    s.save_to_html()
    print("\n✓ Done!")

import requests
from bs4 import BeautifulSoup
import csv
import json
from datetime import datetime
from urllib.parse import urljoin
import time

class CyberSecScraper:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.articles = []
    
    def scrape_threatpost(self): #Issues with DNS 
        """Scrape Threatpost cybersecurity news"""
        try:
            url = "https://threatpost.com/"
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find article containers
            articles = soup.find_all('article', limit=10)
            
            for article in articles:
                title_tag = article.find('h2', class_='c-card__title')
                link_tag = title_tag.find('a') if title_tag else None
                excerpt_tag = article.find('div', class_='c-card__excerpt')
                
                if title_tag and link_tag:
                    self.articles.append({
                        'source': 'Threatpost',
                        'title': title_tag.get_text(strip=True),
                        'link': link_tag.get('href', ''),
                        'summary': excerpt_tag.get_text(strip=True) if excerpt_tag else 'N/A',
                        'scraped_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            print(f"✓ Scraped {len([a for a in self.articles if a['source'] == 'Threatpost'])} articles from Threatpost")
        except Exception as e:
            print(f"✗ Error scraping Threatpost: {e}")
    
    def scrape_bleepingcomputer(self): # Done
        """Scrape BleepingComputer security news"""
        try:
            url = "https://www.bleepingcomputer.com/news/security/"
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            def has_class(tag):
                return tag.has_attr('class') and 'bc_latest_news_text' in tag['class']
            
            articles = soup.find_all(has_class)
            for article in articles:
                title_tag = article.find('h4')
                link_tag = title_tag.find('a') if title_tag else None
                summary_tag = article.find('p')
                if title_tag and link_tag:
                    self.articles.append({
                        'source': 'BleepingComputer',
                        'title': title_tag.get_text(strip=True),
                        'link': urljoin(url, link_tag.get('href', '')),
                        'summary': summary_tag.get_text(strip=True) if summary_tag else 'N/A',
                        'scraped_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            print(f"✓ Scraped {len([a for a in self.articles if a['source'] == 'BleepingComputer'])} articles from BleepingComputer")
        except Exception as e:
            print(f"✗ Error scraping BleepingComputer: {e}")
    
    def scrape_darkreading(self): # Getting blocked by cloudflare ;(
        """Scrape Dark Reading cybersecurity news"""
        try:
            url = "https://www.darkreading.com/cyberattacks-data-breaches"
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            #def has_class(tag):
            #    return tag.find
            #>
            # Find article listings
            #articles = soup.find_all(has_class)
            for article in articles:
                title_tag = article.find('h3')
                link_tag = title_tag.find('a') if title_tag else None
                summary_tag = article.find('p', class_='listing-description')
                
                if title_tag and link_tag:
                    self.articles.append({
                        'source': 'Dark Reading',
                        'title': title_tag.get_text(strip=True),
                        'link': urljoin(url, link_tag.get('href', '')),
                        'summary': summary_tag.get_text(strip=True) if summary_tag else 'N/A',
                        'scraped_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            print(f"✓ Scraped {len([a for a in self.articles if a['source'] == 'Dark Reading'])} articles from Dark Reading")
        except Exception as e:
            print(f"✗ Error scraping Dark Reading: {e}")
    
    def scrape_all(self):
        """Scrape all sources"""
        print("Starting cybersecurity news scrape...\n")
        
        self.scrape_bleepingcomputer()
        time.sleep(1)  # Be polite, don't hammer servers
        
        self.scrape_threatpost()
        time.sleep(1)
        
        self.scrape_darkreading()
        
        print(f"\n✓ Total articles scraped: {len(self.articles)}")
        return self.articles
    
    def save_to_csv(self, filename='cybersec_news.csv'):
        """Save articles to CSV"""
        if not self.articles:
            print("No articles to save!")
            return
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['source', 'title', 'link', 'summary', 'scraped_at'])
            writer.writeheader()
            writer.writerows(self.articles)
        
        print(f"✓ Saved to {filename}")
    
    def save_to_json(self, filename='cybersec_news.json'):
        """Save articles to JSON"""
        if not self.articles:
            print("No articles to save!")
            return
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.articles, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved to {filename}")
    
    def print_summary(self):
        """Print a quick summary of scraped articles"""
        if not self.articles:
            print("No articles found!")
            return
        
        print("\n" + "="*80)
        print("CYBERSECURITY NEWS SUMMARY")
        print("="*80 + "\n")
        
        for i, article in enumerate(self.articles[:100], 1):
            print(f"{i}. [{article['source']}] {article['title']}")
            print(f"   {article['link']}")
            print(f"   {article['summary'][:150]}...\n")

if __name__ == "__main__":
    scraper = CyberSecScraper()
    
    scraper.scrape_bleepingcomputer()
    # Print summary
    scraper.print_summary()
    
    # Save resultsc
    #scraper.save_to_csv()
    #scraper.save_to_json()
    
    print("\n✓ Done! Check cybersec_news.csv and cybersec_news.json")

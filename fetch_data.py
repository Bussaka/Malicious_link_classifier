"""Downloads the external datasets url_model_v4.ipynb trains and evaluates on, into data/external/.

    python fetch_data.py

Feeds change daily, so a re-download gives somewhat different numbers than the committed notebook.
"""
import csv
import json
import os
import time
import urllib.request

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'external')

DOWNLOADS = {
    'tranco.zip': 'https://tranco-list.eu/top-1m.csv.zip',
    'openphish.txt': 'https://openphish.com/feed.txt',
    'urlhaus_recent.csv': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    'urlhaus_full.zip': 'https://urlhaus.abuse.ch/downloads/csv/',
    'phishtank.csv': 'http://data.phishtank.com/data/online-valid.csv',
}

# Hacker News stories with at least this many points - upvoting filters out spam submissions
HN_MIN_POINTS = 3
HN_TARGET_URLS = 120_000

USER_AGENT = 'ThreatScanner-dataset-fetch/1.0'


def fetch(url, timeout=300):
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_with_retry(url, attempts=4):
    for attempt in range(attempts):
        try:
            return fetch(url)
        except Exception as e:
            if attempt == attempts - 1:
                raise
            print(f"  retry {attempt + 1} after error: {e}")
            time.sleep(5 * (attempt + 1))


def fetch_hacker_news(path):
    """Pages backwards through HN stories via the public Algolia API."""
    rows, seen = [], set()
    before = int(time.time())
    while len(rows) < HN_TARGET_URLS:
        url = ('https://hn.algolia.com/api/v1/search_by_date?tags=story&hitsPerPage=1000'
               '&attributesToRetrieve=url,created_at_i,points'
               f'&numericFilters=points%3E%3D{HN_MIN_POINTS},created_at_i%3C{before}')
        hits = json.loads(fetch_with_retry(url))['hits']
        if not hits:
            break
        for hit in hits:
            if hit.get('url') and hit['url'] not in seen:
                seen.add(hit['url'])
                rows.append((hit['url'], hit['created_at_i'], hit['points']))
        before = min(hit['created_at_i'] for hit in hits)
        print(f"  {len(rows)} URLs, back to {time.strftime('%Y-%m-%d', time.gmtime(before))}")
        time.sleep(1)

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'created_at_i', 'points'])
        writer.writerows(rows)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, url in DOWNLOADS.items():
        print(f"Downloading {name} ...")
        with open(os.path.join(OUT_DIR, name), 'wb') as f:
            f.write(fetch_with_retry(url))

    print("Collecting Hacker News story URLs ...")
    fetch_hacker_news(os.path.join(OUT_DIR, 'hn_urls.csv'))
    print(f"Done - files are in {OUT_DIR}")


if __name__ == '__main__':
    main()

import requests
import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')


# OpenPhish feed URL (No API key required)
OPENPHISH_URL = "https://www.openphish.com/feed.txt"

# File to save the phishing URLs
OUTPUT_FILE = "phishing_urls.csv"

def fetch_openphish_urls():
    try:
        print(" Fetching phishing URLs from OpenPhish...")
        response = requests.get(OPENPHISH_URL)
        
        if response.status_code == 200:
            urls = response.text.strip().split("\n")
            print(f" Fetched {len(urls)} phishing URLs!")

            # Save URLs to CSV
            with open(OUTPUT_FILE, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Phishing URL"])
                for url in urls:
                    writer.writerow([url])

            print(f" URLs saved to {OUTPUT_FILE}")

        else:
            print(f" Failed to fetch data (Status Code: {response.status_code})")

    except Exception as e:
        print(f" Error: {e}")

if __name__ == "__main__":
    fetch_openphish_urls()

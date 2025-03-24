import os
import requests
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
VIRUSTOTAL_API_KEY ="fac18fa5e0002cef0a5f19ffa313f751ea2c5963dc7915555915255edf4df4d8"

# VirusTotal API endpoint
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

def check_url_virustotal(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    # Encode URL before sending request
    response = requests.post(VIRUSTOTAL_URL, headers=headers, data={"url": url})
    print(response.json())  # Add this to debug the response

    
    if response.status_code == 200:
        analysis_id = response.json().get("data", {}).get("id")
        return get_analysis_results(analysis_id)
    else:
        print(f"[ERROR] Failed to scan URL (Status Code: {response.status_code})")
        print(response.text)
        return None

def get_analysis_results(analysis_id):
    """Fetch the analysis report using the analysis ID"""
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    response = requests.get(analysis_url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        stats = result["data"]["attributes"]["stats"]
        print(f"✅ Analysis Results: {stats}")
        return stats
    else:
        print(f"[ERROR] Failed to retrieve analysis (Status Code: {response.status_code})")
        print(response.text)
        return None

# Test with a sample URL
if __name__ == "__main__":
    test_url = input("Enter URL to check: ")
    check_url_virustotal(test_url)

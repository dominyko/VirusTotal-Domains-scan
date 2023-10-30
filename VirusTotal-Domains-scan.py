import requests
import time
from tqdm import tqdm, TqdmExperimentalWarning
from urllib.parse import urlparse
from colorama import init, Fore, Back
import warnings
 
# Initialize colorama and suppress potential tqdm warnings
init(autoreset=True)
warnings.filterwarnings("ignore", category=TqdmExperimentalWarning)
 
API_KEY = 'INSERT YOUR API KEY'
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{}"
HEADERS = {
    "x-apikey": API_KEY
}
 
def print_with_full_bg(text, bg_color, fg_color):
    print(bg_color + fg_color + '\n' + text)
    print(MOVE_CURSOR_UP, end='')
 
def normalize_domain(domain):
    parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else 'http://' + domain)
    return parsed.netloc or parsed.path
 
def check_domain_virustotal(domain):
    url = VIRUSTOTAL_URL.format(domain)
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        data = response.json()
        
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        reputation = data.get('data', {}).get('attributes', {}).get('reputation', 0)
        
        return malicious_count, reputation
    else:
        return f"Error {response.status_code}: {response.text}", None
 
def format_time(seconds):
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02}:{m:02}:{s:02}"
 
if _name_ == "_main_":
    print("Enter the list of domains (finish with an empty line):")
    
    domains_raw = []
    while True:
        line = input()
        if not line.strip():
            break
        domains_raw.extend([x.strip() for x in line.split()])
 
    domains_set = {normalize_domain(d) for d in domains_raw}
    duplicates_count = len(domains_raw) - len(domains_set)
    print(f"Removed {duplicates_count} duplicates.")
    
    domains = list(domains_set)
    sleep_time = 15
    total_domains = len(domains)
    
    print(f"\n")
    print(Back.BLACK + Fore.LIGHTYELLOW_EX + f"ANY domains found to be possible malicious or with a bad reputation will be shown down below.")
    
    print(Fore.LIGHTBLACK_EX + f"\nChecking domains...")
    for i, domain in enumerate(tqdm(domains, desc="Domains", unit="domain")):
        malicious_count, reputation = check_domain_virustotal(domain)
        
        if isinstance(malicious_count, int) and (malicious_count > 0 or reputation < 0):
            
            print(Back.BLACK + Fore.LIGHTRED_EX + f"\n---------------------------------------------")
            print(f"\n")
            print(Back.BLACK + Fore.LIGHTRED_EX + f"Domain: {domain}")
            print(Back.BLACK + Fore.LIGHTRED_EX + f"Flagged as malicious by {malicious_count} vendors.")
            print(Back.BLACK + Fore.LIGHTRED_EX + f"Reputation: {reputation}")
            print(Back.BLACK + Fore.LIGHTRED_EX + f"\n---------------------------------------------")
 
        remaining_domains = total_domains - (i + 1)
        estimated_time = remaining_domains * sleep_time
        print(Fore.LIGHTGREEN_EX + f"\nEstimated time remaining: {format_time(estimated_time)}")
        
        time.sleep(sleep_time)
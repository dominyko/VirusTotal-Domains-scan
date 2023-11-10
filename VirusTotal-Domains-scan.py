import requests
import time
from tqdm import tqdm, TqdmExperimentalWarning
from urllib.parse import urlparse
from colorama import init, Fore, Back
import warnings
from datetime import datetime
import ipaddress

# Initialize colorama and suppress potential tqdm warnings
init(autoreset=True)
warnings.filterwarnings("ignore", category=TqdmExperimentalWarning)

API_KEY = 'INSERT YOUR API KEY'
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"  # Define the URL template for IP addresses
HEADERS = {
    "x-apikey": API_KEY
}
def print_with_full_bg(text, bg_color, fg_color):
    print(bg_color + fg_color + '\n' + text)

def normalize_resource(resource):
    try:
        # Check if the input is a valid IP address
        ipaddress.ip_address(resource)
        return resource  # It's a valid IP address, so return it as is
    except ValueError:
        # Not a valid IP address, parse as domain
        parsed = urlparse(resource if resource.startswith(('http://', 'https://')) else 'http://' + resource)
        return parsed.netloc or parsed.path

def check_resource_virustotal(resource):
    try:
        ipaddress.ip_address(resource)
        url = VIRUSTOTAL_IP_URL.format(resource)
    except ValueError:
        url = VIRUSTOTAL_DOMAIN_URL.format(resource)
    
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

def generate_filename():
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"results_{current_time}.txt"

if __name__ == "__main__":
    print("Enter the list of domains and/or IP addresses (finish with an empty line):")
    
    resources_raw = []
    while True:
        line = input()
        if not line.strip():
            break
        resources_raw.extend([x.strip() for x in line.split()])

    resources_set = {normalize_resource(r) for r in resources_raw}
    duplicates_count = len(resources_raw) - len(resources_set)
    print(f"Removed {duplicates_count} duplicates.")
    
    resources = list(resources_set)
    sleep_time = 15
    total_resources = len(resources)
    
    print("\n")
    print(Back.BLACK + Fore.LIGHTYELLOW_EX + "ANY domains or IP addresses found to be possible malicious or with a bad reputation will be shown down below.")
    
    print(Fore.LIGHTBLACK_EX + "\nChecking resources...")
    filename = generate_filename()
    with open(filename, 'a') as file:
        for i, resource in enumerate(tqdm(resources, desc="Resources", unit="resource")):
            malicious_count, reputation = check_resource_virustotal(resource)
            
            if isinstance(malicious_count, int) and (malicious_count > 0 or reputation < 0):
                results = [
                    "\n---------------------------------------------\n",
                    f"Resource: {resource}\n",
                    f"Flagged as malicious by {malicious_count} vendors.\n",
                    f"Reputation: {reputation}\n",
                    "---------------------------------------------\n"
                ]
                file.writelines(results)
                
                # Printing to the console
                print(Back.BLACK + Fore.LIGHTRED_EX + "\n---------------------------------------------")
                print(f"Resource: {resource}")
                print(f"Flagged as malicious by {malicious_count} vendors.")
                print(f"Reputation: {reputation}")
                print(Back.BLACK + Fore.LIGHTRED_EX + "---------------------------------------------")

            remaining_resources = total_resources - (i + 1)
            estimated_time = remaining_resources * sleep_time
            print(Fore.LIGHTGREEN_EX + f"\nEstimated time remaining: {format_time(estimated_time)}")
            
            time.sleep(sleep_time)

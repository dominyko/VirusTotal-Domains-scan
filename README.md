## Description
This script allows users to check a list of domains against the VirusTotal API to determine if they are flagged as malicious or have a bad reputation. The script will display any domains that are possibly malicious or have a bad reputation.

# Features
- [x] Check multiple domains in one go.
- [x] Remove duplicate domains automatically.
- [x] Display domains flagged as malicious.
- [x] Show the reputation of each domain.
- [x] Provide an estimated time remaining for the checks.

# Requirements
- Python 3.x
- requests library
- tqdm library
- colorama library

You can install the required libraries using pip:
`pip install requests tqdm colorama`

## Usage
Clone the repository:
` git clone <repository_url>`
` cd <repository_directory>`

Insert your VirusTotal API key in the script where it says INSERT YOUR API KEY.

### Run the script:

`python <script_name>.py`

Enter the list of domains you want to check (finish with an empty line).

The script will then check each domain and display any that are possibly malicious or have a bad reputation.

# Notes
The script has a sleep time of 15 seconds between each domain check to avoid hitting the API rate limit. Adjust this value if needed based on your API key's rate limits.
Ensure you have a valid VirusTotal API key and are aware of its rate limits.
License
This project is open source and available under the MIT License.

# Contribution
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Note: This README is a basic guide for the provided script. Depending on the actual repository and the intentions of the author, it might need further modifications or additions.

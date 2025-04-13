import requests, json, argparse, urllib3, csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Extract the Global Address List (GAL) on Exchange 2013+ servers via OWA")
parser.add_argument("-i", "--host", dest="hostname", required=True, type=str,
                    help="Hostname for the Exchange Server (e.g. mail.domain.com)")
parser.add_argument("-u", "--username", dest="username", required=True, type=str,
                    help="Username to log in")
parser.add_argument("-p", "--password", dest="password", required=True, type=str,
                    help="Password to log in")
parser.add_argument("-o", "--output-file", dest="output", default="global_address_list.txt", type=str,
                    help="Output file (default: global_address_list.txt)")
parser.add_argument("--format", dest="output_format", choices=["txt", "csv", "json"], default="txt",
                    help="Output format: txt (default), csv, or json")
parser.add_argument("--filter", dest="query", default=None,
                    help="Search filter string (e.g., IT, John, Admin)")

args = parser.parse_args()

print("""
==============================================
     📬 Exchange GAL Extractor via OWA
     🔧 Modified by B4l3rI0n | Original: Pigeonburger
==============================================
""")

url = args.hostname
USERNAME = args.username
PASSWORD = args.password
OUTPUT = args.output
FORMAT = args.output_format
QUERY = args.query
session = requests.Session()

# Add schema if missing
if not url.startswith(('http://', 'https://')):
    url = "https://" + url

print(f"[+] Connecting to {url}/owa ...")

try:
    response = session.get(url + "/owa", verify=False)
    response.raise_for_status()  # Raise an exception for HTTP errors
except requests.exceptions.MissingSchema:
    print("[-] No schema (https:// or http://) included in the URL. Defaulting to https://")
    url = "https://" + url
except requests.exceptions.ConnectionError:
    exit(f"[-] Failed to establish a connection to {url}. Ensure the domain exists and is reachable.")
except requests.exceptions.RequestException as e:
    exit(f"[-] An error occurred while connecting to the server: {str(e)}")

# Ensure OWA is reachable
AUTH_URL = url + "/owa/auth.owa"
PEOPLE_FILTERS_URL = url + "/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = url + "/owa/service.svc?action=FindPeople"

login_data = {
    "username": USERNAME,
    "password": PASSWORD,
    "destination": url,
    "flags": "4",
    "forcedownlevel": "0"
}

headers = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
}

try:
    response = session.post(AUTH_URL, data=login_data, headers=headers, verify=False)
    response.raise_for_status()  # Raise an exception for HTTP errors
except requests.exceptions.RequestException as e:
    exit(f"[-] Failed to log in: {str(e)}")

if "X-OWA-CANARY" not in session.cookies or "logoff" not in response.text.lower():
    exit("[-] Invalid login or session failed. Check credentials or OWA response.")

session_canary = session.cookies["X-OWA-CANARY"]
print("[+] Login successful! Canary token:", session_canary)

filters = session.post(
    PEOPLE_FILTERS_URL,
    headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'GetPeopleFilters'},
    data={}, verify=False).json()

for f in filters:
    if f['DisplayName'] == "Default Global Address List":
        AddressListId = f['FolderId']['Id']
        print("[+] Global Address List ID:", AddressListId)
        break
else:
    exit("[-] Global Address List not found.")

max_results = 99999

peopledata = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": "AUS Eastern Standard Time"
            }
        }
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": max_results
        },
        "QueryString": QUERY,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": AddressListId
            }
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default"
        },
        "ShouldResolveOneOffEmailAddress": False
    }
}

print("[*] Fetching GAL entries...")

response = session.post(
    FIND_PEOPLE_URL,
    headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'FindPeople'},
    data=json.dumps(peopledata), verify=False).json()

userlist = response['Body']['ResultSet']
if not userlist:
    exit("[-] No users found. Possibly no access or GAL is empty.")

emails = set()
for user in userlist:
    try:
        email = user['EmailAddresses'][0]['EmailAddress']
        emails.add(email)
    except (KeyError, IndexError):
        continue

print(f"[+] Fetched {len(emails)} unique email(s).")

if FORMAT == "txt":
    with open(OUTPUT, 'w') as f:
        for email in sorted(emails):
            f.write(email + "\n")
elif FORMAT == "csv":
    with open(OUTPUT if OUTPUT.endswith(".csv") else OUTPUT + ".csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Email'])
        for email in sorted(emails):
            writer.writerow([email])
elif FORMAT == "json":
    with open(OUTPUT if OUTPUT.endswith(".json") else OUTPUT + ".json", 'w') as f:
        json.dump(sorted(list(emails)), f, indent=4)

print(f"[✓] Output written to {OUTPUT}")

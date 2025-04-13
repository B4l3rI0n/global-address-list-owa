# Global Address List OWA Extractor
*Allows extraction of the Global Address List (GAL) via Outlook Web Access.*

A request called `FindPeople` can be made that (with some small modifications) will allow you to get the entire Global Email Address List for your organisation.

In my testing, this script allowed me to get just under 5000 emails in about 5 seconds. As far as I know, this script only works with Exchange 2013 servers.

# Usage

The script can be run like so:
```

python emailextract.py -i webmail.example.com -u username -p password

```

Where the `-i` argument is the URL to the OWA landing page (do not include the `/owa` at the end), the `-u` argument is a valid username, and the `-p` argument is a valid password.


The discovered emails will be printed on screen, and also written to a file called `global_address_list.txt`. You can specify an alternate output file name with the `-o` argument.

---

# EmailExtract - Exchange GAL Extractor via OWA (Exchange >=2013)

EmailExtract is a Python-based tool designed to extract the Global Address List (GAL) from Exchange 2013+ servers via Outlook Web Access (OWA). The tool is enhanced with several new features to ensure better usability and flexibility, including bypassing SSL verification, more reliable login detection, avoiding duplicate emails in the output, and supporting various output formats.

## Modifications:
- **Bypassed SSL verification**: The tool now bypasses SSL verification to handle servers with self-signed certificates or SSL issues.
- **More Reliable Login Detection**: Ensures that the login attempt is successful by checking the presence of a session canary token.
- **Avoid Duplicates in Output File**: Duplicate emails are automatically removed from the output file.
- **Supports CSV, JSON, or Plain Text Output**: The output format can be chosen between CSV, JSON, or plain text.
- **Search Filter for GAL Entries**: You can now provide a search filter (`--filter`) to narrow down the GAL entries based on a specific string (e.g., IT, Admin).

## Requirements:
- Python 3.11 or higher
- `requests` and `urllib3` libraries

## Usage:
To use EmailExtract, run the script with the required arguments. The script supports the following command-line options:

```bash
usage: emailextract.py [-h] -i HOSTNAME -u USERNAME -p PASSWORD [-o OUTPUT] [--format {txt,csv,json}] [--filter QUERY]
```

### Arguments:
- `-i, --host`: **Required** - The hostname of the Exchange server (e.g., `mail.domain.com`).
- `-u, --username`: **Required** - Your username for logging into OWA.
- `-p, --password`: **Required** - Your password for logging into OWA.
- `-o, --output-file`: **Optional** - The file to save the emails to (default: `global_address_list.txt`).
- `--format`: **Optional** - Choose the output format (`txt`, `csv`, or `json`, default is `txt`).
- `--filter`: **Optional** - A search filter string to narrow down the GAL entries (e.g., `IT`, `Admin`, etc.).

### Example:

#### Extract GAL to plain text:
```bash
python emailextract.py -i mail.domain.com -u user@example.com -p 'password123' -o gal_output.txt --filter "IT"
```

#### Extract GAL to CSV:
```bash
python emailextract.py -i mail.domain.com -u user@example.com -p 'password123' --format csv -o gal_output.csv --filter "Admin"
```

#### Extract GAL to JSON:
```bash
python emailextract.py -i mail.domain.com -u user@example.com -p 'password123' --format json -o gal_output.json --filter "John"
```

### Docker Usage:

To run **EmailExtract** in Docker, follow these steps.

#### 1. **Build the Docker Image:**
```bash
docker build -t emailextract .
```

#### 2. **Run the Docker Container:**

You can now run the tool with the following Docker command:

```bash
docker run --rm emailextract \
  -i mail.domain.com \
  -u user@example.com \
  -p 'password123' \
  -o gal_output.txt \
  --format txt \
  --filter "IT"
```

#### 3. **Run with Mounted Volume (to store output on your local system):**
```bash
docker run --rm -v $PWD:/app emailextract \
  -i mail.domain.com \
  -u user@example.com \
  -p 'password123' \
  -o gal_output.txt --filter "Admin"
```

This will mount the current directory (`$PWD`) to the `/app` directory inside the container and save the output file in your local folder.

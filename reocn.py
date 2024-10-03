import os
import requests
import subprocess
import json
import random
import socket
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import tldextract

GREEN = "\033[32m"
RESET = "\033[0m"

#---> random agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
]

def get_random_user_agent():
    return random.choice(user_agents)

#---> logs
def log_message(message):
    print(f"{GREEN}{message}{RESET}")

def create_target_directory(target):
    base_dir = "target"
    os.makedirs(base_dir, exist_ok=True)
    target_dir = os.path.join(base_dir, target)
    os.makedirs(target_dir, exist_ok=True)
    return target_dir

#--> ips
def get_ip_address(target):
    try:
        return socket.gethostbyname(target)
    except socket.error as e:
        log_message(f"Error getting IP address: {e}")
        return ""

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def send_request(url):
    headers = {'User-Agent': get_random_user_agent()}
    session = get_retry_session()
    response = session.get(url, headers=headers)
    return response.text, response.headers

def read_config():
    try:
        with open("config.json", "r") as config_file:
            config = json.load(config_file)
            return config.get("bot_token"), config.get("chat_id")
    except (FileNotFoundError, KeyError) as e:
        log_message(f"[ERROR] Config file issue: {e}")
        return None, None

def write_config(bot_token, chat_id):
    config = {"bot_token": bot_token, "chat_id": chat_id}
    with open("config.json", "w") as config_file:
        json.dump(config, config_file)

def send_telegram_message(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        log_message("✅ [SUCCESS] Message sent to Telegram successfully.")
    else:
        log_message("[ERROR] Failed to send message to Telegram.")

# ---> for exec of shell cmds
def run_command(command, tool_name, output_file=None):
    log_message(f"Running {tool_name}...")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        log_message(f"{tool_name} completed successfully.")
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        return {'success': True, 'output': result.stdout}
    else:
        log_message(f"{tool_name} failed.")
        return {'success': False, 'output': result.stderr}

def ask_for_telegram_confirmation():
    while True:
        response = input("Do you want to send messages to Telegram? (y/n): ").strip().lower()
        if response in ('y', 'n'):
            return response == 'y'
        print("Invalid input. Please enter 'y' or 'n'.")

#--> Print banner
def print_banner(target, ip_address, waf_info):
    banner = f"""
{GREEN}-------------------------------------------------
{GREEN}
{GREEN}███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗
{GREEN}██╔════╝██╔══██╗████╗  ██║██╔══██╗╚════██╗██╔════╝██╔═████╗████╗  ██║
{GREEN}███████╗███████║██╔██╗ ██║██████╔╝ █████╔╝██║     ██║██╔██║██╔██╗ ██║
{GREEN}╚════██║██╔══██║██║╚██╗██║██╔══██╗ ╚═══██╗██║     ████╔╝██║██║╚██╗██║
{GREEN}███████║██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║
{GREEN}╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚╝╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
{GREEN}-------------------------------------------------
{RESET}Target: {target}
{RESET}IP Address: {ip_address}
{RESET}WAF Information: {waf_info}
{GREEN}-------------------------------------------------
    """
    print(banner)

def format_result(tool_name, result):
    message = f"*[{tool_name}]*\n\n```\n{result}\n```"
    return message

#---> waf detection
def detect_waf(target):
    command = f"wafw00f {target}"
    output = run_command(command, "WAF Detection")
    if "is behind" in output['output']:
        return output['output'].split("is behind")[1].strip()
    return "Unknown"

#---> Whois 
def whois_lookup(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running Whois Lookup... 🔧")
    output = run_command(f"go run tools/whois/whoislookup.go -d {target} -o {target_dir}/whois.txt", "Whois Lookup")

    if output['success']:
        # Check if the output file exists before trying to read it
        whois_file_path = f"{target_dir}/whois.txt"
        if os.path.exists(whois_file_path):
            with open(whois_file_path, 'r') as f:
                whois_result = f.read()
            
            tool_message = format_result("🔧 Whois Lookup", whois_result)
            if send_telegram:
                send_telegram_message(bot_token, chat_id, tool_message)
        else:
            log_message(f"[ERROR] Whois file not found: {whois_file_path}")
    else:
        log_message(f"Whois Lookup failed: {output['output']}")


#--> NSLookup
def nslookup(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running NSLookup... 🔧")
    output = run_command(f"nslookup {target}", "NSLookup", f"{target_dir}/nslookup.txt")
    
    if output['success']:
        with open(f"{target_dir}/nslookup.txt", 'r') as f:
            nslookup_result = f.read()
        
        tool_message = format_result("🔍 NSLookup", nslookup_result)
        if send_telegram:
            send_telegram_message(bot_token, chat_id, tool_message)

#--> SSL Checker
def run_ssl_checker(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running SSL Checking...")
    output = run_command(f"go run tools/ssl/ssl-tool.go -d {target} -o {target_dir}/ssl.txt", "SSL Checker")
    if send_telegram:
        send_telegram_message(bot_token, chat_id, "SSL Checker is completed...")

def run_cloud_enum(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running Cloud-Enum... ☁️")
    run_command(f"cloud_enum -k {target} > {target_dir}/cloud_enum.txt", "Cloud Enum")

    extracted = tldextract.extract(target)
    main_keywords = extracted.domain

    cloudbrute_command = (
        f"cloudbrute -d {target} -k {main_keywords} -t 80 -T 10 "
        f"-w ./tools/data/storage_small.txt -C /etc/cloudbrute/config -m storage -o {target_dir}/cloudbrute.txt"
    )
    
    cloudbrute_output = run_command(cloudbrute_command, "Cloud Brute")

    if cloudbrute_output['success']:
        log_message("Cloud Brute completed successfully.")
    else:
        log_message(f"Cloud Brute encountered an error: {cloudbrute_output['output']}")

    if send_telegram:
        with open(f"{target_dir}/cloud_enum.txt", 'r') as f:
            cloud_enum_result = f.read()
        send_telegram_message(bot_token, chat_id, f"☁️ Cloud Enum\n```\n{cloud_enum_result}\n```")

def run_robot_scraper(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running Robots.txt Scraper... 🤖")
    output = run_command(f"go run tools/robot-scraper/robot.go -d {target} -s {target_dir}/robot.txt", "Robots.txt Scraper")
    if send_telegram:
        send_telegram_message(bot_token, chat_id, "🤖 Robots.txt Scraper is completed...")

#---> Subdomain Finding
def run_subdomain_finder(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Finding Subdomains...")
    
    run_command(f"subfinder -d {target} > {target_dir}/subfinder.txt", "Subfinder")
    run_command(f"assetfinder -subs-only {target} > {target_dir}/assetfinder.txt", "Assetfinder")
    
    run_command(f"cat {target_dir}/subfinder.txt {target_dir}/assetfinder.txt | sort | uniq > {target_dir}/subdomains.txt", "Sorting Subdomains")
    
    if send_telegram:
        with open(f"{target_dir}/subdomains.txt", 'r') as f:
            subdomain_result = f.read()
        send_telegram_message(bot_token, chat_id, f"✨ Subdomain Finder\n\n{subdomain_result}\n")

#--> Alive Subdomains
def run_alive_subdomains(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Checking alive subdomains...")

    #--> Running httpx-toolkit
    run_command(f"httpx-toolkit -l {target_dir}/subdomains.txt -ports 80,443,8080,8000,8888 -threads 200 > {target_dir}/httpx-toolkit.txt", "Httpx-toolkit")

    #-->Running httprobe
    run_command(f"httprobe < {target_dir}/subdomains.txt > {target_dir}/httprobe.txt", "Httprobe")
    run_command(f"cat {target_dir}/httpx-toolkit.txt {target_dir}/httprobe.txt | sort | uniq > {target_dir}/alive-subdomains.txt", "Sorting alive subdomains")
   
    if send_telegram:
        with open(f"{target_dir}/alive-subdomains.txt", 'r') as f:
            alive_subdomain_result = f.read()
        send_telegram_message(bot_token, chat_id, f"✅ Alive Subdomains\n\n{alive_subdomain_result}\n")

#--> Crawling
def crawling(target, target_dir, send_telegram, bot_token, chat_id):
    log_message("Running Crawling...")

    combined_urls_file = f"{target_dir}/combined_urls.txt"
    js_urls_file = f"{target_dir}/js.txt"
    
    log_message("Running Waybackurls...hold tight! ⏳")
    try:
        subprocess.run(f"timeout 5m waybackurls < {target_dir}/alive-subdomains.txt > {target_dir}/waybackurls.txt", shell=True, check=True)
        log_message("Waybackurls completed! 🎉")
        subprocess.run(f"cat {target_dir}/waybackurls.txt >> {combined_urls_file}", shell=True)
    except subprocess.CalledProcessError:
        log_message("Waybackurls hit the 5-minute limit. 🛑")

    log_message("Running Gau... almost there! 😅")
    try:
        subprocess.run(f"timeout 5m gau < {target_dir}/alive-subdomains.txt > {target_dir}/gau.txt", shell=True, check=True)
        log_message("Gau finished! 🍀")
        subprocess.run(f"cat {target_dir}/gau.txt >> {combined_urls_file}", shell=True)
    except subprocess.CalledProcessError:
        log_message("Gau took too long and was stopped after 5 minutes. 😬")

    #--> Katana Crawling
    log_message("Unleashing Katana... 🗡️")
    run_command(f"katana -u {target_dir}/alive-subdomains.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {target_dir}/katana.txt", "Katana")
    subprocess.run(f"cat {target_dir}/katana.txt >> {combined_urls_file}", shell=True)

    log_message("Extracting JavaScript URLs... 🔍")
    subprocess.run(f"grep -E '\\.js$' {combined_urls_file} >> {js_urls_file}", shell=True)
    log_message(f"JavaScript URLs saved to {js_urls_file} ✅")

    log_message(f"All URLs have been combined into {combined_urls_file} ✅")
    if send_telegram:
        send_telegram_message(bot_token, chat_id, f"Crawling is done for {target}! 🕵️‍♂️ Combined URLs are stored in {combined_urls_file}. JavaScript URLs are saved in {js_urls_file}.")

#--> Port Scanning
def port_scanning(target_dir, send_telegram, bot_token, chat_id):
    log_message("Running port scanning...")
    run_command(f"naabu -l {target_dir}/alive-subdomains.txt > {target_dir}/naabu-scan.txt", "Port Scanning")
    if send_telegram:
        send_telegram_message(bot_token, chat_id, "Port scanning is completed!")

def main():
    target = input("Enter the target domain (e.g., example.com): ")
    target_dir = create_target_directory(target)
    ip_address = get_ip_address(target)

    bot_token, chat_id = read_config()
    send_telegram = ask_for_telegram_confirmation() if bot_token and chat_id else False

    print_banner(target, ip_address, detect_waf(target))
    whois_lookup(target, target_dir, send_telegram, bot_token, chat_id)
    nslookup(target, target_dir, send_telegram, bot_token, chat_id)
    run_ssl_checker(target, target_dir, send_telegram, bot_token, chat_id)
    run_cloud_enum(target, target_dir, send_telegram, bot_token, chat_id)
    run_robot_scraper(target, target_dir, send_telegram, bot_token, chat_id)
    run_subdomain_finder(target, target_dir, send_telegram, bot_token, chat_id)
    run_alive_subdomains(target, target_dir, send_telegram, bot_token, chat_id)
    crawling(target, target_dir, send_telegram, bot_token, chat_id)
    port_scanning(target_dir, send_telegram, bot_token, chat_id)

if __name__ == "__main__":
    main()

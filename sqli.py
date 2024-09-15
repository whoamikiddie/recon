import os
import requests
import random
import time
import logging
import sys
import concurrent.futures
from urllib.parse import quote
from colorama import Fore, init
from rich import print as rich_print
from rich.panel import Panel
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Initialize colorama
init(autoreset=True)


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:93.0) Gecko/20100101 Firefox/93.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0',
    'Mozilla/5.0 (Android 11; Mobile; rv:93.0) Gecko/93.0 Firefox/93.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/94.0.992.31',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko'
]


def get_random_user_agent():
    return random.choice(USER_AGENTS)

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

def perform_request(url, payload, cookie):
    url_with_payload = f"{url}{payload}"
    start_time = time.time()
    
    headers = {
        'User-Agent': get_random_user_agent()
    }

    try:
        response = requests.get(url_with_payload, headers=headers, cookies={'cookie': cookie} if cookie else None)
        response.raise_for_status()
        success = True
        error_message = None
    except requests.exceptions.RequestException as e:
        success = False
        error_message = str(e)

    response_time = time.time() - start_time
    return success, url_with_payload, response_time, error_message

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        print(f"\n{Fore.YELLOW}Program terminated by the user!")
        save_prompt()
        sys.exit(0)
    else:
        print(f"\n{Fore.RED}An unexpected error occurred: {exc_value}")
        sys.exit(1)

def save_prompt(vulnerable_urls=[]):
    save_choice = input(f"{Fore.CYAN}\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
    if save_choice == 'y':
        output_file = input(f"{Fore.CYAN}[?] Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
        with open(output_file, 'w') as f:
            for url in vulnerable_urls:
                f.write(url + '\n')
        print(f"{Fore.GREEN}Vulnerable URLs have been saved to {output_file}")
        os._exit(0)
    else:
        print(f"{Fore.YELLOW}Vulnerable URLs will not be saved.")
        os._exit(0)

def prompt_for_urls():
    while True:
        try:
            url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
            if url_input:
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found: {url_input}")
                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]
                return urls
            else:
                single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan: ").strip()
                if single_url:
                    return [single_url]
                else:
                    print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")
                    input(f"{Fore.YELLOW}\n[i] Press Enter to try again...")
                    clear_screen()
                    print(f"{Fore.GREEN}Welcome to the Lostxlso SQL-Injector! - Coffinxp - HexSh1dow - AnonKryptiQuz - Naho\n")
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading input file: {url_input}. Exception: {str(e)}")
            input(f"{Fore.YELLOW}[i] Press Enter to try again...")
            clear_screen()
            print(f"{Fore.GREEN}Welcome to the Lostxlso SQL-Injector! - Coffinxp - HexSh1dow - AnonKryptiQuz - Naho\n")

def prompt_for_payloads():
    while True:
        try:
            payload_input = get_file_path("[?] Enter the path to the payloads file: ")
            if not os.path.isfile(payload_input):
                raise FileNotFoundError(f"File not found: {payload_input}")
            with open(payload_input) as file:
                payloads = [line.strip() for line in file if line.strip()]
            return payloads
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
            input(f"{Fore.YELLOW}[i] Press Enter to try again...")
            clear_screen()
            print(f"{Fore.GREEN}Welcome to the Lostxlso SQL-Injector! - Coffinxp - HexSh1dow - AnonKryptiQuz - Naho\n")

def print_scan_summary(total_found, total_scanned, start_time):
    print(f"{Fore.YELLOW}\n[i] Scanning finished.")
    print(f"{Fore.YELLOW}[i] Total found: {total_found}")
    print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
    print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - start_time)} seconds")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    time.sleep(1)
    clear_screen()

    panel = Panel("""                                                       
       ___                                         
   _________ _/ (_)  ______________ _____  ____  ___  _____
  / ___/ __ `/ / /  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 (__  ) /_/ / / /  (__  ) /__/ /_/ / / / / / / /  __/ /    
/____/\__, /_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
        /_/                   
                  By Whoamikiddie                             

            """,
    style="bold green",
    border_style="blue",
    expand=False
    )
    rich_print(panel, "\n")

    print(Fore.GREEN + "Welcome to the SQL Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()

    cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None

    threads = int(input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip() or 5)
    print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
    time.sleep(1)
    clear_screen()
    print(f"{Fore.CYAN}[i] Starting scan...")
    vulnerable_urls = []
    first_vulnerability_prompt = True

    single_url_scan = len(urls) == 1
    start_time = time.time()
    total_scanned = 0

    try:
        if threads == 0:
            for url in urls:
                for payload in payloads:
                    total_scanned += 1
                    success, url_with_payload, response_time, error_message = perform_request(url, payload, cookie)

                    if response_time >= 10:
                        stripped_payload = url_with_payload.replace(url, '')
                        encoded_stripped_payload = quote(stripped_payload, safe='')
                        encoded_url = f"{url}{encoded_stripped_payload}"
                        if single_url_scan:
                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                            encoded_url_with_payload = encoded_url
                        else:
                            list_stripped_payload = url_with_payload
                            for url in urls:
                                list_stripped_payload = list_stripped_payload.replace(url, '')
                            encoded_stripped_payload = quote(list_stripped_payload, safe='')

                            encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                        print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        vulnerable_urls.append(url_with_payload)
                        if single_url_scan and first_vulnerability_prompt:
                            continue_scan = input(f"{Fore.CYAN}\n[?] Vulnerability found. Do you want to continue testing other payloads? (y/n, press Enter for n): ").strip().lower()
                            if continue_scan != 'y':
                                end_time = time.time()
                                time_taken = end_time - start_time
                                print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                                print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
                                print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                                print(f"{Fore.YELLOW}[i] Time taken: {time_taken:.2f} seconds")

                                save_prompt(vulnerable_urls)
                                return
                            first_vulnerability_prompt = False
                    else:
                        stripped_payload = url_with_payload.replace(url, '')
                        encoded_stripped_payload = quote(stripped_payload, safe='')
                        encoded_url = f"{url}{encoded_stripped_payload}"
                        if single_url_scan:
                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                            encoded_url_with_payload = encoded_url
                        else:
                            list_stripped_payload = url_with_payload
                            for url in urls:
                                list_stripped_payload = list_stripped_payload.replace(url, '')
                            encoded_stripped_payload = quote(list_stripped_payload, safe='')

                            encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                        print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for url in urls:
                    for payload in payloads:
                        total_scanned += 1
                        futures.append(executor.submit(perform_request, url, payload, cookie))

                for future in concurrent.futures.as_completed(futures):
                    success, url_with_payload, response_time, error_message = future.result()

                    if response_time >= 10:
                        stripped_payload = url_with_payload.replace(url, '')
                        encoded_stripped_payload = quote(stripped_payload, safe='')
                        encoded_url = f"{url}{encoded_stripped_payload}"
                        if single_url_scan:
                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                            encoded_url_with_payload = encoded_url
                        else:
                            list_stripped_payload = url_with_payload
                            for url in urls:
                                list_stripped_payload = list_stripped_payload.replace(url, '')
                            encoded_stripped_payload = quote(list_stripped_payload, safe='')

                            encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                        print(f"{Fore.GREEN}Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")
                        vulnerable_urls.append(url_with_payload)
                        if single_url_scan and first_vulnerability_prompt:
                            continue_scan = input(f"{Fore.CYAN}\n[?] Vulnerability found. Do you want to continue testing other payloads? (y/n, press Enter for n): ").strip().lower()
                            if continue_scan != 'y':
                                end_time = time.time()
                                time_taken = end_time - start_time
                                print(f"{Fore.YELLOW}\n[i] Scanning finished.")
                                print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
                                print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
                                print(f"{Fore.YELLOW}[i] Time taken: {time_taken:.2f} seconds")

                                save_prompt(vulnerable_urls)
                                return
                            first_vulnerability_prompt = False

                    else:
                        stripped_payload = url_with_payload.replace(url, '')
                        encoded_stripped_payload = quote(stripped_payload, safe='')
                        encoded_url = f"{url}{encoded_stripped_payload}"
                        if single_url_scan:
                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {stripped_payload}")
                            encoded_url_with_payload = encoded_url
                        else:

                            list_stripped_payload = url_with_payload
                            for url in urls:
                                list_stripped_payload = list_stripped_payload.replace(url, '')
                            encoded_stripped_payload = quote(list_stripped_payload, safe='')

                            encoded_url_with_payload = url_with_payload.replace(list_stripped_payload, encoded_stripped_payload)

                            print(f"{Fore.YELLOW}\n[i] Scanning with payload: {list_stripped_payload}")
                        print(f"{Fore.RED}Not Vulnerable: {Fore.WHITE}{encoded_url_with_payload}{Fore.CYAN} - Response Time: {response_time:.2f} seconds")

            print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
            save_prompt(vulnerable_urls)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by the user!\n")
        print(f"{Fore.YELLOW}[i] Total found: {len(vulnerable_urls)}")
        print(f"{Fore.YELLOW}[i] Total scanned: {total_scanned}")
        print(f"{Fore.YELLOW}[i] Time taken: {int(time.time() - start_time)} seconds")
        save_prompt(vulnerable_urls)

if __name__ == "__main__":
    sys.excepthook = handle_exception
    main()

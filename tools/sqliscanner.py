import argparse
import requests
import time
import concurrent.futures


RESET = "\033[0m"
LIGHT_GREEN = "\033[92m"
def perform_request(url, payload, cookie):
    """
    Perform a GET request with the given URL, payload, and cookie.
    Returns a tuple containing:
        - success (bool): True if the request was successful, False otherwise
        - url_with_payload (str): The URL with the payload appended
        - response_time (float): The time taken for the request to complete
        - error_message (str): The error message if the request failed, None otherwise
    """
    url_with_payload = f"{url}{payload}"
    start_time = time.time()

    try:
        response = requests.get(url_with_payload, cookies={'cookie': cookie} if cookie else None)
        response.raise_for_status()
        success = True
        error_message = None
    except requests.exceptions.RequestException as e:
        success = False
        error_message = str(e)

    response_time = time.time() - start_time
    return success, url_with_payload, response_time, error_message

def main():
    parser = argparse.ArgumentParser(description="Perform GET requests to multiple URLs with different payloads.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to scan.")
    group.add_argument("-l", "--list", help="Text file containing a list of URLs to scan.")
    parser.add_argument("-p", "--payloads", required=True, help="Text file containing the payloads to append to the URLs.")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request.")
    parser.add_argument("-t", "--threads", type=int, choices=range(0, 11), default=0, help="Number of concurrent threads (0-10).")
    args = parser.parse_args()

    if args.url:
        urls = [args.url]
    else:
        with open(args.list) as file:
            urls = [line.strip() for line in file.readlines()]

    with open(args.payloads) as file:
        payloads = [line.strip() for line in file.readlines()]

    print(f"{LIGHT_GREEN}       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ {RESET}")
    print(f"{LIGHT_GREEN}       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ {RESET}")
    print(f"{LIGHT_GREEN}       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ {RESET}")
    print(f"{LIGHT_GREEN}       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░  {RESET}")
    print(f"{LIGHT_GREEN}░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     {RESET}")
    print(f"{LIGHT_GREEN}░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     {RESET}")
    print(f"{LIGHT_GREEN} ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     {RESET}")
    print(f"{LIGHT_GREEN}                                                                                                                                     {RESET}")




    print(f"{LIGHT_GREEN}                                                                                                By Whoamikiddie v0.0{RESET}  ")

    try:
        if args.threads == 0:
            for url in urls:
                for payload in payloads:
                    success, url_with_payload, response_time, error_message = perform_request(url, payload, args.cookie)

                    match response_time:
                        case t if t >= 10:
                            print(f"\033[92m✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds\033[0m")
                        case _:
                            print(f"\033[91m✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds\033[0m")
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for url in urls:
                    for payload in payloads:
                        futures.append(executor.submit(perform_request, url, payload, args.cookie))

                for future in concurrent.futures.as_completed(futures):
                    success, url_with_payload, response_time, error_message = future.result()

                    match response_time:
                        case t if t >= 10:
                            print(f"\033[92m✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds\033[0m")
                        case _:
                            print(f"\033[91m✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds\033[0m")
    except KeyboardInterrupt:
        print("\n\033[91m✗ Stopped by user.\033[0m")

if __name__ == "__main__":
    main()
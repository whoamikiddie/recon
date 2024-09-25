import asyncio
import argparse
from json import load

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

async def get_whois(domain, server):
    whois_result = {}
    reader, writer = await asyncio.open_connection(server, 43)
    writer.write((domain + '\r\n').encode())

    raw_resp = b''
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        raw_resp += chunk

    writer.close()
    await writer.wait_closed()
    raw_result = raw_resp.decode()

    if 'No match for' in raw_result:
        whois_result = None

    res_parts = raw_result.split('>>>', 1)
    whois_result['whois'] = res_parts[0]
    return whois_result

def whois_lookup(domain, tld, script_path, output):
    result = {}
    db_path = f'{script_path}/whois_servers.json'
    
    try:
        with open(db_path, 'r') as db_file:
            db_json = load(db_file)

        print(f'\n{Y}[!] Whois Lookup : {W}\n')

        try:
            whois_sv = db_json[tld]
            whois_info = asyncio.run(get_whois(f'{domain}.{tld}', whois_sv))
            print(whois_info['whois'])
            result.update(whois_info)
        except KeyError:
            print(f'{R}[-] Error : {C}This domain suffix is not supported.{W}')
            result.update({'Error': 'This domain suffix is not supported.'})
            print('[whois] Exception = This domain suffix is not supported.')
        except Exception as exc:
            print(f'{R}[-] Error : {C}{exc}{W}')
            result.update({'Error': str(exc)})
            print(f'[whois] Exception = {exc}')

        result.update({'exported': False})

        if output:
            fname = output
            # Save output to the specified file
            with open(fname, 'w') as outfile:
                outfile.write(result.get('whois', 'No WHOIS information available.'))
            print(f'Exporting to {fname} with data: {result.get("whois", "No data to export")}')

        print('[whois] Completed')

    except FileNotFoundError:
        print(f'{R}[-] Error : {C}Whois servers database not found.{W}')
    except Exception as exc:
        print(f'{R}[-] Error : {C}{exc}{W}')

def main():
    parser = argparse.ArgumentParser(description='Perform a WHOIS lookup.')
    parser.add_argument('-d', '--domain', required=True, help='Domain name to look up (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output file name (e.g., output.txt)')
    parser.add_argument('-s', '--script-path', default='.', help='Path to the script directory containing whois_servers.json')

    args = parser.parse_args()

    domain_parts = args.domain.split('.')
    if len(domain_parts) < 2:
        print(f'{R}[-] Error : {C}Invalid domain format. Please provide a full domain (e.g., example.com).{W}')
        return

    tld = domain_parts[-1]
    whois_lookup(domain_parts[0], tld, args.script_path, args.output)

if __name__ == '__main__':
    main()

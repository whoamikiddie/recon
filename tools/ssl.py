import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json
import os
import argparse

R = '\033[31m'  #
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def log_writer(message):
    with open('ssl_log.txt', 'a') as log_file:
        log_file.write(f"{message}\n")

def export(output, data):
    directory = output.get("directory", ".")
    filename = f"ssl.{output.get('format', 'txt')}"
    file_path = os.path.join(directory, filename)

    with open(file_path, 'w') as outfile:
        if output.get('format') == 'txt':
            for key, value in data.items():
                if isinstance(value, dict):
                    outfile.write(f"{key}:\n")
                    for sub_key, sub_value in value.items():
                        outfile.write(f"  {sub_key}: {sub_value}\n")
                elif isinstance(value, list):
                    outfile.write(f"{key}:\n")
                    for i, item in enumerate(value):
                        outfile.write(f"  {i}: {item}\n")
                else:
                    outfile.write(f"{key}: {value}\n")
        else:  # Default to JSON
            json.dump(data, outfile, indent=4)

    print(f'{G}[+] Data exported to {file_path}{W}')

def cert(hostname, output):
    result = {}
    presence = False
    print(f'\n{Y}[!] SSL Certificate Information : {W}\n')

    # Check if SSL is present
    port_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_test.settimeout(5)
    try:
        port_test.connect((hostname, 443))  # Default SSL port
        port_test.close()
        presence = True
    except Exception:
        port_test.close()
        print(f'{R}[-] {C}SSL is not Present on Target URL...Skipping...{W}')
        result.update({'Error': 'SSL is not Present on Target URL'})
        log_writer('[sslinfo] SSL is not Present on Target URL...Skipping...')
        return

    def unpack(nested_tuple, pair):
        for item in nested_tuple:
            if isinstance(item, tuple):
                if len(item) == 2:
                    pair[item[0]] = item[1]
                else:
                    unpack(item, pair)
            else:
                pair[nested_tuple.index(item)] = item

    def process_cert(info):
        pair = {}
        for key, val in info.items():
            if isinstance(val, tuple):
                print(f'{G}[+] {C}{key}{W}')
                unpack(val, pair)
                for sub_key, sub_val in pair.items():
                    print(f'\t{G}└╴{C}{sub_key}: {W}{sub_val}')
                    result.update({f'{key}-{sub_key}': sub_val})
                pair.clear()
            elif isinstance(val, dict):
                print(f'{G}[+] {C}{key}{W}')
                for sub_key, sub_val in val.items():
                    print(f'\t{G}└╴{C}{sub_key}: {W}{sub_val}')
                    result.update({f'{key}-{sub_key}': sub_val})
            elif isinstance(val, list):
                print(f'{G}[+] {C}{key}{W}')
                for sub_val in val:
                    print(f'\t{G}└╴{C}{val.index(sub_val)}: {W}{sub_val}')
                    result.update({f'{key}-{val.index(sub_val)}': sub_val})
            else:
                print(f'{G}[+] {C}{key} : {W}{val}')
                result.update({key: val})

    if presence:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket()
        sock.settimeout(5)
        ssl_conn = ctx.wrap_socket(sock, server_hostname=hostname)
        ssl_conn.connect((hostname, 443))  # Default SSL port
        x509_cert = ssl_conn.getpeercert(binary_form=True)
        decoded_cert = x509.load_der_x509_certificate(x509_cert, default_backend())

        subject_dict = {}
        issuer_dict = {}

        def name_to_dict(attribute):
            attr_name = attribute.oid._name
            attr_value = attribute.value
            return attr_name, attr_value

        for attribute in decoded_cert.subject:
            name, value = name_to_dict(attribute)
            subject_dict[name] = value

        for attribute in decoded_cert.issuer:
            name, value = name_to_dict(attribute)
            issuer_dict[name] = value

        cert_dict = {
            'protocol': ssl_conn.version(),
            'cipher': ssl_conn.cipher(),
            'subject': subject_dict,
            'issuer': issuer_dict,
            'version': str(decoded_cert.version),  # Convert to string
            'serialNumber': decoded_cert.serial_number,
            'notBefore': decoded_cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),  # Use not_valid_before_utc
            'notAfter': decoded_cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),  # Use not_valid_after_utc
        }

        extensions = decoded_cert.extensions
        for ext in extensions:
            if ext.oid != x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                continue
            san_entries = ext.value
            subject_alt_names = [entry.value for entry in san_entries if isinstance(entry, x509.DNSName)]
            cert_dict['subjectAltName'] = subject_alt_names

        process_cert(cert_dict)
        result.update({'exported': False})

        if output:
            export(output, result)

    log_writer('[sslinfo] Completed')

# Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSL Certificate Information Retrieval Tool")
    parser.add_argument("-d", "--domain", required=True, help="The domain to scan for SSL certificate")
    parser.add_argument("-o", "--output", type=str, default=".", help="Directory to save output (default: current directory)")
    parser.add_argument("-f", "--format", type=str, default="txt", choices=["txt"], help="Output format (default: txt)")

    args = parser.parse_args()

    output = {
        "directory": args.output,
        "format": args.format
    }

    cert(args.domain, output)

# DNSServer.py
# Completed from provided skeleton. Fill PASSWORD with your NYU Gradescope email before running.

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

# ----------------------------
# Encryption helpers
# ----------------------------
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # call fernet encrypt
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)  # call fernet decrypt
    return decrypted_data.decode('utf-8')

# ----------------------------
# Exfiltration / parameters
# ----------------------------
salt = b'Tandon'  # must be bytes per assignment
password = "REPLACE_WITH_YOUR_NYU_EMAIL@nyu.edu"  # <<--- REPLACE THIS with your NYU email used on Gradescope
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function (bytes)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # sanity-check (string)

# ----------------------------
# Utility (provided)
# ----------------------------
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# ----------------------------
# DNS records (FQDNs with trailing dot)
# ----------------------------
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },

    # Assignment-specified records (use only these hosts)
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102'
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103'
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104'
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105'
    },
    # nyu.edu must contain extra records including our encrypted TXT
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),  # store the encrypted package as a string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}

# ----------------------------
# DNS server runtime
# ----------------------------
BIND_IP = "127.0.0.1"
BIND_PORT = 53  # standard DNS port; if permission denied, run as admin or change to 5353

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((BIND_IP, BIND_PORT))
    except PermissionError:
        # fallback advice: bind to non-privileged port to test locally
        fallback_port = 5353
        print(f"[!] Permission denied binding to port {BIND_PORT}. Trying fallback port {fallback_port}.")
        server_socket.bind((BIND_IP, fallback_port))
        print(f"[+] Bound to {BIND_IP}:{fallback_port} (fallback). Use dig/nslookup with -p {fallback_port} to test.")
    except Exception as e:
        print("[!] Failed to bind socket:", e)
        server_socket.close()
        sys.exit(1)

    print(f"[+] DNS server listening on {server_socket.getsockname()[0]}:{server_socket.getsockname()[1]}")
    while True:
        try:
            data, addr = server_socket.recvfrom(4096)
            # Parse the request using dns.message.from_wire
            try:
                request = dns.message.from_wire(data)
            except Exception:
                # malformed request - ignore
                continue

            # Create a response message using make_response
            response = dns.message.make_response(request)

            # Get the question from the request
            if len(request.question) == 0:
                # No question - ignore
                continue

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                # MX handling
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))

                # SOA handling
                elif qtype == dns.rdatatype.SOA:
                    # Unpack the stored tuple into SOA constructor parameters
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)

                else:
                    # Generic handling: answer_data might be a str or a tuple/list of strings
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        # answer_data is iterable
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, str(item)) for item in answer_data]

                # Append rrsets and rdata to response.answer
                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

                # Set AA flag (authoritative)
                response.flags |= 1 << 10

            else:
                # Not found in our DB -> NXDOMAIN and set AA flag
                response.set_rcode(dns.rcode.NXDOMAIN)
                response.flags |= 1 << 10

            # Send the response back
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print("\nExiting...")
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            # Log and keep running
            print("[!] Error handling request:", e)
            continue

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    # Optional: print encrypted/decrypted test values (comment out for final submission if you want)
    # print("Encrypted (base64):", encrypted_value.decode('utf-8'))
    # print("Decrypted (sanity-check):", decrypted_value)
    run_dns_server_user()
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
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
    # Derive fernet key from password+salt
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # call the Fernet encrypt method
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    # Re-derive same key and decrypt back to plaintext
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)  # call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

###############################################################################
# EXFIL DATA PREP (Step 3 in the PDF)                                        #
###############################################################################
# The salt is "Tandon" and MUST be bytes. The password is your NYU email.
# The secret string we’re hiding is "AlwaysWatching".
# We’ll encrypt it, then stuff the encrypted blob (as text) into a TXT record. :contentReference[oaicite:1]{index=1}

salt = b"Tandon"                         # byte-object salt
password = "your_netid@nyu.edu"          # <-- PUT YOUR REAL NYU EMAIL HERE
input_string = "AlwaysWatching"          # secret payload we’re exfiltrating

encrypted_value = encrypt_with_aes(input_string, password, salt)  # ciphertext (bytes)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # sanity check / local use only

# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

###############################################################################
# DNS RECORDS (Step 4 in the PDF)                                           #
###############################################################################
# We'll build a dictionary mapping FQDNs to rrtypes.
# Make sure the keys are absolute names ending in a dot.
#
# For nyu.edu we add:
#   A, AAAA, NS, MX, TXT (TXT holds the ENCRYPTED VALUE as a string!)
# NOTE: encrypted_value is bytes; TXT must be text -> decode to UTF-8 string.
#
# Also include safebank.com, google.com, legitsite.com, yahoo.com, nyu.edu A records. :contentReference[oaicite:2]{index=2}

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,        # refresh
            1800,        # retry
            604800,      # expire
            86400,       # minimum
        ),
    },

    # Custom A records from the assignment
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),  # exfil as TXT
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },

    # You could add more if you want, but per instructions this is enough.
}

###############################################################################
# DNS SERVER LOOP (Steps 5-14 in the PDF)                                   #
###############################################################################

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and DNS port 53.
    # socket.AF_INET = IPv4, socket.SOCK_DGRAM = UDP. :contentReference[oaicite:3]{index=3}
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Use a "unique" loopback IP like in previous labs. If your HTTP lab used
    # 127.0.0.1, keep that. If it used 127.0.0.2 or similar, mirror it here.
    SERVER_IP = "127.0.0.1"
    DNS_PORT = 53

    server_socket.bind((SERVER_IP, DNS_PORT))

    while True:
        try:
            # Wait for incoming DNS requests (up to 1024 bytes is fine)
            data, addr = server_socket.recvfrom(1024)

            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)

            # Create a response message using `dns.message.make_response`
            response = dns.message.make_response(request)

            # Get the first question from the request
            question = request.question[0]
            qname = question.name.to_text()  # FQDN string with trailing dot
            qtype = question.rdtype          # numeric rdatatype constant

            # Look up records
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                # Handle MX (list of (preference, mailserver))
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(
                            MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server)
                        )

                # Handle SOA (tuple of 7 fields)
                elif qtype == dns.rdatatype.SOA:
                    (
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    ) = answer_data
                    rdata = SOA(
                        dns.rdataclass.IN,
                        dns.rdatatype.SOA,
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    )
                    rdata_list.append(rdata)

                # All other types (A, AAAA, NS, TXT, etc.)
                else:
                    if isinstance(answer_data, str):
                        # single value -> create one rdata
                        rdata_list = [
                            dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)
                        ]
                    else:
                        # tuple/list of multiple strings -> create rdata for each
                        rdata_list = [
                            dns.rdata.from_text(dns.rdataclass.IN, qtype, data_txt)
                            for data_txt in answer_data
                        ]

                # Attach RRs to the response
                for rdata in rdata_list:
                    # Create (or append to) an RRset for this qname/qtype
                    response.answer.append(
                        dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    )
                    response.answer[-1].add(rdata)

            # Mark response as Authoritative Answer (AA = bit 10)
            # AA flag bit is 0x0400. We'll OR it in.
            response.flags |= (1 << 10)

            # Send the response back to the client
            print("Responding to request:", qname, "type", dns.rdatatype.to_text(qtype))
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


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
    run_dns_server_user()

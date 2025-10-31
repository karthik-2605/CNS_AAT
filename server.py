import socket
import threading
import struct
import sys

KEY = b"bmsce_cns_assignment"
BUF_SIZE = 1024

def xor_cipher(data: bytearray, key: bytes):
    klen = len(key)
    for i in range(len(data)):
        data[i] ^= key[i % klen]

def recv_all(conn, n):
    data = bytearray()
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            return None
        data.extend(part)
    return data

def handle_client(conn, addr):
    print(f"Accepted connection from {addr}")
    try:
        while True:
            # read 4-byte length
            header = recv_all(conn, 4)
            if not header:
                print(f"{addr} disconnected")
                break
            (msglen,) = struct.unpack("!I", header)
            if msglen <= 0 or msglen > BUF_SIZE - 1:
                print("Invalid message length:", msglen)
                break
            raw = recv_all(conn, msglen)
            if raw is None:
                print("Client closed while reading message")
                break
            print(f"Encrypted data received from {addr}: {list(raw)}")
            print()
            data = bytearray(raw)
            xor_cipher(data, KEY)
            print(f"[{addr}] Received decrypted: {data.decode(errors='replace')}")
            print()

            ack = f"ACK: received {len(data)} bytes".encode()
            ack_b = bytearray(ack)
            xor_cipher(ack_b, KEY)
            conn.sendall(struct.pack("!I", len(ack_b)))
            conn.sendall(ack_b)
    except Exception as e:
        print("Exception in client handler:", e)
    finally:
        conn.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        sys.exit(1)
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen(5)
    print("Server listening on port", port)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("server shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()

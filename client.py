import socket
import struct
import sys

KEY = b"bmsce_cns_assignment"
BUF_SIZE = 1024

def xor_cipher(data: bytearray, key: bytes):
    klen = len(key)
    for i in range(len(data)):
        data[i] ^= key[i % klen]

def recv_all(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            return None
        data.extend(part)
    return data

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 client.py <server_ip> <port> <message>")
        sys.exit(1)
    server_ip = sys.argv[1]
    port = int(sys.argv[2])
    msg = sys.argv[3].encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, port))
    except Exception as e:
        print("Connect error:", e)
        sys.exit(1)

    data = bytearray(msg)
    xor_cipher(data, KEY)
    print("Encrypted message bytes:",list(data))
    print()
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

    header = recv_all(sock, 4)
    if header is None:
        print("Server closed connection")
        sock.close()
        return
    (acklen,) = struct.unpack("!I", header)
    ack_b = recv_all(sock, acklen)
    if ack_b is None:
        print("Server closed while reading ack")
        sock.close()
        return
    ack = bytearray(ack_b)
    xor_cipher(ack, KEY)
    print("Received decrypted ACK:", ack.decode(errors='replace'))
    print("Decrypted ACK:",ack.decode(errors='replace'))
    sock.close()

if __name__ == "__main__":
    main()

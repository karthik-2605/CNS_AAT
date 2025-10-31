#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 1024
const char *KEY = "bmsce_cns_assignment";

// XOR encryption/decryption
void xor_cipher(char *data, ssize_t len, const char *key) {
    size_t keylen = strlen(key);
    for (ssize_t i = 0; i < len; ++i) data[i] ^= key[i % keylen];
}

// Send all bytes reliably
ssize_t send_all(int sockfd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *p = (const char*)buf;
    while (sent < len) {
        ssize_t n = send(sockfd, p + sent, len - sent, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += n;
    }
    return sent;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <message>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *msg = argv[3];

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &serv.sin_addr) <= 0) { perror("inet_pton"); close(sockfd); return 1; }

    if (connect(sockfd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    char buf[BUF_SIZE];
    size_t msglen = strlen(msg);
    if (msglen > BUF_SIZE - 1) { fprintf(stderr, "message too long\n"); close(sockfd); return 1; }
    memcpy(buf, msg, msglen);

    // Encrypt the message
    xor_cipher(buf, msglen, KEY);

    // Print encrypted message
    printf("Encrypted message bytes: ");
    for (size_t i = 0; i < msglen; i++) printf("%d ", (unsigned char)buf[i]);
    printf("\n");

    // Send length + encrypted message
    uint32_t netlen = htonl((uint32_t)msglen);
    if (send_all(sockfd, &netlen, sizeof(netlen)) < 0) { perror("send len"); close(sockfd); return 1; }
    if (send_all(sockfd, buf, msglen) < 0) { perror("send msg"); close(sockfd); return 1; }

    // Receive ACK length
    uint32_t ack_netlen;
    ssize_t r = recv(sockfd, &ack_netlen, sizeof(ack_netlen), MSG_WAITALL);
    if (r <= 0) { perror("recv ack length"); close(sockfd); return 1; }
    uint32_t acklen = ntohl(ack_netlen);
    if (acklen == 0 || acklen > BUF_SIZE - 1) { fprintf(stderr, "invalid ack length\n"); close(sockfd); return 1; }

    // Receive encrypted ACK
    ssize_t nbytes = recv(sockfd, buf, acklen, MSG_WAITALL);
    if (nbytes <= 0) { perror("recv ack"); close(sockfd); return 1; }

    // Print encrypted ACK bytes
    printf("Encrypted ACK bytes received: ");
    for (ssize_t i = 0; i < nbytes; i++) printf("%d ", (unsigned char)buf[i]);
    printf("\n");

    // Decrypt ACK
    xor_cipher(buf, nbytes, KEY);
    buf[nbytes] = '\0';
    printf("Decrypted ACK: %s\n", buf);

    close(sockfd);
    return 0;
}

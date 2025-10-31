#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BACKLOG 10
#define BUF_SIZE 1024

const char *KEY = "bmsce_cns_assignment"; 


void xor_cipher(char *data, ssize_t len, const char *key) {
    size_t keylen = strlen(key);
    for (ssize_t i = 0; i < len; ++i) {
        data[i] ^= key[i % keylen];
    }
}


ssize_t send_all(int sockfd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *p = (const char *)buf;
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


void *client_thread(void *arg) {
    int client_fd = *((int*)arg);
    free(arg);

    char buf[BUF_SIZE];
    ssize_t nbytes;

    while (1) {
       
        uint32_t netlen;
        ssize_t r = recv(client_fd, &netlen, sizeof(netlen), MSG_WAITALL);
        if (r == 0) {
            printf("[client %d] disconnected\n", client_fd);
            break;
        }
        if (r < 0) {
            perror("recv length");
            break;
        }
        uint32_t msglen = ntohl(netlen);
        if (msglen == 0 || msglen > BUF_SIZE - 1) {
            fprintf(stderr, "invalid message length: %u\n", msglen);
            break;
        }

        
        nbytes = recv(client_fd, buf, msglen, MSG_WAITALL);
        if (nbytes <= 0) {
            perror("recv message");
            break;
        }

        
        printf("[client %d] Encrypted message bytes: ", client_fd);
        for (ssize_t i = 0; i < nbytes; ++i) printf("%d ", (unsigned char)buf[i]);
        printf("\n");

        
        xor_cipher(buf, nbytes, KEY);
        buf[nbytes] = '\0';
        printf("[client %d] Received decrypted: %s\n", client_fd, buf);

        
        char ack[BUF_SIZE];
        int acklen = snprintf(ack, sizeof(ack), "ACK: received %zd bytes", nbytes);

        
        xor_cipher(ack, acklen, KEY);

        
        printf("[client %d] Sending encrypted ACK: ", client_fd);
        for (int i = 0; i < acklen; i++) printf("%d ", (unsigned char)ack[i]);
        printf("\n");

    
        uint32_t sendlen = htonl((uint32_t)acklen);
        if (send_all(client_fd, &sendlen, sizeof(sendlen)) < 0) {
            perror("send ack len");
            break;
        }
        if (send_all(client_fd, ack, acklen) < 0) {
            perror("send ack");
            break;
        }
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);

    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, BACKLOG) < 0) { perror("listen"); return 1; }

    printf("Server listening on port %d\n", port);

    
    while (1) {
        struct sockaddr_in cliaddr;
        socklen_t clilen = sizeof(cliaddr);
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) { perror("malloc"); continue; }

        *client_fd = accept(listen_fd, (struct sockaddr*)&cliaddr, &clilen);
        if (*client_fd < 0) {
            perror("accept");
            free(client_fd);
            continue;
        }

        printf("Accepted connection from %s:%d -> fd=%d\n",
               inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), *client_fd);

        
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, client_fd) != 0) {
            perror("pthread_create");
            close(*client_fd);
            free(client_fd);
            continue;
        }
        pthread_detach(tid);
    }

    close(listen_fd);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433
#define BUFFER_SIZE 1024

__attribute__((noreturn))
static void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "aborting!\n");
    exit(1);
}

int main(void) {
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context
    SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
    if (!ctx) {
        handle_errors();
    }

    // Load certificates
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }

    // Create a UDP socket
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Create a new SSL object for each connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    char buffer[BUFFER_SIZE];

    while (1) {
        // Receive data from clients
        ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&cli_addr, &cli_len);
        if (len < 0) {
            perror("Receive failed");
            continue;
        }

        // Print received message
        buffer[len] = '\0'; // Null-terminate the received data
        printf("Received: %s\n", buffer);

        // Send the same data back to the client
        //sendto(sockfd, buffer, (size_t)len, 0, (struct sockaddr*)&cli_addr, cli_len);

        // For demonstration purposes: echoing back the message
        //printf("Echoed: %s\n", buffer);
    }

    // Cleanup
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

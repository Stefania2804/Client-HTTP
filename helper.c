#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "helper.h"

#define BUFLEN 4096
#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int open_connection(char *host_ip, int portno, int ip_type, int socket_type, int flag) {
    struct sockaddr_in serv_addr;
    int sockfd = socket(ip_type, socket_type, flag);
    if (sockfd < 0) error("ERROR opening socket");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = ip_type;
    serv_addr.sin_port = htons(portno);
    inet_aton(host_ip, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    return sockfd;
}

void close_connection(int sockfd) {
    close(sockfd);
}

void send_to_server(int sockfd, char *message) {
    int total = strlen(message);
    int sent = 0, bytes;

    while (sent < total) {
        bytes = write(sockfd, message + sent, total - sent);
        if (bytes < 0) error("ERROR writing to socket");
        if (bytes == 0) break;
        sent += bytes;
    }
}

char *receive_from_server(int sockfd) {
    char response[BUFLEN];
    char *buffer = malloc(BUFLEN);
    int received = 0;
    int total_length = 0;
    int header_end = 0;

    while (1) {
        int bytes = read(sockfd, response, BUFLEN - 1);
        if (bytes < 0) error("ERROR reading from socket");
        if (bytes == 0) break;

        response[bytes] = '\0';
        buffer = realloc(buffer, received + bytes + 1);
        memcpy(buffer + received, response, bytes);
        received += bytes;
        buffer[received] = '\0';

        if (!header_end) {
            char *header_end_ptr = strstr(buffer, HEADER_TERMINATOR);
            if (header_end_ptr) {
                header_end = header_end_ptr - buffer + HEADER_TERMINATOR_SIZE;

                char *content_length_str = strstr(buffer, CONTENT_LENGTH);
                if (content_length_str) {
                    content_length_str += CONTENT_LENGTH_SIZE;
                    total_length = atoi(content_length_str);
                }
            }
        }

        if (header_end && total_length > 0 && (received - header_end) >= total_length) {
            break;
        }
    }

    return buffer;
}

char *basic_extract_json_response(char *str) {
    char *json_start = strstr(str, "{");
    if (json_start == NULL) return NULL;
    return json_start;
}

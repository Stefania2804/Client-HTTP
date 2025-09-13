#include "requests.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *compute_get_request(char *host, char *url, char *query_params, char **cookies, int cookies_count, const char *jwt_token) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    if (query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", url);
    }
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (jwt_token && strlen(jwt_token) > 0) {
        sprintf(line, "Authorization: Bearer %s", jwt_token);
        compute_message(message, line);
    }

    if (cookies != NULL) {
        for (int i = 0; i < cookies_count; i++) {
            sprintf(line, "Cookie: %s", cookies[i]);
            compute_message(message, line);
        }
    }
    compute_message(message, "");

    free(line);
    return message;
}

char *compute_post_request(char *host, char *url, const char *content_type, char *body_data, char **cookies, int cookies_count, const char *jwt_token) {
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);
    sprintf(line, "Content-Length: %ld", strlen(body_data));
    compute_message(message, line);

    if (jwt_token && strlen(jwt_token) > 0) {
        sprintf(line, "Authorization: Bearer %s", jwt_token);
        compute_message(message, line);
    }

    if (cookies != NULL) {
        for (int i = 0; i < cookies_count; i++) {
            sprintf(line, "Cookie: %s", cookies[i]);
            compute_message(message, line);
        }
    }

    compute_message(message, "");
    strcat(message, body_data);

    free(line);
    return message;
}

void compute_message(char *message, const char *line) {
    strcat(message, line);
    strcat(message, "\r\n");
}
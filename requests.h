#ifndef REQUESTS_H
#define REQUESTS_H

#define BUFLEN 8192
#define LINELEN 4096

char *compute_get_request(char *host, char *url, char *query_params, char **cookies, int cookies_count, const char *jwt_token);
char *compute_post_request(char *host, char *url, const char *content_type, char *body_data, char **cookies, int cookies_count, const char *jwt_token);
void compute_message(char *message, const char *line);

#endif

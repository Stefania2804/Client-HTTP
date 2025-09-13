#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include "parson.h"
#include "client.h"

char admin_session_cookie[4500] = "";
char user_session_cookie[4500] = "";
char jwt_token[4500] = "";
char current_logged_in_username[256] = {0};

void login_admin() {
    int sockfd = connect_to_server();
    char username[64], password[64], request[8192];

    printf("username=");
    fgets(username, 64, stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("password=");
    fgets(password, 64, stdin);
    password[strcspn(password, "\n")] = '\0';

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);

    char *json_string = json_serialize_to_string(root_value);

    snprintf(request, sizeof(request), "POST /api/v1/tema/admin/login HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %ld\r\n\r\n%s",
             SERVER_HOST, SERVER_PORT, strlen(json_string), json_string);

    char *response = send_request(sockfd, request);
    admin_session_cookie[0] = '\0';     
    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        char *cookie_start = strstr(response, "Set-Cookie: ");
        if (cookie_start) {
            cookie_start += strlen("Set-Cookie: ");
            char *cookie_end = strstr(cookie_start, ";");
            if (cookie_end) {
                int len = cookie_end - cookie_start;
                if (len > 0 && (size_t)len < sizeof(admin_session_cookie)) {
                    strncpy(admin_session_cookie, cookie_start, len);
                    admin_session_cookie[len] = '\0';
                } else if ((size_t)len >= sizeof(admin_session_cookie)) {
                    printf("ERROR: Cookie prea mare.\n");
                }
            }
        }

        if (strstr(response, "200 OK")) {
            printf("SUCCESS: Admin autentificat.\n");
            strncpy(current_logged_in_username, username, sizeof(current_logged_in_username) - 1);
        } else {
            printf("ERROR: Autentificare esuata.\n");
            admin_session_cookie[0] = '\0';
        }
    } else if (response != NULL) {
        printf("%s\n", response);
        admin_session_cookie[0] = '\0';
    } else {
        printf("ERROR: Serverul nu raspunde.\n");
        admin_session_cookie[0] = '\0';
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free_response_if_needed(response);
    close(sockfd);
}

void logout_admin() {
    int sockfd = connect_to_server();
    char request[8192];

    if (strlen(admin_session_cookie) == 0) {
        printf("ERROR: Admin nelogat.\n");
        close(sockfd);
        return;
    }

    snprintf(request, sizeof(request), "GET /api/v1/tema/admin/logout HTTP/1.1\r\nHost: %s:%d\r\nCookie: %s\r\n\r\n",
             SERVER_HOST, SERVER_PORT, admin_session_cookie);

    char *response = send_request(sockfd, request);

    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        if (strstr(response, "200 OK")) {
            printf("SUCCESS: Admin delogat.\n");
            admin_session_cookie[0] = '\0';
            jwt_token[0] = '\0';
            current_logged_in_username[0] = '\0';
        } else {
            printf("ERROR: Delogare esuata.\n");
        }
    } else if (response != NULL) {
        printf("%s\n", response);
    } else {
         printf("ERROR: Serverul nu raspunde.\n");
    }
    free_response_if_needed(response);
    close(sockfd);
}

void add_user() {
    int sockfd = -1;
    char username[64], password[64];
    char request[8192];
    char *json_string = NULL;
    char *response = NULL;

    if (strlen(admin_session_cookie) == 0) {
        printf("ERROR: Admin nelogat.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare la server esuata.\n");
        return;
    }
    printf("username=");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        perror("EROARE: fgets utilizator");
        close(sockfd);
        return;
    }
    username[strcspn(username, "\n")] = '\0';

    printf("password=");
     if (fgets(password, sizeof(password), stdin) == NULL) {
        perror("EROARE: fgets parola");
        close(sockfd);
        return;
    }
    password[strcspn(password, "\n")] = '\0';

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    json_string = json_serialize_to_string(root_value);

    if (json_string == NULL) {
        printf("ERROR: Generare JSON esuata.\n");
        json_value_free(root_value);
        close(sockfd);
        return;
    }
    snprintf(request, sizeof(request),
             "POST /api/v1/tema/admin/users HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Cookie: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n\r\n%s",
             SERVER_HOST, SERVER_PORT, admin_session_cookie, strlen(json_string), json_string);

    json_free_serialized_string(json_string);
    json_value_free(root_value);

    response = send_request(sockfd, request);

    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        if (strncmp(response, "HTTP/1.1 200", 12) == 0 || strncmp(response, "HTTP/1.1 201", 12) == 0) {
            printf("SUCCESS: Utilizator adaugat.\n");
        } else if (strstr(response, "403 Forbidden")) {
            printf("ERROR: Permisiune admin necesara.\n");
        } else if (strstr(response, "400 Bad Request")) {
            printf("ERROR: Date incorecte/utilizator existent.\n");
        } else {
            char status_line[100];
            char *first_crlf = strstr(response, "\r\n");
            if (first_crlf) {
                strncpy(status_line, response, first_crlf - response);
                status_line[first_crlf - response] = '\0';
            } else {
                strncpy(status_line, response, sizeof(status_line) - 1);
                 status_line[sizeof(status_line) - 1] = '\0';
            }
            printf("ERROR: Adaugare utilizator esuata. Status: %s\n", status_line);
        }
    } else if (response != NULL) {
        printf("%s\n", response);
    }
    else {
        printf("ERROR: Serverul nu raspunde.\n");
    }
    free_response_if_needed(response);
    if (sockfd >= 0) {
       close(sockfd);
    }
}

void get_users() {
    int sockfd = -1;
    char request[8192];
    char *response = NULL;
    JSON_Value *root_value = NULL;

    if (strlen(admin_session_cookie) == 0) {
        printf("ERROR: Admin neautentificat sau cookie lipsa.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare la server esuata.\n");
        return;
    }

    snprintf(request, sizeof(request),
             "GET /api/v1/tema/admin/users HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Cookie: %s\r\n"
             "\r\n",
             SERVER_HOST, SERVER_PORT, admin_session_cookie);

    response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde.\n");
        if (sockfd >= 0) close(sockfd);
        return;
    }
     if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
        if (sockfd >= 0) close(sockfd);
        free_response_if_needed(response);
        return;
    }

    char *body_start = strstr(response, "\r\n\r\n");

    if (strstr(response, "HTTP/1.1 401") != NULL || strstr(response, "HTTP/1.1 403") != NULL) {
        printf("ERROR: Permisiuni admin lipsa.\n");
        if (body_start) {
            body_start += 4;
            JSON_Value *err_val = json_parse_string(body_start);
            if (err_val && json_value_get_type(err_val) == JSONObject) {
                JSON_Object *err_obj = json_value_get_object(err_val);
                const char *err_msg = json_object_get_string(err_obj, "error");
                if (err_msg) printf("Mesaj server: %s\n", err_msg);
                else printf("Raspuns server (corp eroare):\n%s\n", body_start);
            } else {
                 printf("Raspuns server (corp eroare, JSON invalid/lipsa):\n%s\n", body_start);
            }
            if (err_val) json_value_free(err_val);
        }
    } else if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        if (body_start != NULL) {
            body_start += 4;
            int is_empty_or_whitespace = 1;
            if (strlen(body_start) > 0) {
                for (size_t i = 0; i < strlen(body_start); i++) {
                    if (!isspace((unsigned char)body_start[i])) {
                        is_empty_or_whitespace = 0;
                        break;
                    }
                }
            }

            if (is_empty_or_whitespace) {
                printf("ERROR: Corp raspuns gol.\n");
            } else {
                root_value = json_parse_string(body_start);
                if (root_value == NULL) {
                    printf("ERROR: Parsare JSON esuata. Corp invalid.\n");
                } else if (json_value_get_type(root_value) != JSONObject) {
                    printf("ERROR: Radacina JSON nu e obiect.\n");
                    json_value_free(root_value);
                    root_value = NULL;
                } else {
                    JSON_Object *root_object = json_value_get_object(root_value);
                    JSON_Array *users_array = json_object_get_array(root_object, "users");

                    if (users_array == NULL) {
                        printf("ERROR: Array 'users' negasit.\n");
                    } else {
                        printf("SUCCESS: Lista utilizatori:\n");
                        size_t count = json_array_get_count(users_array);
                        if (count == 0) {
                            printf("Niciun utilizator gasit.\n");
                        } else {
                            for (size_t i = 0; i < count; i++) {
                                JSON_Object *user_object = json_array_get_object(users_array, i);
                                if (user_object) {
                                    double id_double = json_object_get_number(user_object, "id");
                                    const char *username_json = json_object_get_string(user_object, "username");
                                    const char *password_json = json_object_get_string(user_object, "password");

                                    printf("#%.0f %s:%s\n",
                                           id_double,
                                           username_json ? username_json : "N/A",
                                           password_json ? password_json : "N/A");
                                }
                            }
                        }
                    }
                }
            }
        } else {
            printf("ERROR: Raspuns 200 OK fara corp.\n");
        }
    } else {
        printf("ERROR: Obtinere utilizatori esuata. Raspuns server neasteptat.\n");
        char preview[201];
        strncpy(preview, response, 200);
        preview[200] = '\0';
        printf("Partial raspuns server: %s...\n", preview);
        if (body_start) {
            body_start += 4;
            printf("Corp raspuns: %s\n", body_start);
        }
    }

    if (root_value) {
        json_value_free(root_value);
    }
    if (response) {
        free(response);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
}

void delete_user() {
    int sockfd = -1;
    char username[64];
    char request[8192];

    if (strlen(admin_session_cookie) == 0) {
        printf("ERROR: Admin nelogat.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare la server esuata.\n");
        return;
    }

    printf("username=");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("\nERROR: Citire utilizator esuata.\n");
        close(sockfd);
        return;
    }
    username[strcspn(username, "\n")] = '\0';

    if (strlen(username) == 0) {
        printf("ERROR: Utilizator gol.\n");
        close(sockfd);
        return;
    }
    if (strchr(username, ' ') != NULL || strchr(username, '/') != NULL) {
        printf("ERROR: Format utilizator invalid.\n");
        close(sockfd);
        return;
    }

    snprintf(request, sizeof(request),
             "DELETE /api/v1/tema/admin/users/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Cookie: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             username, SERVER_HOST, SERVER_PORT, admin_session_cookie);
    char *response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde.\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        const char *body_start_ptr;

        if (strstr(response, "HTTP/1.1 200 OK") || strstr(response, "HTTP/1.1 204 No Content")) {
            printf("SUCCESS: Utilizator sters (%s).\n", username);
        } else if (strstr(response, "HTTP/1.1 403 Forbidden")) {
            printf("ERROR: Stergere esuata. Rol admin/sesiune expirata.\n");
            body_start_ptr = strstr(response, "\r\n\r\n");
            if (body_start_ptr) {
                body_start_ptr += 4;
                if (strlen(body_start_ptr) > 0) {
                    JSON_Value *root_val = json_parse_string(body_start_ptr);
                    if (root_val) {
                        JSON_Object *obj = json_value_get_object(root_val);
                        if (obj) {
                            const char *error_msg = json_object_get_string(obj, "error");
                            if (error_msg) {
                                printf("Detaliu eroare server (JSON): %s\n", error_msg);
                            }
                        }
                        json_value_free(root_val);
                    }
                }
            }
        } else if (strstr(response, "HTTP/1.1 404 Not Found")) {
            printf("ERROR: Stergere esuata. Utilizator '%s' negasit.\n", username);
            body_start_ptr = strstr(response, "\r\n\r\n");
            if (body_start_ptr) {
                body_start_ptr += 4;
                if (strlen(body_start_ptr) > 0) {
                    JSON_Value *root_val = json_parse_string(body_start_ptr);
                    if (root_val) {
                        JSON_Object *obj = json_value_get_object(root_val);
                        if (obj) {
                            const char *error_msg = json_object_get_string(obj, "error");
                            if (error_msg) {
                                printf("Detaliu eroare server (JSON): %s\n", error_msg);
                            }
                        }
                        json_value_free(root_val);
                    }
                }
            }
        } else if (strstr(response, "HTTP/1.1 400 Bad Request")) {
            printf("ERROR: Stergere esuata. Utilizator invalid ('%s')/cerere gresita.\n", username);
            body_start_ptr = strstr(response, "\r\n\r\n");
            if (body_start_ptr) {
                body_start_ptr += 4;
                if (strlen(body_start_ptr) > 0) {
                    if (strstr(response, "Content-Type: application/json")) {
                        JSON_Value *root_val = json_parse_string(body_start_ptr);
                        if (root_val) {
                            JSON_Object *obj = json_value_get_object(root_val);
                            if (obj) {
                                const char *error_msg = json_object_get_string(obj, "error");
                                if (error_msg) {
                                    printf("Detaliu eroare server (JSON): %s\n", error_msg);
                                }
                            }
                            json_value_free(root_val);
                        }
                    }
                }
            }
        } else {
            printf("ERROR: Stergere esuata. Eroare server neasteptata.\n");
            body_start_ptr = strstr(response, "\r\n\r\n");
            if (body_start_ptr) {
                body_start_ptr += 4;
                if (strlen(body_start_ptr) > 0) {
                    printf("Corp mesaj server:\n---\n%s\n---\n", body_start_ptr);
                    if (strstr(response, "Content-Type: application/json")) {
                        JSON_Value *root_val = json_parse_string(body_start_ptr);
                        if (root_val) {
                            JSON_Object *obj = json_value_get_object(root_val);
                            if (obj) {
                                const char *error_msg = json_object_get_string(obj, "error");
                                if (error_msg) {
                                    printf("Detaliu eroare server (JSON): %s\n", error_msg);
                                }
                            }
                            json_value_free(root_val);
                        }
                    }
                }
            }
        }
        free_response_if_needed(response);
    }
    close(sockfd);
}

void login() {
    if (admin_session_cookie[0] != '\0') {
        printf("ERROR: Un admin ('%s') este deja logat cu sesiunea admin. Delogati-va intai.\n",
               (current_logged_in_username[0] != '\0' ? current_logged_in_username : "admin necunoscut"));
        return;
    }
    
    int sockfd = connect_to_server();
    char admin_username[64], username[64], password[64], request[8192];
    current_logged_in_username[0] = '\0';

    printf("admin_username=");
    fgets(admin_username, 64, stdin);
    admin_username[strcspn(admin_username, "\n")] = '\0';

    printf("username=");
    fgets(username, 64, stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("password=");
    fgets(password, 64, stdin);
    password[strcspn(password, "\n")] = '\0';

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "admin_username", admin_username);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_string = json_serialize_to_string(root_value);

    snprintf(request, sizeof(request), "POST /api/v1/tema/user/login HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %ld\r\n\r\n%s",
             SERVER_HOST, SERVER_PORT, strlen(json_string), json_string);

    json_free_serialized_string(json_string);
    json_value_free(root_value);

    char *response = send_request(sockfd, request);
    user_session_cookie[0] = '\0';
    jwt_token[0] = '\0';

    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        char *cookie_start = strstr(response, "Set-Cookie: ");
        if (cookie_start) {
            cookie_start += strlen("Set-Cookie: ");
            char *cookie_end = strstr(cookie_start, ";");
            if (cookie_end) {
                int len = cookie_end - cookie_start;
                if (len > 0 && (size_t)len < sizeof(user_session_cookie)) {
                    strncpy(user_session_cookie, cookie_start, len);
                    user_session_cookie[len] = '\0';
                } else if ((size_t)len >= sizeof(user_session_cookie)) {
                     printf("ERROR: Cookie prea mare.\n");
                }
            }
        }

        if (strstr(response, "200 OK")) {
            printf("SUCCESS: Autentificare reusita.\n");
            if (strlen(username) > 0) {
                strncpy(current_logged_in_username, username, sizeof(current_logged_in_username) - 1);
                current_logged_in_username[sizeof(current_logged_in_username) - 1] = '\0';
            }

            if (strlen(user_session_cookie) == 0) {
                printf("Autentificare OK, dar cookie neextras.\n");
            }
        } else {
            printf("ERROR: Autentificare esuata.\n");
            user_session_cookie[0] = '\0';
            current_logged_in_username[0] = '\0';
        }
    } else if (response != NULL) {
        printf("%s\n", response);
        user_session_cookie[0] = '\0';
        current_logged_in_username[0] = '\0';
    } else {
        printf("ERROR: Serverul nu raspunde.\n");
        user_session_cookie[0] = '\0';
        current_logged_in_username[0] = '\0';
    }
    free_response_if_needed(response);
    close(sockfd);
}

void logout() {
    int sockfd = connect_to_server();
    char request[8192];

    if (strlen(user_session_cookie) == 0) {
        printf("ERROR: Utilizator nelogat sau cookie lipsa.\n");
        close(sockfd);
        return;
    }

    snprintf(request, sizeof(request), "GET /api/v1/tema/user/logout HTTP/1.1\r\nHost: %s:%d\r\nCookie: %s\r\n\r\n",
             SERVER_HOST, SERVER_PORT, user_session_cookie);

    char *response = send_request(sockfd, request);
    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        if (strstr(response, "200 OK")) {
            printf("SUCCESS: Utilizator delogat.\n");
            user_session_cookie[0] = '\0';
            jwt_token[0] = '\0';
            current_logged_in_username[0] = '\0';
        } else {
            printf("ERROR: Delogare esuata.\n");
        }
    } else if (response != NULL) {
        printf("%s\n", response);
    } else {
        printf("ERROR: Serverul nu raspunde.\n");
    }
    free_response_if_needed(response);
    close(sockfd);
}

void get_access() {
    int sockfd = -1;
    char request[8192];
    char *response = NULL;
    char *response_body_start = NULL;

    if (strlen(user_session_cookie) == 0) {
        printf("ERROR: Autentificare necesara.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare esuata pentru token acces.\n");
        return;
    }

    snprintf(request, sizeof(request),
             "GET /api/v1/tema/library/access HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Cookie: %s\r\n"
             "Connection: close\r\n\r\n",
             SERVER_HOST, SERVER_PORT, user_session_cookie);

    response = send_request(sockfd, request);

    jwt_token[0] = '\0';

    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        if (strstr(response, "200 OK")) {
            response_body_start = strstr(response, "\r\n\r\n");
            if (response_body_start != NULL) {
                response_body_start += 4;

                JSON_Value *root_value = json_parse_string(response_body_start);
                if (root_value && json_value_get_type(root_value) == JSONObject) {
                    JSON_Object *root_object = json_value_get_object(root_value);
                    const char *token_str = json_object_get_string(root_object, "token");

                    if (token_str != NULL) {
                        if (strlen(token_str) < sizeof(jwt_token)) {
                            strcpy(jwt_token, token_str);
                            printf("SUCCESS: Token JWT extras.\n");
                        } else {
                            printf("ERROR: Token JWT prea mare.\n");
                            jwt_token[0] = '\0';
                        }
                    } else {
                        printf("ERROR: Camp 'token' negasit in JSON.\n");
                    }
                } else {
                    printf("ERROR: Corp raspuns JSON invalid.\n");
                }
                if(root_value) json_value_free(root_value);
            } else {
                printf("ERROR: Corp raspuns negasit (lipsa \\r\\n\\r\\n).\n");
            }
        } else {
            char status_line_buff[128] = {0};
            char *status_line_end = strstr(response, "\r\n");
            size_t status_len;
            if (status_line_end) {
                status_len = (size_t)(status_line_end - response);
            } else {
                status_len = sizeof(status_line_buff) - 1;
            }
            strncpy(status_line_buff, response, status_len);
            status_line_buff[status_len] = '\0';
            printf("ERROR: Obtinere token esuata. Status server: %s\n", status_line_buff);
        }
    } else if (response != NULL) {
        printf("%s\n", response);
    } else {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    }

    free_response_if_needed(response);
    if (sockfd >= 0) {
        close(sockfd);
    }
}

void get_movies() {
    int sockfd = -1;
    char request[8192];

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Neconectat la server.\n");
        return;
    }

    snprintf(request, sizeof(request),
             "GET /api/v1/tema/library/movies HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             SERVER_HOST, SERVER_PORT, jwt_token);

    char *response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        if (strstr(response, "HTTP/1.1 200 OK")) {
            printf("SUCCESS: Lista filmelor:\n");
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                JSON_Value *root_value = json_parse_string(body_start);

                if (root_value != NULL && json_value_get_type(root_value) == JSONObject) {
                    JSON_Object *root_object = json_value_get_object(root_value);
                    JSON_Array *movies_array = json_object_get_array(root_object, "movies");

                    if (movies_array != NULL) {
                        size_t count = json_array_get_count(movies_array);
                        if (count == 0) {
                            printf("Niciun film in biblioteca.\n");
                        } else {
                            for (size_t i = 0; i < count; i++) {
                                JSON_Object *movie_object = json_array_get_object(movies_array, i);
                                if (movie_object != NULL) {
                                    const char *title_json = json_object_get_string(movie_object, "title");
                                    double id_double = json_object_get_number(movie_object, "id");

                                    printf("#%.0f %s\n",
                                           id_double,
                                           title_json ? title_json : "N/A");
                                }
                            }
                        }
                    } else {
                        printf("ERROR: Camp 'movies' negasit/invalid in JSON.\n");
                    }
                } else {
                    printf("ERROR: Parsare JSON esuata sau raspuns nu e obiect JSON.\n");
                }
                if (root_value != NULL) {
                    json_value_free(root_value);
                }
            } else {
                printf("ERROR: Corp lipsa in raspuns 200 OK.\n");
            }
        } else if (strstr(response, "HTTP/1.1 401 Unauthorized")) {
            printf("ERROR: Acces interzis. Token JWT invalid/expirat.\n");
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) printf("Mesaj server: %s\n", body_start + 4);
        } else if (strstr(response, "HTTP/1.1 403 Forbidden")) {
            printf("ERROR: Acces interzis. Permisiuni insuficiente.\n");
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) printf("Mesaj server: %s\n", body_start + 4);
        }
        else {
            printf("ERROR: Obtinere filme esuata. Eroare server.\n");
            char status_line_buff[128] = {0};
            char* first_line_end = strstr(response, "\r\n");
            if (first_line_end) {
                int len = first_line_end - response;
                if ((size_t)len < sizeof(status_line_buff)-1) strncpy(status_line_buff, response, len); else strncpy(status_line_buff, response, sizeof(status_line_buff)-1);
                status_line_buff[sizeof(status_line_buff)-1] = '\0';
                printf("Status server: %s\n", status_line_buff);
            } else {
                printf("Raspuns server: %s\n", response);
            }
             char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) printf("Corp mesaj server: %s\n", body_start + 4);
        }
    }

    free_response_if_needed(response);
    if (sockfd >= 0) {
        close(sockfd);
    }
}

void get_movie() {
    int sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare la server esuata.\n");
        return;
    }

    char id_str[16], request[8192];

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        close(sockfd);
        return;
    }

    printf("id=");
    if (fgets(id_str, sizeof(id_str), stdin) == NULL) {
        printf("ERROR: Citire ID esuata.\n");
        close(sockfd);
        return;
    }
    id_str[strcspn(id_str, "\n")] = '\0';

    if (strlen(id_str) == 0) {
        printf("ERROR: ID film gol.\n");
        close(sockfd);
        return;
    }

    snprintf(request, sizeof(request),
             "GET /api/v1/tema/library/movies/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "\r\n",
             id_str, SERVER_HOST, SERVER_PORT, jwt_token);

    char *response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde sau eroare send_request.\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        if (strstr(response, "200 OK")) {
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                JSON_Value *root_val = json_parse_string(body_start);
                if (root_val) {
                    JSON_Object *movie = json_value_get_object(root_val);
                    if (movie) {
                        printf("{\n");
                        const char *rating_str_from_json = json_object_get_string(movie, "rating");

                        printf("  \"id\": %.0f,\n", json_object_get_number(movie, "id"));
                        printf("  \"title\": \"%s\",\n", json_object_get_string(movie, "title") ?: "N/A");
                        printf("  \"year\": %d,\n", (int)json_object_get_number(movie, "year"));
                        printf("  \"description\": \"%s\",\n", json_object_get_string(movie, "description") ?: "N/A");

                        if (rating_str_from_json != NULL) {
                            printf("  \"rating\": \"%s\"\n", rating_str_from_json);
                        } else {
                            double rating_num_fallback = json_object_get_number(movie, "rating");
                            if (json_object_has_value_of_type(movie, "rating", JSONNumber)) {
                                 printf("  \"rating\": %.1f\n", rating_num_fallback);
                            } else {
                                 printf("  \"rating\": null\n");
                            }
                        }
                        printf("}\n");
                    } else {
                        printf("ERROR: Corp JSON invalid sau detalii film eronate.\n");
                    }
                    json_value_free(root_val);
                } else {
                    printf("ERROR: Parsare JSON din corp esuata.\n");
                }
            } else {
                printf("ERROR: Corp lipsa in raspuns 200 OK.\n");
            }
        } else {
            char status_line[256] = "Eroare necunoscuta";
            char *first_eol = strstr(response, "\r\n");
            if (first_eol) {
                size_t len = first_eol - response;
                if (len < sizeof(status_line) - 1) {
                    strncpy(status_line, response, len);
                    status_line[len] = '\0';
                } else {
                   strcpy(status_line, "Serverul a returnat un status non-OK (linie status prea lunga)");
                }
            }
            printf("ERROR: Obtinere film esuata. Raspuns server: %s\n", status_line);
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                JSON_Value *error_val = json_parse_string(body_start);
                if (error_val) {
                    JSON_Object *error_obj = json_value_get_object(error_val);
                    if (error_obj) {
                        const char* error_msg = json_object_get_string(error_obj, "error");
                        if (error_msg) {
                            printf("Mesaj server: %s\n", error_msg);
                        } else {
                            char body_preview[101]; strncpy(body_preview, body_start, 100); body_preview[100] = '\0';
                            printf("Corp raspuns server (primele 100 caractere): %s\n", body_preview);
                        }
                    }
                    json_value_free(error_val);
                }
            }
        }
    }
    free_response_if_needed(response);
    close(sockfd);
}

void add_movie() {
    int sockfd = -1;
    char title[256], year_str[16], description[1024], rating_str[16];
    char request[8192];
    char *json_payload_string = NULL;
    JSON_Value *root_value = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces biblioteca (pct 4.7).\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare server esuata.\n");
        return;
    }

    printf("title=");
    if (fgets(title, sizeof(title), stdin) == NULL) { printf("ERROR: Citire titlu esuata.\n"); goto cleanup; }
    title[strcspn(title, "\n")] = '\0';

    printf("year=");
    if (fgets(year_str, sizeof(year_str), stdin) == NULL) { printf("ERROR: Citire an esuata.\n"); goto cleanup; }
    year_str[strcspn(year_str, "\n")] = '\0';

    printf("description=");
    if (fgets(description, sizeof(description), stdin) == NULL) { printf("ERROR: Citire descriere esuata.\n"); goto cleanup; }
    description[strcspn(description, "\n")] = '\0';

    printf("rating=");
    if (fgets(rating_str, sizeof(rating_str), stdin) == NULL) { printf("ERROR: Citire rating esuata.\n"); goto cleanup; }
    rating_str[strcspn(rating_str, "\n")] = '\0';

    if (strlen(title) == 0) {
        printf("ERROR: Titlu gol.\n");
        goto cleanup;
    }

    root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    if (root_object == NULL) {
        printf("ERROR: Creare obiect JSON esuata.\n");
        goto cleanup;
    }

    json_object_set_string(root_object, "title", title);
    json_object_set_number(root_object, "year", (double)atoi(year_str));
    json_object_set_string(root_object, "description", description);
    json_object_set_number(root_object, "rating", atof(rating_str));

    json_payload_string = json_serialize_to_string(root_value);
    if (json_payload_string == NULL) {
        printf("ERROR: Serializare JSON esuata.\n");
        goto cleanup;
    }

    snprintf(request, sizeof(request),
             "POST /api/v1/tema/library/movies HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             SERVER_HOST, SERVER_PORT, jwt_token, strlen(json_payload_string), json_payload_string);

    char *response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        char *body_start = strstr(response, "\r\n\r\n");
        char *server_message = body_start ? (body_start + 4) : "Corp mesaj server gol.";

        if (strstr(response, "HTTP/1.1 201 CREATED") || strstr(response, "HTTP/1.1 200 OK")) {
            printf("SUCCESS: Film adaugat.\n");
        } else if (strstr(response, "HTTP/1.1 400 Bad Request")) {
            printf("ERROR: Adaugare film esuata. Date invalide/incomplete.\n");
        } else if (strstr(response, "HTTP/1.1 401 Unauthorized")) {
            printf("ERROR: Adaugare film esuata. Acces interzis (token invalid/expirat).\n");
        } else if (strstr(response, "HTTP/1.1 403 Forbidden")) {
            printf("ERROR: Adaugare film esuata. Acces interzis (permisiuni insuficiente).\n");
        }
        else {
            printf("ERROR: Adaugare film esuata. Eroare server.\n");
            if (body_start && strlen(server_message)>0) printf("Mesaj server: %s\n", server_message);
        }
    }
    free_response_if_needed(response);

cleanup:
    if (json_payload_string != NULL) {
        json_free_serialized_string(json_payload_string);
    }
    if (root_value != NULL) {
        json_value_free(root_value);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
}

void delete_movie() {
    int sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare server esuata.\n");
        return;
    }

    char id_str[16], request[8192];

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        close(sockfd);
        return;
    }

    printf("id=");
    if (fgets(id_str, sizeof(id_str), stdin) == NULL) {
        printf("ERROR: Citire ID esuata.\n");
        close(sockfd);
        return;
    }
    id_str[strcspn(id_str, "\n")] = '\0';

    if (strlen(id_str) == 0) {
        printf("ERROR: ID film gol.\n");
        close(sockfd);
        return;
    }

    snprintf(request, sizeof(request),
             "DELETE /api/v1/tema/library/movies/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "\r\n",
             id_str, SERVER_HOST, SERVER_PORT, jwt_token);

    char *response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde sau eroare send_request.\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        if (strstr(response, "200 OK") || strstr(response, "204 No Content")) {
            printf("SUCCESS: Film sters.\n");
        } else {
            char status_line[256] = "Eroare necunoscuta";
            char *first_eol = strstr(response, "\r\n");
            if (first_eol) {
                size_t len = first_eol - response;
                if (len < sizeof(status_line) - 1) {
                    strncpy(status_line, response, len);
                    status_line[len] = '\0';
                } else {
                   strcpy(status_line, "Serverul a returnat un status non-OK (linie status prea lunga)");
                }
            }
            printf("ERROR: Stergere film esuata. Raspuns server: %s\n", status_line);
            char *body_start = strstr(response, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    JSON_Value *error_val = json_parse_string(body_start);
                    if (error_val) {
                        JSON_Object *error_obj = json_value_get_object(error_val);
                        if (error_obj) {
                            const char* error_msg = json_object_get_string(error_obj, "error");
                            if (error_msg) {
                                printf("Mesaj server: %s\n", error_msg);
                            } else {
                                char body_preview[101]; strncpy(body_preview, body_start, 100); body_preview[100] = '\0';
                                printf("Corp raspuns server (primele 100 caractere): %s\n", body_preview);
                            }
                        }
                        json_value_free(error_val);
                    } else {
                        char body_preview[101]; strncpy(body_preview, body_start, 100); body_preview[100] = '\0';
                        printf("Corp raspuns server (primele 100 caractere, non-JSON): %s\n", body_preview);
                    }
                } else {
                    printf("Corp raspuns server gol.\n");
                }
            }
        }
    }
    free_response_if_needed(response);
    close(sockfd);
}

void update_movie() {
    int sockfd = -1;
    char movie_id_str[16];
    char title[256], year_str[16], description[1024], rating_str[16];
    char *json_payload_str = NULL;
    char full_request[8192];
    char *response = NULL;
    JSON_Value *root_value_payload = NULL;
    JSON_Value *root_value_response = NULL;
    long year_val = 0;
    double rating_val = 0.0;
    char *endptr;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Autentificati-va sau obtineti acces.\n");
        return;
    }
    printf("id=");
    if (!fgets(movie_id_str, sizeof(movie_id_str), stdin)) { printf("ERROR: Citire ID esuata.\n"); return; }
    movie_id_str[strcspn(movie_id_str, "\n")] = '\0';
    if (strlen(movie_id_str) == 0) { printf("ERROR: ID film gol.\n"); return; }

    printf("title=");
    if (!fgets(title, sizeof(title), stdin)) { printf("ERROR: Citire titlu esuata.\n"); return; }
    title[strcspn(title, "\n")] = '\0';

    printf("year=");
    if (!fgets(year_str, sizeof(year_str), stdin)) { printf("ERROR: Citire an esuata.\n"); return; }
    year_str[strcspn(year_str, "\n")] = '\0';
    if (strlen(year_str) > 0) {
        errno = 0;
        year_val = strtol(year_str, &endptr, 10);
        if (errno == ERANGE || year_str == endptr || *endptr != '\0') {
            printf("ERROR: Format an invalid. Introduceti numar valid sau lasati gol.\n");
            year_val = -1;
        }
    } else {
        year_val = 0;
    }

    printf("description=");
    if (!fgets(description, sizeof(description), stdin)) { printf("ERROR: Citire descriere esuata.\n"); return; }
    description[strcspn(description, "\n")] = '\0';

    printf("rating=");
    if (!fgets(rating_str, sizeof(rating_str), stdin)) { printf("ERROR: Citire rating esuata.\n"); return; }
    rating_str[strcspn(rating_str, "\n")] = '\0';
    if (strlen(rating_str) > 0) {
        errno = 0;
        rating_val = strtod(rating_str, &endptr);
        if (errno == ERANGE || rating_str == endptr || *endptr != '\0') {
            printf("ERROR: Format rating invalid. Introduceti numar valid sau lasati gol.\n");
            rating_val = -100.0;
        }
    } else {
        rating_val = 0.0;
    }

    root_value_payload = json_value_init_object();
    if (!root_value_payload) {
        printf("ERROR: Initializare obiect JSON (payload) esuata.\n");
        return;
    }
    JSON_Object *payload_object = json_value_get_object(root_value_payload);
    json_object_set_string(payload_object, "title", title);
    if(year_val != -1) json_object_set_number(payload_object, "year", (double)year_val);
    json_object_set_string(payload_object, "description", description);
    if(rating_val != -100.0) json_object_set_number(payload_object, "rating", rating_val);

    json_payload_str = json_serialize_to_string(root_value_payload);
    if (!json_payload_str) {
        printf("ERROR: Serializare JSON payload esuata.\n");
        json_value_free(root_value_payload);
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        printf("ERROR: Conectare server esuata.\n");
        json_free_serialized_string(json_payload_str);
        json_value_free(root_value_payload);
        return;
    }

    snprintf(full_request, sizeof(full_request),
             "PUT /api/v1/tema/library/movies/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             movie_id_str, SERVER_HOST, SERVER_PORT, jwt_token,
             strlen(json_payload_str), json_payload_str);

    response = send_request(sockfd, full_request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    }
    else {
        char *body_start = strstr(response, "\r\n\r\n");
        char status_line_buffer[128] = {0};

        if (strstr(response, "HTTP/1.1 200 OK")) {
            printf("SUCCESS: Film actualizat.\n");
        } else {
            char* first_line_end = strstr(response, "\r\n");
            if (first_line_end) {
                size_t len = first_line_end - response;
                if (len < sizeof(status_line_buffer) -1) {
                    strncpy(status_line_buffer, response, len);
                    status_line_buffer[len] = '\0';
                } else {
                    strncpy(status_line_buffer, response, sizeof(status_line_buffer)-1);
                     status_line_buffer[sizeof(status_line_buffer)-1] = '\0';
                }
                 printf("ERROR: Actualizare film esuata. Status server: %s\n", status_line_buffer);
            } else {
                printf("ERROR: Actualizare film esuata. Raspuns server malformat.\n");
            }

            const char* server_error_message = NULL;
            if (body_start) {
                body_start += 4;
                root_value_response = json_parse_string(body_start);
                if (root_value_response && json_value_get_type(root_value_response) == JSONObject) {
                    JSON_Object *error_object = json_value_get_object(root_value_response);
                    server_error_message = json_object_get_string(error_object, "error");
                }
            }

            if (strstr(response, "HTTP/1.1 401 Unauthorized") || strstr(response, "HTTP/1.1 403 Forbidden")) {
                printf("Motiv: Acces biblioteca refuzat. Token invalid/expirat sau permisiuni lipsa.\n");
            } else if (strstr(response, "HTTP/1.1 404 Not Found")) {
                printf("Motiv: ID film '%s' negasit (ID invalid).\n", movie_id_str);
            } else if (strstr(response, "HTTP/1.1 400 Bad Request")) {
                printf("Motiv: Date invalide/incomplete. Verificati intrarea.\n");
            } else {
                printf("Motiv: Eroare neasteptata pe server.\n");
            }

            if (server_error_message) {
                printf("Mesaj server: %s\n", server_error_message);
            } else if (body_start && strlen(body_start) > 0) {
                printf("Corp raspuns server brut: %s\n", body_start);
            }
        }
    }

    if (root_value_payload) json_value_free(root_value_payload);
    if (json_payload_str) json_free_serialized_string(json_payload_str);
    if (root_value_response) json_value_free(root_value_response);
    if (response) free_response_if_needed(response);
    if (sockfd >= 0) close(sockfd);
}

void get_collections() {
    int sockfd = -1;
    char request[8192];
    char *response = NULL;
    JSON_Value *root_val = NULL;
    JSON_Array *collections_array_to_process = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        return;
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        return;
    }

    snprintf(request, sizeof(request),
             "GET /api/v1/tema/library/collections HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Connection: close\r\n\r\n",
             SERVER_HOST, SERVER_PORT, jwt_token);

    response = send_request(sockfd, request);

    if (response == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(response, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", response);
    } else {
        char *body_start = strstr(response, "\r\n\r\n");

        if (strstr(response, "HTTP/1.1 200 OK")) {
            printf("SUCCESS: Lista colectii:\n");

            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    root_val = json_parse_string(body_start);

                    if (root_val != NULL) {
                        if (json_value_get_type(root_val) == JSONArray) {
                            collections_array_to_process = json_value_get_array(root_val);
                        } else if (json_value_get_type(root_val) == JSONObject) {
                            JSON_Object *root_object = json_value_get_object(root_val);
                            if (json_object_has_value_of_type(root_object, "collections", JSONArray)) {
                                collections_array_to_process = json_object_get_array(root_object, "collections");
                            } else {
                                printf("ERROR: Format JSON neasteptat pentru colectii.\n");
                            }
                        } else {
                             printf("ERROR: Raspunsul JSON nu este un array sau obiect asteptat.\n");
                        }
                    } else {
                        printf("ERROR: Parsare corp JSON esuata.\n");
                    }

                    if (collections_array_to_process != NULL) {
                        size_t count = json_array_get_count(collections_array_to_process);
                        if (count == 0) {
                            printf("Nicio colectie gasita.\n");
                        } else {
                            for (size_t i = 0; i < count; i++) {
                                JSON_Object *coll_obj = json_array_get_object(collections_array_to_process, i);
                                if (coll_obj) {
                                    printf("#%d: %s\n",
                                           (int)json_object_get_number(coll_obj, "id"),
                                           json_object_get_string(coll_obj, "title") ?: "N/A");
                                }
                            }
                        }
                    } else if (root_val != NULL) {
                        printf("ERROR: Array colectii negasit in JSON.\n");
                    }
                } else {
                    printf("ERROR: Corp raspuns gol dupa headere.\n");
                }
            } else {
                printf("ERROR: Corp lipsa in 200 OK (lipsa \\r\\n\\r\\n).\n");
            }
        } else {
            printf("ERROR: Obtinere lista colectii esuata.\n");
            char status_line_buff[128] = {0};
            char* first_line_end = strstr(response, "\r\n");
            if (first_line_end) {
                int len = first_line_end - response;
                if ((size_t)len < sizeof(status_line_buff)-1) strncpy(status_line_buff, response, len); else strncpy(status_line_buff, response, sizeof(status_line_buff)-1);
                 status_line_buff[sizeof(status_line_buff)-1] = '\0';
                printf("Status server: %s\n", status_line_buff);
            }
            if (body_start) {
                 body_start += 4;
                 if(strlen(body_start) > 0) printf("Corp mesaj server: %s\n", body_start);
            }
        }
    }
    if (root_val) json_value_free(root_val);
    free_response_if_needed(response);
    if (sockfd >= 0) close(sockfd);
}

void get_collection() {
    int sockfd = -1;
    char id_str[16] = {0};
    char request[8192] = {0};
    char *server_response_str = NULL;
    JSON_Value *root_value_response = NULL;
    JSON_Value *err_val_parsed_body = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: JWT token lipseste.\n");
        goto cleanup;
    }
    printf("id=");
    fflush(stdout);
    if (fgets(id_str, sizeof(id_str), stdin) == NULL || strlen(id_str) == 1) {
        printf("ERROR: Failed la citire ID.\n");
        goto cleanup;
    }
    id_str[strcspn(id_str, "\n")] = '\0';
    if (strlen(id_str) == 0) {
        printf("ERROR: Collection ID nu poate fi gol.\n");
        goto cleanup;
    }
    sockfd = connect_to_server();
    if (sockfd < 0) {
        goto cleanup;
    }
    snprintf(request, sizeof(request),
             "GET /api/v1/tema/library/collections/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             id_str, SERVER_HOST, SERVER_PORT, jwt_token);

    server_response_str = send_request(sockfd, request);

    if (server_response_str == NULL) {
        printf("ERROR: Niciun raspuns de la server.\n");
    } else if (strcmp(server_response_str, "ERROR: Failed to receive response.") == 0) {
    } else {
        char *body_start = strstr(server_response_str, "\r\n\r\n");

        if (strstr(server_response_str, "HTTP/1.1 200 OK")) {
            printf("SUCCESS: Detalii colectie\n");
            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    root_value_response = json_parse_string(body_start);
                    JSON_Object *collection_obj = NULL;

                    if (root_value_response && json_value_get_type(root_value_response) == JSONObject) {
                        collection_obj = json_value_get_object(root_value_response);
                    }
                    
                    if (collection_obj) {
                        printf("ID: %.0f\n", json_object_get_number(collection_obj, "id"));
                        printf("Title: %s\n", json_object_get_string(collection_obj, "title") ?: "N/A");
                        printf("Owner: %s\n", json_object_get_string(collection_obj, "owner") ?: "N/A");

                        printf("Movies:\n");
                        JSON_Array *movies_array = json_object_get_array(collection_obj, "movies");
                        if (movies_array) {
                            size_t num_movies_count = json_array_get_count(movies_array);
                            if (num_movies_count > 0) {
                                for (size_t i = 0; i < num_movies_count; i++) {
                                    JSON_Value* movie_val = json_array_get_value(movies_array, i);
                                    JSON_Object *movie_obj = NULL;
                                    if (movie_val && json_value_get_type(movie_val) == JSONObject) {
                                        movie_obj = json_value_get_object(movie_val);
                                    }
                                    
                                    if (movie_obj) {
                                        double movie_id_double = json_object_get_number(movie_obj, "id");
                                        const char* movie_title = json_object_get_string(movie_obj, "title");
                                        printf("#%.0f %s\n", movie_id_double, movie_title ?: "N/A"); 
                                    }else {
                                        printf("  - N/A (invalid movie object at index %zu)\n", i);
                                    }
                                }
                            } else {
                                printf("  (none)\n");
                            }
                        } else {
                            printf("  (N/A - movies data unavailable)\n");
                        }
                    } else {
                        printf("ERROR: Could not parse collection details from response body.\n");
                        printf("ID: N/A\n"); printf("Title: N/A\n"); printf("Owner: N/A\n");
                        printf("Movies:\n  (N/A)\n");
                    }
                } else {
                    printf("ERROR: Received 200 OK but response body is empty.\n");
                    printf("ID: N/A\n"); printf("Title: N/A\n"); printf("Owner: N/A\n");
                    printf("Movies:\n  (N/A)\n");
                }
            } else {
                printf("ERROR: Received 200 OK but could not find response body delimiter.\n");
                printf("ID: N/A\n"); printf("Title: N/A\n"); printf("Owner: N/A\n");
                printf("Movies:\n  (N/A)\n");
            }
        } else {
            printf("ERROR: Nu s-a putut obtine colectia.\n");
            char* first_line_end = strstr(server_response_str, "\r\n");
            if (first_line_end) {
                printf("Server status: %.*s\n", (int)(first_line_end - server_response_str), server_response_str);
            } else {
                char preview[201]; strncpy(preview, server_response_str, 200); preview[200] = '\0';
                printf("Server response: %s...\n", preview);
            }

            if (body_start) { 
                body_start += 4;
                if (strlen(body_start) > 0) {
                    printf("Mesaj server:\n---\n%s\n---\n", body_start);
                    err_val_parsed_body = json_parse_string(body_start);
                    if (err_val_parsed_body && json_value_get_type(err_val_parsed_body) == JSONObject) {
                        JSON_Object *err_obj = json_value_get_object(err_val_parsed_body);
                        const char *err_msg_str = json_object_get_string(err_obj, "error");
                        if (err_msg_str) {
                            printf("Server JSON error detail: %s\n", err_msg_str);
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (root_value_response != NULL) json_value_free(root_value_response);
    if (err_val_parsed_body != NULL) json_value_free(err_val_parsed_body);
    if (server_response_str != NULL) free_response_if_needed(server_response_str);
    if (sockfd >= 0) close(sockfd);
}

int add_single_movie_to_collection_internal(const char* collection_id_str, const char* movie_id_to_add_str) {
    int sockfd_movie = -1;
    char payload_json_movie[64] = {0};
    char request_buffer_movie[8192] = {0};
    char *movie_add_response = NULL;
    int success = 0;

    for (size_t i = 0; movie_id_to_add_str[i] != '\0'; ++i) {
        if (movie_id_to_add_str[i] < '0' || movie_id_to_add_str[i] > '9') {
            printf("    ERROR: Movie ID '%s' is not numeric. Skipping addition.\n", movie_id_to_add_str);
            return 0;
        }
    }
    
    printf("  -> Attempting to add movie_id %s to collection_id %s...\n", movie_id_to_add_str, collection_id_str);

    snprintf(payload_json_movie, sizeof(payload_json_movie), "{\"id\":%s}", movie_id_to_add_str);

    sockfd_movie = connect_to_server();
    if (sockfd_movie < 0) {
        printf("     ERROR: Conectare la server esuata\n");
        return 0;
    }

    snprintf(request_buffer_movie, sizeof(request_buffer_movie),
             "POST /api/v1/tema/library/collections/%s/movies HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             collection_id_str, SERVER_HOST, SERVER_PORT, jwt_token,
             strlen(payload_json_movie), payload_json_movie);

    movie_add_response = send_request(sockfd_movie, request_buffer_movie);
    close(sockfd_movie);

    if (movie_add_response != NULL &&
        (strstr(movie_add_response, "HTTP/1.1 200 OK") || strstr(movie_add_response, "HTTP/1.1 201 CREATED"))) {
        printf("     SUCCESS: Movie ID %s added to collection %s.\n", movie_id_to_add_str, collection_id_str);
        success = 1;
    } else {
        printf("     ERROR: Failed to add movie ID %s to collection %s.\n", movie_id_to_add_str, collection_id_str);
        if (movie_add_response) {
            char* body_start_err = strstr(movie_add_response, "\r\n\r\n");
            char* status_line_end = strstr(movie_add_response, "\r\n");
            if (status_line_end) {
                printf("       Server status: %.*s\n", (int)(status_line_end - movie_add_response), movie_add_response);
            }
            if (body_start_err) {
                 body_start_err += 4;
                 if(strlen(body_start_err) > 0) printf("       Server error body: %s\n", body_start_err);
            } else if (status_line_end == NULL && strlen(movie_add_response) > 0) {
                 printf("       Raw server response: %s\n", movie_add_response);
            }
        } else {
            printf("       No response or send_request failed for adding movie.\n");
        }
    }

    if (movie_add_response) free_response_if_needed(movie_add_response);
    return success;
}

// Add Collection
void add_collection() {
    int sockfd_collection_create = -1;
    char title_str[256] = {0};
    char num_movies_input_str[16] = {0};
    int num_movies_to_add = 0;
    char **movie_ids_to_add_list = NULL; 

    char collection_create_payload_json[512] = {0}; 
    char request_buffer_collection_create[8192] = {0};    

    char *server_response_collection_create = NULL;
    JSON_Value *response_json_collection_create = NULL;
    JSON_Value *error_json_collection_create = NULL;
    char new_collection_id_str[32] = {0};

    if (strlen(jwt_token) == 0) {
        printf("ERROR: JWT token lipseste.\n");
        goto cleanup;
    }

    printf("title=");
    fflush(stdout);
    if (fgets(title_str, sizeof(title_str), stdin) == NULL || strlen(title_str) <= 1) {
        printf("ERROR: Failed to read title or title is empty.\n");
        goto cleanup;
    }
    title_str[strcspn(title_str, "\n")] = '\0';
    if (strlen(title_str) == 0) {
        printf("ERROR: Title cannot be empty.\n");
        goto cleanup;
    }

    printf("num_movies=");
    fflush(stdout);
    if (fgets(num_movies_input_str, sizeof(num_movies_input_str), stdin) == NULL || strlen(num_movies_input_str) <= 1) {
        printf("ERROR: Failed to read number of movies or input is empty.\n");
        goto cleanup;
    }
    num_movies_input_str[strcspn(num_movies_input_str, "\n")] = '\0';
    if (strlen(num_movies_input_str) == 0) {
        printf("ERROR: Number of movies cannot be empty.\n");
        goto cleanup;
    }
    for (size_t i = 0; i < strlen(num_movies_input_str); ++i) {
        if (num_movies_input_str[i] < '0' || num_movies_input_str[i] > '9') {
            printf("ERROR: Number of movies must be a non-negative integer.\n");
            goto cleanup;
        }
    }
    num_movies_to_add = atoi(num_movies_input_str);
    if (num_movies_to_add < 0) {
        printf("ERROR: Number of movies cannot be negative.\n");
        goto cleanup;
    }

    if (num_movies_to_add > 0) {
        movie_ids_to_add_list = (char **)malloc(num_movies_to_add * sizeof(char *));
        if (movie_ids_to_add_list == NULL) {
            printf("ERROR: Failed to allocate memory for movie IDs list.\n");
            goto cleanup;
        }
        for (int i = 0; i < num_movies_to_add; i++) {
            movie_ids_to_add_list[i] = (char *)malloc(16 * sizeof(char));
            if (movie_ids_to_add_list[i] == NULL) {
                printf("ERROR: Failed to allocate memory for movie_id[%d].\n", i);
                for (int k = 0; k < i; k++) free(movie_ids_to_add_list[k]);
                free(movie_ids_to_add_list);
                movie_ids_to_add_list = NULL;
                goto cleanup;
            }
            printf("movie_id[%d]=", i);
            fflush(stdout);
            if (fgets(movie_ids_to_add_list[i], 16, stdin) == NULL || strlen(movie_ids_to_add_list[i]) <= 1) {
                printf("ERROR: Failed to read movie_id[%d] or input is empty.\n", i);
                for (int k = 0; k <= i; k++) free(movie_ids_to_add_list[k]);
                free(movie_ids_to_add_list);
                movie_ids_to_add_list = NULL;
                goto cleanup;
            }
            movie_ids_to_add_list[i][strcspn(movie_ids_to_add_list[i], "\n")] = '\0';
            if (strlen(movie_ids_to_add_list[i]) == 0) {
                printf("ERROR: Movie ID (movie_id[%d]) cannot be empty.\n", i);
                for (int k = 0; k <= i; k++) free(movie_ids_to_add_list[k]);
                free(movie_ids_to_add_list);
                movie_ids_to_add_list = NULL;
                goto cleanup;
            }
             for(size_t j=0; movie_ids_to_add_list[i][j] != '\0'; ++j) {
                if(movie_ids_to_add_list[i][j] < '0' || movie_ids_to_add_list[i][j] > '9') {
                    printf("ERROR: Movie ID '%s' (movie_id[%d]) is not numeric.\n", movie_ids_to_add_list[i], i);
                     for (int k = 0; k <= i; k++) free(movie_ids_to_add_list[k]);
                    free(movie_ids_to_add_list);
                    movie_ids_to_add_list = NULL;
                    goto cleanup;
                }
            }
        }
    }

    printf("\nCreating collection '%s'...\n", title_str);
    JSON_Value *payload_val_coll_create = json_value_init_object();
    if (!payload_val_coll_create) {
        printf("ERROR: Failed to init JSON object for collection creation payload.\n");
        goto cleanup_movies_list;
    }
    JSON_Object *payload_obj_coll_create = json_value_get_object(payload_val_coll_create);
    json_object_set_string(payload_obj_coll_create, "title", title_str);
    char *serialized_payload_coll_create = json_serialize_to_string(payload_val_coll_create);
    json_value_free(payload_val_coll_create);

    if (!serialized_payload_coll_create) {
        printf("ERROR: Failed to serialize JSON payload for collection creation.\n");
        goto cleanup_movies_list;
    }
    strncpy(collection_create_payload_json, serialized_payload_coll_create, sizeof(collection_create_payload_json) - 1);
    json_free_serialized_string(serialized_payload_coll_create);


    sockfd_collection_create = connect_to_server();
    if (sockfd_collection_create < 0) {
        goto cleanup_movies_list;
    }

    snprintf(request_buffer_collection_create, sizeof(request_buffer_collection_create),
             "POST /api/v1/tema/library/collections HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             SERVER_HOST, SERVER_PORT, jwt_token,
             strlen(collection_create_payload_json), collection_create_payload_json);

    server_response_collection_create = send_request(sockfd_collection_create, request_buffer_collection_create);
    close(sockfd_collection_create); 
    sockfd_collection_create = -1;

    if (server_response_collection_create == NULL || strcmp(server_response_collection_create, "ERROR: Failed to receive response.") == 0) {
        printf("ERROR: Creare colectie esuata '%s'. No response or send_request failed.\n", title_str);
        if (server_response_collection_create) printf("%s\n", server_response_collection_create);
        goto cleanup_movies_list_and_response1;
    }
    
    char *body_start_coll_create = strstr(server_response_collection_create, "\r\n\r\n");
    if (strstr(server_response_collection_create, "HTTP/1.1 201 CREATED") || strstr(server_response_collection_create, "HTTP/1.1 200 OK")) {
        printf("SUCCESS: Colectie '%s' creata.\n", title_str);
        if (body_start_coll_create) {
            body_start_coll_create += 4;
            if (strlen(body_start_coll_create) > 0) {
                printf("  Raw server response for collection creation:\n  ---\n  %s\n  ---\n", body_start_coll_create);
                response_json_collection_create = json_parse_string(body_start_coll_create);
                if (response_json_collection_create && json_value_get_type(response_json_collection_create) == JSONObject) {
                    JSON_Object *coll_obj_resp = json_value_get_object(response_json_collection_create);
                    double id_double = json_object_get_number(coll_obj_resp, "id");
                    if (id_double > 0) {
                        snprintf(new_collection_id_str, sizeof(new_collection_id_str), "%.0f", id_double);
                         printf("  New Collection ID: %s, Title: %s, Owner: %s\n",
                               new_collection_id_str,
                               json_object_get_string(coll_obj_resp, "title") ?: "N/A",
                               json_object_get_string(coll_obj_resp, "owner") ?: "N/A");
                    } else {
                        printf("  ERROR: Invalid or missing 'id' in server response for new collection.\n");
                         goto cleanup_movies_list_and_response1;
                    }
                } else {
                    printf("  WARNING: Could not parse server response for new collection ID.\n");
                    goto cleanup_movies_list_and_response1;
                }
            } else {
                 printf("  WARNING: Server response for collection creation had an empty body.\n");
                 goto cleanup_movies_list_and_response1;
            }
        } else {
            printf("  WARNING: Server response for collection creation had no discernible body.\n");
            goto cleanup_movies_list_and_response1;
        }
        
        if(response_json_collection_create) {
            json_value_free(response_json_collection_create);
            response_json_collection_create = NULL;
        }
        free_response_if_needed(server_response_collection_create);
        server_response_collection_create = NULL;

        if (num_movies_to_add > 0 && strlen(new_collection_id_str) > 0) {
            printf("\nAdaugare %d filme la colectia %s...\n", num_movies_to_add, new_collection_id_str);
            int movies_added_successfully = 0;
            for (int i = 0; i < num_movies_to_add; i++) {
                if (add_single_movie_to_collection_internal(new_collection_id_str, movie_ids_to_add_list[i])) {
                    movies_added_successfully++;
                }
            }
            printf("\nAdaugare filme reusita '%s': %d out of %d attempts were successful.\n", title_str, movies_added_successfully, num_movies_to_add);
        } else if (num_movies_to_add > 0 && strlen(new_collection_id_str) == 0) {
            printf("Skip.\n");
        } else {
            printf("Niciun film de adaugat (num_movies = 0).\n");
        }

    } else {
        printf("ERROR: Creare colectie '%s' esuata.\n", title_str);
        char* first_line_end = strstr(server_response_collection_create, "\r\n");
        if (first_line_end) {
            printf("Server status: %.*s\n", (int)(first_line_end - server_response_collection_create), server_response_collection_create);
        }
        if (body_start_coll_create) {
            body_start_coll_create += 4;
            if (strlen(body_start_coll_create) > 0) {
                printf("Mesaj server eroare:\n---\n%s\n---\n", body_start_coll_create);
                error_json_collection_create = json_parse_string(body_start_coll_create);
                if (error_json_collection_create && json_value_get_type(error_json_collection_create) == JSONObject) {
                    JSON_Object *err_obj = json_value_get_object(error_json_collection_create);
                    const char *err_msg_str = json_object_get_string(err_obj, "error");
                    if (err_msg_str) printf("Server JSON error detail: %s\n", err_msg_str);
                }
                 if(error_json_collection_create) {
                    json_value_free(error_json_collection_create);
                    error_json_collection_create = NULL;
                }
            }
        }
        goto cleanup_movies_list_and_response1;
    }

cleanup_movies_list_and_response1:
    if (server_response_collection_create) free_response_if_needed(server_response_collection_create);
cleanup_movies_list:
    if (movie_ids_to_add_list != NULL) {
        for (int i = 0; i < num_movies_to_add; i++) {
            if (movie_ids_to_add_list[i] != NULL) {
                free(movie_ids_to_add_list[i]);
            }
        }
        free(movie_ids_to_add_list);
    }
cleanup:
    if (response_json_collection_create != NULL) json_value_free(response_json_collection_create);
    if (error_json_collection_create != NULL) json_value_free(error_json_collection_create);
    if (sockfd_collection_create >= 0) close(sockfd_collection_create);
}

void delete_collection() {
    int sockfd = -1;
    char id_str[16] = {0};
    char request[8192] = {0};
    char *server_response_str = NULL;
    JSON_Value *err_val_parsed_body = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        return;
    }

    printf("id=");
    fflush(stdout);
    if (fgets(id_str, sizeof(id_str), stdin) == NULL || strlen(id_str) <= 1) {
        printf("ERROR: Citire ID colectie esuata sau ID gol.\n");
        return;
    }
    id_str[strcspn(id_str, "\n")] = '\0';
    if (strlen(id_str) == 0) {
        printf("ERROR: ID colectie gol.\n");
        return;
    }
    for (size_t i = 0; id_str[i] != '\0'; i++) {
        if (id_str[i] < '0' || id_str[i] > '9') {
            printf("ERROR: ID colectie trebuie sa fie numeric.\n");
            return;
        }
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        goto cleanup;
    }

    snprintf(request, sizeof(request),
             "DELETE /api/v1/tema/library/collections/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             id_str, SERVER_HOST, SERVER_PORT, jwt_token);

    server_response_str = send_request(sockfd, request);

    if (server_response_str == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(server_response_str, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", server_response_str);
    } else {
        if (strstr(server_response_str, "HTTP/1.1 200 OK") || strstr(server_response_str, "HTTP/1.1 204 No Content")) {
            printf("SUCCESS: Colectie stearsa.\n");
        } else {
            printf("ERROR: Stergere colectie esuata.\n");
            char status_line_buff[128] = {0};
            char* first_line_end = strstr(server_response_str, "\r\n");
            if (first_line_end) {
                int len = first_line_end - server_response_str;
                if((size_t)len < sizeof(status_line_buff)-1) strncpy(status_line_buff, server_response_str, len); else strncpy(status_line_buff, server_response_str, sizeof(status_line_buff)-1);
                status_line_buff[sizeof(status_line_buff)-1] = '\0';
                printf("Status server: %s\n", status_line_buff);
            } else {
                char preview[201]; strncpy(preview, server_response_str, 200); preview[200] = '\0';
                printf("Raspuns server (partial/malformat): %s...\n", preview);
            }

            char *body_start = strstr(server_response_str, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    printf("Corp mesaj eroare server:\n---\n%s\n---\n", body_start);
                    err_val_parsed_body = json_parse_string(body_start);
                    if (err_val_parsed_body && json_value_get_type(err_val_parsed_body) == JSONObject) {
                        JSON_Object *err_obj = json_value_get_object(err_val_parsed_body);
                        const char *err_msg_str = json_object_get_string(err_obj, "error");
                        if (err_msg_str) {
                            printf("Detaliu eroare JSON server: %s\n", err_msg_str);
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (err_val_parsed_body != NULL) json_value_free(err_val_parsed_body);
    if (server_response_str != NULL) free_response_if_needed(server_response_str);
    if (sockfd >= 0) close(sockfd);
}

void add_movie_to_collection() {
    int sockfd = -1;
    char collection_id_str[16] = {0};
    char movie_id_str[16] = {0};
    char payload_json[64] = {0};
    char request[8192] = {0};
    char *server_response_str = NULL;
    JSON_Value *err_val_parsed_body = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        goto cleanup;
    }

    printf("collection_id=");
    fflush(stdout);
    if (fgets(collection_id_str, sizeof(collection_id_str), stdin) == NULL || strlen(collection_id_str) <= 1) {
        printf("ERROR: Citire ID colectie esuata sau ID gol.\n");
        goto cleanup;
    }
    collection_id_str[strcspn(collection_id_str, "\n")] = '\0';
    if (strlen(collection_id_str) == 0) {
        printf("ERROR: ID colectie gol.\n");
        goto cleanup;
    }

    printf("movie_id=");
    fflush(stdout);
    if (fgets(movie_id_str, sizeof(movie_id_str), stdin) == NULL || strlen(movie_id_str) <= 1) {
        printf("ERROR: Citire ID film esuata sau ID gol.\n");
        goto cleanup;
    }
    movie_id_str[strcspn(movie_id_str, "\n")] = '\0';
    if (strlen(movie_id_str) == 0) {
        printf("ERROR: ID film gol.\n");
        goto cleanup;
    }
    for (size_t i = 0; i < strlen(movie_id_str); i++) {
        if (movie_id_str[i] < '0' || movie_id_str[i] > '9') {
            printf("ERROR: ID film trebuie sa fie numeric pentru payload.\n");
            goto cleanup;
        }
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        goto cleanup;
    }

    snprintf(payload_json, sizeof(payload_json), "{\"id\":%s}", movie_id_str);
    snprintf(request, sizeof(request),
             "POST /api/v1/tema/library/collections/%s/movies HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             collection_id_str, SERVER_HOST, SERVER_PORT, jwt_token,
             strlen(payload_json), payload_json);

    server_response_str = send_request(sockfd, request);

    if (server_response_str == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(server_response_str, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", server_response_str);
    } else {
        char *body_start = strstr(server_response_str, "\r\n\r\n");
        if (strstr(server_response_str, "HTTP/1.1 200 OK") || strstr(server_response_str, "HTTP/1.1 201 CREATED")) {
            printf("SUCCESS: Film adaugat in colectie.\n");
        } else {
            printf("ERROR: Adaugare film in colectie esuata.\n");
            char status_line_buff[128] = {0};
            char* first_line_end = strstr(server_response_str, "\r\n");
            if (first_line_end) {
                 int len = first_line_end - server_response_str;
                if((size_t)len < sizeof(status_line_buff)-1) strncpy(status_line_buff, server_response_str, len); else strncpy(status_line_buff, server_response_str, sizeof(status_line_buff)-1);
                status_line_buff[sizeof(status_line_buff)-1] = '\0';
                printf("Status server: %s\n", status_line_buff);
            } else {
                 char preview[201]; strncpy(preview, server_response_str, 200); preview[200] = '\0';
                printf("Raspuns server (partial/malformat): %s...\n", preview);
            }

            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    printf("Corp mesaj eroare server:\n---\n%s\n---\n", body_start);
                    err_val_parsed_body = json_parse_string(body_start);
                    if (err_val_parsed_body && json_value_get_type(err_val_parsed_body) == JSONObject) {
                        JSON_Object *err_obj = json_value_get_object(err_val_parsed_body);
                        const char *err_msg_str = json_object_get_string(err_obj, "error");
                        if (err_msg_str) {
                            printf("Detaliu eroare JSON server: %s\n", err_msg_str);
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (err_val_parsed_body != NULL) json_value_free(err_val_parsed_body);
    if (server_response_str != NULL) free_response_if_needed(server_response_str);
    if (sockfd >= 0) close(sockfd);
}

void delete_movie_from_collection() {
    int sockfd = -1;
    char collection_id_str[16] = {0};
    char movie_id_str[16] = {0};
    char request[8192] = {0};
    char *server_response_str = NULL;
    JSON_Value *err_val_parsed_body = NULL;

    if (strlen(jwt_token) == 0) {
        printf("ERROR: Token JWT lipsa. Obtineti acces.\n");
        return;
    }

    printf("collection_id=");
    fflush(stdout);
    if (fgets(collection_id_str, sizeof(collection_id_str), stdin) == NULL || strlen(collection_id_str) <= 1) {
        printf("ERROR: Citire ID colectie esuata sau ID gol.\n");
        return;
    }
    collection_id_str[strcspn(collection_id_str, "\n")] = '\0';
    if (strlen(collection_id_str) == 0) {
        printf("ERROR: ID colectie gol.\n");
        return;
    }
    for (size_t i = 0; collection_id_str[i] != '\0'; i++) {
        if (collection_id_str[i] < '0' || collection_id_str[i] > '9') {
            printf("ERROR: ID colectie trebuie sa fie numeric.\n");
            return;
        }
    }

    printf("movie_id=");
    fflush(stdout);
    if (fgets(movie_id_str, sizeof(movie_id_str), stdin) == NULL || strlen(movie_id_str) <= 1) {
        printf("ERROR: Citire ID film esuata sau ID gol.\n");
        return;
    }
    movie_id_str[strcspn(movie_id_str, "\n")] = '\0';
    if (strlen(movie_id_str) == 0) {
        printf("ERROR: ID film gol.\n");
        return;
    }
    for (size_t i = 0; movie_id_str[i] != '\0'; i++) {
        if (movie_id_str[i] < '0' || movie_id_str[i] > '9') {
            printf("ERROR: ID film trebuie sa fie numeric.\n");
            return;
        }
    }

    sockfd = connect_to_server();
    if (sockfd < 0) {
        goto cleanup;
    }

    snprintf(request, sizeof(request),
             "DELETE /api/v1/tema/library/collections/%s/movies/%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             collection_id_str, movie_id_str, SERVER_HOST, SERVER_PORT, jwt_token);

    server_response_str = send_request(sockfd, request);

    if (server_response_str == NULL) {
        printf("ERROR: Serverul nu raspunde (send_request NULL).\n");
    } else if (strcmp(server_response_str, "ERROR: Failed to receive response.") == 0) {
        printf("%s\n", server_response_str);
    } else {
        if (strstr(server_response_str, "HTTP/1.1 200 OK") || strstr(server_response_str, "HTTP/1.1 204 No Content")) {
            printf("SUCCESS: Film sters din colectie.\n");
        } else {
            printf("ERROR: Stergere film din colectie esuata.\n");
            char status_line_buff[128] = {0};
            char* first_line_end = strstr(server_response_str, "\r\n");
            if (first_line_end) {
                int len = first_line_end - server_response_str;
                if((size_t)len < sizeof(status_line_buff)-1) strncpy(status_line_buff, server_response_str, len); else strncpy(status_line_buff, server_response_str, sizeof(status_line_buff)-1);
                status_line_buff[sizeof(status_line_buff)-1] = '\0';
                printf("Status server: %s\n", status_line_buff);
            } else {
                char preview[201]; strncpy(preview, server_response_str, 200); preview[200] = '\0';
                printf("Raspuns server (partial/malformat): %s...\n", preview);
            }

            char *body_start = strstr(server_response_str, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                if (strlen(body_start) > 0) {
                    printf("Corp mesaj eroare server:\n---\n%s\n---\n", body_start);
                    err_val_parsed_body = json_parse_string(body_start);
                    if (err_val_parsed_body && json_value_get_type(err_val_parsed_body) == JSONObject) {
                        JSON_Object *err_obj = json_value_get_object(err_val_parsed_body);
                        const char *err_msg_str = json_object_get_string(err_obj, "error");
                        if (err_msg_str) {
                            printf("Detaliu eroare JSON server: %s\n", err_msg_str);
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (err_val_parsed_body != NULL) json_value_free(err_val_parsed_body);
    if (server_response_str != NULL) free_response_if_needed(server_response_str);
    if (sockfd >= 0) close(sockfd);
}

int connect_to_server() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("EROARE: Creare socket esuata.");
        exit(1);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr) <= 0) {
        perror("EROARE: inet_pton esuat.");
        close(sockfd);
        exit(1);
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("EROARE: Conectare la server esuata.");
        close(sockfd);
        exit(1);
    }
    return sockfd;
}

char *send_request(int sockfd, const char *request) {
    int sent_bytes = send(sockfd, request, strlen(request), 0);
    if (sent_bytes < 0) {
        perror("EROARE: Trimitere cerere esuata");
        return "ERROR: Failed to receive response.";
    }

    char *response = malloc(8192);
    if (!response) {
        perror("EROARE: Alocare memorie (buffer raspuns) esuata");
        return NULL;
    }
    memset(response, 0, 8192);
    int bytes_received = recv(sockfd, response, 8191, 0);
    if (bytes_received < 0) {
        perror("EROARE: Primire raspuns de la server esuata");
        free(response);
        return "ERROR: Failed to receive response.";
    }
    response[bytes_received] = '\0';
    return response;
}

void free_response_if_needed(char* response) {
    if (response != NULL && strcmp(response, "ERROR: Failed to receive response.") != 0) {
        free(response);
    }
}

void handle_command(const char *command) {
    if (strcmp(command, "login_admin") == 0) login_admin();
    else if (strcmp(command, "logout_admin") == 0) logout_admin();
    else if (strcmp(command, "add_user") == 0) add_user();
    else if (strcmp(command, "get_users") == 0) get_users();
    else if (strcmp(command, "delete_user") == 0) delete_user();
    else if (strcmp(command, "login") == 0) login();
    else if (strcmp(command, "logout") == 0) logout();
    else if (strcmp(command, "get_access") == 0) get_access();
    else if (strcmp(command, "get_movies") == 0) get_movies();
    else if (strcmp(command, "get_movie") == 0) get_movie();
    else if (strcmp(command, "add_movie") == 0) add_movie();
    else if (strcmp(command, "delete_movie") == 0) delete_movie();
    else if (strcmp(command, "update_movie") == 0) update_movie();
    else if (strcmp(command, "get_collections") == 0) get_collections();
    else if (strcmp(command, "get_collection") == 0) get_collection();
    else if (strcmp(command, "add_collection") == 0) add_collection();
    else if (strcmp(command, "delete_collection") == 0) delete_collection();
    else if (strcmp(command, "add_movie_to_collection") == 0) add_movie_to_collection();
    else if (strcmp(command, "delete_movie_from_collection") == 0) delete_movie_from_collection();
    else printf("ERROR: Comanda nerecunoscuta.\n");
}

int main() {
    char command[256];
    while (1) {
        printf("> ");
        if (fgets(command, 256, stdin) == NULL) {
            break;
        }
        command[strcspn(command, "\n")] = '\0';
        if (strcmp(command, "exit") == 0) break;
        handle_command(command);
    }
    return 0;
}
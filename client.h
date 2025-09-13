#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "parson.h"

// Constants
#define SERVER_HOST "63.32.125.183"
#define SERVER_PORT 8081

// Session variables
extern char admin_session_cookie[4500];
extern char user_session_cookie[4500];
extern char jwt_token[4500];
extern char current_logged_in_username[256];

int connect_to_server();
char *send_request(int sockfd, const char *request);
void handle_command(const char *command);
void free_response_if_needed(char* response);


// Commands
void login_admin();
void logout_admin();
void add_user();
void get_users();
void delete_user();
void login();
void logout();
void get_access();
void get_movies();
void get_movie();
void add_movie();
void delete_movie();
void update_movie();
void get_collections();
void get_collection();
void add_collection();
void delete_collection();
void add_movie_to_collection();
void delete_movie_from_collection();

#endif // CLIENT_H

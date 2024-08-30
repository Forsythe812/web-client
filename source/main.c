#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex.h>

#define MAX_REDIRECTS 5
#define BUFFER_SIZE 4096

#define SUCCESS        0
#define ERR_BASE       0
#define ERR_PARAM     (ERR_BASE - 1)
#define ERR_URL       (ERR_BASE - 2)
#define ERR_CONNECT   (ERR_BASE - 3)
#define ERR_SSL       (ERR_BASE - 4)
#define ERR_REDIRECT  (ERR_BASE - 5)
#define ERR_FILE      (ERR_BASE - 6)
#define ERR_GAI       (ERR_BASE - 7)
#define ERR_STAT_CODE (ERR_BASE - 8)

int parse_url(const char *url, char *hostname, char *path) {
    if (url == NULL || hostname == NULL || path == NULL) {
        return ERR_PARAM;
    }

    const char *host_start = strstr(url, "//");
    if (host_start) {
        host_start += 2;
    } else {
        host_start = url;
    }

    const char *path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(hostname, host_start, path_start - host_start);
        hostname[path_start - host_start] = '\0';
        strcpy(path, path_start);
    } else {
        strcpy(hostname, host_start);
        strcpy(path, "/");
    }

    return SUCCESS;
}

int is_https(const char *url, char *hostname, char *path, char *request) {
    if (strncmp(url, "https://", 8) == 0) {
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 1;  // HTTPS
    } else if (strncmp(url, "http://", 7) == 0) {
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 0;  // HTTP
    } else {
        fprintf(stderr, "Invalid URL format, use http:// or https://\n");
        return ERR_URL;
    }
}

int print_status_code(const char *response) {
    const char *status_line = strstr(response, "HTTP/1.");
    if (status_line) {
        char status_code[4];
        strncpy(status_code, status_line + 9, 3);  //skip HTTP/1.x
        status_code[3] = '\0'; 
        return atoi(status_code);
    }
    
    fprintf(stderr, "Status code not found in response.\n");
    return ERR_STAT_CODE; 
}

int rebuild_url(const char *current_url, const char *redirect_location, char *new_url) {
    if (!current_url || !redirect_location || !new_url) {
        return ERR_PARAM;
    }

    if (strstr(redirect_location, "http://") || strstr(redirect_location, "https://")) {
        strncpy(new_url, redirect_location, BUFFER_SIZE - 1);
        new_url[BUFFER_SIZE - 1] = '\0';   // Absolute URL
    } else {
        // Get base URL (scheme + host)
        char base_url[BUFFER_SIZE];
        const char *path_start = strstr(current_url, "//");
        if (path_start) {
            path_start = strchr(path_start + 2, '/');
            if (path_start) {
                strncpy(base_url, current_url, path_start - current_url);
                base_url[path_start - current_url] = '\0';
            } else {
                strcpy(base_url, current_url);  // No path, so base URL is the full URL
            }
        } else {
            strcpy(base_url, current_url);
        }

        // Append the relative location to the base URL
        snprintf(new_url, BUFFER_SIZE, "%s%s", base_url, redirect_location);
    }

    return SUCCESS;
}

int fetch_url(const char *url, char *response, FILE *file, int *is_redirect, char *redirect_location) {
    if (!url || !response || !file || !is_redirect || !redirect_location) {
        return ERR_PARAM;
    }

    char hostname[BUFFER_SIZE];
    char path[BUFFER_SIZE];
    char request[BUFFER_SIZE];

    int status;
    int sockfd;
    int bytes_received;
    struct addrinfo hints, *res, *p;

    int use_ssl;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if ((status = parse_url(url, hostname, path)) != SUCCESS) {
        return status;
    }

    use_ssl = is_https(url, hostname, path, request);
    if (use_ssl == ERR_URL) {
        return ERR_URL;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, use_ssl ? "443" : "80", &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return ERR_GAI;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        freeaddrinfo(res);
        return ERR_CONNECT;
    }

    freeaddrinfo(res);

    if (use_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            return ERR_SSL;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return ERR_SSL;
        }

        SSL_write(ssl, request, strlen(request));

        int header_done = 0;
        while ((bytes_received = SSL_read(ssl, response, BUFFER_SIZE - 1)) > 0) {
            response[bytes_received] = '\0';

            if (!header_done) {
                char *header_end = strstr(response, "\r\n\r\n");
                if (header_end) {
                    header_done = 1;

                    int status_code = print_status_code(response);
                    printf("Status Code : %d\n",status_code);

                    // Check for redirect
                    if (status_code == 301 || status_code == 302) {
                        *is_redirect = 1;
                        char *location = strstr(response, "Location:");
                        if (location) {
                            location += 9;
                            while (*location == ' ') location++;
                            char *end_location = strstr(location, "\r\n");
                            if (end_location) {
                                strncpy(redirect_location, location, end_location - location);
                                redirect_location[end_location - location] = '\0';
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                SSL_CTX_free(ctx);
                                close(sockfd);
                                return SUCCESS;
                            }
                        }
                    }

                    char *body_start = header_end + 4;
                    fwrite(body_start, 1, bytes_received - (body_start - response), file);
                }
            } else {
                fwrite(response, 1, bytes_received, file);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        send(sockfd, request, strlen(request), 0);

        int header_done = 0;
        while ((bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0)) > 0) {
            response[bytes_received] = '\0';

            if (!header_done) {
                char *header_end = strstr(response, "\r\n\r\n");
                if (header_end) {
                    header_done = 1;

                    int status_code = print_status_code(response);
                    printf("Status Code : %d\n",status_code);

                    // Check for redirect
                    if (status_code == 301 || status_code == 302) {
                        *is_redirect = 1;
                        char *location = strstr(response, "Location:");
                        if (location) {
                            location += 9;
                            while (*location == ' ') location++;
                            char *end_location = strstr(location, "\r\n");
                            if (end_location) {
                                strncpy(redirect_location, location, end_location - location);
                                redirect_location[end_location - location] = '\0';
                                close(sockfd);
                                return SUCCESS;
                            }
                        }
                    }

                    char *body_start = header_end + 4;
                    fwrite(body_start, 1, bytes_received - (body_start - response), file);
                }
            } else {
                fwrite(response, 1, bytes_received, file);
            }
        }
    }

    close(sockfd);
    return SUCCESS;
}

char *extract_links(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    // Read the entire file into a buffer
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    // Regex pattern to match href attributes within anchor tags
    const char *pattern = "<a\\s+[^>]*href=[\"']([^\"']*)[\"']";

    regex_t regex;
    regmatch_t matches[2];
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        perror("Error compiling regex");
        free(buffer);
        return NULL;
    }

    // String to accumulate all links found
    char *all_links = malloc(1);  // Start with an empty string
    all_links[0] = '\0';  // Null-terminate the empty string

    char *cursor = buffer;
    while (regexec(&regex, cursor, 2, matches, 0) == 0) {
        int href_start = matches[1].rm_so;
        int href_end = matches[1].rm_eo;
        int href_length = href_end - href_start;

        // Allocate memory for the link and copy the href value
        char *href_value = malloc(href_length + 1);
        strncpy(href_value, cursor + href_start, href_length);
        href_value[href_length] = '\0';  // Null-terminate the href value

        // Reallocate all_links to hold the new link plus a newline character
        size_t current_length = strlen(all_links);
        all_links = realloc(all_links, current_length + href_length + 2);  // +2 for newline and null terminator
        if (!all_links) {
            perror("Error reallocating memory for all_links");
            regfree(&regex);
            free(buffer);
            free(href_value);
            return NULL;
        }

        // Append the new link and a newline to all_links
        strcat(all_links, href_value);
        strcat(all_links, "\n");

        free(href_value);  // Free the temporary link

        // Move cursor past the current match
        cursor += matches[0].rm_eo;
    }

    regfree(&regex);
    free(buffer);

    return all_links;
}

int write_links(const char *filename, const char *links) {
    if (filename == NULL || links == NULL) {
        return ERR_PARAM;  // Handle invalid parameters
    }

    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file to write links");
        return ERR_FILE;
    }

    // Write all links to the file
    fprintf(file, "%s", links);

    fclose(file);
    return SUCCESS;
}

int get_url_content(const char *url, const char *output_file) {
    char current_url[BUFFER_SIZE];
    strncpy(current_url, url, BUFFER_SIZE);
    current_url[BUFFER_SIZE - 1] = '\0';  // Ensure null termination

    char response[BUFFER_SIZE];
    char redirect_location[BUFFER_SIZE];
    char new_url[BUFFER_SIZE];
    int is_redirect;
    int redirect_count = 0;

    // Open the output file specified in the command line argument
    FILE *file = fopen(output_file, "wb");
    if (!file) {
        perror("Failed to open file");
        return ERR_FILE;
    }

    // Loop to handle redirects
    do {
        is_redirect = 0;
        printf("Fetching URL: %s\n", current_url);
        int fetch_result = fetch_url(current_url, response, file, &is_redirect, redirect_location);
        if (fetch_result != SUCCESS) {
            fprintf(stderr, "Error fetching URL: %d\n", fetch_result);
            fclose(file);
            return fetch_result;
        }

        if (is_redirect) {
            printf("Redirecting to: %s\n", redirect_location);
            int rebuild_result = rebuild_url(current_url, redirect_location, new_url);
            if (rebuild_result != SUCCESS) {
                fprintf(stderr, "Error rebuilding URL: %d\n", rebuild_result);
                fclose(file);
                return rebuild_result;
            }
            strncpy(current_url, new_url, BUFFER_SIZE);  // Update the URL to the new location
            current_url[BUFFER_SIZE - 1] = '\0';  // Ensure null termination
            redirect_count++;
        }
    } while (is_redirect && redirect_count < MAX_REDIRECTS);

    fclose(file);

    if (redirect_count >= MAX_REDIRECTS) {
        printf("Too many redirects\n");
        return ERR_REDIRECT;
    }

    printf("Response written to: %s\n", output_file);

    char *links = extract_links(output_file);

    printf("\nFetching links...\n\n");
    if (links != NULL) {
        printf("All Links:\n%s", links);

        // Write links to links.txt
        int result = write_links("links.txt", links);
        if (result == SUCCESS) {
            printf("Links successfully written to links.txt\n");
        } else {
            printf("Error writing links to links.txt\n");
        }

        free(links);
    }

    return SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <URL> <output_file_name(example.txt / example.html)>\n", argv[0]);
        return ERR_PARAM;
    }

    return get_url_content(argv[1], argv[2]);
}

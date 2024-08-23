#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex.h>

#define MAX_REDIRECTS 5  // Limit the number of redirects to avoid infinite loops
#define BUFFER_SIZE 4096  // Size for reading chunks

void extract_links(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return;
    }

    // Read the entire file into a buffer
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        return;
    }

    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    // Regex pattern to match href attributes within anchor tags
    const char *pattern = "<a\\s+[^>]*href=[\"']([^\"']*)[\"']";

    regex_t regex;
    regmatch_t matches[2];  // Array to store the match groups (full match and the captured group)
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        perror("Error compiling regex");
        free(buffer);
        return;
    }

    char *cursor = buffer;
    while (regexec(&regex, cursor, 2, matches, 0) == 0) {
        // Extract the href value
        int href_start = matches[1].rm_so;
        int href_end = matches[1].rm_eo;
        int href_length = href_end - href_start;

        char href_value[href_length + 1];
        strncpy(href_value, cursor + href_start, href_length);
        href_value[href_length] = '\0';  // Null-terminate the href value

        // Check if the href_value starts with "http://" or "https://"
        if (strncmp(href_value, "http://", 7) == 0 || strncmp(href_value, "https://", 8) == 0) {
            // Print the extracted href value if it starts with http or https
            printf("Found link: %s\n", href_value);
        }

        // Move cursor past the current match
        cursor += matches[0].rm_eo;
    }

    regfree(&regex);
    free(buffer);
}

void parse_url(const char *url, char *hostname, char *path) {
    const char *host_start = strstr(url, "//");
    if (host_start) {
        host_start += 2;  // Skip past "http://" or "https://"
    } else {
        host_start = url;
    }

    const char *path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(hostname, host_start, path_start - host_start);
        hostname[path_start - host_start] = '\0';  // Null-terminate the hostname
        strcpy(path, path_start);  // Copy the rest as the path
    } else {
        strcpy(hostname, host_start);
        strcpy(path, "/");
    }
}

void handle_http_chunked(int sockfd, const char *request, FILE *file) {
    send(sockfd, request, strlen(request), 0);  // Send HTTP request
    
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int chunk_size;

    // Read and discard headers
    int header_done = 0;
    char *body_start = NULL;
    
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';

        if (!header_done) {
            // Find the end of headers
            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                // Move body_start pointer after the headers
                body_start += 4;
                header_done = 1;
                break;
            }
        }
    }

    // Write remaining body data after headers to file
    if (body_start) {
        fwrite(body_start, 1, bytes_received - (body_start - buffer), file);
    }

    // Now, process the chunks
    while (1) {
        // Read chunk size (in hexadecimal)
        if ((bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) <= 0) {
            break;  // Connection closed or error
        }
        buffer[bytes_received] = '\0';

        // Parse the chunk size
        sscanf(buffer, "%x", &chunk_size);
        if (chunk_size == 0) {
            break;  // End of chunks
        }

        // Read and process the actual chunk data
        int total_bytes_read = 0;
        while (total_bytes_read < chunk_size) {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                break;  // Connection closed or error
            }

            fwrite(buffer, 1, bytes_received, file);  // Write chunk data to file
            total_bytes_read += bytes_received;
        }

        // Read and discard the trailing CRLF after the chunk
        recv(sockfd, buffer, 2, 0);
    }
}

void handle_https_chunked(SSL *ssl, const char *request, FILE *file) {
    SSL_write(ssl, request, strlen(request));  // Send HTTPS request

    char buffer[BUFFER_SIZE];
    int bytes_received;
    int chunk_size;

    // Read and discard headers
    int header_done = 0;
    char *body_start = NULL;
    
    while ((bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_received] = '\0';

        if (!header_done) {
            // Find the end of headers
            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                // Move body_start pointer after the headers
                body_start += 4;
                header_done = 1;
                break;
            }
        }
    }

    // Write remaining body data after headers to file
    if (body_start) {
        fwrite(body_start, 1, bytes_received - (body_start - buffer), file);
    }

    // Now, process the chunks
    while (1) {
        // Read chunk size (in hexadecimal)
        if ((bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0) {
            break;  // Connection closed or error
        }
        buffer[bytes_received] = '\0';

        // Parse the chunk size
        sscanf(buffer, "%x", &chunk_size);
        if (chunk_size == 0) {
            break;  // End of chunks
        }

        // Read and process the actual chunk data
        int total_bytes_read = 0;
        while (total_bytes_read < chunk_size) {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_received <= 0) {
                break;  // Connection closed or error
            }

            fwrite(buffer, 1, bytes_received, file);  // Write chunk data to file
            total_bytes_read += bytes_received;
        }

        // Read and discard the trailing CRLF after the chunk
        SSL_read(ssl, buffer, 2);
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int use_ssl = 0;
    char redirect_url[2048];
    char hostname[1024];
    char path[1024];
    char new_url[2048];
    int redirect_count = 0;

    // Start with the initial URL
    char *url = "https://www.ccu.edu.tw/";
    char request[1024];

    FILE *file = fopen("response_body.txt", "w");  // Open a file to store the body only

    while (redirect_count < MAX_REDIRECTS) {
        // Parse the URL into hostname and path
        parse_url(url, hostname, path);

        // Check if it's HTTP or HTTPS
        if (strncmp(url, "https://", 8) == 0) {
            use_ssl = 1;
            snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        } else if (strncmp(url, "http://", 7) == 0) {
            use_ssl = 0;
            snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        } else {
            fprintf(stderr, "Invalid URL format. Must start with http:// or https://\n");
            return 1;
        }

        // Initialize OpenSSL if HTTPS
        if (use_ssl) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            ctx = SSL_CTX_new(TLS_client_method());
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                return 1;
            }
        }

        // Create a TCP socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Error creating socket");
            return 1;
        }

        // Resolve the hostname
        server = gethostbyname(hostname);
        if (server == NULL) {
            perror("Error resolving hostname");
            return 1;
        }

        // Set up the server address structure
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        if (use_ssl) {
            server_addr.sin_port = htons(443);  // HTTPS port
        } else {
            server_addr.sin_port = htons(80);   // HTTP port
        }
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

        // Connect to the server
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Error connecting to server");
            return 1;
        }

        // Handle HTTPS or HTTP
        if (use_ssl) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sockfd);
            if (SSL_connect(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                return 1;
            }
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            handle_https_chunked(ssl, request, file);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        } else {
            handle_http_chunked(sockfd, request, file);
        }

        close(sockfd);

        // Assuming you're not handling redirection in chunked transfer cases for simplicity
        break;
    }

    fclose(file);  // Close the file

    extract_links("response_body.txt");

    return 0;
}

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <semaphore.h>

#define SUCCESS          0
#define ERR_BASE         0
#define ERR_PARAM       (ERR_BASE-1)
#define ERR_URL         (ERR_BASE-2)
#define ERR_CONNECT     (ERR_BASE-3)
#define ERR_SSL         (ERR_BASE-4)
#define ERR_REDIRECT    (ERR_BASE-5)
#define ERR_FILE        (ERR_BASE-6)
#define ERR_GAI         (ERR_BASE-7)
#define ERR_STAT_CODE   (ERR_BASE-8)
#define ERR_MKDIR       (ERR_BASE-9)
#define ERR_SHM_OPEN    (ERR_BASE-10)
#define ERR_SHM_MAP     (ERR_BASE-11)
#define ERR_SHM_UNLINK  (ERR_BASE-12)
#define ERR_FORK        (ERR_BASE-13)
#define ERR_WAIT        (ERR_BASE-14)
#define ERR_GETADDRINFO (ERR_BASE-15)
#define ERR_SOCKET      (ERR_BASE-16)
#define ERR_OUT_OF_MEM  (ERR_BASE-17)
#define ERR_READ_WEB    (ERR_BASE-18)
#define ERR_CREATE_DIR  (ERR_BASE-19)
#define ERR_FETCH_URL   (ERR_BASE-20)
#define ERR_HTTP_STATUS (ERR_BASE-21)
#define ERR_FILE_TYPE   (ERR_BASE-22)
#define ERR_OPEN_FILE   (ERR_BASE-23)

#define MAX_URLS 10000
#define MAX_URL_LENGTH 1024
#define BUFFER_SIZE 4096
#define HOST_SIZE 256
#define PORT_SIZE 10
#define REQUEST_SIZE 1024
#define FILE_PATH 1024

typedef struct {
    char crawled_urls[MAX_URLS][MAX_URL_LENGTH];
    int crawled_count;
    int status[MAX_URLS]; // 0: not_crawled, 1: can_crawl 2: crawling, 3: crawled
    int depth[MAX_URLS];
} CrawledData;

CrawledData *crawled_data;
sem_t *sem;

int mk_dir(const char *dir_name) {
    struct stat st = {0};
    if (stat(dir_name, &st) == -1) {
        if (mkdir(dir_name, 0700) == -1) {
            fprintf(stderr, "Failed to create directory %s: %s\n", dir_name, strerror(errno));
            return ERR_CREATE_DIR;
        }
    }
    return SUCCESS;
}

char *sanitize_filename(const char *url) {
    char *filename = malloc(strlen(url) + 1);
    if (!filename) {
        return NULL;
    }
    int i, j = 0;
    for (i = 0; url[i]; i++) {
        if (url[i] == '/' || url[i] == ':' || url[i] == '?' || url[i] == '&' || url[i] == '=') {
            filename[j++] = '_';
        } else {
            filename[j++] = url[i];
        }
    }
    filename[j] = '\0';
    return filename;
}

SSL_CTX *create_ssl_context() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context.\n");
        return NULL;
    }

    return ctx;
}

int create_socket(const char *hostname, const char *port) {
    struct addrinfo hints, *result, *rp;
    int sockfd = -1;
    int ret_code = SUCCESS;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &result) != 0) {
        return ERR_GETADDRINFO;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            ret_code = ERR_SOCKET;
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            ret_code = SUCCESS;
            break;
        }

        close(sockfd);
        sockfd = -1;
        ret_code = ERR_CONNECT;
    }

    if (rp == NULL) {
        ret_code = ERR_CONNECT;
    }

    freeaddrinfo(result);
    return ret_code == SUCCESS ? sockfd : ret_code;
}

int parse_response(int is_https, SSL *ssl, int sockfd, char *url, int depth, char *temp, char **url_type, CrawledData *crawled_data) {
    char buffer[BUFFER_SIZE];
    int bytes_read = 0, is_chunked = 0;
    char *header_end, *response, *chunk_start, *chunk_end, *file_type;
    size_t response_len = 0, chunk_size;

    // Read the first chunk of the response (either SSL or plain socket)
    bytes_read = (is_https ? SSL_read(ssl, buffer, sizeof(buffer)) : recv(sockfd, buffer, sizeof(buffer), 0));
    if (bytes_read <= 0) {
        return ERR_READ_WEB;
    }
    buffer[bytes_read] = '\0';
    
    // Extract HTTP status code
    int status_code = -1;
    sscanf(buffer, "HTTP/1.1 %d", &status_code);

    // Handle redirect (3xx status codes)
    if (status_code >= 300 && status_code < 400) {
        printf("HTTP Status Code: %d\n", status_code);
        if (temp != NULL) {
            strncpy(temp, buffer, bytes_read);
            temp[bytes_read] = '\0';
        }
        return ERR_FETCH_URL;
    } 
    
    // Handle successful response (2xx status codes)
    if (status_code >= 200 && status_code < 300) {
        printf("HTTP Status Code: %d\n", status_code);
        memset(temp, 0, BUFFER_SIZE);
    } else {
        // Unhandled status codes
        printf("HTTP Status Code: %d\n", status_code);
        return ERR_HTTP_STATUS;
    }

    // Check if the response is chunked
    if (strstr(buffer, "\r\nTransfer-Encoding: chunked")) {
        is_chunked = 1;
    }

    // Check if the content type is HTML
    if (strstr(buffer, "\r\nContent-Type: text/html")) {
        *url_type = "html";
        file_type = ".html";
    } else {
        *url_type = "unknown";  // Skip non-HTML content
        return ERR_FILE_TYPE;
    }

    // Allocate memory to store the response
    response = malloc(sizeof(char) * (bytes_read + 1));
    if (response == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        if (is_https) {
            SSL_free(ssl);
        }
        close(sockfd);
        return ERR_OUT_OF_MEM;
    }

    memcpy(response, buffer, bytes_read);
    response_len += bytes_read;
    response[response_len] = '\0';

    // Continue reading the rest of the response
    while ((bytes_read = (is_https ? SSL_read(ssl, buffer, sizeof(buffer)) : recv(sockfd, buffer, sizeof(buffer), 0))) > 0) {
        response = realloc(response, response_len + bytes_read + 1);
        if (response == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            if (is_https) {
                SSL_free(ssl);
            }
            close(sockfd);
            return ERR_OUT_OF_MEM;
        }
        memcpy(response + response_len, buffer, bytes_read);
        response_len += bytes_read;
        response[response_len] = '\0';
    }

    // Handle chunked transfer encoding if needed
    if (is_chunked) {
        char *decoded_response = NULL;
        size_t decoded_len = 0;

        chunk_start = strstr(response, "\r\n\r\n");
        if (chunk_start) {
            chunk_start += 4;
            while (1) {
                chunk_size = strtol(chunk_start, &chunk_end, 16);
                if (chunk_size == 0) {
                    break;
                }
                chunk_end += 2;

                decoded_response = realloc(decoded_response, decoded_len + chunk_size + 1);
                if (decoded_response == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    if (is_https) {
                        SSL_free(ssl);
                    }
                    close(sockfd);
                    free(response);
                    return ERR_OUT_OF_MEM;
                }

                memcpy(decoded_response + decoded_len, chunk_end, chunk_size);
                decoded_len += chunk_size;
                chunk_end += chunk_size + 2;

                chunk_start = chunk_end;
            }
            decoded_response[decoded_len] = '\0';
            free(response);
            response = decoded_response;
            response_len = decoded_len;
        }
    }

    // Save HTML content to a file
    char filename[FILE_PATH];
    char *save_filename = sanitize_filename(url);
    if (!save_filename) {
        free(response);
        return ERR_OUT_OF_MEM;
    }
    snprintf(filename, sizeof(filename), "%s/depth_%d_%s%s", output_dir, depth, save_filename, file_type);
    free(save_filename);

    FILE *fp = fopen(filename, "wb");
    if (fp) {
        fwrite(response, 1, response_len, fp);
        fclose(fp);
        printf("HTML content saved to %s\n", filename);
    } else {
        fprintf(stderr, "Error opening file: %s\n", filename);
        free(response);
        return ERR_OPEN_FILE;
    }

    free(response);
    return SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <URL> <output directory>\n", argv[0]);
        return ERR_PARAM;
    }

    char *url = argv[1];
    char *output_dir = argv[2];

    // Create the output directory if it doesn't exist
    if (mk_dir(output_dir) != SUCCESS) {
        fprintf(stderr, "Failed to create output directory: %s\n", output_dir);
        return ERR_MKDIR;
    }

    // Extract hostname and port from the URL
    char hostname[HOST_SIZE];
    char port[PORT_SIZE] = "443";  // Default to HTTPS (443)
    int is_https = 1;              // Assume HTTPS

    if (strncmp(url, "http://", 7) == 0) {
        sscanf(url, "http://%255[^:/]", hostname);
        strcpy(port, "80");        // HTTP uses port 80
        is_https = 0;
    } else if (strncmp(url, "https://", 8) == 0) {
        sscanf(url, "https://%255[^:/]", hostname);
    } else {
        fprintf(stderr, "Invalid URL scheme. Only HTTP/HTTPS are supported.\n");
        return ERR_URL;
    }

    // Create socket and establish connection
    int sockfd = create_socket(hostname, port);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create or connect socket\n");
        return sockfd;
    }

    // Initialize SSL if HTTPS is used
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (is_https) {
        ctx = create_ssl_context();
        if (!ctx) {
            fprintf(stderr, "Failed to create SSL context\n");
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
    }

    // Prepare and send the HTTP GET request
    char request[REQUEST_SIZE];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0\r\n"
             "Connection: close\r\n\r\n", hostname);

    if (is_https) {
        SSL_write(ssl, request, strlen(request));
    } else {
        send(sockfd, request, strlen(request), 0);
    }

    // Parse the response and save the HTML content
    char *url_type = NULL;
    char temp[BUFFER_SIZE];
    int result = parse_response(is_https, ssl, sockfd, url, 0, temp, &url_type, crawled_data);

    if (result == SUCCESS) {
        printf("Successfully fetched and saved HTML content.\n");
    } else {
        fprintf(stderr, "Failed to fetch content: Error %d\n", result);
    }

    // Clean up SSL and socket resources
    if (is_https) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);

    return result;
}

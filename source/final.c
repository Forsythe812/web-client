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

#define MAX_URLS 10000
#define MAX_URL_LENGTH 1024

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

        // struct timeval timeout;
        // timeout.tv_sec = 5;
        // timeout.tv_usec = 0;
        // setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        // setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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
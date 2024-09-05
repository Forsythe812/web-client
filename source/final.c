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

#define ERR_PARAM              (ERR_BASE-1)
#define ERR_URL                (ERR_BASE-2)
#define ERR_CONNECT            (ERR_BASE-3)
#define ERR_SSL                (ERR_BASE-4)
#define ERR_REDIRECT           (ERR_BASE-5)
#define ERR_FILE               (ERR_BASE-6)
#define ERR_GAI                (ERR_BASE-7)
#define ERR_STAT_CODE          (ERR_BASE-8)
#define ERR_MKDIR              (ERR_BASE-9)
#define ERR_SHM_OPEN           (ERR_BASE-10)
#define ERR_SHM_MAP            (ERR_BASE-11)
#define ERR_SHM_UNLINK         (ERR_BASE-12)
#define ERR_FORK               (ERR_BASE-13)
#define ERR_WAIT               (ERR_BASE-14)
#define ERR_GETADDRINFO        (ERR_BASE-15)
#define ERR_SOCKET             (ERR_BASE-16)
#define ERR_CREATE_DIR         (ERR_BASE-17)
#define ERR_READ_WEB           (ERR_BASE-18)
#define ERR_FETCH_URL          (ERR_BASE-19)
#define ERR_HTTP_STATUS        (ERR_BASE-20)
#define ERR_FILE_TYPE          (ERR_BASE-21)
#define ERR_OUT_OF_MEM         (ERR_BASE-22)
#define ERR_OPEN_FILE          (ERR_BASE-23)
#define ERR_OPEN_SHARED_MEMORY (ERR_BASE-24)
#define ERR_RESIZE_SHARED_MEMORY (ERR_BASE-25)
#define ERR_MAP_SHARED_MEMORY  (ERR_BASE-26)
#define ERR_SEM_OPEN           (ERR_BASE-27)
#define ERR_SSL_CONNECT        (ERR_BASE-28)
#define ERR_MAX_DEPTH           (ERR_BASE-29)
#define ERR_MAX_URLS            (ERR_BASE-30)
#define ERR_ALREADY_CRAWLED     (ERR_BASE-31)
#define ERR_URL_TOO_LONG        (ERR_BASE-32)

#define MAX_URLS 10000
#define MAX_URL_LENGTH 1024
#define MAX_DEPTH 2
#define BUFFER_SIZE 1024
#define MAX_CHILD 2
#define REQUEST_SIZE 1024
#define PORT_SIZE 10
#define PATH_SIZE 1024
#define HOST_SIZE 1024
#define FILE_PATH 1024
#define SHM_NAME "/crawler_shm"
#define SEM_NAME "/crawler_sem"

typedef struct {
    char crawled_urls[MAX_URLS][MAX_URL_LENGTH];
    int crawled_count;
    int status[MAX_URLS]; // 0: not_crawled, 1: can_crawl 2: crawling, 3: crawled
    int depth[MAX_URLS];
} CrawledData;

CrawledData *crawled_data;
sem_t *sem;
char *output_dir;

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

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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

int crawled(CrawledData *crawled_data, int depth, const char *url, sem_t *sem) {
    if (strlen(url) >= MAX_URL_LENGTH) {
        fprintf(stderr, "URL exceeds the maximum allowed length.\n");
        return ERR_URL_TOO_LONG;
    }

    sem_wait(sem);
    for (int i = 0; i < crawled_data->crawled_count; i++) {
        if (strcmp(crawled_data->crawled_urls[i], url) == 0) {
            sem_post(sem);
            return crawled_data->status[i];
        }
    }

    if (crawled_data->crawled_count < MAX_URLS) {
        printf("Adding URL: %s\n", url);
        strcpy(crawled_data->crawled_urls[crawled_data->crawled_count], url);
        crawled_data->status[crawled_data->crawled_count] = 0;
        crawled_data->depth[crawled_data->crawled_count] = depth + 1;
        crawled_data->crawled_count++;
        sem_post(sem);
        return SUCCESS;
    } else {
        sem_post(sem);
        fprintf(stderr, "Maximum number of URLs exceeded.\n");
        return ERR_MAX_URLS;
    }

    return ERR_ALREADY_CRAWLED;
}

int parse_html(const char *html_content, int depth, const char *base_url, CrawledData *crawled_data, sem_t *sem) {
    const char *a_tag_start = "<a href=";
    const char *pos = html_content;

    char hostname[HOST_SIZE] = "";
    char path[PATH_SIZE] = "";

    const char *start_of_path = strchr(base_url + strlen("https://"), '/');
    if (start_of_path) {
        size_t host_len = start_of_path - (base_url + strlen("https://"));
        strncpy(hostname, base_url + strlen("https://"), host_len);
        hostname[host_len] = '\0';
        
        while (*start_of_path == '/') start_of_path++;
        strcpy(path, start_of_path);

        char *first_slash = strchr(path, '/');
        if (first_slash) {
            *first_slash = '\0';
        }
    }

    while ((pos = strstr(pos, a_tag_start)) != NULL && crawled_data->crawled_count < MAX_URLS) {
        pos = strstr(pos, a_tag_start);
        if (pos == NULL) {
            break;
        }

        pos += strlen(a_tag_start);

        char quote_char = '\0';
        if (*pos == '"' || *pos == '\'') {
            quote_char = *pos;
            pos++;
        }

        const char *end;
        if (quote_char) {
            end = strchr(pos, quote_char);
        } else {
            end = strpbrk(pos, " >");
        }

        if (end == NULL) {
            break;
        }

        size_t href_length = end - pos;
        char *href = malloc(href_length + 1);
        strncpy(href, pos, href_length);
        href[href_length] = '\0';

        char *full_url = malloc(strlen(base_url) + strlen(href) + 2);
        if (strncmp(href, "http", 4) == 0) {
            strcpy(full_url, href);
        } else {
            sprintf(full_url, "https://%s/%s/%s", hostname, path, href);
        }

        crawled(crawled_data, depth, full_url, sem);

        free(href);
        free(full_url);
        pos = end + 1;
    }

    return SUCCESS;
}

int read_response(int is_https, SSL *ssl, int sockfd, char *url, int depth, char *temp, char **url_type, CrawledData *crawled_data) {
    char buffer[BUFFER_SIZE];
    int bytes_read = 0, is_chunked = 0, is_html = 0;
    char *header_end, *content_type, *response, *chunk_start, *chunk_end, *file_type;
    size_t response_len = 0, chunk_size;

    bytes_read = (is_https ? SSL_read(ssl, buffer, sizeof(buffer)) : recv(sockfd, buffer, sizeof(buffer), 0));
    if (bytes_read <= 0) {
        return ERR_READ_WEB;
    }
    buffer[bytes_read] = '\0';
    
    int status_code = -1;
    sscanf(buffer, "HTTP/1.1 %d", &status_code);

    // Handle redirection (HTTP 3xx)
    if (status_code >= 300 && status_code < 400) {
        printf("HTTP Status Code: %d\n", status_code);
        if (temp != NULL) {
            strncpy(temp, buffer, bytes_read);
            temp[bytes_read] = '\0';
        }
        return ERR_FETCH_URL;
    } else if (status_code >= 200 && status_code < 300) {
        printf("HTTP Status Code: %d\n", status_code);
        memset(temp, 0, BUFFER_SIZE);
    } else {
        printf("HTTP Status Code: %d\n", status_code);
        return ERR_HTTP_STATUS;
    }

    // Check if the response is chunked
    if (strstr(buffer, "\r\nTransfer-Encoding: chunked")) {
        is_chunked = 1;
    }

    // Check if the content type is HTML
    if (strstr(buffer, "\r\nContent-Type: text/html")) {
        is_html = 1;
        file_type = ".html";
        *url_type = "html";
    } else {
        *url_type = "unknown";  // Skip non-HTML content
        return ERR_FILE_TYPE;
    }

    // Process HTML content
    if (is_html) {
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

        // Save the HTML content
        char *body_start = strstr(response, "<body");
        if (body_start) {
            body_start = strchr(body_start, '>');
            if (body_start) {
                body_start += 1;
            }
        } else {
            body_start = response;
        }

        char *body_end = strstr(body_start, "</body>");
        if (body_end) {
            *body_end = '\0';
        }

        char filename[FILE_PATH];
        char *save_filename = sanitize_filename(url);
        snprintf(filename, sizeof(filename), "%s/%s%s", output_dir, save_filename, file_type);
        free(save_filename);

        FILE *fp = fopen(filename, "wb");
        if (fp) {
            fwrite(body_start, 1, strlen(body_start), fp);
            fclose(fp);
            printf("HTML Response saved to %s\n", filename);
        } else {
            fprintf(stderr, "Failed to save HTML response to file: %s\n", filename);
        }

        free(response);  
    }

    return SUCCESS;
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

int get_url(char *url, SSL_CTX *ctx, int depth, int count, char **final_url, char **url_type, CrawledData *crawled_data) {
    if (count > 10) {
        fprintf(stderr, "Max depth reached\n");
        return ERR_MAX_DEPTH;
    }

    char hostname[HOST_SIZE] = "";
    char path[PATH_SIZE] = "";
    char port[PORT_SIZE] = "";
    int is_https = 0, result;
    if (strncmp(url, "http://", 7) == 0) {
        sscanf(url, "http://%255[^:/]/%255[^\n]", hostname, path);
    } else if (strncmp(url, "https://", 8) == 0) {
        sscanf(url, "https://%255[^/]/%255[^\n]", hostname, path);
        is_https = 1;
    } else {
        fprintf(stderr, "Invalid URL scheme\n");
        return ERR_FETCH_URL;
    }

    is_https == 0 ? strcpy(port, "80") : strcpy(port, "443");
    if (strlen(path) == 0) strcpy(path, "/");
    int sockfd = create_socket(hostname, port);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    char *new_location = NULL;
    char buffer[BUFFER_SIZE], temp[BUFFER_SIZE];
    int bytes;
    int is_chunked = 0;

    char request[REQUEST_SIZE];
    snprintf(request, sizeof(request),
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: Mozilla/7.64.1\r\n"
            "Connection: close\r\n\r\n", path, hostname);

    if (is_https) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        SSL_set_tlsext_host_name(ssl, hostname);
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sockfd);
            return ERR_SSL_CONNECT;
        }
        
        SSL_write(ssl, request, strlen(request));
        result = read_response(1, ssl, sockfd, url, depth, temp, url_type, crawled_data);
        SSL_free(ssl);
    } else {
        send(sockfd, request, strlen(request), 0);
        result = read_response(0, NULL, sockfd, url, depth, temp, url_type, crawled_data);
    }

    close(sockfd);

    if (result == ERR_FETCH_URL) {
        char *location = strstr(temp, "Location: ");
        if (location) {
            location += 10;
            char *end = strchr(location, '\r');
            if (!end) {
                end = strchr(location, '\n');
            }
            if (end) {
                new_location = strndup(location, end - location);
                char *redirect_url;
                if (new_location[0] == '/') {
                    char base_url[256];
                    snprintf(base_url, sizeof(base_url), "%s://%s", is_https ? "https" : "http", hostname);
                    redirect_url = malloc(strlen(base_url) + strlen(new_location) + 1);
                    strcpy(redirect_url, base_url);
                    strcat(redirect_url, new_location);
                } else {
                    redirect_url = strdup(new_location);
                }
                get_url(redirect_url, ctx, depth, count + 1, final_url, url_type, crawled_data);
                free(redirect_url);
                free(new_location);
            }
        }
    }

    if (result == SUCCESS) {
        *final_url = strdup(url);
    }

    return SUCCESS;
}

int get_and_parse(char *url, int depth, SSL_CTX *ctx, CrawledData *crawled_data, sem_t *sem) {
    printf("Connecting to %s...\n", url);
    int count = 0;
    char *final_url = NULL;
    char *url_type = NULL;
    int result = get_url(url, ctx, depth, count, &final_url, &url_type, crawled_data);
    if (result == SUCCESS) {
        sem_wait(sem);
        for (int i = 0; i < crawled_data->crawled_count; i++) {
            if (strcmp(crawled_data->crawled_urls[i], url) == 0) {
                crawled_data->status[i] = 3;
                printf("crawled: %s\n", crawled_data->crawled_urls[i]);
                break;
            }
        }
        sem_post(sem);
    }

    if (strcmp(url_type, "html") == 0 && depth < MAX_DEPTH) {
        char *read_filename = sanitize_filename(final_url);
        if (read_filename == NULL) {
            fprintf(stderr, "Filename sanitization failed\n");
            return ERR_OUT_OF_MEM;
        }

        char filepath[FILE_PATH];
        snprintf(filepath, sizeof(filepath), "%s/depth_%d_%s.html", output_dir, depth, read_filename);
        free(read_filename);

        FILE *file = fopen(filepath, "r");
        if (!file) {
            fprintf(stderr, "Error opening file: %s\n", filepath);
            return ERR_OPEN_FILE;
        }

        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *response = malloc(file_size + 1);
        if (!response) {
            fprintf(stderr, "Error allocating memory\n");
            fclose(file);
            return ERR_OUT_OF_MEM;
        }

        fread(response, 1, file_size, file);
        response[file_size] = '\0';

        parse_html(response, depth, final_url, crawled_data, sem);

        free(response);
        fclose(file);
    }

    return SUCCESS;
}

void child_process (SSL_CTX *ctx, CrawledData *crawled_data, int id, sem_t *sem) {
    while (1) {
        sem_wait(sem);
        char *url_to_crawl = NULL;
        int depth;
        int can_crawl = 0;
        int all_crawled = 1;
        for (int i = 0; i < crawled_data->crawled_count; i++) {
            if (crawled_data->status[i] != 3) {
                all_crawled = 0;
            }

            if (crawled_data->status[i] == 1) {
                url_to_crawl = crawled_data->crawled_urls[i];
                depth = crawled_data->depth[i];
                crawled_data->status[i] = 2;
                can_crawl = 1;
                break;
            }
        }
        sem_post(sem);

        if (all_crawled == 1) {
            printf("Child %d: All URLS have been crawled.\n", id);
            break;
        }
        
        if (url_to_crawl && can_crawl == 1) {
            printf("Child %d processing URL: %s\n", id, url_to_crawl);
            get_and_parse(url_to_crawl, depth, ctx, crawled_data, sem);
        } else {
            sleep(3);
        }
    }
    exit(SUCCESS);
}

int get_url_content(char *url, char *dir) {
    // Create shared memory
    sem_unlink(SEM_NAME);
    shm_unlink(SHM_NAME);

    output_dir = dir; 

    int shm_fd = shm_open("/crawled_data", O_CREAT | O_RDWR, 0700);
    if (shm_fd == -1) {
        fprintf(stderr, "Failed to open shared memory: %s\n", strerror(errno));
        return ERR_OPEN_SHARED_MEMORY;
    }

    if (ftruncate(shm_fd, sizeof(CrawledData)) == -1) {
        fprintf(stderr, "Failed to resize shared memory: %s\n", strerror(errno));
        shm_unlink("/crawled_data");
        return ERR_RESIZE_SHARED_MEMORY;
    }

    crawled_data = mmap(NULL, sizeof(CrawledData), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (crawled_data == MAP_FAILED) {
        fprintf(stderr, "Failed to map shared memory: %s\n", strerror(errno));
        shm_unlink("/crawled_data");
        return ERR_MAP_SHARED_MEMORY;
    }
    memset(crawled_data, 0, sizeof(CrawledData));

    // Create semaphore
    sem_unlink("/crawled_data_sem");
    sem = sem_open("/crawled_data_sem", O_CREAT | O_EXCL, 0700, 1);
    if (sem == SEM_FAILED) {
        fprintf(stderr, "Failed to open existing semaphore.\n");
        munmap(crawled_data, sizeof(CrawledData));
        shm_unlink("/crawled_data");
        return ERR_SEM_OPEN;
    }

    // Prepare SSL context
    SSL_CTX *ctx = create_ssl_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        sem_close(sem);
        sem_unlink("/crawled_data_sem");
        munmap(crawled_data, sizeof(CrawledData));
        shm_unlink("/crawled_data");
        return ERR_SSL_CONNECT;
    }

    // Create the output directory
    if (mk_dir(output_dir) != SUCCESS) {
        fprintf(stderr, "Failed to create output directory\n");
        SSL_CTX_free(ctx);
        sem_close(sem);
        sem_unlink("/crawled_data_sem");
        munmap(crawled_data, sizeof(CrawledData));
        shm_unlink("/crawled_data");
        return ERR_CREATE_DIR;
    }

    // Set the first URL in CrawledData
    sem_wait(sem);
    strcpy(crawled_data->crawled_urls[crawled_data->crawled_count], url);
    crawled_data->status[crawled_data->crawled_count] = 1;
    crawled_data->depth[crawled_data->crawled_count] = 1;
    crawled_data->crawled_count++;
    sem_post(sem);

    // Create child processes to handle URL crawling
    pid_t pid[MAX_CHILD];
    int active_child_process = 0;

    for (int i = 0; i < MAX_CHILD; i++) {
        pid[i] = fork();
        if (pid[i] == -1) {
            fprintf(stderr, "Failed to fork\n");
            // Cleanup
            for (int j = 0; j < i; j++) {
                kill(pid[j], SIGTERM);
            }
            SSL_CTX_free(ctx);
            sem_close(sem);
            sem_unlink("/crawled_data_sem");
            shm_unlink("/crawled_data");
            munmap(crawled_data, sizeof(CrawledData));
            return ERR_FORK;
        } else if (pid[i] == 0) {
            // Child process function
            child_process(ctx, crawled_data, i + 1, sem);
        } else {
            active_child_process++;
        }
    }

    // Monitor child processes
    while (active_child_process > 0) {
        sem_wait(sem);
        for (int i = 0; i < crawled_data->crawled_count; i++) {
            if (crawled_data->status[i] == 0) {
                crawled_data->status[i] = 1;
            }
        }
        sem_post(sem);

        for (int i = 0; i < MAX_CHILD; i++) {
            int status;
            pid_t result = waitpid(pid[i], &status, WNOHANG);
            if (result == -1) {
                fprintf(stderr, "waitpid\n");
            } else if (result > 0) {
                printf("Child process %d (PID: %d) has terminated.\n", i + 1, pid[i]);
                active_child_process--;
            }
        }
        sleep(2);
    }

    // Clean up
    SSL_CTX_free(ctx);
    sem_close(sem);
    sem_unlink("/crawled_data_sem");
    munmap(crawled_data, sizeof(CrawledData));
    shm_unlink("/crawled_data");
    EVP_cleanup();
    return SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <URL> <output_directory>\n", argv[0]);
        return ERR_PARAM;
    }

    char *start_url = argv[1];
    char *output_directory = argv[2];

    int result = get_url_content(start_url, output_directory);
    if (result != SUCCESS) {
        fprintf(stderr, "Failed to fetch URL content\n");
        return result;
    }

    return SUCCESS;
}
